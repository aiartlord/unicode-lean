{-|
Module      : Unicode.Security.Crypto.AiWatermarkDetectability
Description : Character-level detector for AI-watermark codepoint patterns.

Haskell port of @Unicode.Security.Crypto.AiWatermarkDetectability@ from
unicode-lean, transliterated from the verified Rust reference
implementation.

Answers the question: does this input contain markers attributable to a
watermarking protocol? The threat model is a provenance-attribution
attacker — an input either carries an AI provider's watermark codepoints
(a legitimate provenance marker) or carries injected markers that
impersonate a provider's scheme to discredit the content as AI-generated.
Character-level detection alone cannot distinguish the two; the detector
reports the matched scheme and leaves provider-specific authentication to
downstream code.

Ten probes run in a fixed priority order (most-specific first, first hit
wins):

  1. @adversarial@              — NNBSP count >= 3 at arithmetic-progression positions.
  2. @gpt5ZwspModulo@           — ZWSP count >= 3 at arithmetic-progression positions.
  3. @unknown@                  — invisible markers from >= 2 distinct categories.
  4. @nnbspBoundary@            — single-category NNBSP.
  5. @variationSelectorCarrier@ — VS NOT adjacent to an emoji codepoint.
  6. @zwjNonEmoji@              — ZWJ NOT adjacent to an emoji codepoint.
  7. @smartQuoteAlternation@    — paired curly quotes, no ASCII straight quotes.
  8. @emDashPattern@            — em-dashes, no ASCII hyphen-minus.
  9. @statisticalTokenChoice@   — input contains an AI-favored lexical pattern.
 10. @defaultIgnorableCarrier@  — single-category residual Default_Ignorable.

The Emoji property table is bundled in the port's own @data/emoji-data.txt@
(UTS #51 17.0, byte-identical to the UCD source the Lean spec cites); the
adjacency probe parses the @Emoji@ rows from it through the same NOINLINE
runtime-table idiom the rest of the security layer uses, never a host emoji
library. The Default_Ignorable predicate is the port's own
'Unicode.Security.Policy.isDefaultIgnorableCodepoint', never a host
normalizer.
-}
module Unicode.Security.Crypto.AiWatermarkDetectability
  ( CueClass (GreenListBias, PseudorandomSeq, SemanticDrift)
  , SubThreat
      ( NnbspBoundary, VariationSelectorCarrier, ZwjNonEmoji
      , DefaultIgnorableCarrier, Gpt5ZwspModulo, EmDashPattern
      , SmartQuoteAlternation, StatisticalTokenChoice, Adversarial, Unknown
      )
  , subThreatTag
  , subThreatCueClass
  , Classification (Clear, Hazard)
  , classificationIsClear
  , classificationTag
  , classificationPositions
  , Verdict (Verdict, verdictInput, verdictClassify, verdictMarkerCount)
  , Context (Context, contextZwspModuloTolerance, contextAdversarialTolerance)
  , defaultContext
  , detectWithContext
  , detect
  ) where

import Data.Char (isSpace)
import Data.List (dropWhileEnd, isPrefixOf)
import Data.Maybe (listToMaybe, mapMaybe)
import Numeric (readHex)
import System.IO.Unsafe (unsafePerformIO)

import Paths_unicode_haskell (getDataFileName)
import Unicode.Security.Policy (isDefaultIgnorableCodepoint)

-- ─────────────────────────────────────────────────────────────────────
-- §1 Types
-- ─────────────────────────────────────────────────────────────────────

-- | The conceptual watermark cue class a sub-threat probes for, drawn from
-- the fixed vocabulary the Lean spec pins in
-- @Unicode.Generated.WatermarkSchemes.CueClass@. Ported inline because the
-- port exposes no generated watermark-schemes module.
data CueClass
  = -- | A codepoint-frequency bias toward a pinned "green list" of tokens.
    GreenListBias
  | -- | A fixed-period or carrier-byte channel surfacing a pseudorandom
    -- function.
    PseudorandomSeq
  | -- | A stylistic-distribution drift away from natural human writing.
    SemanticDrift
  deriving stock (Eq, Show)

-- | Sub-threats this detector can fire. Each variant has a corresponding
-- probe in 'detectWithContext'; the payload carries the position value the
-- conformance harness's attribution column reads back.
data SubThreat
  = -- | Single-category NNBSP (U+202F) markers; the 'Int' is how many.
    NnbspBoundary Int
  | -- | Variation selector(s) not adjacent to an emoji; the 'Int' is how many.
    VariationSelectorCarrier Int
  | -- | ZWJ(s) not adjacent to an emoji; the 'Int' is how many.
    ZwjNonEmoji Int
  | -- | Residual Default_Ignorable markers; the 'Int' is how many.
    DefaultIgnorableCarrier Int
  | -- | ZWSP (U+200B) markers at arithmetic-progression positions; the 'Int'
    -- is the first ZWSP position.
    Gpt5ZwspModulo Int
  | -- | Em-dash (U+2014) stylistic signature; the 'Int' is the first em-dash.
    EmDashPattern Int
  | -- | Paired curly-quote stylistic signature; the 'Int' is the first quote.
    SmartQuoteAlternation Int
  | -- | AI-favored lexical pattern hit; the 'Int' is the match start.
    StatisticalTokenChoice Int
  | -- | Over-regular marker placement impersonating a scheme. Fields: the
    -- name of the surfaced scheme, then the first marker position.
    Adversarial String Int
  | -- | Multi-category invisible-marker mixing; the 'Int' is the total
    -- invisible-marker count (attribution to a single scheme fails).
    Unknown Int
  deriving stock (Eq, Show)

-- | Human-facing classification tag for this sub-threat.
subThreatTag :: SubThreat -> String
subThreatTag (NnbspBoundary _count)            = "NnbspBoundary"
subThreatTag (VariationSelectorCarrier _count) = "VariationSelectorCarrier"
subThreatTag (ZwjNonEmoji _count)              = "ZwjNonEmoji"
subThreatTag (DefaultIgnorableCarrier _count)  = "DefaultIgnorableCarrier"
subThreatTag (Gpt5ZwspModulo _pos)             = "Gpt5ZwspModulo"
subThreatTag (EmDashPattern _pos)              = "EmDashPattern"
subThreatTag (SmartQuoteAlternation _pos)      = "SmartQuoteAlternation"
subThreatTag (StatisticalTokenChoice _pos)     = "StatisticalTokenChoice"
subThreatTag (Adversarial _scheme _pos)        = "Adversarial"
subThreatTag (Unknown _anomaly)                = "Unknown"

-- | Map this sub-threat to the conceptual watermark cue class it probes for.
-- Marker-encoded sub-threats route to 'PseudorandomSeq'; vocabulary-bias to
-- 'GreenListBias'; stylistic-distribution to 'SemanticDrift'; 'Unknown'
-- (multi-category mixing) implicates no single scheme.
subThreatCueClass :: SubThreat -> Maybe CueClass
subThreatCueClass (NnbspBoundary _count)            = Just PseudorandomSeq
subThreatCueClass (VariationSelectorCarrier _count) = Just PseudorandomSeq
subThreatCueClass (ZwjNonEmoji _count)              = Just PseudorandomSeq
subThreatCueClass (DefaultIgnorableCarrier _count)  = Just PseudorandomSeq
subThreatCueClass (Gpt5ZwspModulo _pos)             = Just PseudorandomSeq
subThreatCueClass (EmDashPattern _pos)              = Just SemanticDrift
subThreatCueClass (SmartQuoteAlternation _pos)      = Just SemanticDrift
subThreatCueClass (StatisticalTokenChoice _pos)     = Just GreenListBias
subThreatCueClass (Adversarial _scheme _pos)        = Just PseudorandomSeq
subThreatCueClass (Unknown _anomaly)                = Nothing

-- | Top-level AiWatermarkDetectability classification.
data Classification
  = -- | No watermark marker detected (semantically @noWatermark@).
    Clear
  | -- | A hazard: the fired sub-threat plus the implicated marker positions.
    Hazard SubThreat [Int]
  deriving stock (Eq, Show)

-- | True iff no watermark marker was detected.
classificationIsClear :: Classification -> Bool
classificationIsClear Clear            = True
classificationIsClear (Hazard _sub _p) = False

-- | Human-facing tag for a hazard, or 'Nothing' when clear.
classificationTag :: Classification -> Maybe String
classificationTag Clear             = Nothing
classificationTag (Hazard sub _pos) = Just (subThreatTag sub)

-- | Implicated positions ('[]' when clear).
classificationPositions :: Classification -> [Int]
classificationPositions Clear                    = []
classificationPositions (Hazard _sub positions)  = positions

-- | Verdict — the structured output of 'detect'. 'verdictMarkerCount' is the
-- count of codepoints matching the fired scheme's probe (0 when clear).
data Verdict = Verdict
  { verdictInput       :: ![Int]
  , verdictClassify    :: !Classification
  , verdictMarkerCount :: !Int
  }
  deriving stock (Eq, Show)

-- | Optional context for the modulo-probe tolerances. Each field controls
-- how strictly the corresponding probe checks its arithmetic-progression
-- condition; the defaults of @0@ require exact equality of consecutive gaps.
data Context = Context
  { -- | ZWSP-modulo tolerance. @0@ requires the ZWSP-position arithmetic
    -- progression to be exact. @k > 0@ accepts position gaps within +/- k of
    -- the first gap, catching modulo schedules with light jitter.
    contextZwspModuloTolerance :: !Int
    -- | NNBSP-arithmetic tolerance (the @adversarial@ probe). Same semantic
    -- as 'contextZwspModuloTolerance' but for the NNBSP positions.
  , contextAdversarialTolerance :: !Int
  }
  deriving stock (Eq, Show)

-- | The empty context — exact-arithmetic settings
-- (@contextZwspModuloTolerance = 0@, @contextAdversarialTolerance = 0@).
defaultContext :: Context
defaultContext = Context
  { contextZwspModuloTolerance  = 0
  , contextAdversarialTolerance = 0
  }

-- ─────────────────────────────────────────────────────────────────────
-- §2 Emoji property table (bundled data/emoji-data.txt, Emoji rows)
-- ─────────────────────────────────────────────────────────────────────

-- | The @Emoji@ (@Emoji=Yes@) closed intervals parsed once from
-- @data/emoji-data.txt@ at first use, through the NOINLINE runtime-table
-- idiom the rest of the security layer uses.
emojiRanges :: [(Int, Int)]
emojiRanges = unsafePerformIO $ do
  path <- getDataFileName "data/emoji-data.txt"
  parseEmojiRanges <$> readFile path
{-# NOINLINE emojiRanges #-}

-- | Parse the @Emoji@ (@Emoji=Yes@) closed intervals from emoji-data.txt.
-- Each non-comment row is @\<range\> ; \<property\> # \<comment\>@; only rows
-- whose property is exactly @Emoji@ are kept.
parseEmojiRanges :: String -> [(Int, Int)]
parseEmojiRanges = mapMaybe parseEmojiLine . lines

-- | Parse one emoji-data.txt row into its @Emoji@ interval, or 'Nothing' when
-- the row is blank, a comment, or a non-@Emoji@ property.
parseEmojiLine :: String -> Maybe (Int, Int)
parseEmojiLine raw =
  let body     = takeWhile (/= '#') raw
      stripped = trim body
  in if null stripped
       then Nothing
       else case splitSemicolon stripped of
              (rangeField, propField)
                | trim propField == "Emoji" -> parseRange (trim rangeField)
                | otherwise                 -> Nothing

-- | Split on the first @;@ into (before, after). When no @;@ is present the
-- whole string is the first field and the second is empty (which fails the
-- @Emoji@ property check upstream).
splitSemicolon :: String -> (String, String)
splitSemicolon s =
  case break (== ';') s of
    (before, ';' : after) -> (before, after)
    (before, _noSemi)     -> (before, "")

-- | Parse a @range@ field — either @lo..hi@ or a single @cp@ — as a closed
-- hex interval.
parseRange :: String -> Maybe (Int, Int)
parseRange field =
  case splitDotDot field of
    Just (lo, hi) -> (,) <$> parseHex (trim lo) <*> parseHex (trim hi)
    Nothing       -> fmap (\cp -> (cp, cp)) (parseHex field)

-- | Split on the first @..@ into (before, after), or 'Nothing' when absent.
splitDotDot :: String -> Maybe (String, String)
splitDotDot = go []
  where
    go _acc []                    = Nothing
    go acc ('.' : '.' : rest)     = Just (reverse acc, rest)
    go acc (c : rest)             = go (c : acc) rest

-- | Parse a whole hex literal, or 'Nothing' on any trailing junk.
parseHex :: String -> Maybe Int
parseHex s =
  case readHex (trim s) of
    [(n, "")] -> Just n
    _other    -> Nothing

-- | Strip leading and trailing ASCII/Unicode whitespace.
trim :: String -> String
trim = dropWhileEnd isSpace . dropWhile isSpace

-- | True iff @cp@ has the @Emoji = Yes@ property per emoji-data.txt.
isEmoji :: Int -> Bool
isEmoji cp = any (\(lo, hi) -> lo <= cp && cp <= hi) emojiRanges

-- ─────────────────────────────────────────────────────────────────────
-- §3 Codepoint probes
-- ─────────────────────────────────────────────────────────────────────

-- | True iff @cp@ is U+202F NARROW NO-BREAK SPACE.
isNnbsp :: Int -> Bool
isNnbsp cp = cp == 0x202F

-- | True iff @cp@ is U+200D ZERO WIDTH JOINER.
isZwj :: Int -> Bool
isZwj cp = cp == 0x200D

-- | True iff @cp@ is a Variation Selector — the basic block U+FE00..U+FE0F
-- (VS1..VS16) or the Plane-14 IVS block U+E0100..U+E01EF (VS17..VS256).
isVariationSelector :: Int -> Bool
isVariationSelector cp =
  (0xFE00 <= cp && cp <= 0xFE0F) || (0xE0100 <= cp && cp <= 0xE01EF)

-- | True iff @cp@ is Default_Ignorable_Code_Point. Reuses the port's own UCD
-- predicate 'isDefaultIgnorableCodepoint', never a host normalizer.
isDefaultIgnorable :: Int -> Bool
isDefaultIgnorable = isDefaultIgnorableCodepoint

-- | True iff @cp@ is U+200B ZERO WIDTH SPACE.
isZwsp :: Int -> Bool
isZwsp cp = cp == 0x200B

-- | True iff @cp@ is U+2014 EM DASH.
isEmDash :: Int -> Bool
isEmDash cp = cp == 0x2014

-- | True iff @cp@ is U+002D HYPHEN-MINUS (ASCII).
isHyphenMinus :: Int -> Bool
isHyphenMinus cp = cp == 0x002D

-- | True iff @cp@ is one of the four "curly" quotation marks: U+2018 / U+2019
-- (single open/close) and U+201C / U+201D (double open/close).
isCurlyQuote :: Int -> Bool
isCurlyQuote cp = cp == 0x2018 || cp == 0x2019 || cp == 0x201C || cp == 0x201D

-- | True iff @cp@ is an ASCII straight quote — U+0022 (double) or U+0027
-- (single / apostrophe).
isStraightQuote :: Int -> Bool
isStraightQuote cp = cp == 0x0022 || cp == 0x0027

-- | Codepoint at index @i@ of @input@, or 'Nothing' when @i@ is out of range.
-- Total; never uses the partial @!!@.
codepointAt :: [Int] -> Int -> Maybe Int
codepointAt input i
  | i < 0     = Nothing
  | otherwise = listToMaybe (drop i input)

-- | True iff @input[i]@ is adjacent (immediate predecessor OR immediate
-- successor) to an emoji codepoint. Two-sided check. Used by the VS and ZWJ
-- probes to exclude legitimate emoji-context occurrences.
isAdjacentToEmoji :: [Int] -> Int -> Bool
isAdjacentToEmoji input i = prevIsEmoji || nextIsEmoji
  where
    prevIsEmoji = case i of
      0        -> False
      _nonzero -> maybe False isEmoji (codepointAt input (i - 1))
    nextIsEmoji = maybe False isEmoji (codepointAt input (i + 1))

-- | All positions in @input@ matching predicate @p@ (ascending).
allPositions :: (Int -> Bool) -> [Int] -> [Int]
allPositions p input = [ idx | (idx, cp) <- zip [0 ..] input, p cp ]

-- | True iff @positions@ forms an arithmetic progression with all consecutive
-- gaps within @tolerance@ of the first gap. Empty and singleton lists are
-- vacuously arithmetic. @positions@ is assumed ascending (produced by
-- 'allPositions'), so gaps are non-negative.
positionsAreArithmeticWithin :: [Int] -> Int -> Bool
positionsAreArithmeticWithin positions tolerance =
  case positions of
    (p0 : p1 : _rest) ->
      let firstGap = p1 - p0
          gaps     = zipWith (-) (drop 1 positions) positions
      in all (\gap -> gap <= firstGap + tolerance && firstGap <= gap + tolerance) gaps
    _fewerThanTwo -> True

-- | First start-position at which @pattern@ appears as a contiguous
-- sub-slice of @input@, or 'Nothing' if absent.
containsSublist :: [Int] -> [Int] -> Maybe Int
containsSublist pattern input
  | null pattern || length pattern > length input = Nothing
  | otherwise =
      let maxStart = length input - length pattern
      in listToMaybe
           [ start | start <- [0 .. maxStart], pattern `isPrefixOf` drop start input ]

-- | The "AI-favored" lexical-pattern catalog (each word as its codepoint
-- sequence), transcribed verbatim from the pinned @aiFavoredVocabulary@
-- literal in the Lean spec (parsed from @Ucd/Security/AiFavoredVocabulary.txt@
-- and drift-gated there against a fresh parse).
aiFavoredVocabulary :: [[Int]]
aiFavoredVocabulary =
  [ [100, 101, 108, 118, 101]
  , [100, 101, 108, 118, 105, 110, 103]
  , [116, 97, 112, 101, 115, 116, 114, 121]
  , [105, 110, 116, 114, 105, 99, 97, 116, 101]
  , [110, 117, 97, 110, 99, 101, 100]
  , [109, 111, 114, 101, 111, 118, 101, 114]
  , [102, 117, 114, 116, 104, 101, 114, 109, 111, 114, 101]
  , [114, 101, 97, 108, 109]
  , [101, 108, 117, 99, 105, 100, 97, 116, 101]
  , [115, 104, 111, 119, 99, 97, 115, 105, 110, 103]
  , [117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 115]
  , [117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 100]
  , [112, 105, 118, 111, 116, 97, 108]
  , [98, 111, 108, 115, 116, 101, 114]
  , [109, 117, 108, 116, 105, 102, 97, 99, 101, 116, 101, 100]
  , [116, 101, 115, 116, 97, 109, 101, 110, 116]
  , [102, 111, 115, 116, 101, 114]
  , [104, 111, 108, 105, 115, 116, 105, 99]
  , [112, 97, 114, 97, 100, 105, 103, 109]
  , [116, 114, 97, 110, 115, 102, 111, 114, 109, 97, 116, 105, 118, 101]
  , [115, 112, 101, 97, 114, 104, 101, 97, 100]
  , [109, 101, 116, 105, 99, 117, 108, 111, 117, 115]
  , [109, 101, 116, 105, 99, 117, 108, 111, 117, 115, 108, 121]
  , [101, 109, 112, 111, 119, 101, 114]
  , [101, 109, 112, 111, 119, 101, 114, 105, 110, 103]
  , [112, 114, 111, 102, 111, 117, 110, 100]
  , [112, 114, 111, 102, 111, 117, 110, 100, 108, 121]
  , [99, 111, 109, 112, 101, 108, 108, 105, 110, 103]
  , [99, 111, 109, 112, 114, 101, 104, 101, 110, 115, 105, 118, 101]
  , [99, 114, 117, 99, 105, 97, 108]
  , [100, 97, 117, 110, 116, 105, 110, 103]
  , [114, 111, 98, 117, 115, 116]
  , [115, 116, 114, 101, 97, 109, 108, 105, 110, 101]
  , [101, 110, 114, 105, 99, 104]
  , [101, 120, 101, 109, 112, 108, 105, 102, 121]
  , [99, 97, 112, 116, 105, 118, 97, 116, 105, 110, 103]
  , [100, 105, 115, 99, 101, 114, 110, 105, 110, 103]
  , [109, 101, 115, 109, 101, 114, 105, 122, 101]
  , [105, 110, 116, 114, 105, 99, 97, 116, 101, 108, 121]
  , [105, 109, 98, 117, 101]
  , [ 112, 108, 97, 121, 115, 32, 97, 32, 99, 114, 117, 99, 105, 97, 108, 32, 114, 111, 108
    , 101
    ]
  , [ 112, 108, 97, 121, 115, 32, 97, 32, 112, 105, 118, 111, 116, 97, 108, 32, 114, 111
    , 108, 101
    ]
  , [ 105, 116, 32, 105, 115, 32, 105, 109, 112, 111, 114, 116, 97, 110, 116, 32, 116, 111
    , 32, 110, 111, 116, 101
    ]
  , [ 105, 116, 32, 105, 115, 32, 119, 111, 114, 116, 104, 32, 110, 111, 116, 105, 110, 103
    ]
  , [105, 110, 32, 99, 111, 110, 99, 108, 117, 115, 105, 111, 110]
  , [105, 110, 32, 101, 115, 115, 101, 110, 99, 101]
  , [100, 101, 108, 118, 101, 32, 105, 110, 116, 111]
  , [100, 101, 108, 118, 105, 110, 103, 32, 105, 110, 116, 111]
  , [116, 97, 112, 101, 115, 116, 114, 121, 32, 111, 102]
  , [114, 101, 97, 108, 109, 32, 111, 102]
  ]

-- ─────────────────────────────────────────────────────────────────────
-- §4 Top-level detection
-- ─────────────────────────────────────────────────────────────────────

-- | The detection function. Runs every probe in the fixed priority order
-- (most-specific first); the first hit wins. See the module header for the
-- probe inventory and the ordering rationale.
detectWithContext :: Context -> [Int] -> Verdict
detectWithContext ctx input =
  Verdict
    { verdictInput       = input
    , verdictClassify    = classification
    , verdictMarkerCount = firedCount
    }
  where
    nnbspPositions = allPositions isNnbsp input
    nnbspCount     = length nnbspPositions

    -- Probe 1: adversarial — NNBSP too-regular.
    adversarialFires =
      nnbspCount >= 3
        && positionsAreArithmeticWithin nnbspPositions (contextAdversarialTolerance ctx)

    -- Probe 2: gpt5ZwspModulo — ZWSP arithmetic progression.
    zwspPositions = allPositions isZwsp input
    zwspCount     = length zwspPositions
    zwspModuloFires =
      zwspCount >= 3
        && positionsAreArithmeticWithin zwspPositions (contextZwspModuloTolerance ctx)

    vsAllPos       = allPositions isVariationSelector input
    vsNonEmojiPos  = filter (\i -> not (isAdjacentToEmoji input i)) vsAllPos
    vsNonEmojiCount = length vsNonEmojiPos

    zwjAllPos       = allPositions isZwj input
    zwjNonEmojiPos  = filter (\i -> not (isAdjacentToEmoji input i)) zwjAllPos
    zwjNonEmojiCount = length zwjNonEmojiPos

    -- Probe 7: smartQuoteAlternation — curly quotes only.
    curlyPositions   = allPositions isCurlyQuote input
    curlyCount       = length curlyPositions
    hasStraightQuote = any isStraightQuote input
    smartQuoteFires  = curlyCount >= 2 && not hasStraightQuote

    -- Probe 8: emDashPattern — em-dashes without hyphen-minus.
    emDashPositions = allPositions isEmDash input
    emDashCount     = length emDashPositions
    hasHyphenMinus  = any isHyphenMinus input
    emDashFires     = emDashCount >= 2 && not hasHyphenMinus

    -- Probe 9: statisticalTokenChoice — scan the pinned vocabulary. Each word
    -- is compared as a contiguous sub-slice of the input; first hit wins.
    vocabHit = listToMaybe (mapMaybe (\pattern -> containsSublist pattern input) aiFavoredVocabulary)

    -- Residual default-ignorables (excluding VS and ZWJ, handled above).
    isResidualDi cp = isDefaultIgnorable cp && not (isVariationSelector cp) && not (isZwj cp)
    diPositions     = allPositions isResidualDi input
    diCount         = length diPositions

    -- Probe 3: unknown — invisible markers from >= 2 distinct categories.
    categoryCount =
      boolToInt (nnbspCount > 0)
        + boolToInt (vsNonEmojiCount > 0)
        + boolToInt (zwjNonEmojiCount > 0)
        + boolToInt (diCount > 0)
    unknownFires        = categoryCount >= 2
    totalInvisibleCount = nnbspCount + vsNonEmojiCount + zwjNonEmojiCount + diCount

    (classification, firedCount)
      | adversarialFires =
          ( Hazard (Adversarial "nnbspBoundary" (headOr0 nnbspPositions)) nnbspPositions
          , nnbspCount
          )
      | zwspModuloFires =
          ( Hazard (Gpt5ZwspModulo (headOr0 zwspPositions)) zwspPositions
          , zwspCount
          )
      | unknownFires =
          let allInvisiblePos =
                [ idx
                | (idx, cp) <- zip [0 ..] input
                , isNnbsp cp || isVariationSelector cp || isZwj cp || isDefaultIgnorable cp
                ]
          in ( Hazard (Unknown totalInvisibleCount) allInvisiblePos
             , totalInvisibleCount
             )
      | nnbspCount > 0 =
          ( Hazard (NnbspBoundary nnbspCount) nnbspPositions, nnbspCount )
      | vsNonEmojiCount > 0 =
          ( Hazard (VariationSelectorCarrier vsNonEmojiCount) vsNonEmojiPos, vsNonEmojiCount )
      | zwjNonEmojiCount > 0 =
          ( Hazard (ZwjNonEmoji zwjNonEmojiCount) zwjNonEmojiPos, zwjNonEmojiCount )
      | smartQuoteFires =
          ( Hazard (SmartQuoteAlternation (headOr0 curlyPositions)) curlyPositions, curlyCount )
      | emDashFires =
          ( Hazard (EmDashPattern (headOr0 emDashPositions)) emDashPositions, emDashCount )
      | otherwise =
          case vocabHit of
            Just pos -> ( Hazard (StatisticalTokenChoice pos) [pos], 1 )
            Nothing ->
              if diCount > 0
                then ( Hazard (DefaultIgnorableCarrier diCount) diPositions, diCount )
                else ( Clear, 0 )

-- | Convenience wrapper over 'detectWithContext' with the empty context —
-- exact-arithmetic settings (@contextZwspModuloTolerance = 0@,
-- @contextAdversarialTolerance = 0@).
detect :: [Int] -> Verdict
detect = detectWithContext defaultContext

-- | @1@ for 'True', @0@ for 'False' — the @usize::from(bool)@ the Rust probe
-- counts categories with.
boolToInt :: Bool -> Int
boolToInt True  = 1
boolToInt False = 0

-- | First element, or @0@ for an empty list — the @.first().unwrap_or(0)@ the
-- Rust probes use for the first-position payload.
headOr0 :: [Int] -> Int
headOr0 []        = 0
headOr0 (x : _xs) = x
