{-|
Module      : Unicode.Security.Identity.EmojiZwjIntegrity
Description : Detection of malformed / unsanctioned emoji ZWJ-sequence shapes.

Haskell port of @Unicode.Security.Identity.EmojiZwjIntegrity@ from
unicode-lean, transliterated byte-faithfully from the verified Rust reference
implementation (the identity-layer
detector I3).

Threat model. An adversary crafts an emoji-shaped codepoint sequence
containing one or more @U+200D@ ZERO WIDTH JOINERs but violating the
sanctioned RGI ZWJ-sequence shape — by exceeding the RGI length cap, by
joining a non-emoji codepoint, by emitting adjacent ZWJ pairs, or by
overflowing the skin-tone count. Any non-RGI ZWJ-containing sequence is
renderer-dependent, and that renderer divergence is the attack surface.

Sanctioning data. UTS #51 defines the RGI ZWJ sequences in
@emoji-zwj-sequences.txt@, bundled in the port's own
@data/emoji-zwj-sequences.txt@ (never a host emoji library) and parsed through
the same NOINLINE runtime-table idiom the rest of the security layer uses. The
registered set gives both the exact-match membership test
('isRegisteredZwjSequence') and the ZWJ /alphabet/ — every distinct codepoint
occurring at any position of any registered sequence, excluding the joiner —
which is the canonical "what may flank a ZWJ?" predicate ('isEmojiTarget').

Algorithm (one pass over @input@).

  * Phase 1 — collect ZWJ positions and the skin-tone count.
  * Phase 2 — short-circuit 'Clear' if there are no ZWJs and the skin-tone
    count is at most 1.
  * Phase 3 — a registered RGI sequence is always 'Clear'.
  * Phase 4 — check sub-threats by priority:

      1. 'DoubleZwj'            — ZWJ-ZWJ adjacency.
      2. 'NonEmojiInjection'    — ZWJ adjacent to a non-emoji codepoint.
      3. 'OverLength'           — sequence longer than the RGI cap.
      4. 'SkinToneOverflow'     — skin-tone count @>= 5@.
      5. 'UnregisteredSequence' — catch-all when ZWJs are present but the
                                  sequence is not registered.
-}
module Unicode.Security.Identity.EmojiZwjIntegrity
  ( maxRgiLength
  , zwj
  , SubThreat
      ( DoubleZwj, NonEmojiInjection, OverLength, SkinToneOverflow
      , UnregisteredSequence
      )
  , subThreatTag
  , Classification (Clear, Hazard)
  , classificationIsClear
  , classificationTag
  , classificationPositions
  , Verdict
      ( Verdict, verdictInput, verdictClassify, verdictZwjPositions
      , verdictChainLength, verdictIsRegisteredRgi, verdictSkinToneCount
      )
  , isRegisteredZwjSequence
  , isEmojiTarget
  , isZwj
  , isEmojiModifier
  , detect
  , reasonCode
  ) where

import Data.Char (isSpace)
import Data.List (dropWhileEnd)
import Data.Maybe (listToMaybe, mapMaybe)
import Data.Set (Set)
import qualified Data.Set as Set
import Numeric (readHex)
import System.IO.Unsafe (unsafePerformIO)

import Paths_unicode_haskell (getDataFileName)

-- ─────────────────────────────────────────────────────────────────────
-- §1 Constants
-- ─────────────────────────────────────────────────────────────────────

-- | Conservative cap on the length of a sanctioned RGI ZWJ sequence
-- (@maxRgiLength@ in the Lean spec). The longest current entry (a four-person
-- family with skin tones) reaches ~13-14 codepoints; 16 is a safe upper bound.
maxRgiLength :: Int
maxRgiLength = 16

-- | The ZERO WIDTH JOINER codepoint.
zwj :: Int
zwj = 0x200D

-- ─────────────────────────────────────────────────────────────────────
-- §2 Types
-- ─────────────────────────────────────────────────────────────────────

-- | Sub-threats this detector can fire, in priority order. Each payload
-- carries the position values the conformance harness's attribution column
-- reads back, mirroring the Rust @SubThreat@ variants field-for-field.
data SubThreat
  = -- | ZWJ-ZWJ adjacency; the '[Int]' holds the first ZWJ of each adjacent
    -- pair.
    DoubleZwj [Int]
  | -- | A ZWJ flanked by a non-emoji codepoint (or sitting at an input edge).
    -- Fields: position of the offending ZWJ, then the non-emoji codepoint that
    -- flanks it (@0@ for an edge ZWJ).
    NonEmojiInjection Int Int
  | -- | The sequence is longer than 'maxRgiLength'. Fields: the observed
    -- sequence length, then the RGI length cap that was exceeded.
    OverLength Int Int
  | -- | Five or more skin-tone modifiers (the family-emoji maximum is four);
    -- the 'Int' is the observed skin-tone modifier count.
    SkinToneOverflow Int
  | -- | ZWJs are present and no other sub-threat matched, but the sequence is
    -- not a registered RGI ZWJ sequence; the 'Int' is the length of the
    -- unregistered ZWJ chain.
    UnregisteredSequence Int
  deriving stock (Eq, Show)

-- | Fixture-row tag string for this sub-threat (matches @SubThreat.tag@).
subThreatTag :: SubThreat -> String
subThreatTag (DoubleZwj _positions)              = "DoubleZWJ"
subThreatTag (NonEmojiInjection _zwjPos _cp)     = "NonEmojiInjection"
subThreatTag (OverLength _length _maxLength)     = "OverLength"
subThreatTag (SkinToneOverflow _count)           = "SkinToneOverflow"
subThreatTag (UnregisteredSequence _chainLen)    = "UnregisteredSequence"

-- | Top-level classification for EmojiZwjIntegrity.
data Classification
  = -- | A well-formed or non-ZWJ input.
    Clear
  | -- | A hazard: the fired sub-threat, the implicated codepoint positions,
    -- and the decoded-byte projection (always @[]@ here; kept for shape parity
    -- with the Lean @Classification.hazard@).
    Hazard SubThreat [Int] [Int]
  deriving stock (Eq, Show)

-- | True iff the classification is 'Clear'.
classificationIsClear :: Classification -> Bool
classificationIsClear Clear                = True
classificationIsClear (Hazard _sub _p _d)  = False

-- | Human-facing tag for a hazard, or 'Nothing' when clear.
classificationTag :: Classification -> Maybe String
classificationTag Clear                   = Nothing
classificationTag (Hazard sub _pos _dec)  = Just (subThreatTag sub)

-- | Implicated positions ('[]' when clear).
classificationPositions :: Classification -> [Int]
classificationPositions Clear                       = []
classificationPositions (Hazard _sub positions _d)  = positions

-- | Verdict — the structured output of 'detect' (mirrors the Lean @Verdict@).
data Verdict = Verdict
  { verdictInput           :: ![Int]
    -- ^ The scanned input codepoints.
  , verdictClassify        :: !Classification
    -- ^ The classification verdict.
  , verdictZwjPositions    :: ![Int]
    -- ^ Positions of every ZWJ in the input.
  , verdictChainLength     :: !Int
    -- ^ The chain length (@0@ when there are no ZWJs, else the input length).
  , verdictIsRegisteredRgi :: !Bool
    -- ^ True iff the input is exactly a registered RGI ZWJ sequence.
  , verdictSkinToneCount   :: !Int
    -- ^ Count of skin-tone modifier codepoints (@U+1F3FB@..@U+1F3FF@).
  }
  deriving stock (Eq, Show)

-- ─────────────────────────────────────────────────────────────────────
-- §3 RGI ZWJ-sequence data (bundled data/emoji-zwj-sequences.txt)
-- ─────────────────────────────────────────────────────────────────────

-- | The registered RGI ZWJ sequences parsed once from
-- @data/emoji-zwj-sequences.txt@ at first use, through the NOINLINE
-- runtime-table idiom the rest of the security layer uses.
zwjSequences :: [[Int]]
zwjSequences = unsafePerformIO $ do
  path <- getDataFileName "data/emoji-zwj-sequences.txt"
  parseZwjSequences <$> readFile path
{-# NOINLINE zwjSequences #-}

-- | Parse the registered RGI ZWJ sequences from @emoji-zwj-sequences.txt@.
-- Each non-comment row is @\<cp\> \<cp\> ... ; RGI_Emoji_ZWJ_Sequence ; \<desc\>@;
-- the codepoint list is the field before the first @;@.
parseZwjSequences :: String -> [[Int]]
parseZwjSequences = mapMaybe parseZwjLine . lines

-- | Parse one @emoji-zwj-sequences.txt@ row into its codepoint sequence, or
-- 'Nothing' when the row is blank, a comment, or carries a non-hex token (the
-- whole row is dropped on any parse failure, mirroring the Rust @break@).
parseZwjLine :: String -> Maybe [Int]
parseZwjLine raw =
  let body     = takeWhile (/= '#') raw
      stripped = trim body
  in if null stripped
       then Nothing
       else
         let seqField = takeWhile (/= ';') stripped
             tokens   = words seqField
         in case traverse parseHex tokens of
              Just cps | not (null cps) -> Just cps
              Just _empty               -> Nothing
              Nothing                   -> Nothing

-- | The ZWJ alphabet: every distinct codepoint occurring at any position of
-- any registered RGI ZWJ sequence, excluding the joiner @U+200D@ itself.
zwjAlphabet :: Set Int
zwjAlphabet =
  Set.fromList [ cp | codepoints <- zwjSequences, cp <- codepoints, cp /= zwj ]

-- | True iff @cps@ is exactly a registered RGI ZWJ sequence.
isRegisteredZwjSequence :: [Int] -> Bool
isRegisteredZwjSequence cps = any (== cps) zwjSequences

-- | True iff @cp@ appears at some position of a registered RGI ZWJ sequence
-- (the canonical "what may flank a ZWJ?" predicate).
isEmojiTarget :: Int -> Bool
isEmojiTarget cp = Set.member cp zwjAlphabet

-- ─────────────────────────────────────────────────────────────────────
-- §4 Core predicates
-- ─────────────────────────────────────────────────────────────────────

-- | True iff @cp@ is the ZWJ codepoint.
isZwj :: Int -> Bool
isZwj cp = cp == zwj

-- | True iff @cp@ is an emoji skin-tone modifier (@U+1F3FB@..@U+1F3FF@).
isEmojiModifier :: Int -> Bool
isEmojiModifier cp = 0x1F3FB <= cp && cp <= 0x1F3FF

-- | Positions of every ZWJ in @input@ (ascending).
zwjPositions :: [Int] -> [Int]
zwjPositions input = [ idx | (idx, cp) <- zip [0 ..] input, isZwj cp ]

-- | Count of skin-tone modifier codepoints.
skinToneCount :: [Int] -> Int
skinToneCount input = length (filter isEmojiModifier input)

-- | Positions of the first ZWJ in each ZWJ-ZWJ adjacent pair.
doubleZwjPositions :: [Int] -> [Int]
doubleZwjPositions input =
  [ idx
  | (idx, (cp, next)) <- zip [0 ..] (zip input (drop 1 input))
  , isZwj cp && isZwj next
  ]

-- | Codepoint at index @i@ of @input@, or 'Nothing' when @i@ is out of range.
-- Total; never uses the partial @!!@.
codepointAt :: [Int] -> Int -> Maybe Int
codepointAt input i
  | i < 0     = Nothing
  | otherwise = listToMaybe (drop i input)

-- | The first ZWJ position where either neighbour is a non-emoji codepoint, as
-- @(zwjPos, offendingCp)@. A ZWJ at an input edge (no preceding or no following
-- codepoint) is itself an injection-class hazard, reported with offending
-- codepoint @0@.
firstNonEmojiInjection :: [Int] -> Maybe (Int, Int)
firstNonEmojiInjection input = go 0 input
  where
    go :: Int -> [Int] -> Maybe (Int, Int)
    go _idx []           = Nothing
    go idx (cp : rest)
      | not (isZwj cp)   = go (idx + 1) rest
      | otherwise        =
          let prev = if idx == 0 then Nothing else codepointAt input (idx - 1)
              next = codepointAt input (idx + 1)
          in case (prev, next) of
               (Just prevCp, Just nextCp)
                 | not (isEmojiTarget prevCp) -> Just (idx, prevCp)
                 | not (isEmojiTarget nextCp) -> Just (idx, nextCp)
                 | otherwise                  -> go (idx + 1) rest
               (Nothing, _next)               -> Just (idx, 0)
               (Just _prevCp, Nothing)        -> Just (idx, 0)

-- ─────────────────────────────────────────────────────────────────────
-- §5 Top-level detection
-- ─────────────────────────────────────────────────────────────────────

-- | The EmojiZwjIntegrity detection function. See the module header for the
-- phase inventory and the sub-threat priority ladder.
detect :: [Int] -> Verdict
detect input =
  Verdict
    { verdictInput           = input
    , verdictClassify        = classification
    , verdictZwjPositions    = zwjs
    , verdictChainLength     = chainLen
    , verdictIsRegisteredRgi = isRgi
    , verdictSkinToneCount   = stCount
    }
  where
    zwjs     = zwjPositions input
    stCount  = skinToneCount input
    isRgi    = isRegisteredZwjSequence input
    chainLen = if null zwjs then 0 else length input

    classification
      -- Phase 2: no ZWJs and at most one skin tone is clear.
      | null zwjs && stCount <= 1 = Clear
      -- Phase 3: a registered RGI sequence is always clear.
      | isRgi                     = Clear
      | otherwise                 = phase4

    phase4 =
      let dzwj = doubleZwjPositions input
      in if not (null dzwj)
           -- Phase 4.1: ZWJ-ZWJ adjacency.
           then Hazard (DoubleZwj dzwj) dzwj []
           else case firstNonEmojiInjection input of
             -- Phase 4.2: ZWJ adjacent to a non-emoji codepoint.
             Just (zwjPos, offendCp) ->
               Hazard (NonEmojiInjection zwjPos offendCp) [zwjPos] []
             Nothing
               -- Phase 4.3: length cap.
               | length input > maxRgiLength ->
                   Hazard (OverLength (length input) maxRgiLength) [] []
               -- Phase 4.4: skin-tone overflow.
               | stCount >= 5 ->
                   Hazard (SkinToneOverflow stCount) [] []
               -- Phase 4.5: catch-all for unregistered ZWJ sequences.
               | not (null zwjs) ->
                   Hazard (UnregisteredSequence (length input)) zwjs []
               | otherwise -> Clear

-- | Fully-qualified reason code for a fired sub-threat, of the shape
-- @unicode.security.I.emoji-zwj-integrity.\<subThreatTag\>@. For
-- 'DoubleZwj' this is @unicode.security.I.emoji-zwj-integrity.DoubleZWJ@.
reasonCode :: SubThreat -> String
reasonCode sub = "unicode.security.I.emoji-zwj-integrity." ++ subThreatTag sub

-- ─────────────────────────────────────────────────────────────────────
-- §6 Parsing helpers
-- ─────────────────────────────────────────────────────────────────────

-- | Parse a whole hex literal, or 'Nothing' on any trailing junk.
parseHex :: String -> Maybe Int
parseHex s =
  case readHex s of
    [(n, "")] -> Just n
    _other    -> Nothing

-- | Strip leading and trailing whitespace.
trim :: String -> String
trim = dropWhileEnd isSpace . dropWhile isSpace
