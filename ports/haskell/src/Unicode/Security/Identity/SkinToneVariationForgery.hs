{-|
Module      : Unicode.Security.Identity.SkinToneVariationForgery
Description : Detection of skin-tone modifier and variation-selector abuse on emoji bases.

Haskell port of @Unicode.Security.Identity.SkinToneVariationForgery@ from
unicode-lean, transliterated byte-faithfully from the verified Rust reference
implementation (the identity-layer detector for skin-tone / variation-selector
misuse per UTS #51).

Threat model. Tier A₁. An adversary places a skin-tone modifier on a codepoint
that does NOT bear @Emoji_Modifier_Base@, stacks multiple skin tones on one
base, or forces a text-style render on an emoji-default codepoint via @U+FE0E@
(VS15) — sometimes to hide a payload-bearing glyph in plain sight.

Distinct from VariationSelectorPayload (pair-aligned VS runs that decode to
bytes): this catches the orthogonal case of /semantic/ VS / skin-tone misuse on
a single base. Both can fire on the same input.

Emoji property data. The detector reuses the port's own bundled emoji property
table (the same @data/emoji-data.txt@ that
"Unicode.Security.Crypto.AiWatermarkDetectability" reads), never a host emoji
library. The skin-tone modifier predicate is reused directly from
"Unicode.Security.Identity.EmojiZwjIntegrity" ('isEmojiModifier', the
@U+1F3FB@..@U+1F3FF@ set). Two further predicates are parsed from the same
already-bundled file through the shared property parser: 'isSkinToneBase'
(@Emoji_Modifier_Base@ rows) and 'isEmojiPresentation' (@Emoji_Presentation@
rows). No new data file is introduced.

Sub-threats (priority order):

  1. 'StackedSkinTones'      — a base immediately followed by >= 2 skin-tone modifiers.
  2. 'InvalidSkinToneTarget' — a skin-tone modifier on a non-@Emoji_Modifier_Base@.
  3. 'ForcedTextStyle'       — @U+FE0E@ on an @Emoji_Presentation@ codepoint.
-}
module Unicode.Security.Identity.SkinToneVariationForgery
  ( SubThreat (StackedSkinTones, InvalidSkinToneTarget, ForcedTextStyle)
  , subThreatTag
  , Classification (Clear, Hazard)
  , classificationIsClear
  , classificationTag
  , classificationPositions
  , Verdict
      ( Verdict, verdictInput, verdictClassify, verdictSkinToneCount
      , verdictVariationSelector15Count, verdictVariationSelector16Count
      )
  , isSkinTone
  , isSkinToneBase
  , isEmojiPresentation
  , isVs15
  , isVs16
  , detect
  , reasonCode
  ) where

import Data.Char (isSpace)
import Data.List (dropWhileEnd)
import Data.Maybe (listToMaybe, mapMaybe)
import Numeric (readHex)
import System.IO.Unsafe (unsafePerformIO)

import Paths_unicode_haskell (getDataFileName)
import Unicode.Security.Identity.EmojiZwjIntegrity (isEmojiModifier)

-- ─────────────────────────────────────────────────────────────────────
-- §1 Types
-- ─────────────────────────────────────────────────────────────────────

-- | Sub-threats this detector can fire, in priority order. Each payload
-- carries the position and codepoint values the conformance harness's
-- attribution column reads back, mirroring the Rust @SubThreat@ variants
-- field-for-field.
data SubThreat
  = -- | A base at the given position followed by >= 2 skin-tone modifiers.
    -- Fields: position of the base codepoint, then the first two stacked
    -- skin-tone modifier codepoints.
    StackedSkinTones Int [Int]
  | -- | A skin-tone modifier at @basePos + 1@ on a non-modifier-base. Fields:
    -- position of the (invalid) base, then the base codepoint that lacks
    -- @Emoji_Modifier_Base@, then the skin-tone modifier codepoint.
    InvalidSkinToneTarget Int Int Int
  | -- | A @U+FE0E@ at @basePos + 1@ forcing text-style on an
    -- @Emoji_Presentation@ codepoint. Fields: position of the
    -- @Emoji_Presentation@ codepoint, then that codepoint.
    ForcedTextStyle Int Int
  deriving stock (Eq, Show)

-- | Fixture-row tag string for this sub-threat (matches @SubThreat.tag@).
subThreatTag :: SubThreat -> String
subThreatTag (StackedSkinTones _basePos _modifiers)         = "StackedSkinTones"
subThreatTag (InvalidSkinToneTarget _basePos _base _mod)    = "InvalidSkinToneTarget"
subThreatTag (ForcedTextStyle _basePos _base)               = "ForcedTextStyle"

-- | Top-level classification for SkinToneVariationForgery.
data Classification
  = -- | No skin-tone / variation-selector abuse present.
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
  { verdictInput                    :: ![Int]
    -- ^ The scanned input codepoints.
  , verdictClassify                 :: !Classification
    -- ^ The classification verdict.
  , verdictSkinToneCount            :: !Int
    -- ^ Count of skin-tone modifier codepoints.
  , verdictVariationSelector15Count :: !Int
    -- ^ Count of @U+FE0E@ (VS15) codepoints.
  , verdictVariationSelector16Count :: !Int
    -- ^ Count of @U+FE0F@ (VS16) codepoints.
  }
  deriving stock (Eq, Show)

-- ─────────────────────────────────────────────────────────────────────
-- §2 Emoji property tables (bundled data/emoji-data.txt)
-- ─────────────────────────────────────────────────────────────────────

-- | The @Emoji_Modifier_Base@ closed intervals parsed once from the port's
-- bundled emoji property table at first use, through the NOINLINE
-- runtime-table idiom the rest of the security layer uses.
emojiModifierBaseRanges :: [(Int, Int)]
emojiModifierBaseRanges = unsafePerformIO $ do
  path <- getDataFileName "data/emoji-data.txt"
  parseEmojiProperty "Emoji_Modifier_Base" <$> readFile path
{-# NOINLINE emojiModifierBaseRanges #-}

-- | The @Emoji_Presentation@ closed intervals parsed once from the port's
-- bundled emoji property table at first use, through the same NOINLINE idiom.
emojiPresentationRanges :: [(Int, Int)]
emojiPresentationRanges = unsafePerformIO $ do
  path <- getDataFileName "data/emoji-data.txt"
  parseEmojiProperty "Emoji_Presentation" <$> readFile path
{-# NOINLINE emojiPresentationRanges #-}

-- | Parse the closed intervals for a single emoji property from the bundled
-- emoji property table. Each non-comment row is
-- @\<range\> ; \<property\> # \<comment\>@; only rows whose property field is
-- exactly @property@ are kept.
parseEmojiProperty :: String -> String -> [(Int, Int)]
parseEmojiProperty property = mapMaybe (parsePropertyLine property) . lines

-- | Parse one emoji property row into its interval when its property field
-- matches @property@, or 'Nothing' when the row is blank, a comment, or a
-- different property.
parsePropertyLine :: String -> String -> Maybe (Int, Int)
parsePropertyLine property raw =
  let body     = takeWhile (/= '#') raw
      stripped = trim body
  in if null stripped
       then Nothing
       else case splitSemicolon stripped of
              (rangeField, propField)
                | trim propField == property -> parseRange (trim rangeField)
                | otherwise                  -> Nothing

-- | Split on the first @;@ into (before, after). When no @;@ is present the
-- whole string is the first field and the second is empty (which fails the
-- property check upstream).
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
    go _acc []                = Nothing
    go acc ('.' : '.' : rest) = Just (reverse acc, rest)
    go acc (c : rest)         = go (c : acc) rest

-- | Parse a whole hex literal, or 'Nothing' on any trailing junk.
parseHex :: String -> Maybe Int
parseHex s =
  case readHex (trim s) of
    [(n, "")] -> Just n
    _other    -> Nothing

-- | Strip leading and trailing whitespace.
trim :: String -> String
trim = dropWhileEnd isSpace . dropWhile isSpace

-- ─────────────────────────────────────────────────────────────────────
-- §3 Core predicates (reuse the port's own emoji tables)
-- ─────────────────────────────────────────────────────────────────────

-- | True iff @cp@ is an emoji skin-tone modifier. Reuses the port's own
-- predicate ('isEmojiModifier', the @U+1F3FB@..@U+1F3FF@ set) from
-- "Unicode.Security.Identity.EmojiZwjIntegrity".
isSkinTone :: Int -> Bool
isSkinTone = isEmojiModifier

-- | True iff @cp@ has @Emoji_Modifier_Base@ per the bundled emoji property
-- table.
isSkinToneBase :: Int -> Bool
isSkinToneBase cp = any (\(lo, hi) -> lo <= cp && cp <= hi) emojiModifierBaseRanges

-- | True iff @cp@ has @Emoji_Presentation@ per the bundled emoji property
-- table.
isEmojiPresentation :: Int -> Bool
isEmojiPresentation cp = any (\(lo, hi) -> lo <= cp && cp <= hi) emojiPresentationRanges

-- | True iff @cp@ is @U+FE0E@ (VS15, text-style variation selector).
isVs15 :: Int -> Bool
isVs15 cp = cp == 0xFE0E

-- | True iff @cp@ is @U+FE0F@ (VS16, emoji-style variation selector).
isVs16 :: Int -> Bool
isVs16 cp = cp == 0xFE0F

-- ─────────────────────────────────────────────────────────────────────
-- §4 Sub-detectors
-- ─────────────────────────────────────────────────────────────────────

-- | First position @p@ whose next two codepoints are both skin-tone
-- modifiers, as @(basePos, [mod1, mod2])@.
firstStackedSkinTones :: [Int] -> Maybe (Int, [Int])
firstStackedSkinTones input =
  listToMaybe
    [ (i, [m1, m2])
    | (i, m1, m2) <- zip3 [0 ..] (drop 1 input) (drop 2 input)
    , isSkinTone m1
    , isSkinTone m2
    ]

-- | First skin-tone modifier whose preceding codepoint is NOT
-- @Emoji_Modifier_Base@, as @(basePos, baseCp, modifierCp)@.
firstInvalidSkinToneTarget :: [Int] -> Maybe (Int, Int, Int)
firstInvalidSkinToneTarget input =
  listToMaybe
    [ (i, base, next)
    | (i, base, next) <- zip3 [0 ..] input (drop 1 input)
    , isSkinTone next
    , not (isSkinToneBase base)
    ]

-- | First @U+FE0E@ whose preceding codepoint has @Emoji_Presentation@, as
-- @(basePos, baseCp)@.
firstForcedTextStyle :: [Int] -> Maybe (Int, Int)
firstForcedTextStyle input =
  listToMaybe
    [ (i, base)
    | (i, base, next) <- zip3 [0 ..] input (drop 1 input)
    , isVs15 next
    , isEmojiPresentation base
    ]

-- | Count of skin-tone modifier codepoints.
skinToneCount :: [Int] -> Int
skinToneCount input = length (filter isSkinTone input)

-- | Count of @U+FE0E@ (VS15) codepoints.
vs15Count :: [Int] -> Int
vs15Count input = length (filter isVs15 input)

-- | Count of @U+FE0F@ (VS16) codepoints.
vs16Count :: [Int] -> Int
vs16Count input = length (filter isVs16 input)

-- ─────────────────────────────────────────────────────────────────────
-- §5 Top-level detection
-- ─────────────────────────────────────────────────────────────────────

-- | The SkinToneVariationForgery detection function. See the module header for
-- the sub-threat priority ladder.
detect :: [Int] -> Verdict
detect input =
  Verdict
    { verdictInput                    = input
    , verdictClassify                 = classification
    , verdictSkinToneCount            = skinToneCount input
    , verdictVariationSelector15Count = vs15Count input
    , verdictVariationSelector16Count = vs16Count input
    }
  where
    classification =
      case firstStackedSkinTones input of
        -- Priority 1: a base followed by two stacked skin tones.
        Just (basePos, modifiers) ->
          let positions = [ basePos + 1 + k | k <- [0 .. length modifiers - 1] ]
          in Hazard (StackedSkinTones basePos modifiers) positions []
        Nothing ->
          case firstInvalidSkinToneTarget input of
            -- Priority 2: a skin tone on a non-modifier-base.
            Just (basePos, baseCp, modifierCp) ->
              Hazard (InvalidSkinToneTarget basePos baseCp modifierCp) [basePos + 1] []
            Nothing ->
              case firstForcedTextStyle input of
                -- Priority 3: VS15 forcing text style on an emoji-presentation cp.
                Just (basePos, baseCp) ->
                  Hazard (ForcedTextStyle basePos baseCp) [basePos + 1] []
                Nothing -> Clear

-- | Fully-qualified reason code for a fired sub-threat, of the shape
-- @unicode.security.I.skin-tone-variation-forgery.\<subThreatTag\>@.
reasonCode :: SubThreat -> String
reasonCode sub = "unicode.security.I.skin-tone-variation-forgery." ++ subThreatTag sub
