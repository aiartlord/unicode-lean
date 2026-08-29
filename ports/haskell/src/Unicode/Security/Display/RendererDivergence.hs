{-|
Module      : Unicode.Security.Display.RendererDivergence
Description : Detection of codepoint shapes that render differently across stacks.

Haskell port of @Unicode.Security.Display.RendererDivergence@ from unicode-lean,
transliterated byte-faithfully from the verified Rust reference
implementation (the display-layer detector, reason-code letter @D@).

Threat model. An adversary crafts content that renders one way in the auditor's
renderer (a benign glyph or an empty span) and a different way in the consumer's
renderer (a misleading glyph, a wider glyph, or a different sequence). This is
the "fingerprint stability" family — clear inputs render the same across the
renderer cohort the Standard documents as stable.

What the detector draws. A heuristic three-value split, surfaced through the
universal clear/hazard carrier: an input is 'Clear' when none of the documented
variance triggers fire, and otherwise is classified by the first trigger in
priority order — a combining-mark stack overflow, a variation selector, an
unregistered ZWJ shape, a fullwidth/halfwidth codepoint, or mixed direction. It
reuses the port's own tables (the VariationSelectorPayload detector's
'Unicode.Security.CodepointPredicates.isVariationSelector', the grapheme
'Unicode.Segmentation.Grapheme.lookupGCB' @Extend@ class, the EmojiZwjIntegrity
'Unicode.Security.Identity.EmojiZwjIntegrity.isRegisteredZwjSequence' RGI
registry, and the RtlInjection detector's 'Unicode.Security.CodepointPredicates.isStrongLtr'
\/ 'Unicode.Security.CodepointPredicates.isStrongRtl' strong-bidi classes), never a host
rendering or shaping library.

Sub-threats (priority order).

  1. 'CombiningStackOverflow'    — Zalgo-like combining-mark stack @>= 4@ on a base.
  2. 'VariationSelectorVariance' — any variation selector present.
  3. 'UnregisteredZwjVariance'   — a ZWJ-containing input not in the RGI ZWJ set.
  4. 'FullwidthVariance'         — a fullwidth/halfwidth codepoint present.
  5. 'MixedDirectionVariance'    — both strong-LTR and strong-RTL codepoints.
-}
module Unicode.Security.Display.RendererDivergence
  ( minCombiningStack
  , zwj
  , SubThreat
      ( CombiningStackOverflow, VariationSelectorVariance, UnregisteredZwjVariance
      , FullwidthVariance, MixedDirectionVariance
      )
  , subThreatTag
  , Classification (Clear, Hazard)
  , classificationIsClear
  , classificationTag
  , classificationPositions
  , Verdict
      ( Verdict, verdictInput, verdictClassify, verdictVsCount
      , verdictCombiningCount, verdictFullwidthCount, verdictHasZwj
      , verdictStrongLtrCount, verdictStrongRtlCount
      )
  , isVariationSelector
  , isZwj
  , isFullwidthHalfwidth
  , isGraphemeExtend
  , detect
  , reasonCode
  ) where

import Data.Maybe (listToMaybe)

import Unicode.Segmentation.Grapheme (lookupGCB)
import Unicode.Segmentation.GraphemeTables (GCB (Extend))
import Unicode.Security.Identity.EmojiZwjIntegrity (isRegisteredZwjSequence)
import qualified Unicode.Security.CodepointPredicates as Predicates

-- ─────────────────────────────────────────────────────────────────────
-- §1 Constants
-- ─────────────────────────────────────────────────────────────────────

-- | The combining-mark stack depth (on a single base) at or beyond which the
-- input is treated as a Zalgo-style rendering-variance hazard.
minCombiningStack :: Int
minCombiningStack = 4

-- | The ZERO WIDTH JOINER codepoint.
zwj :: Int
zwj = 0x200D

-- ─────────────────────────────────────────────────────────────────────
-- §2 Types
-- ─────────────────────────────────────────────────────────────────────

-- | Sub-threat enumeration for RendererDivergence, in priority order. Each
-- payload carries the position and codepoint values the conformance harness's
-- attribution column reads back, mirroring the Rust @SubThreat@ variants
-- field-for-field.
data SubThreat
  = -- | A combining-mark stack of @stackLen@ marks on the base at @basePos@.
    -- Fields: the base position, then the stack depth tested
    -- (@>= minCombiningStack@).
    CombiningStackOverflow Int Int
  | -- | A variation selector present in the input. Fields: the position of the
    -- first variation selector, then its codepoint.
    VariationSelectorVariance Int Int
  | -- | A ZWJ-containing input not present in the registered RGI ZWJ set; the
    -- 'Int' is the position of the first ZWJ.
    UnregisteredZwjVariance Int
  | -- | A fullwidth/halfwidth codepoint present. Fields: the position of the
    -- first fullwidth/halfwidth codepoint, then that codepoint.
    FullwidthVariance Int Int
  | -- | Both strong-LTR and strong-RTL codepoints in one input. Fields: the
    -- strong-LTR count, then the strong-RTL count.
    MixedDirectionVariance Int Int
  deriving stock (Eq, Show)

-- | Fixture-row tag string for this sub-threat (matches @SubThreat.tag@).
subThreatTag :: SubThreat -> String
subThreatTag (CombiningStackOverflow _basePos _stackLen) = "CombiningStackOverflow"
subThreatTag (VariationSelectorVariance _vsPos _vsCp)     = "VariationSelectorVariance"
subThreatTag (UnregisteredZwjVariance _zwjPos)            = "UnregisteredZwjVariance"
subThreatTag (FullwidthVariance _fwPos _fwCp)             = "FullwidthVariance"
subThreatTag (MixedDirectionVariance _ltrCount _rtlCount) = "MixedDirectionVariance"

-- | Top-level classification for RendererDivergence (stable = 'Clear').
data Classification
  = -- | Rendering is consistent across the documented renderer cohort.
    Clear
  | -- | A documented variance mode fired: the sub-threat, the implicated
    -- codepoint positions, and the decoded-byte projection (always @[]@ here;
    -- kept for shape parity with the Lean @Classification.hazard@).
    Hazard SubThreat [Int] [Int]
  deriving stock (Eq, Show)

-- | True iff the classification is 'Clear' (i.e. stable).
classificationIsClear :: Classification -> Bool
classificationIsClear Clear               = True
classificationIsClear (Hazard _sub _p _d) = False

-- | Human-facing tag for a hazard, or 'Nothing' when clear.
classificationTag :: Classification -> Maybe String
classificationTag Clear                  = Nothing
classificationTag (Hazard sub _pos _dec) = Just (subThreatTag sub)

-- | Implicated positions ('[]' when clear).
classificationPositions :: Classification -> [Int]
classificationPositions Clear                      = []
classificationPositions (Hazard _sub positions _d) = positions

-- | Verdict — the structured output of 'detect' (mirrors the Lean @Verdict@).
data Verdict = Verdict
  { verdictInput           :: ![Int]
    -- ^ The scanned input codepoints.
  , verdictClassify        :: !Classification
    -- ^ The classification verdict.
  , verdictVsCount         :: !Int
    -- ^ Count of variation selectors.
  , verdictCombiningCount  :: !Int
    -- ^ Count of combining (grapheme @Extend@) marks.
  , verdictFullwidthCount  :: !Int
    -- ^ Count of fullwidth/halfwidth codepoints.
  , verdictHasZwj          :: !Bool
    -- ^ Whether the input contains any ZWJ.
  , verdictStrongLtrCount  :: !Int
    -- ^ Count of strong-LTR codepoints.
  , verdictStrongRtlCount  :: !Int
    -- ^ Count of strong-RTL codepoints.
  }
  deriving stock (Eq, Show)

-- ─────────────────────────────────────────────────────────────────────
-- §3 Core predicates
-- ─────────────────────────────────────────────────────────────────────

-- | True iff @cp@ is a variation selector — reuses the VariationSelectorPayload
-- detector's predicate (ranges @FE00@..@FE0F@, @E0100@..@E01EF@, @180B@..@180D@).
isVariationSelector :: Int -> Bool
isVariationSelector = Predicates.isVariationSelector

-- | True iff @cp@ is the ZWJ codepoint.
isZwj :: Int -> Bool
isZwj cp = cp == zwj

-- | True iff @cp@ is in the Halfwidth/Fullwidth Forms range @FF01@..@FFEF@.
isFullwidthHalfwidth :: Int -> Bool
isFullwidthHalfwidth cp = 0xFF01 <= cp && cp <= 0xFFEF

-- | True iff @cp@ has @Grapheme_Cluster_Break = Extend@ — a combining mark that
-- stacks onto the preceding base. Reuses the port's grapheme-segmentation table
-- via 'lookupGCB'; the RendererDivergence detector uses it to measure
-- Zalgo-style combining-mark stacks.
isGraphemeExtend :: Int -> Bool
isGraphemeExtend cp = lookupGCB cp == Extend

-- ─────────────────────────────────────────────────────────────────────
-- §4 Sub-detectors
-- ─────────────────────────────────────────────────────────────────────

countVs :: [Int] -> Int
countVs input = length (filter isVariationSelector input)

countCombining :: [Int] -> Int
countCombining input = length (filter isGraphemeExtend input)

countFullwidth :: [Int] -> Int
countFullwidth input = length (filter isFullwidthHalfwidth input)

inputHasZwj :: [Int] -> Bool
inputHasZwj input = any isZwj input

countStrongLtr :: [Int] -> Int
countStrongLtr input = length (filter Predicates.isStrongLtr input)

countStrongRtl :: [Int] -> Int
countStrongRtl input = length (filter Predicates.isStrongRtl input)

-- | Position and codepoint of the first variation selector.
firstVsPos :: [Int] -> Maybe (Int, Int)
firstVsPos input =
  listToMaybe [ (idx, cp) | (idx, cp) <- zip [0 ..] input, isVariationSelector cp ]

-- | Position of the first ZWJ.
firstZwjPos :: [Int] -> Maybe Int
firstZwjPos input =
  listToMaybe [ idx | (idx, cp) <- zip [0 ..] input, isZwj cp ]

-- | Position and codepoint of the first fullwidth/halfwidth codepoint.
firstFullwidthPos :: [Int] -> Maybe (Int, Int)
firstFullwidthPos input =
  listToMaybe [ (idx, cp) | (idx, cp) <- zip [0 ..] input, isFullwidthHalfwidth cp ]

-- | The first base position (a non-@Extend@ codepoint) immediately followed by
-- @minStack@ consecutive @Extend@ codepoints. Returns @(basePos, minStack)@ on
-- hit.
firstCombiningStack :: [Int] -> Int -> Maybe (Int, Int)
firstCombiningStack input minStack = go 0 input
  where
    go :: Int -> [Int] -> Maybe (Int, Int)
    go _idx []          = Nothing
    go idx (cp : rest)
      | not (isGraphemeExtend cp) =
          let following = take minStack rest
          in if length following == minStack && all isGraphemeExtend following
               then Just (idx, minStack)
               else go (idx + 1) rest
      | otherwise = go (idx + 1) rest

-- ─────────────────────────────────────────────────────────────────────
-- §5 Top-level detection
-- ─────────────────────────────────────────────────────────────────────

-- | The RendererDivergence detection function. Priority ladder mirrors the
-- verified Rust reference exactly; see the module header for the sub-threat
-- inventory.
detect :: [Int] -> Verdict
detect input =
  Verdict
    { verdictInput          = input
    , verdictClassify       = classification
    , verdictVsCount        = vsCount
    , verdictCombiningCount = combiningCount
    , verdictFullwidthCount = fullwidthCount
    , verdictHasZwj         = hasZwj
    , verdictStrongLtrCount = ltrCount
    , verdictStrongRtlCount = rtlCount
    }
  where
    vsCount        = countVs input
    combiningCount = countCombining input
    fullwidthCount = countFullwidth input
    hasZwj         = inputHasZwj input
    ltrCount       = countStrongLtr input
    rtlCount       = countStrongRtl input

    classification =
      -- Priority 1: combining-mark stack overflow (Zalgo).
      case firstCombiningStack input minCombiningStack of
        Just (basePos, stackLen) ->
          Hazard (CombiningStackOverflow basePos stackLen) [basePos] []
        Nothing ->
          -- Priority 2: any variation selector triggers presentation variance.
          case firstVsPos input of
            Just (pos, cp) ->
              Hazard (VariationSelectorVariance pos cp) [pos] []
            Nothing ->
              -- Priority 3: a ZWJ-containing input not in the registered RGI set.
              if hasZwj && not (isRegisteredZwjSequence input)
                then case firstZwjPos input of
                  Just pos -> Hazard (UnregisteredZwjVariance pos) [pos] []
                  Nothing  -> Clear
                else
                  -- Priority 4: fullwidth/halfwidth.
                  case firstFullwidthPos input of
                    Just (pos, cp) ->
                      Hazard (FullwidthVariance pos cp) [pos] []
                    Nothing ->
                      -- Priority 5: mixed direction.
                      if ltrCount > 0 && rtlCount > 0
                        then Hazard (MixedDirectionVariance ltrCount rtlCount) [] []
                        else Clear

-- | Fully-qualified reason code for a fired sub-threat, of the shape
-- @unicode.security.D.renderer-divergence.\<subThreatTag\>@.
reasonCode :: SubThreat -> String
reasonCode sub = "unicode.security.D.renderer-divergence." ++ subThreatTag sub
