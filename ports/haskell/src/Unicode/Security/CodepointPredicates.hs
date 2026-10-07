{-# LANGUAGE StrictData #-}

{-|
Module      : Unicode.Security.CodepointPredicates
Description : Codepoint predicates shared by the policy surface and the
              standalone detectors.

The predicates here are used both by "Unicode.Security.Policy" and by detector
modules that "Unicode.Security.Policy" is meant to dispatch.  They live below
both so that a detector can reuse them without importing the policy surface,
which would close a module cycle and make the detector unreachable from the
scan path it belongs to.

Nothing here is policy.  These are properties of a codepoint, fixed by the
Unicode Character Database: a bidi strong class, a variation selector block, a
bidi format-control block.  What a scan does when it finds one is decided in
"Unicode.Security.Policy".
-}
module Unicode.Security.CodepointPredicates
  ( bidiStrong
  , isStrongLtr
  , isStrongRtl
  , isBidiFormatControl
  , isVariationSelector
  ) where

import Unicode.Generated.DerivedBidiClass
  ( BidiStrong (BidiAL, BidiL, BidiOther, BidiR)
  , defaultRanges
  , explicitRanges
  )
import Unicode.RangeIndex (RangeMap)
import qualified Unicode.RangeIndex as RangeIndex (classOf, rangeMapOf)

-- | The strong bidi class of a codepoint.  An explicit range wins; otherwise
-- the last matching @\@missing@ default range applies, and @BidiL@ stands as
-- the base case for a codepoint no default range covers.
bidiStrong :: Int -> BidiStrong
bidiStrong cp =
  case RangeIndex.classOf cp explicitIndex of
    Just cls -> cls
    Nothing -> foldl pickDefault BidiL defaultRanges
  where
    pickDefault acc (lo, hi, cls) = if lo <= cp && cp <= hi then cls else acc

-- | The 2323 explicit @Bidi_Class@ ranges keyed by range start, built once.
-- They assign one class per codepoint and so do not overlap, which makes the
-- range with the greatest start at or below a codepoint the same range a
-- first-match scan found. The 24 @\@missing@ default ranges stay a fold: they
-- overlap by design — the first covers the whole codespace — and the fold
-- takes the last match, which is what carries that design.
explicitIndex :: RangeMap BidiStrong
explicitIndex = RangeIndex.rangeMapOf explicitRanges
{-# NOINLINE explicitIndex #-}

-- | Strong right-to-left: Hebrew and the like (@R@), or Arabic-letter (@AL@).
isStrongRtl :: Int -> Bool
isStrongRtl cp =
  case bidiStrong cp of
    BidiR     -> True
    BidiAL    -> True
    BidiL     -> False
    BidiOther -> False

-- | Strong left-to-right.
isStrongLtr :: Int -> Bool
isStrongLtr cp = bidiStrong cp == BidiL

-- | The bidi format-controls: the embedding\/override block U+202A..U+202E and
-- the isolate block U+2066..U+2069.
isBidiFormatControl :: Int -> Bool
isBidiFormatControl cp =
  (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069)

-- | The three variation-selector blocks: VS1..VS16, the supplement
-- VS17..VS256, and the Mongolian free variation selectors.
isVariationSelector :: Int -> Bool
isVariationSelector cp =
  (cp >= 0xFE00 && cp <= 0xFE0F)
    || (cp >= 0xE0100 && cp <= 0xE01EF)
    || (cp >= 0x180B && cp <= 0x180D)
