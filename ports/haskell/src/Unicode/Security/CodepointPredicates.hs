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

import Data.List (find)

import Unicode.Generated.DerivedBidiClass
  ( BidiStrong (BidiAL, BidiL, BidiOther, BidiR)
  , defaultRanges
  , explicitRanges
  )

-- | The strong bidi class of a codepoint.  An explicit range wins; otherwise
-- the last matching @\@missing@ default range applies, and @BidiL@ stands as
-- the base case for a codepoint no default range covers.
bidiStrong :: Int -> BidiStrong
bidiStrong cp =
  case find inRange explicitRanges of
    Just (_lo, _hi, cls) -> cls
    Nothing -> foldl pickDefault BidiL defaultRanges
  where
    inRange (lo, hi, _cls) = lo <= cp && cp <= hi
    pickDefault acc (lo, hi, cls) = if lo <= cp && cp <= hi then cls else acc

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
