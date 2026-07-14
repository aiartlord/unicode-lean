{-|
Module      : Unicode.Normalization.Lookup
Description : NFC table accessors over the UCD subset.

Haskell port of @Unicode.Normalization.Lookup@ from unicode-lean.

Thin accessors that bridge the 'Unicode.Generated.UnicodeData' table
and the NFC algorithms in this @Unicode.Normalization@ namespace.
Keeps table-shape concerns out of the algorithm implementations.

Lookup is linear-scan over the 3045-row NFC-relevant subset. The
table is pre-sorted by codepoint, so a future swap to
@Data.IntMap.Strict@ or a binary-search 'Data.Vector' is purely an
optimisation and does not change behaviour. Mirrors the same
optimisation note in the Lean source.
-}
module Unicode.Normalization.Lookup
  ( lookupRow
  , canonicalCombiningClass
  , canonicalDecomposition
  , isCompositionExclusion
  , isFullCompositionExclusion
  ) where

import Data.List (find)
import Data.Word (Word8)

import qualified Unicode.Generated.CompositionExclusions as CompositionExclusions
import qualified Unicode.Generated.DerivedNormalizationProps as DerivedNormalizationProps
import qualified Unicode.Generated.UnicodeData as UnicodeData
import Unicode.Generated.UnicodeData (UnicodeDataRow)

-- | Find the 'UnicodeDataRow' for a codepoint, if one is present in
-- the pinned NFC-relevant subset. Returns 'Nothing' for codepoints
-- that are both @canonicalCombiningClass = 0@ and have no canonical
-- decomposition.
lookupRow :: Int -> Maybe UnicodeDataRow
lookupRow cp = find (\r -> UnicodeData.codepoint r == cp) UnicodeData.rows

-- | Canonical_Combining_Class for a codepoint. Unlisted codepoints
-- have @CCC = 0@ per the UCD's implicit default for the NFC-relevant
-- filter.
--
-- Re-exported under this module so the algorithm files in
-- @Unicode.Normalization.*@ never need to import the Generated
-- table directly.
canonicalCombiningClass :: Int -> Word8
canonicalCombiningClass cp = case lookupRow cp of
    Just r  -> UnicodeData.canonicalCombiningClass r
    Nothing -> 0

-- | Canonical decomposition target sequence for a codepoint. Returns
-- the empty list when the codepoint has no canonical decomposition
-- (every codepoint outside the pinned subset, and many inside it).
canonicalDecomposition :: Int -> [Int]
canonicalDecomposition cp = case lookupRow cp of
    Just r  -> UnicodeData.canonicalDecomposition r
    Nothing -> []

-- | Whether a codepoint appears in @CompositionExclusions.txt@. When
-- 'True', the codepoint decomposes canonically but must NOT recompose
-- during NFC synthesis.
--
-- This is the narrow primary-exclusion set (81 codepoints in UCD
-- 17.0.0). The NFC compose pass uses the broader
-- 'isFullCompositionExclusion' instead — see the docstring there.
isCompositionExclusion :: Int -> Bool
isCompositionExclusion cp = cp `elem` CompositionExclusions.codepoints

-- | Whether a codepoint is marked @Full_Composition_Exclusion@ in
-- @DerivedNormalizationProps.txt@. Strictly broader than
-- 'isCompositionExclusion': includes singleton and non-starter
-- decompositions in addition to the @CompositionExclusions.txt@ set.
-- The NFC compose pass uses this broader test when deciding which
-- canonical decompositions may recompose.
isFullCompositionExclusion :: Int -> Bool
isFullCompositionExclusion cp =
    any (\(lo, hi) -> lo <= cp && cp <= hi)
        DerivedNormalizationProps.fullCompositionExclusion
