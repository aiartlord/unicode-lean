{-|
Module      : Unicode.Normalization.Lookup
Description : NFC table accessors over the UCD subset.

Haskell port of @Unicode.Normalization.Lookup@ from unicode-lean.

Thin accessors that bridge the 'Unicode.Generated.UnicodeData' table
and the NFC algorithms in this @Unicode.Normalization@ namespace.
Keeps table-shape concerns out of the algorithm implementations.

Each accessor answers from an index built once from the generated
table: a 'Data.IntMap.Strict.IntMap' keyed by codepoint for the row
lookup, a 'Data.IntSet.IntSet' for the primary exclusion list, and a
'Unicode.RangeIndex.RangeIndex' for the @Full_Composition_Exclusion@
ranges. The indices are the same relations the generated lists carry,
so the answers are identical; building them once makes every lookup
logarithmic in the table size rather than linear in it. This is the
swap the Lean source's optimisation note describes, and it is what
makes normalization affordable per codepoint — every decomposition
step asks 'canonicalCombiningClass' and 'canonicalDecomposition' for
every codepoint it visits.
-}
module Unicode.Normalization.Lookup
  ( lookupRow
  , canonicalCombiningClass
  , canonicalDecomposition
  , isCompositionExclusion
  , isFullCompositionExclusion
  ) where

import Data.IntMap.Strict (IntMap)
import qualified Data.IntMap.Strict as IntMap (fromListWith, lookup)
import Data.IntSet (IntSet)
import qualified Data.IntSet as IntSet (fromList, member)
import Data.Word (Word8)

import Unicode.RangeIndex (RangeIndex)
import qualified Unicode.RangeIndex as RangeIndex (fromRanges, member)
import qualified Unicode.Generated.CompositionExclusions as CompositionExclusions
import qualified Unicode.Generated.DerivedNormalizationProps as DerivedNormalizationProps
import qualified Unicode.Generated.UnicodeData as UnicodeData
import Unicode.Generated.UnicodeData (UnicodeDataRow)

-- | Find the 'UnicodeDataRow' for a codepoint, if one is present in
-- the pinned NFC-relevant subset. Returns 'Nothing' for codepoints
-- that are both @canonicalCombiningClass = 0@ and have no canonical
-- decomposition.
lookupRow :: Int -> Maybe UnicodeDataRow
lookupRow cp = IntMap.lookup cp rowIndex

-- | The generated table keyed by codepoint, built once. Where two rows
-- shared a codepoint the earlier one wins, which is the row a
-- left-to-right search of 'UnicodeData.rows' would have returned.
rowIndex :: IntMap UnicodeDataRow
rowIndex =
    IntMap.fromListWith
        (\_later earlier -> earlier)
        [ (UnicodeData.codepoint r, r) | r <- UnicodeData.rows ]
{-# NOINLINE rowIndex #-}

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
isCompositionExclusion cp = IntSet.member cp exclusionSet

-- | The primary exclusion list as a set, built once from the generated
-- codepoint list.
exclusionSet :: IntSet
exclusionSet = IntSet.fromList CompositionExclusions.codepoints
{-# NOINLINE exclusionSet #-}

-- | Whether a codepoint is marked @Full_Composition_Exclusion@ in
-- @DerivedNormalizationProps.txt@. Strictly broader than
-- 'isCompositionExclusion': includes singleton and non-starter
-- decompositions in addition to the @CompositionExclusions.txt@ set.
-- The NFC compose pass uses this broader test when deciding which
-- canonical decompositions may recompose.
isFullCompositionExclusion :: Int -> Bool
isFullCompositionExclusion cp = RangeIndex.member cp fullExclusionIndex

-- | The @Full_Composition_Exclusion@ ranges indexed for logarithmic
-- membership, built once from the generated range list. The compose pass asks
-- this for every candidate composite, so a scan here is paid per composing
-- pair.
fullExclusionIndex :: RangeIndex
fullExclusionIndex =
    RangeIndex.fromRanges DerivedNormalizationProps.fullCompositionExclusion
{-# NOINLINE fullExclusionIndex #-}
