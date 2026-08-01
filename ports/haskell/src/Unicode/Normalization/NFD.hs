{-|
Module      : Unicode.Normalization.NFD
Description : Normalization Form D (UAX #15 §1.3).

Haskell port of @Unicode.Normalization.NFD@ from unicode-lean.

@toNFD = reorder . canonicalDecomposeSequence@ — canonical decomposition
followed by canonical reordering. Differs from NFKD only in the
decomposition stage: NFD applies only canonical (not compatibility)
mappings. Hangul syllables decompose algorithmically; the reorder stage
is identical to NFKD's.
-}
module Unicode.Normalization.NFD
  ( toNFD
  ) where

import Unicode.Normalization.Hangul (decomposeSyllable)
import Unicode.Normalization.Lookup (canonicalDecomposition)
import Unicode.Normalization.Reorder (reorder)

-- | Maximum recursion depth for canonical decomposition. UAX #15 bounds the
-- longest canonical decomposition chain at a small integer; 32 leaves a
-- comfortable margin over every published UCD.
maxDepth :: Int
maxDepth = 32

-- | Fully canonically decompose a single codepoint: Hangul syllables
-- algorithmically, else the canonical mapping applied recursively to a fixed
-- point. Returns @[cp]@ when the codepoint has no canonical decomposition.
fullCanonicalDecomposeFuel :: Int -> Int -> [Int]
fullCanonicalDecomposeFuel 0 cp = [cp]
fullCanonicalDecomposeFuel fuel cp =
  case decomposeSyllable cp of
    Just jamo -> jamo
    Nothing ->
      let canon = canonicalDecomposition cp
      in if null canon
           then [cp]
           else concatMap (fullCanonicalDecomposeFuel (fuel - 1)) canon

-- | Fully canonically decompose a single codepoint at the default depth.
fullCanonicalDecompose :: Int -> [Int]
fullCanonicalDecompose = fullCanonicalDecomposeFuel maxDepth

-- | Fully canonically decompose a codepoint sequence, concatenating each
-- codepoint's expansion in order.
canonicalDecomposeSequence :: [Int] -> [Int]
canonicalDecomposeSequence = concatMap fullCanonicalDecompose

-- | Normalize a codepoint sequence to NFD.
toNFD :: [Int] -> [Int]
toNFD = reorder . canonicalDecomposeSequence
