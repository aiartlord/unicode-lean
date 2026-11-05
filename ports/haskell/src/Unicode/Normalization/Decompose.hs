{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE StrictData #-}

-- SPDX-License-Identifier: LicenseRef-Allodial-Tiered

-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
--                                      // unicode // normalization // decompose
-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

-- | Recursive canonical decomposition per UAX #15.

module Unicode.Normalization.Decompose
    ( maxDepth
    , fullCanonicalDecomposeFuel
    , fullCanonicalDecompose
    , decomposeSequence
    ) where

import qualified Unicode.Normalization.Hangul as Hangul
    ( decomposeSyllable
    )
import qualified Unicode.Normalization.Lookup as Lookup
    ( canonicalDecomposition
    )

maxDepth :: Int
maxDepth = 32

fullCanonicalDecomposeFuel :: Int -> Int -> [Int]
fullCanonicalDecomposeFuel fuel cp
    | fuel == 0 = [cp]
    | otherwise =
        case Hangul.decomposeSyllable cp of
            Just jamo -> jamo
            Nothing   ->
                case Lookup.canonicalDecomposition cp of
                    []   -> [cp]
                    step -> concatMap (fullCanonicalDecomposeFuel (fuel - 1)) step

fullCanonicalDecompose :: Int -> [Int]
fullCanonicalDecompose =
    fullCanonicalDecomposeFuel maxDepth

decomposeSequence :: [Int] -> [Int]
decomposeSequence cps =
    concatMap fullCanonicalDecompose cps
