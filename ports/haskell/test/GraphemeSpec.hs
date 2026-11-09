{-# LANGUAGE StrictData #-}

-- SPDX-License-Identifier: LicenseRef-Allodial-Tiered

-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
--                                // test // unicode // segmentation // grapheme
-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

-- | UAX #29 extended grapheme clusters, judged against the published corpus.
--
-- The corpus and the two gates it answers to live in @BreakCorpus@, shared
-- with the line-break suite: agree with every published row, and separately
-- account for the whole file so a row lost between the corpus module and that
-- fold is a failure rather than a smaller denominator.
module GraphemeSpec (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertFailure, testCase, (@?=))

import BreakCorpus (corpusTests)
import GraphemeTestRows (publishedCount, publishedRows)
import VectorCases
    ( VectorCase (caseBreaks, caseInput, caseName, caseRule)
    , graphemeAlgorithm
    , graphemeCases
    , graphemePublishedRowCount
    )

import Unicode.Segmentation.Grapheme (graphemeBreaks, graphemeClusters)

tests :: TestTree
tests =
    testGroup "Unicode.Segmentation.Grapheme"
        [ corpusTests
            "published corpus"
            graphemeBreaks
            publishedRows
            publishedCount
        , vectorTests
        , clusterTests
        ]

-- | One case per UAX #29 rule, the same bytes every port replays, so no port
-- can carry a weaker set of rule checks than another. The published corpus is
-- the authority; these name which rule each boundary exercises.
vectorTests :: TestTree
vectorTests =
    testGroup "shared vectors"
        [ testCase "the fixture is the grapheme one and carries cases" $ do
            graphemeAlgorithm @?= "uax29-grapheme-cluster"
            null graphemeCases @?= False
        , testCase "the corpus and the vectors agree on the row count" $
            graphemePublishedRowCount @?= publishedCount
        , testCase "every case's boundary mask is reproduced" $
            case failures of
                [] -> pure ()
                firstFailure : _rest -> assertFailure firstFailure
        ]
  where
    failures =
        [ caseRule entry ++ ": " ++ caseName entry
        | entry <- graphemeCases
        , graphemeBreaks (caseInput entry) /= caseBreaks entry
        ]

-- | Cluster counts are a shape the boundary masks do not state.
clusterTests :: TestTree
clusterTests =
    testGroup "clusters"
        [ testCase "regional indicators pair off" $
            length (graphemeClusters [0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8]) @?= 2
        , testCase "an emoji zero-width-joiner sequence is one cluster" $
            length
                (graphemeClusters [0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467])
                @?= 1
        , testCase "each ASCII letter is its own cluster" $
            length (graphemeClusters [0x61, 0x62, 0x63]) @?= 3
        ]
