{-# LANGUAGE StrictData #-}

-- SPDX-License-Identifier: LicenseRef-Allodial-Tiered

-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
--                              // test // unicode // segmentation // line-break
-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

-- | UAX #14 default line breaking, judged against the published corpus.
--
-- The corpus and the two gates it answers to live in @BreakCorpus@, shared
-- with the grapheme suite. This module supplies the implementation under test
-- and the rows to judge it by.
--
-- Agreeing with all of @LineBreakTest.txt@ is also the evidence the two
-- departures from the Lean declared at @Unicode.Segmentation.LineBreak@'s head
-- needed — suffix reads in place of positional @lits[i]!@, and dropping the
-- Lean's write-only @spSinceNoSp@ snapshot field.
module LineBreakSpec (tests, main) where

import Test.Tasty (TestTree, defaultMain, testGroup)
import Test.Tasty.HUnit (assertFailure, testCase, (@?=))

import BreakCorpus
    ( corpusTests
    )
import LineBreakTestRows
    ( publishedCount
    , publishedRows
    )
import VectorCases
    ( VectorCase (caseBreaks, caseInput, caseName, caseRule)
    , lineBreakAlgorithm
    , lineBreakCases
    , lineBreakPublishedRowCount
    )
import Unicode.Segmentation.LineBreak
    ( lineBreaks
    )

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests =
    testGroup "Unicode.Segmentation.LineBreak"
        [ corpusTests
            "published corpus"
            lineBreaks
            publishedRows
            publishedCount
        , vectorTests
        ]

-- | One case per UAX #14 rule, the same bytes every port replays, so no port
-- can carry a weaker set of rule checks than another. The published corpus is
-- the authority; these name which rule each boundary exercises.
vectorTests :: TestTree
vectorTests =
    testGroup "shared vectors"
        [ testCase "the fixture is the line-break one and carries cases" $ do
            lineBreakAlgorithm @?= "uax14-line-break"
            null lineBreakCases @?= False
        , testCase "the corpus and the vectors agree on the row count" $
            lineBreakPublishedRowCount @?= publishedCount
        , testCase "every case's boundary mask is reproduced" $
            case failures of
                [] -> pure ()
                firstFailure : _rest -> assertFailure firstFailure
        ]
  where
    failures =
        [ caseRule entry ++ ": " ++ caseName entry
        | entry <- lineBreakCases
        , lineBreaks (caseInput entry) /= caseBreaks entry
        ]
