{-# LANGUAGE StrictData #-}

-- SPDX-License-Identifier: LicenseRef-Allodial-Tiered

-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
--                              // test // unicode // segmentation // line-break
-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

-- | UAX #14 default line breaking, judged against the published corpus.
--
-- The corpus and the two gates it answers to live in
-- @Unicode.Segmentation.BreakCorpus@, shared with the grapheme suite. This
-- module supplies the implementation under test and the rows to judge it by.
--
-- Agreeing with all of @LineBreakTest.txt@ is also the evidence the two
-- departures from the Lean declared at @Unicode.Segmentation.LineBreak@'s head
-- needed — suffix reads in place of positional @lits[i]!@, and dropping the
-- Lean's write-only @spSinceNoSp@ snapshot field.
module LineBreakSpec (tests, main) where

import Test.Tasty (TestTree, defaultMain)

import BreakCorpus
    ( corpusTests
    )
import LineBreakTestRows
    ( publishedCount
    , publishedRows
    )
import Unicode.Segmentation.LineBreak
    ( lineBreaks
    )

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests =
    corpusTests
        "Unicode.Segmentation.LineBreak"
        lineBreaks
        publishedRows
        publishedCount
