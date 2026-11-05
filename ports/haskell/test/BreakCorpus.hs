{-# LANGUAGE StrictData #-}

-- SPDX-License-Identifier: LicenseRef-Allodial-Tiered

-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
--                            // test // unicode // segmentation // break-corpus
-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

-- | The gate every published UAX break corpus gets, once.
--
-- Hand-written vectors cannot establish a segmentation algorithm. Its rules
-- read context on both sides of a boundary and the answer depends on state
-- carried from earlier in the sequence, so a wrong rule survives any vector a
-- human would pick. The Unicode Consortium publishes a corpus per algorithm for
-- exactly that reason.
--
-- The four break suites share one row format — which is why the spec repo
-- serves all of them from a single parser
-- (@Unicode.Conformance.BreakTestRun@, `:9-12`) — so they share one judge here
-- too. Each algorithm's spec supplies its implementation and its corpus; the
-- two gates and the failure report live here.
--
-- Those two gates are the spec repo's own: agree with every published row, and
-- separately account for the whole file, so a row lost between the corpus
-- module and this fold is a failure rather than a smaller denominator
-- (@BreakTestRun@'s `#eval`, `:119-129`).
module BreakCorpus
    ( corpusTests
    ) where

import Numeric (showHex)

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertFailure, testCase, (@?=))

-- | Judge one implementation against one published corpus.
--
-- @label@ names the algorithm under test, @breaksOf@ is the implementation,
-- @rows@ the published rows as (codepoints, expected flags), and @published@
-- the count the pinned file carries, asserted rather than taken from @rows@.
corpusTests
    :: String
    -> ([Int] -> [Bool])
    -> [([Int], [Bool])]
    -> Int
    -> TestTree
corpusTests label breaksOf rows published =
    testGroup label
        [ shapeTests
        , conformanceTests
        ]
  where
    indexed :: [(Int, ([Int], [Bool]))]
    indexed = zip [0 ..] rows

    -- What the corpus must be before it can judge anything.
    shapeTests =
        testGroup "corpus shape"
            [ testCase "every published row reaches the fold" $
                length rows @?= published
            , testCase "each row carries one more flag than codepoints" $
                [ index
                | (index, (codepoints, flags)) <- indexed
                , length flags /= length codepoints + 1
                ]
                    @?= []
            ]

    conformanceTests =
        testGroup "published corpus"
            [ testCase "the implementation agrees with every published row" $
                case disagreements of
                    [] -> pure ()
                    firstFailure : _rest ->
                        assertFailure
                            (report published (length disagreements) firstFailure)
            ]

    -- Each row whose expected flags differ from what the implementation
    -- produces, as the row's file index, its codepoints, the published flags
    -- and the produced ones.
    disagreements :: [(Int, [Int], [Bool], [Bool])]
    disagreements =
        [ (index, codepoints, flags, produced)
        | (index, (codepoints, flags)) <- indexed
        , let produced = breaksOf codepoints
        , produced /= flags
        ]

-- | A failure names the count and the first failing row in full. A conformance
-- red is only actionable if it says which row and which position disagreed, so
-- the first differing boundary is reported alongside the two flag lists.
report :: Int -> Int -> (Int, [Int], [Bool], [Bool]) -> String
report published failureCount (index, codepoints, flags, produced) =
    unlines
        [ show failureCount
            ++ " of "
            ++ show published
            ++ " published rows disagree; first at row index "
            ++ show index
        , "  codepoints : " ++ unwords (map hex codepoints)
        , "  published  : " ++ unwords (map flag flags)
        , "  produced   : " ++ unwords (map flag produced)
        , "  first differing boundary: " ++ firstBoundary flags produced
        ]

-- | The index of the first boundary the two flag lists disagree on, or a note
-- that they differ only in length.
firstBoundary :: [Bool] -> [Bool] -> String
firstBoundary flags produced =
    case [ index
         | (index, left, right) <- zip3 [0 :: Int ..] flags produced
         , left /= right
         ] of
        boundary : _rest -> show boundary
        [] ->
            "none — the lists differ in length ("
                ++ show (length flags)
                ++ " published, "
                ++ show (length produced)
                ++ " produced)"

hex :: Int -> String
hex codepoint = "U+" ++ pad (map upper (showHex codepoint ""))
  where
    pad digits
        | length digits >= 4 = digits
        | otherwise = replicate (4 - length digits) '0' ++ digits

    upper character =
        case character of
            'a' -> 'A'
            'b' -> 'B'
            'c' -> 'C'
            'd' -> 'D'
            'e' -> 'E'
            'f' -> 'F'
            other -> other

-- | The marker the published files write: a break opportunity, or none.
flag :: Bool -> String
flag isBreak = if isBreak then "/" else "x"
