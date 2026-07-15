module GraphemeSpec (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit ((@?=), testCase)

import Unicode.Segmentation.Grapheme (graphemeBreaks, graphemeClusters)

tests :: TestTree
tests = testGroup "Unicode.Segmentation.Grapheme"
  [ testCase "core UAX #29 break cases" $ do
      graphemeBreaks [0x61, 0x62, 0x63] @?= [True, True, True, True]
      graphemeBreaks [0x65, 0x0301] @?= [True, False, True]
      graphemeBreaks [0x0d, 0x0a] @?= [True, False, True]
      graphemeBreaks [0x1f1ef, 0x1f1f5] @?= [True, False, True]
  , testCase "RI parity and ZWJ sequence clusters" $ do
      length (graphemeClusters [0x1f1ef, 0x1f1f5, 0x1f1fa, 0x1f1f8]) @?= 2
      length (graphemeClusters [0x1f468, 0x200d, 0x1f469, 0x200d, 0x1f467]) @?= 1
  ]
