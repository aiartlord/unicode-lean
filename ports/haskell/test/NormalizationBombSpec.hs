{-|
  Tests for "Unicode.Security.Form.NormalizationBomb" — mirrors the
  @detect_*@ ground-truth theorems in
  @Unicode/Security/Form/NormalizationBomb.lean@, plus the two ratio-branch
  shapes the module docstring guarantees.
-}
module NormalizationBombSpec (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, testCase)

import Unicode.Security.Form.NormalizationBomb
  ( Detection (detectionPositions, detectionSub)
  , detect
  )

sub :: [Int] -> Maybe String
sub = detectionSub . detect

tests :: TestTree
tests = testGroup "Unicode.Security.Form.NormalizationBomb"
  [ testCase "empty input is clear" $
      assertEqual "empty" Nothing (sub [])

  , testCase "ASCII is clear" $
      assertEqual "Hello" Nothing (sub [0x48, 0x65, 0x6C, 0x6C, 0x6F])

  , testCase "Korean syllable stays clear (NFD ratio exactly 300)" $
      assertEqual "Korean" Nothing (sub [0xD55C])

  , testCase "circled one stays clear" $
      assertEqual "circled one" Nothing (sub [0x2460])

  , testCase "Arabic ligature FDFA fires SingleCpBlowup" $ do
      assertEqual "tag" (Just "SingleCpBlowup") (sub [0xFDFA])
      assertEqual "position" [0] (detectionPositions (detect [0xFDFA]))

  , testCase "FDFB fires NfkdHighExpansion (8× ratio)" $
      assertEqual "nfkd" (Just "NfkdHighExpansion") (sub [0xFDFB])

  , testCase "Greek extended U+1F82 fires NfdHighExpansion (4× NFD ratio)" $
      assertEqual "nfd" (Just "NfdHighExpansion") (sub [0x1F82])
  ]
