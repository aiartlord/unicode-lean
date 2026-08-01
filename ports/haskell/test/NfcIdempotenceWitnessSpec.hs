{-|
  Tests for "Unicode.Security.Form.NfcIdempotenceWitness" — mirrors the
  @detect_*@ ground-truth theorems in
  @Unicode/Security/Form/NfcIdempotenceWitness.lean@.
-}
module NfcIdempotenceWitnessSpec (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, testCase)

import Unicode.Security.Form.NfcIdempotenceWitness
  ( Detection (detectionPositions, detectionSub)
  , detect
  )

sub :: [Int] -> Maybe String
sub = detectionSub . detect

tests :: TestTree
tests = testGroup "Unicode.Security.Form.NfcIdempotenceWitness"
  [ testCase "empty input is clear" $
      assertEqual "empty" Nothing (sub [])

  , testCase "ASCII is clear" $
      assertEqual "Hello" Nothing (sub [0x48, 0x65, 0x6C, 0x6C, 0x6F])

  , testCase "precomposed e-acute is clear" $
      assertEqual "precomposed" Nothing (sub [0x00E9])

  , testCase "decomposed e-acute fires NonNfcForm" $ do
      assertEqual "tag" (Just "NonNfcForm") (sub [0x0065, 0x0301])
      assertEqual "position" [0] (detectionPositions (detect [0x0065, 0x0301]))

  , testCase "fi ligature fires NonNfkcCompatForm" $
      assertEqual "nfkc" (Just "NonNfkcCompatForm") (sub [0xFB01])
  ]
