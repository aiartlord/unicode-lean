{-|
  Tests for "Unicode.Security.Form.LocaleCaseInversion" — mirrors the
  @detect_*@ ground-truth theorems in
  @Unicode/Security/Form/LocaleCaseInversion.lean@.
-}
module LocaleCaseInversionSpec (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, testCase)

import Unicode.Security.Form.LocaleCaseInversion
  ( Detection (detectionPositions, detectionSub)
  , detect
  )

tags :: [Int] -> Maybe String
tags = detectionSub . detect

tests :: TestTree
tests = testGroup "Unicode.Security.Form.LocaleCaseInversion"
  [ testCase "empty input is clear" $
      assertEqual "empty" Nothing (tags [])

  , testCase "ASCII without I is clear" $
      assertEqual "Hello" Nothing (tags [0x48, 0x65, 0x6C, 0x6C, 0x6F])

  , testCase "capital I fires Turkish at position 0" $ do
      assertEqual "tag" (Just "TurkishCaseDivergence") (tags [0x0049])
      assertEqual "position" [0] (detectionPositions (detect [0x0049]))

  , testCase "dotted I fires Turkish" $
      assertEqual "dotted I" (Just "TurkishCaseDivergence") (tags [0x0130])

  , testCase "I + grave picks Turkish first" $
      assertEqual "priority" (Just "TurkishCaseDivergence") (tags [0x0049, 0x0300])

  , testCase "J + grave falls through to Lithuanian" $
      assertEqual "lithuanian" (Just "LithuanianCaseDivergence") (tags [0x004A, 0x0300])
  ]
