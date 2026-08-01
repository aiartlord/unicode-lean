{-|
  Tests for "Unicode.Security.Crypto.Bip39Canonical" — mirrors the detect
  ground-truth vectors in
  @Unicode/Security/Crypto/Bip39CanonicalVectorsDetect.lean@.

  Each probe in the priority order is exercised by one non-canonical input,
  plus the two clear cases (empty input and a well-formed 12-word English
  mnemonic).
-}
module Bip39CanonicalSpec (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, testCase)

import Unicode.Security.Crypto.Bip39Canonical
  ( Classification (Clear, Hazard)
  , classificationPositions
  , classificationTag
  , detect
  , languageName
  , verdictClassify
  , verdictWordCount
  )

abandon :: [Int]
abandon = [0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E]

about :: [Int]
about = [0x61, 0x62, 0x6F, 0x75, 0x74]

-- | The sub-threat tag reported for an input (Nothing when clear).
tagOf :: [Int] -> Maybe String
tagOf = classificationTag . verdictClassify . detect

-- | The clear-case language name, or "hazard" for a non-clear verdict.
clearLanguageOf :: [Int] -> String
clearLanguageOf input =
  case verdictClassify (detect input) of
    Clear lang        -> languageName lang
    Hazard _sub _pos  -> "hazard"

tests :: TestTree
tests = testGroup "Unicode.Security.Crypto.Bip39Canonical"
  [ testCase "trailing whitespace fires with its position" $ do
      assertEqual "tag" (Just "TrailingWhitespace") (tagOf (abandon ++ [0x20]))
      assertEqual "position"
        [7]
        (classificationPositions (verdictClassify (detect (abandon ++ [0x20]))))

  , testCase "mixed case fires on the first uppercase" $
      assertEqual "tag" (Just "MixedCase") (tagOf (0x41 : drop 1 abandon))

  , testCase "double space fires whitespace anomaly" $
      assertEqual "tag" (Just "WhitespaceAnomaly") (tagOf (abandon ++ [0x20, 0x20] ++ about))

  , testCase "leading space fires whitespace anomaly" $
      assertEqual "tag" (Just "WhitespaceAnomaly") (tagOf (0x20 : abandon))

  , testCase "ligature fires non-NFKD" $
      assertEqual "tag" (Just "NonNFKD") (tagOf [0xFB00])

  , testCase "no-break space fires non-NFKD" $
      assertEqual "tag" (Just "NonNFKD") (tagOf [0x61, 0x00A0, 0x62])

  , testCase "unknown word fires wordlist mismatch" $
      assertEqual "tag" (Just "WordlistMismatch") (tagOf [0x71, 0x7A, 0x71, 0x7A])

  , testCase "empty input is clear English" $ do
      assertEqual "tag" Nothing (tagOf [])
      assertEqual "language" "english" (clearLanguageOf [])
      assertEqual "word count" 0 (verdictWordCount (detect []))

  , testCase "well-formed 12-word English mnemonic is clear" $
      let mnemonic = concat (replicate 11 (abandon ++ [0x20])) ++ about
      in do
        assertEqual "tag" Nothing (tagOf mnemonic)
        assertEqual "language" "english" (clearLanguageOf mnemonic)
        assertEqual "word count" 12 (verdictWordCount (detect mnemonic))
  ]
