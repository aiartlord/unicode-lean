{-|
  Tests for "Unicode.Normalization.NFKD" — mirrors the @toNFKD@ vector
  theorems in @Unicode/Normalization/NFKD.lean@.

  Each Lean @theorem toNFKD_* := by ...@ becomes a HUnit case with the
  same codepoint input and expected output, anchoring the compatibility
  decomposition + canonical reorder pipeline against the pinned UCD.
-}
module NFKDSpec (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, testCase)

import Unicode.Normalization.NFKD (toNFKD)

tests :: TestTree
tests = testGroup "Unicode.Normalization.NFKD"
  [ testCase "toNFKD_empty — empty sequence" $
      assertEqual "empty" [] (toNFKD [])

  , testCase "toNFKD_ascii — pure ASCII unchanged" $
      assertEqual "Hi" [0x0048, 0x0069] (toNFKD [0x0048, 0x0069])

  , testCase "toNFKD_decomposes_A_grave — canonical branch" $
      assertEqual "A grave" [0x0041, 0x0300] (toNFKD [0x00C0])

  , testCase "toNFKD_decomposes_super_2 — compatibility-only" $
      assertEqual "superscript two" [0x0032] (toNFKD [0x00B2])

  , testCase "toNFKD_nbsp — no-break space" $
      assertEqual "nbsp" [0x0020] (toNFKD [0x00A0])

  , testCase "toNFKD_diaeresis — space + combining diaeresis" $
      assertEqual "diaeresis" [0x0020, 0x0308] (toNFKD [0x00A8])

  , testCase "toNFKD_ligature_ff — ligature to two f's" $
      assertEqual "ligature ff" [0x0066, 0x0066] (toNFKD [0xFB00])

  , testCase "toNFKD_hangul — algorithmic syllable decomposition" $
      assertEqual "hangul GA" [0x1100, 0x1161] (toNFKD [0xAC00])
  ]
