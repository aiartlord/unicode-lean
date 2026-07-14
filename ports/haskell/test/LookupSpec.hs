{-|
  Tests for "Unicode.Normalization.Lookup" — mirrors the closed-form
  theorems in @Unicode/Normalization/Lookup.lean@.

  Each Lean @theorem ... := by decide +kernel@ becomes a HUnit case
  with the same codepoint input and the same expected output. These
  anchor the Generated table bindings: a regenerated UCD table that
  silently dropped or reordered the relevant rows would fail one of
  these tests.
-}
module LookupSpec (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, testCase)

import Unicode.Normalization.Lookup
  ( canonicalCombiningClass
  , canonicalDecomposition
  , isCompositionExclusion
  , isFullCompositionExclusion
  )

tests :: TestTree
tests = testGroup "Unicode.Normalization.Lookup"
  [ cccCases
  , decompCases
  , exclusionCases
  ]

cccCases :: TestTree
cccCases = testGroup "canonicalCombiningClass"
  [ testCase "latin_A_ccc — U+0041 is NFC-inert" $
      assertEqual "Latin A"
        0
        (canonicalCombiningClass 0x0041)

  , testCase "combining_grave_ccc — U+0300 is class 230 (above)" $
      assertEqual "combining grave accent"
        230
        (canonicalCombiningClass 0x0300)

  , testCase "combining_acute_ccc — U+0301 is class 230 (above)" $
      assertEqual "combining acute accent"
        230
        (canonicalCombiningClass 0x0301)

  , testCase "nukta_ccc — U+093C (DEVANAGARI SIGN NUKTA) is class 7" $
      assertEqual "Devanagari nukta"
        7
        (canonicalCombiningClass 0x093C)

  , testCase "unlisted_ccc — codepoint above U+10FFFF default is 0" $
      assertEqual "unlisted codepoint"
        0
        (canonicalCombiningClass 0xFFFFF)
  ]

decompCases :: TestTree
decompCases = testGroup "canonicalDecomposition"
  [ testCase "latin_A_decomp — U+0041 has no canonical decomposition" $
      assertEqual "Latin A"
        []
        (canonicalDecomposition 0x0041)

  , testCase "latin_A_grave_decomp — U+00C0 decomposes to A + combining grave" $
      assertEqual "LATIN CAPITAL LETTER A WITH GRAVE"
        [0x0041, 0x0300]
        (canonicalDecomposition 0x00C0)

  , testCase "angstrom_decomp — U+212B decomposes to U+00C5 (singleton)" $
      assertEqual "ANGSTROM SIGN"
        [0x00C5]
        (canonicalDecomposition 0x212B)

  , testCase "unlisted_decomp — codepoint outside the table has no decomp" $
      assertEqual "unlisted codepoint"
        []
        (canonicalDecomposition 0xFFFFF)
  ]

exclusionCases :: TestTree
exclusionCases = testGroup "composition exclusions"
  [ testCase "devanagari_qa_is_exclusion — U+0958 is in the primary set" $
      assertEqual "DEVANAGARI LETTER QA"
        True
        (isCompositionExclusion 0x0958)

  , testCase "latin_A_not_exclusion — U+0041 is NOT in the primary set" $
      assertEqual "Latin A"
        False
        (isCompositionExclusion 0x0041)

  , testCase "devanagari_qa_is_full_exclusion — U+0958 also in broader set" $
      assertEqual "DEVANAGARI LETTER QA"
        True
        (isFullCompositionExclusion 0x0958)

  , testCase "combining_grave_tone_full_exclusion — U+0340 is FCE but not CE" $
      assertEqual "COMBINING GRAVE TONE MARK"
        (False, True)
        ( isCompositionExclusion 0x0340
        , isFullCompositionExclusion 0x0340
        )
  ]
