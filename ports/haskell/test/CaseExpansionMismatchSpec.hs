{-|
  Tests for "Unicode.Security.Form.CaseExpansionMismatch" — mirrors the
  @detect_*@ ground-truth theorems in the verified Rust reference.

  Three groups: the 6 shared context-free detector-fixture vectors
  (@case_expansion_mismatch.json@ under the port's testdata tree) run through
  'detect' and asserted against their @required_findings@ reason codes; the
  Rust @detect_*@ spot checks (empty / "Hello" ASCII clear; ß upper; ﬁ upper;
  ﬃ upper with max length 3; İ lower); and the mid-string position check
  (@[0x61, 0x00DF]@ reports position 1).
-}
module CaseExpansionMismatchSpec (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Unicode.Security.Form.CaseExpansionMismatch
  ( Classification (Clear, Hazard)
  , classificationIsClear
  , classificationPositions
  , classificationTag
  , detect
  , reasonCode
  , verdictClassify
  , verdictLowerExpansionCount
  , verdictMaxExpansionLen
  , verdictUpperExpansionCount
  )

-- | The sub-threat tag reported for an input ('Nothing' when clear).
tag :: [Int] -> Maybe String
tag = classificationTag . verdictClassify . detect

-- | True iff 'detect' classifies the input as clear.
isClear :: [Int] -> Bool
isClear = classificationIsClear . verdictClassify . detect

-- | The fully-qualified reason code emitted for an input, or 'Nothing' when
-- clear — the projection the shared fixture's @required_findings@ carries.
findingCode :: [Int] -> Maybe String
findingCode input =
  case verdictClassify (detect input) of
    Hazard sub _positions _decoded -> Just (reasonCode sub)
    Clear                          -> Nothing

-- ── Shared context-free detector fixture ─────────────────────────────────
-- case_expansion_mismatch.json (6 vectors), each run through detect.
-- required_findings [] means the input must be clear; a populated list means
-- findingCode must match the single required reason code.

fixtureTests :: [TestTree]
fixtureTests =
  [ testCase "empty-clear" $
      assertEqual "code" Nothing (findingCode [])
  , testCase "ascii-hello-clear" $
      assertEqual "code" Nothing (findingCode [72, 101, 108, 108, 111])
  , testCase "sharp-s-upper" $
      assertEqual "code"
        (Just "unicode.security.F.case-expansion-mismatch.UpperExpansion")
        (findingCode [223])
  , testCase "fi-ligature-upper" $
      assertEqual "code"
        (Just "unicode.security.F.case-expansion-mismatch.UpperExpansion")
        (findingCode [64257])
  , testCase "ffi-ligature-upper" $
      assertEqual "code"
        (Just "unicode.security.F.case-expansion-mismatch.UpperExpansion")
        (findingCode [64259])
  , testCase "dotted-I-lower" $
      assertEqual "code"
        (Just "unicode.security.F.case-expansion-mismatch.LowerExpansion")
        (findingCode [304])
  ]

-- ── §4 detect spot checks (one per Rust detect_* theorem) ─────────────────

spotCheckTests :: [TestTree]
spotCheckTests =
  [ testCase "detect_empty_clear" $
      assertBool "clear" (isClear [])
  , testCase "detect_ascii_clear" $ do
      let v = detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]
      assertBool "clear" (classificationIsClear (verdictClassify v))
      assertEqual "max_expansion_len" 1 (verdictMaxExpansionLen v)
  , testCase "detect_sharp_s_upper" $ do
      let v = detect [0x00DF]
      assertEqual "tag" (Just "UpperExpansion") (classificationTag (verdictClassify v))
      assertEqual "positions" [0] (classificationPositions (verdictClassify v))
      assertEqual "upper_expansion_count" 1 (verdictUpperExpansionCount v)
      assertEqual "max_expansion_len" 2 (verdictMaxExpansionLen v)
  , testCase "detect_fi_ligature_upper" $
      assertEqual "tag" (Just "UpperExpansion") (tag [0xFB01])
  , testCase "detect_dotted_I_lower" $ do
      let v = detect [0x0130]
      assertEqual "tag" (Just "LowerExpansion") (classificationTag (verdictClassify v))
      assertEqual "lower_expansion_count" 1 (verdictLowerExpansionCount v)
  , testCase "detect_ffi_ligature_len3" $ do
      let v = detect [0xFB03]
      assertEqual "tag" (Just "UpperExpansion") (classificationTag (verdictClassify v))
      assertEqual "max_expansion_len" 3 (verdictMaxExpansionLen v)
  ]

-- ── Structural check (mid-string expansion position) ─────────────────────

structureTests :: [TestTree]
structureTests =
  [ testCase "reports_first_expansion_position" $
      -- A leading ASCII then ß: the upper expansion is reported at position 1.
      assertEqual "positions" [1] (classificationPositions (verdictClassify (detect [0x61, 0x00DF])))
  ]

tests :: TestTree
tests = testGroup "Unicode.Security.Form.CaseExpansionMismatch"
  (fixtureTests ++ spotCheckTests ++ structureTests)
