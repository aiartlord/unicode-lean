{-|
  Tests for "Unicode.Security.Boundary.AdmissibilityFormDrift" — mirrors the
  @detect_*@ ground-truth theorems in the verified Rust reference.

  Two groups: the 4 shared context-free detector-fixture vectors
  (@fixtures/security/detectors/admissibility_form_drift.json@) run through
  'detect' and asserted against their @required_findings@ reason codes; and the
  4 Rust @detect_*@ spot checks (empty clear; ASCII "admin" clear with both
  admissibility booleans true; ﬁ ligature drift with @input_admissible=False@ /
  @nfkc_admissible=True@; decomposed Hangul jamos drift).
-}
module AdmissibilityFormDriftSpec (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Unicode.Security.Boundary.AdmissibilityFormDrift
  ( Classification (Clear, Hazard)
  , classificationIsClear
  , classificationTag
  , detect
  , reasonCode
  , verdictClassify
  , verdictInputAdmissible
  , verdictNfkcAdmissible
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
-- fixtures/security/detectors/admissibility_form_drift.json (4 vectors), each
-- run through detect. required_findings [] means the input must be clear; a
-- populated list means findingCode must match the single required reason code.

fixtureTests :: [TestTree]
fixtureTests =
  [ testCase "empty-clear" $
      assertEqual "code" Nothing (findingCode [])
  , testCase "ascii-admin-clear" $
      assertEqual "code" Nothing (findingCode [97, 100, 109, 105, 110])
  , testCase "fi-ligature-drift" $
      assertEqual "code"
        (Just "unicode.security.X.admissibility-form-drift.AdmissibilityFormDrift")
        (findingCode [64257])
  , testCase "jamo-sequence-drift" $
      assertEqual "code"
        (Just "unicode.security.X.admissibility-form-drift.AdmissibilityFormDrift")
        (findingCode [4370, 4449, 4523])
  ]

-- ── §3 detect spot checks (one per Rust detect_* theorem) ─────────────────

spotCheckTests :: [TestTree]
spotCheckTests =
  [ testCase "detect_empty_clear" $
      assertBool "clear" (isClear [])
  , testCase "detect_ascii_clear" $ do
      let v = detect [0x61, 0x64, 0x6D, 0x69, 0x6E]
      assertBool "clear" (classificationIsClear (verdictClassify v))
      assertBool "input_admissible" (verdictInputAdmissible v)
      assertBool "nfkc_admissible" (verdictNfkcAdmissible v)
  , testCase "detect_fi_ligature_drift" $ do
      let v = detect [0xFB01]
      assertEqual "tag" (Just "AdmissibilityFormDrift") (classificationTag (verdictClassify v))
      assertBool "input_inadmissible" (not (verdictInputAdmissible v))
      assertBool "nfkc_admissible" (verdictNfkcAdmissible v)
  , testCase "detect_jamo_sequence_drift" $
      assertEqual "tag" (Just "AdmissibilityFormDrift") (tag [0x1112, 0x1161, 0x11AB])
  ]

tests :: TestTree
tests = testGroup "Unicode.Security.Boundary.AdmissibilityFormDrift"
  (fixtureTests ++ spotCheckTests)
