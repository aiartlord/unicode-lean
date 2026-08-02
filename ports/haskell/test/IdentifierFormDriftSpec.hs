{-|
  Tests for "Unicode.Security.Boundary.IdentifierFormDrift" — mirrors the
  @detect_*@ ground-truth theorems in the verified Rust reference.

  Three groups: the 8 shared context-free detector-fixture vectors run through
  'detect' and asserted against their @required_findings@ reason codes; the
  Rust @detect_*@ spot checks (empty / ASCII "Hello" / Greek α clear;
  math-italic-a, fullwidth-A, circled-A, fi-ligature, roman-IV all shift); and
  a mid-string first-shift-position check.
-}
module IdentifierFormDriftSpec (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Unicode.Security.Boundary.IdentifierFormDrift
  ( Classification (Clear, Hazard)
  , classificationIsClear
  , classificationPositions
  , classificationTag
  , detect
  , reasonCode
  , verdictClassify
  , verdictShiftCount
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
-- fixtures/security/detectors/identifier_form_drift.json (8 vectors), each run
-- through detect. required_findings [] means the input must be clear; a
-- populated list means findingCode must match the single required reason code.

statusShiftCode :: Maybe String
statusShiftCode = Just "unicode.security.X.identifier-form-drift.IdentifierStatusShift"

fixtureTests :: [TestTree]
fixtureTests =
  [ testCase "empty-clear" $
      assertEqual "code" Nothing (findingCode [])
  , testCase "ascii-hello-clear" $
      assertEqual "code" Nothing (findingCode [72, 101, 108, 108, 111])
  , testCase "greek-alpha-clear" $
      assertEqual "code" Nothing (findingCode [945])
  , testCase "math-italic-a-shift" $
      assertEqual "code" statusShiftCode (findingCode [119886])
  , testCase "fullwidth-A-shift" $
      assertEqual "code" statusShiftCode (findingCode [65313])
  , testCase "circled-A-shift" $
      assertEqual "code" statusShiftCode (findingCode [9398])
  , testCase "fi-ligature-shift" $
      assertEqual "code" statusShiftCode (findingCode [64257])
  , testCase "roman-iv-shift" $
      assertEqual "code" statusShiftCode (findingCode [8547])
  ]

-- ── §4 detect spot checks (one per Rust detect_* theorem) ─────────────────

spotCheckTests :: [TestTree]
spotCheckTests =
  [ testCase "detect_empty_clear" $
      assertBool "clear" (isClear [])
  , testCase "detect_ascii_clear" $ do
      let v = detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]
      assertBool "clear" (classificationIsClear (verdictClassify v))
      assertEqual "shift_count" 0 (verdictShiftCount v)
  , testCase "detect_greek_alpha_clear" $
      assertBool "clear" (isClear [0x03B1])
  , testCase "detect_math_italic_a_shift" $ do
      let v = detect [0x1D44E]
      assertEqual "tag" (Just "IdentifierStatusShift") (classificationTag (verdictClassify v))
      assertEqual "positions" [0] (classificationPositions (verdictClassify v))
      assertEqual "shift_count" 1 (verdictShiftCount v)
  , testCase "detect_fullwidth_A_shift" $
      assertEqual "tag" (Just "IdentifierStatusShift") (tag [0xFF21])
  , testCase "detect_circled_A_shift" $
      assertEqual "tag" (Just "IdentifierStatusShift") (tag [0x24B6])
  , testCase "detect_fi_ligature_shift" $
      assertEqual "tag" (Just "IdentifierStatusShift") (tag [0xFB01])
  , testCase "detect_roman_iv_shift" $
      assertEqual "tag" (Just "IdentifierStatusShift") (tag [0x2163])
  ]

-- ── Structural check (a shift embedded mid-string) ───────────────────────

structureTests :: [TestTree]
structureTests =
  [ testCase "detect_reports_first_shift_position" $ do
      -- "ab" + U+1D44E: positions 0,1 are Allowed/identity, position 2 shifts.
      let v = detect [0x61, 0x62, 0x1D44E]
      assertEqual "positions" [2] (classificationPositions (verdictClassify v))
      assertEqual "shift_count" 1 (verdictShiftCount v)
  , testCase "reason_code_is_stable" $
      assertEqual "code" statusShiftCode (findingCode [0x1D44E])
  ]

tests :: TestTree
tests = testGroup "Unicode.Security.Boundary.IdentifierFormDrift"
  (fixtureTests ++ spotCheckTests ++ structureTests)
