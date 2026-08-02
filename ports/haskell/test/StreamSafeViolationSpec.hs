{-|
  Tests for "Unicode.Security.Form.StreamSafeViolation" — mirrors the
  @detect_*@ ground-truth theorems in the verified Rust reference
  @ports/rust/src/security/form/stream_safe_violation.rs@.

  Two groups: the shared context-free detector fixture
  (@fixtures/security/detectors/stream_safe_violation.json@), each vector run
  through 'detect'; and the 30/31 boundary plus the Rust @#[test]@ module's
  run-inventory structure checks (bare run, two short runs, first-overrun wins),
  with the reason-code round-trip against the fixture's @required_findings@.

  U+0301 COMBINING ACUTE ACCENT has CCC = 230 (a non-starter); the ASCII
  letters in these vectors have CCC = 0 (starters).
-}
module StreamSafeViolationSpec (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Unicode.Security.Form.StreamSafeViolation
  ( Classification (Hazard)
  , SubThreat (StreamSafeOverrun)
  , classificationIsClear
  , classificationPositions
  , classificationTag
  , detect
  , reasonCode
  , verdictClassify
  , verdictMaxRunLen
  , verdictOverrunCount
  , verdictTotalNonStarters
  )

-- | U+0301 COMBINING ACUTE ACCENT, CCC = 230.
acute :: Int
acute = 0x0301

-- | "a" (U+0061, a starter) followed by @n@ combining acute accents.
aPlusMarks :: Int -> [Int]
aPlusMarks n = 0x61 : replicate n acute

-- ── Shared context-free detector fixture ────────────────────────────────
-- fixtures/security/detectors/stream_safe_violation.json, run through detect.

fixtureTests :: [TestTree]
fixtureTests =
  [ testCase "empty-clear" $
      assertBool "empty is clear" (classificationIsClear (verdictClassify (detect [])))

  , testCase "ascii-hello-clear" $
      assertBool "Hello is clear"
        (classificationIsClear (verdictClassify (detect [72, 101, 108, 108, 111])))

  , testCase "one-combine-clear" $
      assertBool "a + one mark is clear"
        (classificationIsClear (verdictClassify (detect [97, 769])))

  , testCase "thirty-marks-boundary-clear" $ do
      let v = detect (aPlusMarks 30)
      assertBool "30 marks stays clear under strict >" (classificationIsClear (verdictClassify v))
      assertEqual "tag" Nothing (classificationTag (verdictClassify v))
      assertEqual "maxRunLen" 30 (verdictMaxRunLen v)
      assertEqual "overrunCount" 0 (verdictOverrunCount v)
      assertEqual "totalNonStarters" 30 (verdictTotalNonStarters v)

  , testCase "thirtyone-marks-overrun" $ do
      let v = detect (aPlusMarks 31)
      assertBool "31 marks fires" (not (classificationIsClear (verdictClassify v)))
      assertEqual "tag" (Just "StreamSafeOverrun") (classificationTag (verdictClassify v))
      assertEqual "positions" [1] (classificationPositions (verdictClassify v))
      assertEqual "classification"
        (Hazard (StreamSafeOverrun 1 31) [1] [])
        (verdictClassify v)
      assertEqual "reason code"
        "unicode.security.F.stream-safe-violation.StreamSafeOverrun"
        (reasonCode (StreamSafeOverrun 1 31))
      assertEqual "maxRunLen" 31 (verdictMaxRunLen v)
      assertEqual "overrunCount" 1 (verdictOverrunCount v)
      assertEqual "totalNonStarters" 31 (verdictTotalNonStarters v)
  ]

-- ── Run-inventory structure checks (Rust #[test] module) ─────────────────

structureTests :: [TestTree]
structureTests =
  [ testCase "bare mark run starts at zero" $ do
      let v = detect (replicate 31 acute)
      assertEqual "tag" (Just "StreamSafeOverrun") (classificationTag (verdictClassify v))
      assertEqual "positions" [0] (classificationPositions (verdictClassify v))
      assertEqual "maxRunLen" 31 (verdictMaxRunLen v)
      assertEqual "totalNonStarters" 31 (verdictTotalNonStarters v)

  , testCase "two short runs clear, totals summed" $ do
      let v = detect (aPlusMarks 30 ++ [0x62] ++ replicate 30 acute)
      assertBool "clear" (classificationIsClear (verdictClassify v))
      assertEqual "maxRunLen" 30 (verdictMaxRunLen v)
      assertEqual "overrunCount" 0 (verdictOverrunCount v)
      assertEqual "totalNonStarters" 60 (verdictTotalNonStarters v)

  , testCase "first overrun reports long run start" $ do
      let v = detect (aPlusMarks 5 ++ [0x62] ++ replicate 31 acute)
      assertEqual "tag" (Just "StreamSafeOverrun") (classificationTag (verdictClassify v))
      assertEqual "positions" [7] (classificationPositions (verdictClassify v))
      assertEqual "maxRunLen" 31 (verdictMaxRunLen v)
      assertEqual "overrunCount" 1 (verdictOverrunCount v)
      assertEqual "totalNonStarters" 36 (verdictTotalNonStarters v)
  ]

tests :: TestTree
tests = testGroup "Unicode.Security.Form.StreamSafeViolation"
  (fixtureTests ++ structureTests)
