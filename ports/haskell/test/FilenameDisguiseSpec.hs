{-|
  Tests for "Unicode.Security.Display.FilenameDisguise" — mirrors the
  @detect_*@ ground-truth theorems in the verified Rust reference.

  Three groups: the 10 shared context-free detector-fixture vectors
  (@fixtures/security/detectors/filename_disguise.json@) run through 'detect'
  and asserted against their @required_findings@ reason codes; the 10 Rust
  @detect_*@ spot checks; and the 1 structural priority-ladder check (a bidi
  control outranks a fullwidth extension).
-}
module FilenameDisguiseSpec (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Unicode.Security.Display.FilenameDisguise
  ( Classification (Clear, Hazard)
  , classificationIsClear
  , classificationPositions
  , classificationTag
  , detect
  , reasonCode
  , verdictClassify
  , verdictLastDotPos
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
-- fixtures/security/detectors/filename_disguise.json (10 vectors), each run
-- through detect. required_findings [] means the input must be clear; a
-- populated list means findingCode must match the single required reason code.

fixtureTests :: [TestTree]
fixtureTests =
  [ testCase "empty-clear" $
      assertEqual "code" Nothing (findingCode [])
  , testCase "plain-document-txt-clear" $
      assertEqual "code" Nothing
        (findingCode [100, 111, 99, 117, 109, 101, 110, 116, 46, 116, 120, 116])
  , testCase "no-extension-clear" $
      assertEqual "code" Nothing (findingCode [102, 111, 111])
  , testCase "archive-tar-gz-clear" $
      assertEqual "code" Nothing
        (findingCode [97, 114, 99, 104, 105, 118, 101, 46, 116, 97, 114, 46, 103, 122])
  , testCase "hebrew-native-rtl-clear" $
      assertEqual "code" Nothing (findingCode [1488, 1489, 1490, 46, 116, 120, 116])
  , testCase "rlo-flip-hazard" $
      assertEqual "code"
        (Just "unicode.security.D.filename-disguise.RloFlip")
        (findingCode [100, 111, 99, 117, 109, 101, 110, 116, 8238, 116, 120, 116, 46, 101, 120, 101])
  , testCase "isolate-flip-hazard" $
      assertEqual "code"
        (Just "unicode.security.D.filename-disguise.RloFlip")
        (findingCode [100, 111, 99, 8295, 116, 120, 116, 46, 101, 120, 101, 8297])
  , testCase "fullwidth-ext-hazard" $
      assertEqual "code"
        (Just "unicode.security.D.filename-disguise.WidthClassExt")
        (findingCode [102, 105, 108, 101, 46, 65317, 65336, 65317])
  , testCase "combining-in-ext-hazard" $
      assertEqual "code"
        (Just "unicode.security.D.filename-disguise.CombiningInExt")
        (findingCode [102, 105, 108, 101, 46, 101, 769, 120, 101])
  , testCase "triple-extension-hazard" $
      assertEqual "code"
        (Just "unicode.security.D.filename-disguise.MultipleExtensions")
        (findingCode [115, 101, 116, 117, 112, 46, 116, 97, 114, 46, 103, 122, 46, 115, 105, 103])
  ]

-- ── §4 detect spot checks (one per Rust detect_* theorem) ─────────────────

spotCheckTests :: [TestTree]
spotCheckTests =
  [ testCase "detect_empty_clear" $
      assertBool "clear" (isClear [])
  , testCase "detect_plain_txt_clear" $ do
      let v = detect [0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x2E, 0x74, 0x78, 0x74]
      assertBool "clear" (classificationIsClear (verdictClassify v))
      assertEqual "last_dot_pos" (Just 8) (verdictLastDotPos v)
  , testCase "detect_no_extension_clear" $ do
      let v = detect [0x66, 0x6F, 0x6F]
      assertBool "clear" (classificationIsClear (verdictClassify v))
      assertEqual "last_dot_pos" Nothing (verdictLastDotPos v)
  , testCase "detect_tar_gz_clear" $
      assertBool "clear"
        (isClear [0x61, 0x72, 0x63, 0x68, 0x69, 0x76, 0x65, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A])
  , testCase "detect_rlo_flip" $ do
      let v = detect
                [0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x202E, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65]
      assertEqual "tag" (Just "RloFlip") (classificationTag (verdictClassify v))
      assertEqual "positions" [8] (classificationPositions (verdictClassify v))
  , testCase "detect_fullwidth_exe" $
      assertEqual "tag" (Just "WidthClassExt")
        (tag [0x66, 0x69, 0x6C, 0x65, 0x2E, 0xFF25, 0xFF38, 0xFF25])
  , testCase "detect_combining_in_ext" $
      assertEqual "tag" (Just "CombiningInExt")
        (tag [0x66, 0x69, 0x6C, 0x65, 0x2E, 0x65, 0x0301, 0x78, 0x65])
  , testCase "detect_triple_extension" $
      assertEqual "tag" (Just "MultipleExtensions")
        (tag [0x73, 0x65, 0x74, 0x75, 0x70, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A, 0x2E, 0x73, 0x69, 0x67])
  , testCase "detect_hebrew_clear" $
      assertBool "clear" (isClear [0x05D0, 0x05D1, 0x05D2, 0x2E, 0x74, 0x78, 0x74])
  , testCase "detect_isolate_flip" $
      assertEqual "tag" (Just "RloFlip")
        (tag [0x64, 0x6F, 0x63, 0x2067, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65, 0x2069])
  ]

-- ── Structural check (follows from the priority ladder) ──────────────────

structureTests :: [TestTree]
structureTests =
  [ testCase "bidi_beats_fullwidth" $
      -- A bidi control outranks a fullwidth extension.
      assertEqual "tag" (Just "RloFlip") (tag [0x202E, 0x66, 0x2E, 0xFF25])
  ]

tests :: TestTree
tests = testGroup "Unicode.Security.Display.FilenameDisguise"
  (fixtureTests ++ spotCheckTests ++ structureTests)
