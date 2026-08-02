{-|
  Tests for "Unicode.Security.Display.RendererDivergence" — mirrors the
  @detect_*@ ground-truth theorems in the verified Rust reference
  @ports/rust/src/security/display/renderer_divergence.rs@.

  Three groups: the 9 shared context-free detector-fixture vectors
  (@fixtures/security/detectors/renderer_divergence.json@) run through 'detect'
  and asserted against their @required_findings@ reason codes; the 9 Rust
  @detect_*@ spot checks; and the 2 structural priority-ladder checks
  (combining-stack outranks a later variation selector, and three marks stay
  below the stack threshold).
-}
module RendererDivergenceSpec (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Unicode.Security.Display.RendererDivergence
  ( Classification (Clear, Hazard)
  , classificationIsClear
  , classificationPositions
  , classificationTag
  , detect
  , reasonCode
  , verdictClassify
  , verdictCombiningCount
  , verdictHasZwj
  , verdictStrongLtrCount
  , verdictStrongRtlCount
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
-- fixtures/security/detectors/renderer_divergence.json (9 vectors), each run
-- through detect. required_findings [] means the input must be clear; a
-- populated list means findingCode must match the single required reason code.

fixtureTests :: [TestTree]
fixtureTests =
  [ testCase "empty-clear" $
      assertEqual "code" Nothing (findingCode [])
  , testCase "ascii-hello-clear" $
      assertEqual "code" Nothing (findingCode [72, 101, 108, 108, 111])
  , testCase "han-clear" $
      assertEqual "code" Nothing (findingCode [20013, 25991])
  , testCase "family-of-four-rgi-clear" $
      assertEqual "code" Nothing
        (findingCode [128104, 8205, 128105, 8205, 128103, 8205, 128102])
  , testCase "variation-selector-variance" $
      assertEqual "code"
        (Just "unicode.security.D.renderer-divergence.VariationSelectorVariance")
        (findingCode [128512, 65039])
  , testCase "unregistered-zwj-variance" $
      assertEqual "code"
        (Just "unicode.security.D.renderer-divergence.UnregisteredZwjVariance")
        (findingCode [128104, 8205, 128105])
  , testCase "combining-stack-overflow-zalgo" $
      assertEqual "code"
        (Just "unicode.security.D.renderer-divergence.CombiningStackOverflow")
        (findingCode [97, 769, 770, 771, 772])
  , testCase "fullwidth-variance" $
      assertEqual "code"
        (Just "unicode.security.D.renderer-divergence.FullwidthVariance")
        (findingCode [65313])
  , testCase "mixed-direction-variance" $
      assertEqual "code"
        (Just "unicode.security.D.renderer-divergence.MixedDirectionVariance")
        (findingCode [65, 66, 1488, 1489])
  ]

-- ── §5 detect spot checks (one per Rust detect_* theorem) ─────────────────

spotCheckTests :: [TestTree]
spotCheckTests =
  [ testCase "detect_empty_clear" $
      assertBool "clear" (isClear [])
  , testCase "detect_ascii_clear" $
      assertBool "clear" (isClear [0x48, 0x65, 0x6C, 0x6C, 0x6F])
  , testCase "detect_han_clear" $
      assertBool "clear" (isClear [0x4E2D, 0x6587])
  , testCase "detect_vs_variance" $
      assertEqual "tag" (Just "VariationSelectorVariance") (tag [0x1F600, 0xFE0F])
  , testCase "detect_rgi_family_clear" $ do
      let v = detect [0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466]
      assertBool "clear" (classificationIsClear (verdictClassify v))
      assertBool "has_zwj" (verdictHasZwj v)
  , testCase "detect_unregistered_zwj_variance" $
      assertEqual "tag" (Just "UnregisteredZwjVariance") (tag [0x1F468, 0x200D, 0x1F469])
  , testCase "detect_zalgo_variance" $ do
      let v = detect [0x0061, 0x0301, 0x0302, 0x0303, 0x0304]
      assertEqual "tag" (Just "CombiningStackOverflow") (classificationTag (verdictClassify v))
      assertEqual "positions" [0] (classificationPositions (verdictClassify v))
      assertEqual "combiningCount" 4 (verdictCombiningCount v)
  , testCase "detect_fullwidth_variance" $
      assertEqual "tag" (Just "FullwidthVariance") (tag [0xFF21])
  , testCase "detect_mixed_direction" $ do
      let v = detect [0x41, 0x42, 0x05D0, 0x05D1]
      assertEqual "tag" (Just "MixedDirectionVariance") (classificationTag (verdictClassify v))
      assertBool "both strong"
        (verdictStrongLtrCount v > 0 && verdictStrongRtlCount v > 0)
  ]

-- ── Structural checks (follow from the priority ladder) ──────────────────

structureTests :: [TestTree]
structureTests =
  [ testCase "combining_stack_beats_vs" $
      -- A combining stack outranks a variation selector present later.
      assertEqual "tag" (Just "CombiningStackOverflow")
        (tag [0x0061, 0x0301, 0x0302, 0x0303, 0x0304, 0xFE0F])
  , testCase "three_marks_below_threshold" $
      -- Exactly three combining marks is below the stack threshold.
      assertBool "not overflow"
        (tag [0x0061, 0x0301, 0x0302, 0x0303] /= Just "CombiningStackOverflow")
  ]

tests :: TestTree
tests = testGroup "Unicode.Security.Display.RendererDivergence"
  (fixtureTests ++ spotCheckTests ++ structureTests)
