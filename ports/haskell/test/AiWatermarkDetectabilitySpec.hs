{-|
  Tests for "Unicode.Security.Crypto.AiWatermarkDetectability" — mirrors the
  ground-truth vectors in the verified Rust reference
  @ports/rust/src/security/crypto/ai_watermark_detectability.rs@.

  Three groups: the shared context-free detector fixture
  (@fixtures/security/detectors/ai_watermark_detectability.json@, 24 vectors)
  run through 'detect'; the two Context-tolerance vectors from the Rust test
  module (@detect_zwsp_jittered_*@) run through 'detectWithContext'; and the
  probe / priority / cue-class spot checks transcribed from the Rust @#[test]@
  module.
-}
module AiWatermarkDetectabilitySpec (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Unicode.Security.Crypto.AiWatermarkDetectability
  ( Classification (Clear)
  , Context (contextZwspModuloTolerance)
  , CueClass (GreenListBias, PseudorandomSeq, SemanticDrift)
  , SubThreat
      ( Adversarial, DefaultIgnorableCarrier, EmDashPattern, Gpt5ZwspModulo
      , NnbspBoundary, SmartQuoteAlternation, StatisticalTokenChoice, Unknown
      , VariationSelectorCarrier, ZwjNonEmoji
      )
  , classificationPositions
  , classificationTag
  , defaultContext
  , detect
  , detectWithContext
  , subThreatCueClass
  , verdictClassify
  , verdictMarkerCount
  )

-- | The sub-threat tag reported for a bare input (Nothing when clear).
tag :: [Int] -> Maybe String
tag = classificationTag . verdictClassify . detect

-- | The implicated positions for a bare input.
positions :: [Int] -> [Int]
positions = classificationPositions . verdictClassify . detect

-- | The marker count for a bare input.
markerCount :: [Int] -> Int
markerCount = verdictMarkerCount . detect

-- ── Shared context-free detector fixture ─────────────────────────────────
-- fixtures/security/detectors/ai_watermark_detectability.json (24 vectors),
-- each run through detect. required_findings [] means the tag must be Nothing.

fixtureTests :: [TestTree]
fixtureTests =
  [ testCase "empty-clear" $
      assertEqual "tag" Nothing (tag [])
  , testCase "ascii-clear" $
      assertEqual "tag" Nothing (tag [97, 98, 99])
  , testCase "han-clear" $
      assertEqual "tag" Nothing (tag [20013, 25991])
  , testCase "nnbsp-boundary" $
      assertEqual "tag" (Just "NnbspBoundary") (tag [97, 8239, 98])
  , testCase "multiple-nnbsp-aggregates" $
      assertEqual "tag" (Just "NnbspBoundary") (tag [97, 8239, 98, 8239, 99])
  , testCase "vs-in-plain-text" $
      assertEqual "tag" (Just "VariationSelectorCarrier") (tag [97, 65039, 98])
  , testCase "vs-after-emoji-clear" $
      assertEqual "tag" Nothing (tag [128512, 65039])
  , testCase "zwj-in-plain-text" $
      assertEqual "tag" (Just "ZwjNonEmoji") (tag [97, 8205, 98])
  , testCase "zwj-emoji-sequence-clear" $
      assertEqual "tag" Nothing (tag [128105, 8205, 128300])
  , testCase "soft-hyphen-default-ignorable" $
      assertEqual "tag" (Just "DefaultIgnorableCarrier") (tag [97, 173, 98])
  , testCase "zwsp-default-ignorable" $
      assertEqual "tag" (Just "DefaultIgnorableCarrier") (tag [97, 8203, 98])
  , testCase "unknown-nnbsp-plus-di" $
      assertEqual "tag" (Just "Unknown") (tag [97, 8239, 173, 98])
  , testCase "unknown-vs-plus-zwj" $
      assertEqual "tag" (Just "Unknown") (tag [97, 65039, 8205, 98])
  , testCase "unknown-nnbsp-plus-zwj" $
      assertEqual "tag" (Just "Unknown") (tag [97, 8239, 8205, 98])
  , testCase "adversarial-arithmetic-nnbsp" $
      assertEqual "tag" (Just "Adversarial") (tag [97, 8239, 98, 8239, 99, 8239, 100])
  , testCase "gpt5-zwsp-modulo" $
      assertEqual "tag" (Just "Gpt5ZwspModulo") (tag [97, 8203, 98, 8203, 99, 8203, 100])
  , testCase "zwsp-two-below-modulo-threshold" $
      assertEqual "tag" (Just "DefaultIgnorableCarrier") (tag [97, 8203, 98, 8203, 99])
  , testCase "zwsp-jittered-strict-default-ignorable" $
      assertEqual "tag" (Just "DefaultIgnorableCarrier")
        (tag [97, 8203, 98, 8203, 99, 100, 8203, 101])
  , testCase "smart-quote-alternation" $
      assertEqual "tag" (Just "SmartQuoteAlternation") (tag [8220, 97, 98, 99, 8221])
  , testCase "smart-quote-with-straight-clear" $
      assertEqual "tag" Nothing (tag [8220, 97, 34, 8221])
  , testCase "em-dash-pattern" $
      assertEqual "tag" (Just "EmDashPattern")
        (tag [97, 98, 32, 8212, 32, 99, 100, 32, 8212, 32, 101, 102])
  , testCase "em-dash-with-hyphen-clear" $
      assertEqual "tag" Nothing (tag [97, 98, 45, 99, 100, 32, 8212, 32, 101, 102])
  , testCase "statistical-token-delve" $
      assertEqual "tag" (Just "StatisticalTokenChoice") (tag [100, 101, 108, 118, 101])
  , testCase "statistical-token-moreover-embedded" $
      assertEqual "tag" (Just "StatisticalTokenChoice")
        (tag [59, 32, 109, 111, 114, 101, 111, 118, 101, 114, 44, 32])
  ]

-- ── Context tolerance vectors (Rust detect_zwsp_jittered_*) ───────────────

toleranceVectorTests :: [TestTree]
toleranceVectorTests =
  [ testCase "detect_zwsp_jittered_strict_clear" $
      -- ZWSPs at 1, 3, 6 (gaps 2, 3). Bare detect (tolerance 0) does not fire
      -- gpt5ZwspModulo; falls through to defaultIgnorableCarrier.
      assertEqual "tag" (Just "DefaultIgnorableCarrier")
        (tag [0x61, 0x200B, 0x62, 0x200B, 0x63, 0x64, 0x200B, 0x65])
  , testCase "detect_zwsp_jittered_tolerant_fires" $
      let ctx   = defaultContext { contextZwspModuloTolerance = 1 }
          input = [0x61, 0x200B, 0x62, 0x200B, 0x63, 0x64, 0x200B, 0x65]
          v     = detectWithContext ctx input
      in assertEqual "tag" (Just "Gpt5ZwspModulo") (classificationTag (verdictClassify v))
  , testCase "detect_with_context_default_matches_detect" $
      let d = detect [0x61, 0x202F, 0x62]
          c = detectWithContext defaultContext [0x61, 0x202F, 0x62]
      in assertEqual "classify" (verdictClassify d) (verdictClassify c)
  ]

-- ── Probe / detect / priority spot checks (Rust #[test] module) ───────────

spotCheckTests :: [TestTree]
spotCheckTests =
  [ testCase "detect_nnbsp_fires" $ do
      assertEqual "tag" (Just "NnbspBoundary") (tag [0x61, 0x202F, 0x62])
      assertEqual "positions" [1] (positions [0x61, 0x202F, 0x62])
      assertEqual "marker_count" 1 (markerCount [0x61, 0x202F, 0x62])
  , testCase "detect_vs_in_plain_text_fires" $ do
      assertEqual "tag" (Just "VariationSelectorCarrier") (tag [0x61, 0xFE0F, 0x62])
      assertEqual "marker_count" 1 (markerCount [0x61, 0xFE0F, 0x62])
  , testCase "detect_vs_after_emoji_clear" $
      assertEqual "classify" Clear (verdictClassify (detect [0x1F600, 0xFE0F]))
  , testCase "detect_zwj_in_plain_text_fires" $ do
      assertEqual "tag" (Just "ZwjNonEmoji") (tag [0x61, 0x200D, 0x62])
      assertEqual "marker_count" 1 (markerCount [0x61, 0x200D, 0x62])
  , testCase "detect_zwj_emoji_sequence_clear" $
      assertEqual "classify" Clear (verdictClassify (detect [0x1F469, 0x200D, 0x1F52C]))
  , testCase "detect_soft_hyphen_fires" $ do
      assertEqual "tag" (Just "DefaultIgnorableCarrier") (tag [0x61, 0x00AD, 0x62])
      assertEqual "marker_count" 1 (markerCount [0x61, 0x00AD, 0x62])
  , testCase "detect_zwsp_fires" $ do
      assertEqual "tag" (Just "DefaultIgnorableCarrier") (tag [0x61, 0x200B, 0x62])
      assertEqual "marker_count" 1 (markerCount [0x61, 0x200B, 0x62])
  , testCase "detect_priority_unknown_over_nnbsp_with_di" $
      assertEqual "tag" (Just "Unknown") (tag [0x61, 0x202F, 0x00AD, 0x62])
  , testCase "detect_priority_unknown_over_vs_with_zwj" $
      assertEqual "tag" (Just "Unknown") (tag [0x61, 0xFE0F, 0x200D, 0x62])
  , testCase "detect_multiple_nnbsp_aggregates" $ do
      assertEqual "tag" (Just "NnbspBoundary") (tag [0x61, 0x202F, 0x62, 0x202F, 0x63])
      assertEqual "marker_count" 2 (markerCount [0x61, 0x202F, 0x62, 0x202F, 0x63])
      assertEqual "positions" [1, 3] (positions [0x61, 0x202F, 0x62, 0x202F, 0x63])
  , testCase "detect_adversarial_arithmetic_nnbsp" $ do
      let v = detect [0x61, 0x202F, 0x62, 0x202F, 0x63, 0x202F, 0x64]
      assertEqual "tag" (Just "Adversarial") (classificationTag (verdictClassify v))
      assertEqual "marker_count" 3 (verdictMarkerCount v)
  , testCase "detect_nnbsp_two_below_adversarial_threshold" $
      assertEqual "tag" (Just "NnbspBoundary") (tag [0x61, 0x202F, 0x62, 0x202F, 0x63])
  , testCase "detect_gpt5_zwsp_modulo" $ do
      let v = detect [0x61, 0x200B, 0x62, 0x200B, 0x63, 0x200B, 0x64]
      assertEqual "tag" (Just "Gpt5ZwspModulo") (classificationTag (verdictClassify v))
      assertEqual "marker_count" 3 (verdictMarkerCount v)
  , testCase "detect_zwsp_two_below_modulo_threshold" $
      assertEqual "tag" (Just "DefaultIgnorableCarrier") (tag [0x61, 0x200B, 0x62, 0x200B, 0x63])
  , testCase "detect_smart_quote_alternation" $ do
      let v = detect [0x201C, 0x61, 0x62, 0x63, 0x201D]
      assertEqual "tag" (Just "SmartQuoteAlternation") (classificationTag (verdictClassify v))
      assertEqual "marker_count" 2 (verdictMarkerCount v)
  , testCase "detect_smart_quote_with_straight_clear" $
      assertEqual "classify" Clear (verdictClassify (detect [0x201C, 0x61, 0x22, 0x201D]))
  , testCase "detect_em_dash_pattern" $ do
      let v = detect [0x61, 0x62, 0x20, 0x2014, 0x20, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66]
      assertEqual "tag" (Just "EmDashPattern") (classificationTag (verdictClassify v))
      assertEqual "marker_count" 2 (verdictMarkerCount v)
  , testCase "detect_em_dash_with_hyphen_clear" $
      assertEqual "classify" Clear
        (verdictClassify (detect [0x61, 0x62, 0x2D, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66]))
  , testCase "detect_statistical_token_delve" $ do
      let v = detect [0x64, 0x65, 0x6C, 0x76, 0x65]
      assertEqual "tag" (Just "StatisticalTokenChoice") (classificationTag (verdictClassify v))
      assertEqual "marker_count" 1 (verdictMarkerCount v)
  , testCase "detect_statistical_token_moreover_embedded" $ do
      let v = detect [0x3B, 0x20, 0x6D, 0x6F, 0x72, 0x65, 0x6F, 0x76, 0x65, 0x72, 0x2C, 0x20]
      assertEqual "tag" (Just "StatisticalTokenChoice") (classificationTag (verdictClassify v))
      assertEqual "positions" [2] (classificationPositions (verdictClassify v))
  , testCase "detect_unknown_nnbsp_plus_di" $ do
      let v = detect [0x61, 0x202F, 0x00AD, 0x62]
      assertEqual "tag" (Just "Unknown") (classificationTag (verdictClassify v))
      assertEqual "marker_count" 2 (verdictMarkerCount v)
  , testCase "detect_unknown_vs_plus_zwj" $ do
      let v = detect [0x61, 0xFE0F, 0x200D, 0x62]
      assertEqual "tag" (Just "Unknown") (classificationTag (verdictClassify v))
      assertEqual "marker_count" 2 (verdictMarkerCount v)
  , testCase "detect_unknown_nnbsp_plus_zwj" $ do
      let v = detect [0x61, 0x202F, 0x200D, 0x62]
      assertEqual "tag" (Just "Unknown") (classificationTag (verdictClassify v))
      assertEqual "marker_count" 2 (verdictMarkerCount v)
  , testCase "detect_single_category_skips_unknown" $
      assertEqual "tag" (Just "NnbspBoundary") (tag [0x61, 0x202F, 0x62])
  , testCase "detect_priority_adversarial_over_nnbsp" $
      assertEqual "tag" (Just "Adversarial") (tag [0x61, 0x202F, 0x62, 0x202F, 0x63, 0x202F, 0x64])
  , testCase "detect_priority_zwsp_modulo_over_di" $
      assertEqual "tag" (Just "Gpt5ZwspModulo") (tag [0x61, 0x200B, 0x62, 0x200B, 0x63, 0x200B, 0x64])
  ]

-- ── Cue-class coverage (Rust every_cue_class_is_probed / unknown_has_none) ─

cueClassTests :: [TestTree]
cueClassTests =
  [ testCase "every_cue_class_is_probed" $
      mapM_
        (\cls ->
           assertBool ("cue class " ++ show cls ++ " is not probed by any sub-threat")
             (any (\st -> subThreatCueClass st == Just cls) subThreats))
        [GreenListBias, PseudorandomSeq, SemanticDrift]
  , testCase "unknown_has_no_cue_class" $
      assertEqual "unknown" Nothing (subThreatCueClass (Unknown 0))
  ]
  where
    subThreats =
      [ NnbspBoundary 0, VariationSelectorCarrier 0, ZwjNonEmoji 0
      , DefaultIgnorableCarrier 0, Gpt5ZwspModulo 0, EmDashPattern 0
      , SmartQuoteAlternation 0, StatisticalTokenChoice 0, Adversarial "" 0
      ]

tests :: TestTree
tests = testGroup "Unicode.Security.Crypto.AiWatermarkDetectability"
  (fixtureTests ++ toleranceVectorTests ++ spotCheckTests ++ cueClassTests)
