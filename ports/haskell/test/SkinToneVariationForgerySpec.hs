{-|
  Tests for "Unicode.Security.Identity.SkinToneVariationForgery" — mirrors the
  @detect_*@ ground-truth theorems in the verified Rust reference.

  Three groups: the 8 shared context-free detector-fixture vectors run through
  'detect' and asserted against their @required_findings@ reason codes; the
  Rust @detect_*@ spot checks (empty / ASCII "He" / plain-emoji / wave+single
  skin tone clear; stacked, invalid-on-ASCII, invalid-on-smiley,
  forced-text-style); and the position/count structural checks.
-}
module SkinToneVariationForgerySpec (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Unicode.Security.Identity.SkinToneVariationForgery
  ( Classification (Clear, Hazard)
  , classificationIsClear
  , classificationPositions
  , classificationTag
  , detect
  , isEmojiPresentation
  , isSkinTone
  , isSkinToneBase
  , reasonCode
  , verdictClassify
  , verdictSkinToneCount
  , verdictVariationSelector15Count
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
-- fixtures/security/detectors/skin_tone_variation_forgery.json (8 vectors),
-- each run through detect. required_findings [] means the input must be clear;
-- a populated list means findingCode must match the single required reason code.

stacked :: Maybe String
stacked = Just "unicode.security.I.skin-tone-variation-forgery.StackedSkinTones"

invalidTarget :: Maybe String
invalidTarget = Just "unicode.security.I.skin-tone-variation-forgery.InvalidSkinToneTarget"

forced :: Maybe String
forced = Just "unicode.security.I.skin-tone-variation-forgery.ForcedTextStyle"

fixtureTests :: [TestTree]
fixtureTests =
  [ testCase "empty-clear" $
      assertEqual "code" Nothing (findingCode [])
  , testCase "ascii-clear" $
      assertEqual "code" Nothing (findingCode [72, 101])
  , testCase "plain-emoji-clear" $
      assertEqual "code" Nothing (findingCode [128512])
  , testCase "wave-single-skin-tone-clear" $
      assertEqual "code" Nothing (findingCode [128075, 127995])
  , testCase "stacked-skin-tones" $
      assertEqual "code" stacked (findingCode [128075, 127995, 127996])
  , testCase "invalid-target-ascii" $
      assertEqual "code" invalidTarget (findingCode [65, 127995])
  , testCase "invalid-target-smiley" $
      assertEqual "code" invalidTarget (findingCode [128512, 127995])
  , testCase "forced-text-style" $
      assertEqual "code" forced (findingCode [128512, 65038])
  ]

-- ── §6 detect spot checks (one per Rust detect_* theorem) ─────────────────

spotCheckTests :: [TestTree]
spotCheckTests =
  [ testCase "detect_empty_clear" $
      assertBool "clear" (isClear [])
  , testCase "detect_ascii_clear" $
      assertBool "clear" (isClear [0x48, 0x65])
  , testCase "detect_plain_emoji_clear" $
      assertBool "clear" (isClear [0x1F600])
  , testCase "detect_wave_skin_tone_clear" $ do
      let v = detect [0x1F44B, 0x1F3FB]
      assertBool "clear" (classificationIsClear (verdictClassify v))
      assertEqual "skin_tone_count" 1 (verdictSkinToneCount v)
  , testCase "detect_stacked_skin_tones" $ do
      let v = detect [0x1F44B, 0x1F3FB, 0x1F3FC]
      assertEqual "tag" (Just "StackedSkinTones") (classificationTag (verdictClassify v))
      assertEqual "positions" [1, 2] (classificationPositions (verdictClassify v))
  , testCase "detect_invalid_target_ascii" $ do
      let v = detect [0x0041, 0x1F3FB]
      assertEqual "tag" (Just "InvalidSkinToneTarget") (classificationTag (verdictClassify v))
      assertEqual "positions" [1] (classificationPositions (verdictClassify v))
  , testCase "detect_invalid_target_smiley" $
      assertEqual "tag" (Just "InvalidSkinToneTarget") (tag [0x1F600, 0x1F3FB])
  , testCase "detect_forced_text_style" $ do
      let v = detect [0x1F600, 0xFE0E]
      assertEqual "tag" (Just "ForcedTextStyle") (classificationTag (verdictClassify v))
      assertEqual "vs15_count" 1 (verdictVariationSelector15Count v)
  ]

-- ── Reused-predicate sanity + reason-code stability ──────────────────────

structureTests :: [TestTree]
structureTests =
  [ testCase "reused_predicates" $ do
      assertBool "1F3FB is a skin tone" (isSkinTone 0x1F3FB)
      assertBool "1F44B is a modifier base" (isSkinToneBase 0x1F44B)
      assertBool "1F600 is emoji presentation" (isEmojiPresentation 0x1F600)
      assertBool "1F600 is not a modifier base" (not (isSkinToneBase 0x1F600))
  , testCase "reason_code_is_stable" $
      assertEqual "code" stacked (findingCode [0x1F44B, 0x1F3FB, 0x1F3FC])
  ]

tests :: TestTree
tests = testGroup "Unicode.Security.Identity.SkinToneVariationForgery"
  (fixtureTests ++ spotCheckTests ++ structureTests)
