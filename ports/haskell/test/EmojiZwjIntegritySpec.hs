{-|
  Tests for "Unicode.Security.Identity.EmojiZwjIntegrity" — mirrors the
  @detect_*@ ground-truth theorems in the verified Rust reference
  @ports/rust/src/security/identity/emoji_zwj_integrity.rs@.

  Four groups: the 12 shared context-free detector-fixture vectors
  (@fixtures/security/detectors/emoji_zwj_integrity.json@) run through 'detect'
  and asserted against their @required_findings@ reason codes; the 11 Rust
  @detect_*@ spot checks; the 3 structural priority-ladder checks; and the
  data-layer sanity checks (skin-tone predicate, ZWJ alphabet, exact registered
  membership).
-}
module EmojiZwjIntegritySpec (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Unicode.Security.Identity.EmojiZwjIntegrity
  ( Classification (Clear, Hazard)
  , SubThreat (OverLength)
  , classificationIsClear
  , classificationPositions
  , classificationTag
  , detect
  , isEmojiModifier
  , isEmojiTarget
  , isRegisteredZwjSequence
  , maxRgiLength
  , reasonCode
  , subThreatTag
  , verdictClassify
  , verdictIsRegisteredRgi
  , verdictSkinToneCount
  , verdictZwjPositions
  , zwj
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
-- fixtures/security/detectors/emoji_zwj_integrity.json (12 vectors), each run
-- through detect. required_findings [] means the input must be clear; a
-- populated list means findingCode must match the single required reason code.

fixtureTests :: [TestTree]
fixtureTests =
  [ testCase "empty-clear" $
      assertEqual "code" Nothing (findingCode [])
  , testCase "ascii-hello-clear" $
      assertEqual "code" Nothing (findingCode [72, 101, 108, 108, 111])
  , testCase "plain-emoji-clear" $
      assertEqual "code" Nothing (findingCode [128512])
  , testCase "one-skintone-clear" $
      assertEqual "code" Nothing (findingCode [128075, 127995])
  , testCase "family-of-four-rgi-clear" $
      assertEqual "code" Nothing
        (findingCode [128104, 8205, 128105, 8205, 128103, 8205, 128102])
  , testCase "man-technologist-rgi-clear" $
      assertEqual "code" Nothing (findingCode [128104, 8205, 128187])
  , testCase "double-zwj-hazard" $
      assertEqual "code"
        (Just "unicode.security.I.emoji-zwj-integrity.DoubleZWJ")
        (findingCode [128512, 8205, 8205, 128512])
  , testCase "non-emoji-injection-ascii-hazard" $
      assertEqual "code"
        (Just "unicode.security.I.emoji-zwj-integrity.NonEmojiInjection")
        (findingCode [128512, 8205, 97])
  , testCase "grinning-laptop-non-emoji-injection-hazard" $
      assertEqual "code"
        (Just "unicode.security.I.emoji-zwj-integrity.NonEmojiInjection")
        (findingCode [128512, 8205, 128187])
  , testCase "skin-tone-overflow-hazard" $
      assertEqual "code"
        (Just "unicode.security.I.emoji-zwj-integrity.SkinToneOverflow")
        (findingCode [128075, 127995, 127996, 127997, 127998, 127999])
  , testCase "unregistered-man-woman-hazard" $
      assertEqual "code"
        (Just "unicode.security.I.emoji-zwj-integrity.UnregisteredSequence")
        (findingCode [128104, 8205, 128105])
  , testCase "over-length-chain-hazard" $
      assertEqual "code"
        (Just "unicode.security.I.emoji-zwj-integrity.OverLength")
        (findingCode
           [ 128104, 8205, 128104, 8205, 128104, 8205, 128104, 8205, 128104
           , 8205, 128104, 8205, 128104, 8205, 128104, 8205, 128104
           ])
  ]

-- ── §5 detect spot checks (one per Rust detect_* theorem) ─────────────────

spotCheckTests :: [TestTree]
spotCheckTests =
  [ testCase "detect_empty_clear" $ do
      let v = detect []
      assertBool "clear" (classificationIsClear (verdictClassify v))
      assertEqual "tag" Nothing (classificationTag (verdictClassify v))
      assertEqual "zwjPositions" [] (verdictZwjPositions v)
      assertEqual "skinToneCount" 0 (verdictSkinToneCount v)
  , testCase "detect_ascii_clear" $
      assertBool "clear" (isClear [0x48, 0x65, 0x6C, 0x6C, 0x6F])
  , testCase "detect_plain_emoji_clear" $
      assertBool "clear" (isClear [0x1F600])
  , testCase "detect_one_skintone_clear" $ do
      let v = detect [0x1F44B, 0x1F3FB]
      assertBool "clear" (classificationIsClear (verdictClassify v))
      assertEqual "skinToneCount" 1 (verdictSkinToneCount v)
  , testCase "detect_family_rgi_clear" $ do
      let v = detect [0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466]
      assertBool "clear" (classificationIsClear (verdictClassify v))
      assertBool "registered" (verdictIsRegisteredRgi v)
  , testCase "detect_double_zwj" $ do
      let v = detect [0x1F600, 0x200D, 0x200D, 0x1F600]
      assertEqual "tag" (Just "DoubleZWJ") (classificationTag (verdictClassify v))
      assertEqual "positions" [1] (classificationPositions (verdictClassify v))
  , testCase "detect_non_emoji_injection" $
      assertEqual "tag" (Just "NonEmojiInjection") (tag [0x1F600, 0x200D, 0x0061])
  , testCase "detect_skin_tone_overflow" $ do
      let v = detect [0x1F44B, 0x1F3FB, 0x1F3FC, 0x1F3FD, 0x1F3FE, 0x1F3FF]
      assertEqual "tag" (Just "SkinToneOverflow") (classificationTag (verdictClassify v))
      assertEqual "skinToneCount" 5 (verdictSkinToneCount v)
  , testCase "detect_man_laptop_registered_clear" $
      assertBool "clear" (isClear [0x1F468, 0x200D, 0x1F4BB])
  , testCase "detect_unregistered" $
      assertEqual "tag" (Just "UnregisteredSequence") (tag [0x1F468, 0x200D, 0x1F469])
  , testCase "detect_grinning_laptop_non_emoji_injection" $
      assertEqual "tag" (Just "NonEmojiInjection") (tag [0x1F600, 0x200D, 0x1F4BB])
  ]

-- ── Structural checks (follow from the priority ladder) ──────────────────

structureTests :: [TestTree]
structureTests =
  [ testCase "over_length_fires_past_cap" $ do
      -- 9 men joined by 8 ZWJs = 17 codepoints (> maxRgiLength).
      let input = interleaveMen 9
      assertEqual "length" 17 (length input)
      let v = detect input
      assertEqual "tag" (Just "OverLength") (classificationTag (verdictClassify v))
      assertEqual "classification"
        (Hazard (OverLength 17 maxRgiLength) [] [])
        (verdictClassify v)
  , testCase "trailing_zwj_is_injection" $ do
      let v = detect [0x1F468, 0x200D]
      assertEqual "tag" (Just "NonEmojiInjection") (classificationTag (verdictClassify v))
      assertEqual "positions" [1] (classificationPositions (verdictClassify v))
  , testCase "double_zwj_beats_unregistered" $
      -- man ZWJ ZWJ boy — adjacent ZWJs present; DoubleZWJ wins the ladder.
      assertEqual "tag" (Just "DoubleZWJ") (tag [0x1F468, 0x200D, 0x200D, 0x1F466])
  ]
  where
    -- @n@ MAN codepoints joined by @n-1@ ZWJs.
    interleaveMen :: Int -> [Int]
    interleaveMen n =
      concat [ if i > 0 then [0x200D, 0x1F468] else [0x1F468] | i <- [0 .. n - 1] ]

-- ── Data-layer sanity (Rust data-layer #[test] module) ───────────────────

dataLayerTests :: [TestTree]
dataLayerTests =
  [ testCase "is_emoji_modifier_checks" $ do
      assertBool "1F3FB" (isEmojiModifier 0x1F3FB)
      assertBool "1F3FF" (isEmojiModifier 0x1F3FF)
      assertBool "not 1F3FA" (not (isEmojiModifier 0x1F3FA))
      assertBool "not 1F600" (not (isEmojiModifier 0x1F600))
  , testCase "zwj_alphabet_admits_heart_rejects_grinning" $ do
      -- U+2764 HEAVY BLACK HEART appears in couple-with-heart RGI sequences.
      assertBool "heart" (isEmojiTarget 0x2764)
      -- U+1F468 MAN appears in family/couple RGI sequences.
      assertBool "man" (isEmojiTarget 0x1F468)
      -- U+1F600 GRINNING FACE appears in no registered RGI ZWJ sequence.
      assertBool "not grinning" (not (isEmojiTarget 0x1F600))
      -- The joiner itself is excluded from the alphabet.
      assertBool "not zwj" (not (isEmojiTarget zwj))
  , testCase "registered_membership_is_exact" $ do
      -- MAN + ZWJ + LAPTOP (man technologist) is a registered RGI sequence.
      assertBool "man technologist" (isRegisteredZwjSequence [0x1F468, 0x200D, 0x1F4BB])
      -- MAN + ZWJ + WOMAN is not a registered RGI sequence.
      assertBool "man woman not registered"
        (not (isRegisteredZwjSequence [0x1F468, 0x200D, 0x1F469]))
  , testCase "reason_code_round_trip" $
      assertEqual "code"
        "unicode.security.I.emoji-zwj-integrity.OverLength"
        (reasonCode (OverLength 17 maxRgiLength))
  , testCase "sub_threat_tag_over_length" $
      assertEqual "tag" "OverLength" (subThreatTag (OverLength 17 maxRgiLength))
  ]

tests :: TestTree
tests = testGroup "Unicode.Security.Identity.EmojiZwjIntegrity"
  (fixtureTests ++ spotCheckTests ++ structureTests ++ dataLayerTests)
