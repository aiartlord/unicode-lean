{-|
  Tests for "Unicode.Security.Display.SourceDisplayDivergence" — mirrors the
  @detect_*@ ground-truth theorems in the verified Rust reference
  @ports/rust/src/security/display/source_display_divergence.rs@.

  Three groups: the 10 shared context-free detector-fixture vectors
  (@fixtures/security/detectors/source_display_divergence.json@) run through
  'detect' and asserted against their @required_findings@ reason codes; the Rust
  clear \/ single-passthrough \/ compound spot checks; and a structural check
  that a two-family input surfaces both fires.
-}
module SourceDisplayDivergenceSpec (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Unicode.Security.Display.SourceDisplayDivergence
  ( Classification (Clear, Hazard)
  , classificationIsClear
  , classificationTag
  , detect
  , reasonCode
  , verdictClassify
  , verdictFires
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
    Hazard sub -> Just (reasonCode sub)
    Clear      -> Nothing

-- ── Shared context-free detector fixture ─────────────────────────────────
-- fixtures/security/detectors/source_display_divergence.json (10 vectors), each
-- run through detect. required_findings [] means the input must be clear; a
-- populated list means findingCode must match the single required reason code.

fixtureTests :: [TestTree]
fixtureTests =
  [ testCase "empty-clear" $
      assertEqual "code" Nothing (findingCode [])
  , testCase "hello-world-clear" $
      assertEqual "code" Nothing
        (findingCode [72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100])
  , testCase "let-x-1-clear" $
      assertEqual "code" Nothing
        (findingCode [108, 101, 116, 32, 120, 32, 61, 32, 49, 59])
  , testCase "tag-block-passthrough" $
      assertEqual "code"
        (Just "unicode.security.D.source-display-divergence.TagBlock")
        (findingCode [917569, 917570])
  , testCase "variation-selector-passthrough" $
      assertEqual "code"
        (Just "unicode.security.D.source-display-divergence.VariationSelector")
        (findingCode [65, 65039])
  , testCase "zero-width-passthrough" $
      assertEqual "code"
        (Just "unicode.security.D.source-display-divergence.ZeroWidth")
        (findingCode [72, 8203, 105])
  , testCase "bidi-control-passthrough" $
      assertEqual "code"
        (Just "unicode.security.D.source-display-divergence.BidiControl")
        (findingCode [8238, 65])
  , testCase "identifier-homoglyph-passthrough" $
      assertEqual "code"
        (Just "unicode.security.D.source-display-divergence.IdentifierHomoglyph")
        (findingCode [78, 101, 116, 104, 101, 114, 1077, 117, 109])
  , testCase "compound-vs-plus-zero-width" $
      assertEqual "code"
        (Just "unicode.security.D.source-display-divergence.Compound")
        (findingCode [65, 65039, 8203])
  , testCase "compound-tag-plus-zero-width" $
      assertEqual "code"
        (Just "unicode.security.D.source-display-divergence.Compound")
        (findingCode [917569, 917570, 8203])
  ]

-- ── detect spot checks (one per Rust detect_* theorem) ────────────────────

spotCheckTests :: [TestTree]
spotCheckTests =
  [ testCase "detect_empty_clear" $
      assertBool "clear" (isClear [])
  , testCase "detect_hello_world_clear" $
      assertBool "clear"
        (isClear [0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64])
  , testCase "detect_let_x_1_clear" $
      assertBool "clear"
        (isClear [0x6C, 0x65, 0x74, 0x20, 0x78, 0x20, 0x3D, 0x20, 0x31, 0x3B])
  , testCase "detect_tag_block_passthrough" $
      assertEqual "tag" (Just "TagBlock") (tag [0xE0041, 0xE0042])
  , testCase "detect_variation_selector_passthrough" $
      assertEqual "tag" (Just "VariationSelector") (tag [0x0041, 0xFE0F])
  , testCase "detect_zero_width_passthrough" $
      assertEqual "tag" (Just "ZeroWidth") (tag [0x0048, 0x200B, 0x69])
  , testCase "detect_bidi_control_passthrough" $
      assertEqual "tag" (Just "BidiControl") (tag [0x202E, 0x41])
  , testCase "detect_identifier_homoglyph_passthrough" $
      assertEqual "tag" (Just "IdentifierHomoglyph")
        (tag [0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D])
  , testCase "detect_compound_vs_plus_zero_width" $
      assertEqual "tag" (Just "Compound") (tag [0x0041, 0xFE0F, 0x200B])
  , testCase "detect_compound_tag_plus_zero_width" $
      assertEqual "tag" (Just "Compound") (tag [0xE0041, 0xE0042, 0x200B])
  ]

-- ── Structural check (follows from the aggregation rule) ──────────────────

structureTests :: [TestTree]
structureTests =
  [ testCase "compound_records_both_fires" $ do
      let v = detect [0x0041, 0xFE0F, 0x200B]
      assertEqual "tag" (Just "Compound") (classificationTag (verdictClassify v))
      assertEqual "fire_count" 2 (length (verdictFires v))
  ]

tests :: TestTree
tests = testGroup "Unicode.Security.Display.SourceDisplayDivergence"
  (fixtureTests ++ spotCheckTests ++ structureTests)
