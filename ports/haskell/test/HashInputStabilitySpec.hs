{-|
  Tests for "Unicode.Security.Crypto.HashInputStability" — mirrors the
  ground-truth vectors in the verified Rust reference
  @ports/rust/src/security/crypto/hash_input_stability.rs@.

  Two groups: the shared context-free detector fixture
  (@fixtures/security/detectors/hash_input_stability.json@), run through
  'detect'; and every Context-bearing vector transcribed verbatim from the
  Rust test module's Context-vector comment block, run through
  'detectWithContext'. The @hashStable@ spot checks and the RfcRule
  tag round-trip complete the transcription of the Rust @#[test]@ module.
-}
module HashInputStabilitySpec (tests) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Unicode.Security.Crypto.HashInputStability
  ( Classification (Clear)
  , Context
      ( contextDeclaredEncoding, contextRfcRule, contextAsWritten
      , contextServerBytes
      )
  , RfcRule
      ( Pgp4880TrailingWhitespace, Pgp9580LineEnding, Rfc8785NfcRequirement
      , Rfc8259ControlChar, Rfc7515JwsBase64Url, Rfc6376DkimRelaxed
      , Rfc5751SmimeLineEnding
      )
  , classificationPositions
  , classificationTag
  , defaultContext
  , detect
  , detectWithContext
  , hashStable
  , rfcRuleFromTag
  , rfcRuleTag
  , verdictClassify
  , verdictStableSize
  )

-- | The sub-threat tag reported for a bare input (Nothing when clear).
tag :: [Int] -> Maybe String
tag = classificationTag . verdictClassify . detect

-- | The sub-threat tag reported for an input under a context.
ctxTag :: Context -> [Int] -> Maybe String
ctxTag ctx = classificationTag . verdictClassify . detectWithContext ctx

-- ── §4 hash_stable spot checks ──────────────────────────────────────────

hashStableTests :: [TestTree]
hashStableTests =
  [ testCase "stable_empty" $
      assertEqual "empty" ([] :: [Int]) (hashStable [])
  , testCase "stable_ascii_idempotent" $ do
      assertEqual "ascii" [0x61, 0x62, 0x63] (hashStable [0x61, 0x62, 0x63])
      assertEqual "idempotent"
        (hashStable [0x61, 0x62, 0x63])
        (hashStable (hashStable [0x61, 0x62, 0x63]))
  , testCase "stable_strips_trailing_space" $
      assertEqual "space" [0x61] (hashStable [0x61, 0x20])
  , testCase "stable_strips_trailing_tab" $
      assertEqual "tab" [0x61] (hashStable [0x61, 0x09])
  , testCase "stable_strips_trailing_lf" $
      assertEqual "lf" [0x61] (hashStable [0x61, 0x0A])
  , testCase "stable_strips_trailing_crlf" $
      assertEqual "crlf" [0x61] (hashStable [0x61, 0x0D, 0x0A])
  , testCase "stable_preserves_internal_space" $
      assertEqual "internal" [0x61, 0x20, 0x62] (hashStable [0x61, 0x20, 0x62])
  , testCase "stable_composes_nfc" $
      assertEqual "nfc" [0x00E9] (hashStable [0x0065, 0x0301])
  , testCase "stable_preserves_trailing_nbsp" $
      assertEqual "nbsp" [0x61, 0x00A0] (hashStable [0x61, 0x00A0])
  ]

-- ── Shared context-free detector fixture ────────────────────────────────
-- fixtures/security/detectors/hash_input_stability.json, run through detect.

fixtureTests :: [TestTree]
fixtureTests =
  [ testCase "empty-clear" $
      assertEqual "tag" Nothing (tag [])
  , testCase "ascii-idempotent-clear" $
      assertEqual "tag" Nothing (tag [97, 98, 99])
  , testCase "trailing-space" $ do
      assertEqual "tag" (Just "TrailingWhitespace") (tag [97, 32])
      assertEqual "stable_size" 1 (verdictStableSize (detect [97, 32]))
      assertEqual "positions" [1]
        (classificationPositions (verdictClassify (detect [97, 32])))
  , testCase "trailing-crlf" $ do
      assertEqual "tag" (Just "TrailingWhitespace") (tag [97, 13, 10])
      assertEqual "stable_size" 1 (verdictStableSize (detect [97, 13, 10]))
  , testCase "decomposed-e-acute-normalization-drift" $ do
      assertEqual "tag" (Just "NormalizationDrift") (tag [101, 769])
      assertEqual "positions" [0]
        (classificationPositions (verdictClassify (detect [101, 769])))
  , testCase "precomposed-e-acute-clear" $
      assertEqual "tag" Nothing (tag [233])
  , testCase "priority-trailing-over-nfc" $
      assertEqual "tag" (Just "TrailingWhitespace") (tag [101, 769, 32])
  , testCase "internal-space-clear" $
      assertEqual "tag" Nothing (tag [97, 32, 98])
  ]

-- ── Context-bearing probe vectors (transcribed verbatim from the Rust
--    test module's Context-vector comment block) ─────────────────────────

encodingCtx :: String -> Context
encodingCtx label = defaultContext { contextDeclaredEncoding = Just label }

rfcCtx :: RfcRule -> Context
rfcCtx rule = defaultContext { contextRfcRule = Just rule }

contextVectorTests :: [TestTree]
contextVectorTests =
  [ testCase "declared_encoding utf-16, [0x61,0x62,0x63] -> EncodingMismatch [0]" $ do
      let v = detectWithContext (encodingCtx "utf-16") [0x61, 0x62, 0x63]
      assertEqual "tag" (Just "EncodingMismatch") (classificationTag (verdictClassify v))
      assertEqual "positions" [0] (classificationPositions (verdictClassify v))
  , testCase "declared_encoding utf-8, [0x61,0xD800,0x62] -> EncodingMismatch [1] (invalid surrogate)" $ do
      let v = detectWithContext (encodingCtx "utf-8") [0x61, 0xD800, 0x62]
      assertEqual "tag" (Just "EncodingMismatch") (classificationTag (verdictClassify v))
      assertEqual "positions" [1] (classificationPositions (verdictClassify v))
  , testCase "declared_encoding utf-8, [0x61,0x110000,0x62] -> EncodingMismatch [1] (out of range)" $ do
      let v = detectWithContext (encodingCtx "utf-8") [0x61, 0x110000, 0x62]
      assertEqual "tag" (Just "EncodingMismatch") (classificationTag (verdictClassify v))
      assertEqual "positions" [1] (classificationPositions (verdictClassify v))
  , testCase "declared_encoding UTF-8|utf-8|UTF8|utf8, [0x61,0x62,0x63] -> clear" $
      mapM_
        (\label ->
           assertEqual ("label " ++ label)
             Clear
             (verdictClassify (detectWithContext (encodingCtx label) [0x61, 0x62, 0x63])))
        ["UTF-8", "utf-8", "UTF8", "utf8"]
  , testCase "rfc_rule Pgp4880TrailingWhitespace, [0x61,0x20] -> SignedMessageRule [1]" $ do
      let v = detectWithContext (rfcCtx Pgp4880TrailingWhitespace) [0x61, 0x20]
      assertEqual "tag" (Just "SignedMessageRule") (classificationTag (verdictClassify v))
      assertEqual "positions" [1] (classificationPositions (verdictClassify v))
  , testCase "rfc_rule Pgp9580LineEnding, [0x61,0x0A,0x62] -> SignedMessageRule [1] (bare LF)" $ do
      let v = detectWithContext (rfcCtx Pgp9580LineEnding) [0x61, 0x0A, 0x62]
      assertEqual "tag" (Just "SignedMessageRule") (classificationTag (verdictClassify v))
      assertEqual "positions" [1] (classificationPositions (verdictClassify v))
  , testCase "rfc_rule Pgp9580LineEnding, [abc CRLF def] -> clear" $
      assertEqual "tag" Nothing
        (ctxTag (rfcCtx Pgp9580LineEnding) [0x61, 0x62, 0x63, 0x0D, 0x0A, 0x64, 0x65, 0x66])
  , testCase "rfc_rule Rfc8785NfcRequirement, [0x0065,0x0301] -> SignedMessageRule [0]" $ do
      let v = detectWithContext (rfcCtx Rfc8785NfcRequirement) [0x0065, 0x0301]
      assertEqual "tag" (Just "SignedMessageRule") (classificationTag (verdictClassify v))
      assertEqual "positions" [0] (classificationPositions (verdictClassify v))
  , testCase "rfc_rule Rfc8259ControlChar, [0x61,0x01,0x62] -> SignedMessageRule [1]" $ do
      let v = detectWithContext (rfcCtx Rfc8259ControlChar) [0x61, 0x01, 0x62]
      assertEqual "tag" (Just "SignedMessageRule") (classificationTag (verdictClassify v))
      assertEqual "positions" [1] (classificationPositions (verdictClassify v))
  , testCase "rfc_rule Rfc7515JwsBase64Url, [0x41,0x2B,0x42] -> SignedMessageRule [1] ('+')" $ do
      let v = detectWithContext (rfcCtx Rfc7515JwsBase64Url) [0x41, 0x2B, 0x42]
      assertEqual "tag" (Just "SignedMessageRule") (classificationTag (verdictClassify v))
      assertEqual "positions" [1] (classificationPositions (verdictClassify v))
  , testCase "rfc_rule Rfc7515JwsBase64Url, [Aa0-_zZ9] -> clear" $
      assertEqual "tag" Nothing
        (ctxTag (rfcCtx Rfc7515JwsBase64Url) [0x41, 0x61, 0x30, 0x2D, 0x5F, 0x7A, 0x5A, 0x39])
  , testCase "rfc_rule Rfc6376DkimRelaxed, [0x61,0x20,0x20,0x62] -> SignedMessageRule [2]" $ do
      let v = detectWithContext (rfcCtx Rfc6376DkimRelaxed) [0x61, 0x20, 0x20, 0x62]
      assertEqual "tag" (Just "SignedMessageRule") (classificationTag (verdictClassify v))
      assertEqual "positions" [2] (classificationPositions (verdictClassify v))
  , testCase "rfc_rule Rfc6376DkimRelaxed, [0x61,0x20,0x62] -> clear (single space)" $
      assertEqual "tag" Nothing (ctxTag (rfcCtx Rfc6376DkimRelaxed) [0x61, 0x20, 0x62])
  , testCase "rfc_rule Rfc5751SmimeLineEnding, [0x61,0x0A,0x62] -> SignedMessageRule [1] (bare LF)" $ do
      let v = detectWithContext (rfcCtx Rfc5751SmimeLineEnding) [0x61, 0x0A, 0x62]
      assertEqual "tag" (Just "SignedMessageRule") (classificationTag (verdictClassify v))
      assertEqual "positions" [1] (classificationPositions (verdictClassify v))
  , testCase "as_written [0x61,0x62,0x63], input [0x61,0x62,0x64] -> AuditLogReinterpretation [2]" $ do
      let ctx = defaultContext { contextAsWritten = Just [0x61, 0x62, 0x63] }
          v   = detectWithContext ctx [0x61, 0x62, 0x64]
      assertEqual "tag" (Just "AuditLogReinterpretation") (classificationTag (verdictClassify v))
      assertEqual "positions" [2] (classificationPositions (verdictClassify v))
  , testCase "as_written [0x61,0x62,0x63], input [0x61,0x62,0x63] -> clear" $
      assertEqual "tag" Nothing
        (ctxTag (defaultContext { contextAsWritten = Just [0x61, 0x62, 0x63] }) [0x61, 0x62, 0x63])
  , testCase "server_bytes [0x61,0x62,0x64], input [0x61,0x62,0x63] -> WebhookSignatureDrift [2]" $ do
      let ctx = defaultContext { contextServerBytes = Just [0x61, 0x62, 0x64] }
          v   = detectWithContext ctx [0x61, 0x62, 0x63]
      assertEqual "tag" (Just "WebhookSignatureDrift") (classificationTag (verdictClassify v))
      assertEqual "positions" [2] (classificationPositions (verdictClassify v))
  , testCase "server_bytes [0x61,0x62,0x63], input [0x61,0x62,0x63] -> clear" $
      assertEqual "tag" Nothing
        (ctxTag (defaultContext { contextServerBytes = Just [0x61, 0x62, 0x63] }) [0x61, 0x62, 0x63])
  , testCase "declared_encoding utf-16 + rfc_rule Pgp9580, [0x0065,0x0301,0x0A] -> EncodingMismatch (priority over rfc)" $
      assertEqual "tag" (Just "EncodingMismatch")
        (ctxTag
           (defaultContext
              { contextDeclaredEncoding = Just "utf-16"
              , contextRfcRule = Just Pgp9580LineEnding
              })
           [0x0065, 0x0301, 0x0A])
  , testCase "server_bytes [0x61,0x62,0x65] + as_written [0x61,0x62,0x66], input [0x61,0x62,0x63] -> WebhookSignatureDrift (priority over audit)" $
      assertEqual "tag" (Just "WebhookSignatureDrift")
        (ctxTag
           (defaultContext
              { contextServerBytes = Just [0x61, 0x62, 0x65]
              , contextAsWritten = Just [0x61, 0x62, 0x66]
              })
           [0x61, 0x62, 0x63])
  , testCase "rfc_rule Pgp4880TrailingWhitespace, [0x61,0x20] -> SignedMessageRule (priority over trailing)" $
      assertEqual "tag" (Just "SignedMessageRule")
        (ctxTag (rfcCtx Pgp4880TrailingWhitespace) [0x61, 0x20])
  ]

-- ── detect_with_context default matches detect + RfcRule tag round-trip ──

miscTests :: [TestTree]
miscTests =
  [ testCase "detect_with_context default matches detect" $ do
      let d = detect [0x61, 0x62, 0x63]
          c = detectWithContext defaultContext [0x61, 0x62, 0x63]
      assertEqual "classify" (verdictClassify d) (verdictClassify c)
      assertEqual "stable_size" (verdictStableSize d) (verdictStableSize c)
  , testCase "rfc_rule tag round-trip" $ do
      mapM_
        (\rule -> assertEqual (rfcRuleTag rule) (Just rule) (rfcRuleFromTag (rfcRuleTag rule)))
        allRules
      assertEqual "nope" Nothing (rfcRuleFromTag "nope")
  , testCase "every rfc_rule tag is distinct" $
      assertBool "distinct tags"
        (length (dedup (map rfcRuleTag allRules)) == length allRules)
  ]
  where
    allRules =
      [ Pgp4880TrailingWhitespace, Pgp9580LineEnding, Rfc8785NfcRequirement
      , Rfc8259ControlChar, Rfc7515JwsBase64Url, Rfc6376DkimRelaxed
      , Rfc5751SmimeLineEnding
      ]
    dedup = foldr (\x seen -> if x `elem` seen then seen else x : seen) []

tests :: TestTree
tests = testGroup "Unicode.Security.Crypto.HashInputStability"
  (hashStableTests ++ fixtureTests ++ contextVectorTests ++ miscTests)
