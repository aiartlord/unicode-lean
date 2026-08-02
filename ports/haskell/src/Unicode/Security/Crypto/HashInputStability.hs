{-|
Module      : Unicode.Security.Crypto.HashInputStability
Description : Hash-input-stability detector — canonical hash-input form.

Haskell port of @Unicode.Security.Crypto.HashInputStability@ from
unicode-lean, transliterated from the verified Rust reference
implementation.

Per UTS #39 §6.1 + RFC 4880 / 9580 + RFC 8785, an input hashed by a signer
must be byte-identical to the input hashed by the verifier; if the two ends
pick different canonical forms (NFC vs NFD, trim policy, line-ending
convention) the resulting hashes diverge silently while both sides believe
they signed the same content.

The canonical (hash-stable) form is @trimTrailing (toNFC input)@, where
@trimTrailing@ strips only ASCII whitespace {U+0020, U+0009, U+000A,
U+000D}; Unicode whitespace (U+00A0, U+2000..U+200A, U+3000) is content and
is not stripped. NFC is the port's 'Unicode.Normalization.NFC.toNFC', never
a host normalizer.

Six probes run in strict priority order (first hit wins):

  1. @encodingMismatch@         (context: 'contextDeclaredEncoding')
  2. @webhookSignatureDrift@    (context: 'contextServerBytes')
  3. @auditLogReinterpretation@ (context: 'contextAsWritten')
  4. @signedMessageRule@        (context: 'contextRfcRule')
  5. @trailingWhitespace@       (bare input)
  6. @normalizationDrift@       (bare input)
  7. clear

Context-specific probes fire first because they carry more precise threat
information than the generic probes. 'detect' is the convenience wrapper
@detectWithContext defaultContext input@ that leaves the four context-bearing
probes silent.
-}
module Unicode.Security.Crypto.HashInputStability
  ( RfcRule
      ( Pgp4880TrailingWhitespace, Pgp9580LineEnding, Rfc8785NfcRequirement
      , Rfc8259ControlChar, Rfc7515JwsBase64Url, Rfc6376DkimRelaxed
      , Rfc5751SmimeLineEnding
      )
  , rfcRuleTag
  , rfcRuleFromTag
  , SubThreat
      ( NormalizationDrift, TrailingWhitespace, EncodingMismatch
      , SignedMessageRule, AuditLogReinterpretation, WebhookSignatureDrift
      )
  , subThreatTag
  , Context (Context, contextDeclaredEncoding, contextRfcRule, contextAsWritten, contextServerBytes)
  , defaultContext
  , Classification (Clear, Hazard)
  , classificationIsClear
  , classificationTag
  , classificationPositions
  , Verdict (Verdict, verdictInput, verdictClassify, verdictStableForm, verdictStableSize)
  , hashStable
  , detectWithContext
  , detect
  ) where

import Data.Maybe (listToMaybe)

import Unicode.Normalization.NFC (toNFC)

-- ─────────────────────────────────────────────────────────────────────
-- §1 Types
-- ─────────────────────────────────────────────────────────────────────

-- | RFC canonicalisation profiles that the @signedMessageRule@ probe checks
-- against. Each variant names a specific canonicalisation rule from a
-- published RFC; callers pass one as 'contextRfcRule' to opt the probe in.
data RfcRule
  = -- | RFC 4880 §5.2.4 — detached signatures normalise trailing whitespace;
    -- trailing whitespace in the body causes signature mismatch.
    Pgp4880TrailingWhitespace
  | -- | RFC 9580 (current OpenPGP) — line-endings normalise to CRLF before
    -- signing; a bare LF or bare CR violates the canonicalisation rule.
    Pgp9580LineEnding
  | -- | RFC 8785 §3.2.5 — JSON Canonicalization Scheme requires strings to be
    -- in NFC before serialisation.
    Rfc8785NfcRequirement
  | -- | RFC 8259 §7 — JSON strings must escape control characters
    -- (U+0000..U+001F); unescaped control bytes in a string violate.
    Rfc8259ControlChar
  | -- | RFC 7515 §2 — JWS Base64URL encoding; any character outside
    -- @[A-Za-z0-9_-]@ is a canonicalisation violation.
    Rfc7515JwsBase64Url
  | -- | RFC 6376 §3.4.4 — DKIM relaxed body canonicalization collapses internal
    -- whitespace runs to a single SP; a multi-char internal whitespace run
    -- indicates the canonicalisation has not been applied.
    Rfc6376DkimRelaxed
  | -- | RFC 5751 §3.1.1 — S/MIME canonical text; like PGP 9580, a bare LF or
    -- bare CR (not part of a CRLF pair) violates.
    Rfc5751SmimeLineEnding
  deriving stock (Eq, Show)

-- | Fixture-string identifier for an 'RfcRule' — used by the conformance
-- harness's attribution parser to round-trip rule selections.
rfcRuleTag :: RfcRule -> String
rfcRuleTag Pgp4880TrailingWhitespace = "pgp4880TrailingWhitespace"
rfcRuleTag Pgp9580LineEnding         = "pgp9580LineEnding"
rfcRuleTag Rfc8785NfcRequirement     = "rfc8785NfcRequirement"
rfcRuleTag Rfc8259ControlChar        = "rfc8259ControlChar"
rfcRuleTag Rfc7515JwsBase64Url       = "rfc7515JwsBase64Url"
rfcRuleTag Rfc6376DkimRelaxed        = "rfc6376DkimRelaxed"
rfcRuleTag Rfc5751SmimeLineEnding    = "rfc5751SmimeLineEnding"

-- | Inverse of 'rfcRuleTag'. Returns 'Nothing' for unrecognised strings.
rfcRuleFromTag :: String -> Maybe RfcRule
rfcRuleFromTag "pgp4880TrailingWhitespace" = Just Pgp4880TrailingWhitespace
rfcRuleFromTag "pgp9580LineEnding"         = Just Pgp9580LineEnding
rfcRuleFromTag "rfc8785NfcRequirement"     = Just Rfc8785NfcRequirement
rfcRuleFromTag "rfc8259ControlChar"        = Just Rfc8259ControlChar
rfcRuleFromTag "rfc7515JwsBase64Url"       = Just Rfc7515JwsBase64Url
rfcRuleFromTag "rfc6376DkimRelaxed"        = Just Rfc6376DkimRelaxed
rfcRuleFromTag "rfc5751SmimeLineEnding"    = Just Rfc5751SmimeLineEnding
rfcRuleFromTag _unrecognised               = Nothing

-- | Sub-threats this detector can fire. Two probes fire from the raw input
-- alone ('TrailingWhitespace', 'NormalizationDrift'); the other four require
-- the corresponding @Context@ field to be set.
data SubThreat
  = -- | Input diverges from its NFC form; the 'Int' is the first diverging
    -- codepoint index.
    NormalizationDrift Int
  | -- | Input has trailing ASCII whitespace; the 'Int' is how many codepoints.
    TrailingWhitespace Int
  | -- | Declared encoding disagrees with the codepoint array (or the array
    -- holds an invalid scalar). Fields: declared label, detected encoding
    -- (@"utf-8"@ or @"invalid"@).
    EncodingMismatch String String
  | -- | Input violates the named RFC's canonicalisation rule. Fields: fixture
    -- tag of the violated 'RfcRule', first violating position.
    SignedMessageRule String Int
  | -- | The re-read input differs from 'contextAsWritten'; the 'Int' is the
    -- first divergent position.
    AuditLogReinterpretation Int
  | -- | The client input differs from 'contextServerBytes'; the 'Int' is the
    -- first divergent position.
    WebhookSignatureDrift Int
  deriving stock (Eq, Show)

-- | Human-facing classification tag for this sub-threat.
subThreatTag :: SubThreat -> String
subThreatTag (NormalizationDrift _pos)          = "NormalizationDrift"
subThreatTag (TrailingWhitespace _count)        = "TrailingWhitespace"
subThreatTag (EncodingMismatch _decl _det)      = "EncodingMismatch"
subThreatTag (SignedMessageRule _rule _pos)     = "SignedMessageRule"
subThreatTag (AuditLogReinterpretation _pos)    = "AuditLogReinterpretation"
subThreatTag (WebhookSignatureDrift _pos)       = "WebhookSignatureDrift"

-- | Context passed to 'detectWithContext' to enable the four context-bearing
-- probes. Each field is 'Nothing' by default — the empty context is the
-- identity case: @detectWithContext defaultContext input@ equals
-- @detect input@.
data Context = Context
  { -- | The encoding label the caller claims their input is in. When set and
    -- not (case-insensitively) UTF-8, fires @encodingMismatch@ immediately.
    contextDeclaredEncoding :: !(Maybe String)
    -- | The RFC canonicalisation rule the caller is operating under. When set,
    -- scans @input@ for violations and fires @signedMessageRule@.
  , contextRfcRule          :: !(Maybe RfcRule)
    -- | The original "as-written" form of an audit-log entry whose re-read is
    -- @input@. When set, fires @auditLogReinterpretation@ on first divergence.
  , contextAsWritten        :: !(Maybe [Int])
    -- | The server-side recomputed bytes for a webhook signature. When set,
    -- fires @webhookSignatureDrift@ on first divergence against @input@.
  , contextServerBytes      :: !(Maybe [Int])
  }
  deriving stock (Eq, Show)

-- | The empty context — every context-bearing probe silent.
defaultContext :: Context
defaultContext = Context
  { contextDeclaredEncoding = Nothing
  , contextRfcRule          = Nothing
  , contextAsWritten        = Nothing
  , contextServerBytes      = Nothing
  }

-- | Top-level classification.
data Classification
  = -- | The input is already hash-stable under every enabled probe.
    Clear
  | -- | A hazard was found: the sub-threat and its implicated positions.
    Hazard SubThreat [Int]
  deriving stock (Eq, Show)

-- | True iff the input is clear.
classificationIsClear :: Classification -> Bool
classificationIsClear Clear            = True
classificationIsClear (Hazard _sub _p) = False

-- | Human-facing tag for a hazard, or 'Nothing' when clear.
classificationTag :: Classification -> Maybe String
classificationTag Clear             = Nothing
classificationTag (Hazard sub _pos) = Just (subThreatTag sub)

-- | Implicated positions ('[]' when clear).
classificationPositions :: Classification -> [Int]
classificationPositions Clear                = []
classificationPositions (Hazard _sub positions) = positions

-- | Verdict — the structured output of 'detect'. 'verdictStableSize' is the
-- codepoint count of the hash-stable canonical form; downstream callers
-- compare it against the input length to size the byte-drift their hash sees.
data Verdict = Verdict
  { verdictInput      :: ![Int]
  , verdictClassify   :: !Classification
  , verdictStableForm :: ![Int]
  , verdictStableSize :: !Int
  }
  deriving stock (Eq, Show)

-- ─────────────────────────────────────────────────────────────────────
-- §3 Canonicalisation pipeline
-- ─────────────────────────────────────────────────────────────────────

-- | True iff @cp@ is an ASCII whitespace codepoint that line-oriented
-- hash-input protocols treat as framing rather than content: U+0020 SPACE,
-- U+0009 TAB, U+000A LF, U+000D CR.
isAsciiWhitespace :: Int -> Bool
isAsciiWhitespace cp = cp == 0x0020 || cp == 0x0009 || cp == 0x000A || cp == 0x000D

-- | Count of trailing ASCII whitespace codepoints in @input@.
countTrailingWhitespace :: [Int] -> Int
countTrailingWhitespace = length . takeWhile isAsciiWhitespace . reverse

-- | Strip trailing ASCII whitespace.
trimTrailing :: [Int] -> [Int]
trimTrailing input = take (length input - countTrailingWhitespace input) input

-- | The hash-stable form of an input: NFC then trim, in spec order.
hashStable :: [Int] -> [Int]
hashStable = trimTrailing . toNFC

-- ─────────────────────────────────────────────────────────────────────
-- §5 Priority position-finder
-- ─────────────────────────────────────────────────────────────────────

-- | First position at which @a@ and @b@ diverge, or the length of the shared
-- prefix when one strictly extends the other. 'Nothing' when identical.
firstArrayDivergence :: [Int] -> [Int] -> Maybe Int
firstArrayDivergence [] []                       = Nothing
firstArrayDivergence [] (_bHead : _bTail)        = Just 0
firstArrayDivergence (_aHead : _aTail) []        = Just 0
firstArrayDivergence (aHead : aTail) (bHead : bTail)
  | aHead /= bHead = Just 0
  | otherwise      = fmap (+ 1) (firstArrayDivergence aTail bTail)

-- ─────────────────────────────────────────────────────────────────────
-- §6 Context-bearing probes
-- ─────────────────────────────────────────────────────────────────────

-- | Lower-case an ASCII letter (U+0041..U+005A → U+0061..U+007A).
asciiLower :: Int -> Int
asciiLower cp = if 0x41 <= cp && cp <= 0x5A then cp + 0x20 else cp

-- | True iff @label@ (after ASCII case-fold) names UTF-8: accepts "utf-8",
-- "UTF-8", "UTF8", "utf8". Non-ASCII characters pass through unchanged.
isUtf8Label :: String -> Bool
isUtf8Label label =
  let normalised = map (\c -> toEnum (asciiLower (fromEnum c))) label
  in normalised == "utf-8" || normalised == "utf8"

-- | True iff @cp@ is a valid Unicode scalar value: in @[0, 0x10FFFF]@ and not
-- a surrogate @[0xD800, 0xDFFF]@.
isValidScalar :: Int -> Bool
isValidScalar cp = cp <= 0x10FFFF && not (0xD800 <= cp && cp <= 0xDFFF)

-- | First position in @input@ holding a codepoint that is not a valid Unicode
-- scalar, or 'Nothing' if every codepoint is valid.
firstInvalidScalar :: [Int] -> Maybe Int
firstInvalidScalar input =
  listToMaybe [ i | (i, cp) <- zip [0 ..] input, not (isValidScalar cp) ]

-- | Probe: @encodingMismatch@. Validity is dispatched first — an invalid
-- scalar fires with @detected_enc = "invalid"@ regardless of the declared
-- label; otherwise a non-UTF-8 label fires with @detected_enc = "utf-8"@ at
-- position 0. Returns @(declared, detected, first_pos)@ when firing.
encodingMismatchProbe :: String -> [Int] -> Maybe (String, String, Int)
encodingMismatchProbe declared input =
  case firstInvalidScalar input of
    Just pos -> Just (declared, "invalid", pos)
    Nothing ->
      if isUtf8Label declared
        then Nothing
        else Just (declared, "utf-8", 0)

-- | Probe: @signedMessageRule@ for @pgp4880TrailingWhitespace@. Same condition
-- as @trailingWhitespace@; returns the first position of the trailing run.
pgp4880Violation :: [Int] -> Maybe Int
pgp4880Violation input =
  let trailing = countTrailingWhitespace input
  in if trailing > 0 then Just (length input - trailing) else Nothing

-- | Probe: @signedMessageRule@ for @pgp9580LineEnding@. First bare LF (U+000A
-- not preceded by CR) or bare CR (U+000D not followed by LF).
pgp9580Violation :: [Int] -> Maybe Int
pgp9580Violation = go 0 Nothing
  where
    go _index _prev [] = Nothing
    go index prev (cp : rest)
      | cp == 0x000A =
          -- LF: violating iff not preceded by CR.
          if prev == Just 0x000D then go (index + 1) (Just cp) rest else Just index
      | cp == 0x000D =
          -- CR: violating iff not followed by LF.
          let followedByLf = case rest of
                (nxt : _nextTail) -> nxt == 0x000A
                []                -> False
          in if followedByLf then go (index + 1) (Just cp) rest else Just index
      | otherwise = go (index + 1) (Just cp) rest

-- | Probe: @signedMessageRule@ for @rfc8785NfcRequirement@. Same condition as
-- @normalizationDrift@; returns the first NFC divergence position.
rfc8785Violation :: [Int] -> Maybe Int
rfc8785Violation input =
  let nfc = toNFC input
  in if input == nfc then Nothing else firstArrayDivergence input nfc

-- | Probe: @signedMessageRule@ for @rfc8259ControlChar@. First C0 control
-- (U+0000..U+001F) — the JSON-permitted whitespace still requires escaping,
-- so it also counts.
rfc8259Violation :: [Int] -> Maybe Int
rfc8259Violation input =
  listToMaybe [ i | (i, cp) <- zip [0 ..] input, cp <= 0x1F ]

-- | True iff @cp@ is in the JWS Base64URL alphabet @[A-Za-z0-9_-]@.
isBase64Url :: Int -> Bool
isBase64Url cp =
  (0x41 <= cp && cp <= 0x5A)      -- A-Z
    || (0x61 <= cp && cp <= 0x7A) -- a-z
    || (0x30 <= cp && cp <= 0x39) -- 0-9
    || cp == 0x2D                 -- '-'
    || cp == 0x5F                 -- LOW LINE

-- | Probe: @signedMessageRule@ for @rfc7515JwsBase64Url@. First codepoint
-- outside @[A-Za-z0-9_-]@.
rfc7515Violation :: [Int] -> Maybe Int
rfc7515Violation input =
  listToMaybe [ i | (i, cp) <- zip [0 ..] input, not (isBase64Url cp) ]

-- | True iff @cp@ is DKIM whitespace: U+0020 SPACE or U+0009 HTAB.
isDkimWhitespace :: Int -> Bool
isDkimWhitespace cp = cp == 0x20 || cp == 0x09

-- | Probe: @signedMessageRule@ for @rfc6376DkimRelaxed@. Position of the
-- second whitespace codepoint in the first internal whitespace run longer
-- than one.
rfc6376Violation :: [Int] -> Maybe Int
rfc6376Violation = go 0 Nothing
  where
    go _index _prev [] = Nothing
    go index prev (cp : rest)
      | isDkimWhitespace cp && index > 0 && maybe False isDkimWhitespace prev = Just index
      | otherwise = go (index + 1) (Just cp) rest

-- | Probe: @signedMessageRule@ for @rfc5751SmimeLineEnding@. Reuses the PGP
-- 9580 bare-line-ending rule.
rfc5751Violation :: [Int] -> Maybe Int
rfc5751Violation = pgp9580Violation

-- | Dispatch the RFC-rule probe. First violation position, or 'Nothing' if
-- clean.
rfcRuleViolation :: RfcRule -> [Int] -> Maybe Int
rfcRuleViolation Pgp4880TrailingWhitespace = pgp4880Violation
rfcRuleViolation Pgp9580LineEnding         = pgp9580Violation
rfcRuleViolation Rfc8785NfcRequirement     = rfc8785Violation
rfcRuleViolation Rfc8259ControlChar        = rfc8259Violation
rfcRuleViolation Rfc7515JwsBase64Url       = rfc7515Violation
rfcRuleViolation Rfc6376DkimRelaxed        = rfc6376Violation
rfcRuleViolation Rfc5751SmimeLineEnding    = rfc5751Violation

-- ─────────────────────────────────────────────────────────────────────
-- §7 Top-level detection
-- ─────────────────────────────────────────────────────────────────────

-- | The full detection function. Runs all six probes in priority order, with
-- the context-bearing probes ahead of the generic ones.
detectWithContext :: Context -> [Int] -> Verdict
detectWithContext ctx input =
  Verdict
    { verdictInput      = input
    , verdictClassify   = classification
    , verdictStableForm = stable
    , verdictStableSize = length stable
    }
  where
    stable = hashStable input

    -- Probe 1: encodingMismatch.
    encodingHit = case contextDeclaredEncoding ctx of
      Just label -> encodingMismatchProbe label input
      Nothing    -> Nothing

    -- Probe 2: webhookSignatureDrift.
    webhookHit = case contextServerBytes ctx of
      Just server -> firstArrayDivergence input server
      Nothing     -> Nothing

    -- Probe 3: auditLogReinterpretation.
    auditHit = case contextAsWritten ctx of
      Just written -> firstArrayDivergence written input
      Nothing      -> Nothing

    -- Probe 4: signedMessageRule.
    rfcHit = case contextRfcRule ctx of
      Just rule -> fmap (\pos -> (rule, pos)) (rfcRuleViolation rule input)
      Nothing   -> Nothing

    -- Probe 5: trailingWhitespace.
    trailingCount = countTrailingWhitespace input

    -- Probe 6: normalizationDrift.
    nfc = toNFC input
    nonNfcPos = if input == nfc then Nothing else firstArrayDivergence input nfc

    classification =
      classify encodingHit webhookHit auditHit rfcHit trailingCount (length input) nonNfcPos

-- | The priority resolver: first hit wins, in the spec's fixed order.
classify
  :: Maybe (String, String, Int)
  -> Maybe Int
  -> Maybe Int
  -> Maybe (RfcRule, Int)
  -> Int
  -> Int
  -> Maybe Int
  -> Classification
classify encodingHit webhookHit auditHit rfcHit trailingCount inputLen nonNfcPos =
  case encodingHit of
    Just (declared, detected, pos) -> Hazard (EncodingMismatch declared detected) [pos]
    Nothing ->
      case webhookHit of
        Just pos -> Hazard (WebhookSignatureDrift pos) [pos]
        Nothing ->
          case auditHit of
            Just pos -> Hazard (AuditLogReinterpretation pos) [pos]
            Nothing ->
              case rfcHit of
                Just (rule, pos) -> Hazard (SignedMessageRule (rfcRuleTag rule) pos) [pos]
                Nothing ->
                  if trailingCount > 0
                    then Hazard (TrailingWhitespace trailingCount) [inputLen - trailingCount]
                    else
                      case nonNfcPos of
                        Just p  -> Hazard (NormalizationDrift p) [p]
                        Nothing -> Clear

-- | Convenience wrapper over 'detectWithContext' with the empty context —
-- equivalent to running only the two bare-input probes (@trailingWhitespace@,
-- @normalizationDrift@).
detect :: [Int] -> Verdict
detect = detectWithContext defaultContext
