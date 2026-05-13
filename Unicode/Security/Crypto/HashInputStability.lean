/-
  Unicode.Security.Crypto.HashInputStability

  K2 — Detection of inputs that are not in canonical hash-input
  form.  Per UTS #39 §6.1 + RFC 4880 / 9580 + RFC 8785, an
  input hashed by a signer must be byte-identical to the input
  hashed by the verifier; if the two ends pick different
  canonical forms (NFC vs NFD, trim policy, line-ending
  convention) the resulting hashes diverge silently — yet both
  sides believe they signed the same content.

  Threat model.  Tier A₂ (pipeline injector).  Adversary
  submits text whose canonical form differs across stages of a
  signing pipeline:

    * PGP signed messages (RFC 4880 / 9580) — body
      canonicalisation rules vary by signature mode.
    * RFC 8785 JSON canonicalization — strings must be in NFC
      before serialisation.
    * Audit-log entries read back after disk write — line
      endings normalised by editors.
    * Webhook signatures — client computes HMAC over UTF-8
      bytes; server re-encodes and recomputes.

  Canonical form (K2-INV-1):

      hashStable input = trimTrailing (NFC input)

  where `trimTrailing` strips ASCII whitespace
  `{U+0020 SPACE, U+0009 TAB, U+000A LF, U+000D CR}`.  Unicode
  whitespace categories (`U+00A0` NBSP, `U+2000..U+200A`,
  `U+3000` IDEOGRAPHIC SPACE) are NOT stripped — those are
  content, not framing.

  Sub-threats and the inputs that enable them:

    1. `trailingWhitespace` — input has trailing ASCII
       whitespace; the trim step changes byte-length.  Always
       active.
    2. `normalizationDrift` — input != NFC(input); the NFC step
       changes codepoint content.  Always active.
    3. `encodingMismatch` — `ctx.declaredEncoding` is set and
       the declared label disagrees with the actual codepoint
       array (v1 treats the codepoint array as UTF-8-decoded;
       any non-"utf-8" declaration fires the variant).
    4. `signedMessageRule` — `ctx.rfcRule` is set and the input
       violates the named RFC's canonicalisation rule.  Four
       rules currently emitted: PGP 4880 trailing-whitespace,
       PGP 9580 line-ending CRLF, RFC 8785 NFC requirement,
       RFC 8259 JSON unescaped control characters.
    5. `auditLogReinterpretation` — `ctx.asWritten` is set and
       differs from the (re-read) `input` at some position.
    6. `webhookSignatureDrift` — `ctx.serverBytes` is set and
       differs from the (client) `input` at some position.

  Top-level entry points:

    * `detectWithContext (ctx : Context) (input : Array Nat) :
       Verdict`  — full surface, all six probes.
    * `detect (input : Array Nat) : Verdict` — convenience
       wrapper that calls `detectWithContext { } input`,
       leaving the four context-bearing probes silent.

  Priority order (first hit wins):

      encodingMismatch
      webhookSignatureDrift
      auditLogReinterpretation
      signedMessageRule
      trailingWhitespace
      normalizationDrift
      clear

  Context-specific probes fire first because they carry more
  precise threat information than the generic probes.
-/

import Unicode.Security.Calculus
import Unicode.Normalization.NFC

namespace Unicode.Security.Crypto.HashInputStability

open Unicode.Security.Calculus

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

/-- RFC canonicalisation profiles that K2's `signedMessageRule`
    probe checks against.  Each constructor names a specific
    canonicalisation rule from a published RFC.  Callers pass
    one of these as `Context.rfcRule` to opt the probe in. -/
inductive RfcRule where
  /-- RFC 4880 §5.2.4 — detached signatures normalise trailing
      whitespace; presence of trailing whitespace in the
      message body causes signature mismatch. -/
  | pgp4880TrailingWhitespace
  /-- RFC 9580 (current OpenPGP) — line-endings normalise to
      CRLF before signing; presence of bare LF or CR violates
      the canonicalisation rule. -/
  | pgp9580LineEnding
  /-- RFC 8785 §3.2.5 — JSON Canonicalization Scheme requires
      strings to be in NFC before serialisation. -/
  | rfc8785NfcRequirement
  /-- RFC 8259 §7 — JSON strings must escape control
      characters (U+0000..U+001F).  Unescaped control bytes
      in a string literal violate the canonicalisation. -/
  | rfc8259ControlChar
  deriving DecidableEq, Repr, Inhabited

namespace RfcRule

/-- Fixture-string identifier for an `RfcRule`.  Used by the
    conformance harness's attribution parser to round-trip
    rule selections in/out of the fixture file. -/
@[inline] def tag : RfcRule → String
  | .pgp4880TrailingWhitespace => "pgp4880TrailingWhitespace"
  | .pgp9580LineEnding         => "pgp9580LineEnding"
  | .rfc8785NfcRequirement     => "rfc8785NfcRequirement"
  | .rfc8259ControlChar        => "rfc8259ControlChar"

/-- Inverse of `tag`.  Returns `none` for unrecognised strings. -/
def fromTag : String → Option RfcRule
  | "pgp4880TrailingWhitespace" => some .pgp4880TrailingWhitespace
  | "pgp9580LineEnding"         => some .pgp9580LineEnding
  | "rfc8785NfcRequirement"     => some .rfc8785NfcRequirement
  | "rfc8259ControlChar"        => some .rfc8259ControlChar
  | other                       =>
    Function.const String none other

end RfcRule

/-- Sub-threats K2 can fire.  Names + arguments follow
    `L6-cryptographic-stability.md` §K2.3.  All six are now
    emitted by the v1 detector.  The first two
    (`trailingWhitespace`, `normalizationDrift`) fire from the
    raw input alone.  The other four require fields on the
    `Context` argument to `detectWithContext` to be set. -/
inductive SubThreat where
  | normalizationDrift       (firstDivergentPos : Nat)
  | trailingWhitespace       (count : Nat)
  | encodingMismatch         (declaredEnc : String) (detectedEnc : String)
  | signedMessageRule        (rfcRule : String) (firstPos : Nat)
  | auditLogReinterpretation (firstDivergentPos : Nat)
  | webhookSignatureDrift    (firstPos : Nat)
  deriving DecidableEq, Repr, Inhabited

/-- Context passed to `detectWithContext` to enable the four
    context-bearing probes (`encodingMismatch`,
    `signedMessageRule`, `auditLogReinterpretation`,
    `webhookSignatureDrift`).  Each field is optional — when
    none is set, only the bare-input probes fire.  Default
    `{}` produces the legacy behaviour identical to the bare
    `detect input` entry point. -/
structure Context where
  /-- The encoding label the caller claims their input is in.
      When provided and not equal to "utf-8", K2 fires
      `encodingMismatch` immediately (the codepoint array IS
      the decoded UTF-8 representation; any other declaration
      indicates label drift).  Case-insensitive comparison. -/
  declaredEncoding : Option String := none
  /-- The RFC canonicalisation rule the caller is operating
      under.  When provided, K2 scans `input` for violations
      of that rule and fires `signedMessageRule` on the first
      violating position. -/
  rfcRule : Option RfcRule := none
  /-- The original "as-written" form of an audit-log entry
      whose re-read is `input`.  When provided, K2 compares
      the two codepoint-by-codepoint and fires
      `auditLogReinterpretation` on the first divergence. -/
  asWritten : Option (Array Nat) := none
  /-- The server-side recomputed bytes for a webhook signature.
      When provided, K2 compares the client `input` against
      this array and fires `webhookSignatureDrift` on the
      first divergence. -/
  serverBytes : Option (Array Nat) := none
  deriving Inhabited

/-- Top-level K2 classification. -/
inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : Array Nat)
  deriving DecidableEq, Repr, Inhabited

/-- K2 verdict — the structured output of `detect`.
    `stableSize` is the codepoint count of the hash-stable
    canonical form; downstream callers compare it against
    `input.size` to size the byte-drift their hash would see. -/
structure Verdict where
  input        : Array Nat
  classify     : Classification
  stableForm   : Array Nat
  stableSize   : Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Universal projections (isClear / tag / positions)
-- ═══════════════════════════════════════════════════════════════════════════════

namespace Classification

@[inline] def isClear : Classification → Bool
  | .clear              => true
  | .hazard sub ps      =>
    Function.const (SubThreat × Array Nat) false (sub, ps)

@[inline] def tag : Classification → Option String
  | .clear              => none
  | .hazard sub ps      =>
    Function.const (Array Nat) (
      match sub with
      | .normalizationDrift pos =>
        Function.const Nat (some "NormalizationDrift") pos
      | .trailingWhitespace count =>
        Function.const Nat (some "TrailingWhitespace") count
      | .encodingMismatch declared detected =>
        Function.const (String × String) (some "EncodingMismatch")
          (declared, detected)
      | .signedMessageRule rfc pos =>
        Function.const (String × Nat) (some "SignedMessageRule") (rfc, pos)
      | .auditLogReinterpretation pos =>
        Function.const Nat (some "AuditLogReinterpretation") pos
      | .webhookSignatureDrift pos =>
        Function.const Nat (some "WebhookSignatureDrift") pos
    ) ps

@[inline] def positions : Classification → Array Nat
  | .clear              => #[]
  | .hazard sub ps      => Function.const SubThreat ps sub

end Classification

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Canonicalisation pipeline
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cp` is an ASCII whitespace codepoint that
    line-oriented hash-input protocols treat as framing rather
    than content.  Covers U+0020 SPACE, U+0009 TAB, U+000A LF,
    U+000D CR.  Unicode whitespace (U+00A0, U+2000-U+200A,
    U+3000) is *content* under K2's threat model and not
    stripped. -/
@[inline] def isAsciiWhitespace (cp : Nat) : Bool :=
  decide (cp = 0x0020) || decide (cp = 0x0009)
    || decide (cp = 0x000A) || decide (cp = 0x000D)

/-- Count of trailing ASCII whitespace codepoints in `input`. -/
def countTrailingWhitespace (input : Array Nat) : Nat :=
  (input.reverse.takeWhile isAsciiWhitespace).size

/-- Strip trailing ASCII whitespace. -/
def trimTrailing (input : Array Nat) : Array Nat :=
  input.extract 0 (input.size - countTrailingWhitespace input)

/-- The K2 hash-stable form of an input.  Composes the two
    canonicalisation stages in spec order: NFC then trim. -/
def hashStable (input : Array Nat) : Array Nat :=
  trimTrailing (Unicode.Normalization.NFC.toNFC input)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Canonicalisation spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input has empty stable form. -/
theorem stable_empty :
    hashStable #[] = #[] := by native_decide

/-- Already-canonical ASCII is a fixed point. -/
theorem stable_ascii_idempotent :
    let cps : Array Nat := #[0x61, 0x62, 0x63]
    hashStable (hashStable cps) = hashStable cps := by native_decide

/-- Trailing U+0020 is stripped. -/
theorem stable_strips_trailing_space :
    hashStable #[0x61, 0x20] = #[0x61] := by native_decide

/-- Trailing U+0009 TAB is stripped. -/
theorem stable_strips_trailing_tab :
    hashStable #[0x61, 0x09] = #[0x61] := by native_decide

/-- Trailing U+000A LF is stripped. -/
theorem stable_strips_trailing_lf :
    hashStable #[0x61, 0x0A] = #[0x61] := by native_decide

/-- Trailing CRLF is stripped. -/
theorem stable_strips_trailing_crlf :
    hashStable #[0x61, 0x0D, 0x0A] = #[0x61] := by native_decide

/-- Internal U+0020 between non-whitespace content is
    preserved — only TRAILING whitespace is framing. -/
theorem stable_preserves_internal_space :
    hashStable #[0x61, 0x20, 0x62] = #[0x61, 0x20, 0x62] := by
  native_decide

/-- Decomposed é (a + combining acute) NFC-composes to U+00E9. -/
theorem stable_composes_nfc :
    let cps : Array Nat := #[0x0065, 0x0301]
    hashStable cps = #[0x00E9] := by native_decide

/-- Unicode whitespace U+00A0 NBSP is content, not framing —
    trailing NBSP is NOT stripped. -/
theorem stable_preserves_trailing_nbsp :
    hashStable #[0x61, 0x00A0] = #[0x61, 0x00A0] := by
  native_decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Hazard probes (per-priority position-finders)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- First position at which `a` and `b` diverge.  Returns
    `none` when they are identical. -/
def firstArrayDivergence (a b : Array Nat) : Option Nat :=
  let n := if a.size ≤ b.size then a.size else b.size
  match (Array.range n).findSome? (fun i =>
    if ha : i < a.size then
      if hb : i < b.size then
        if a[i] != b[i] then some i else none
      else none
    else none) with
  | some i => some i
  | none   => if a.size = b.size then none else some n

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 Context-bearing probes
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Lower-case an ASCII letter (codepoint 'A'..'Z' → 'a'..'z').
    Used to make the declared-encoding label comparison case-
    insensitive (callers may pass "UTF-8" or "utf-8"). -/
private def asciiLower (cp : Nat) : Nat :=
  if 0x41 ≤ cp ∧ cp ≤ 0x5A then cp + 0x20 else cp

/-- Normalise an encoding label by lowercasing its ASCII
    letters.  Non-ASCII characters pass through unchanged. -/
private def normaliseEncodingLabel (s : String) : String :=
  String.ofList (s.toList.map (fun c => Char.ofNat (asciiLower c.toNat)))

/-- True iff `label` (after ASCII case-fold) names the UTF-8
    encoding.  Accepts "utf-8", "UTF-8", "UTF8", "utf8". -/
private def isUtf8Label (label : String) : Bool :=
  let l := normaliseEncodingLabel label
  decide (l = "utf-8") || decide (l = "utf8")

/-- Probe: `encodingMismatch`.  Fires when the caller declares
    a non-UTF-8 encoding label.  The codepoint array passed to
    K2 IS the UTF-8-decoded representation by construction, so
    any non-UTF-8 declaration is necessarily a label-drift.
    Returns `(declaredEnc, detectedEnc, firstPos)` triple when
    firing, `none` otherwise. -/
def encodingMismatchProbe (declared : String) :
    Option (String × String × Nat) :=
  if isUtf8Label declared then none
  else some (declared, "utf-8", 0)

/-- Probe: `signedMessageRule` for `pgp4880TrailingWhitespace`.
    Same condition as `trailingWhitespace` but reported under
    the RFC-specific tag.  Returns the firstPos at which the
    trailing run begins. -/
def pgp4880Violation (input : Array Nat) : Option Nat :=
  let trailingCount := countTrailingWhitespace input
  if trailingCount > 0 then some (input.size - trailingCount)
  else none

/-- Probe: `signedMessageRule` for `pgp9580LineEnding`.  Scans
    `input` for the first bare LF (U+000A not preceded by CR)
    or bare CR (U+000D not followed by LF).  Returns the
    position of the bare line-ending codepoint. -/
def pgp9580Violation (input : Array Nat) : Option Nat :=
  (Array.range input.size).findSome? (fun i =>
    if h : i < input.size then
      let cp := input[i]
      if cp = 0x000A then
        -- LF: violating iff not preceded by CR
        if hPrev : 0 < i then
          if hLt : i - 1 < input.size then
            if input[i - 1] = 0x000D then none else some i
          else
            Function.const (0 < i) (some i) hPrev
        else some i
      else if cp = 0x000D then
        -- CR: violating iff not followed by LF
        if hLt : i + 1 < input.size then
          if input[i + 1] = 0x000A then none else some i
        else some i
      else none
    else none)

/-- Probe: `signedMessageRule` for `rfc8785NfcRequirement`.
    Fires on the same condition as `normalizationDrift` but
    reported under the JSON-canonicalisation rule.  Returns
    the firstPos at which `input` diverges from its NFC form. -/
def rfc8785Violation (input : Array Nat) : Option Nat :=
  let nfc := Unicode.Normalization.NFC.toNFC input
  if input == nfc then none else firstArrayDivergence input nfc

/-- Probe: `signedMessageRule` for `rfc8259ControlChar`.  Scans
    `input` for the first unescaped C0 control codepoint
    (U+0000..U+001F other than the JSON-permitted whitespace
    U+0009 TAB / U+000A LF / U+000D CR — those still require
    escaping in JSON strings per RFC 8259 §7, so they also
    count as violations).  Returns the position of the first
    violating control char. -/
def rfc8259Violation (input : Array Nat) : Option Nat :=
  (Array.range input.size).findSome? (fun i =>
    if h : i < input.size then
      let cp := input[i]
      if cp ≤ 0x1F then some i else none
    else none)

/-- Dispatch the RFC-rule probe.  Returns the position of the
    first violation when the rule is violated, `none` when the
    input is clean per the rule. -/
def rfcRuleViolation (rule : RfcRule) (input : Array Nat) : Option Nat :=
  match rule with
  | .pgp4880TrailingWhitespace => pgp4880Violation input
  | .pgp9580LineEnding         => pgp9580Violation input
  | .rfc8785NfcRequirement     => rfc8785Violation input
  | .rfc8259ControlChar        => rfc8259Violation input

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The full K2 detection function.  Runs all six probes in
    priority order:

      1. encodingMismatch
      2. webhookSignatureDrift
      3. auditLogReinterpretation
      4. signedMessageRule
      5. trailingWhitespace
      6. normalizationDrift
      7. clear

    Context-specific probes fire first because they carry more
    precise threat information than the generic probes.  -/
def detectWithContext (ctx : Context) (input : Array Nat) : Verdict :=
  let stable := hashStable input

  -- Probe 1: encodingMismatch.
  let encodingHit : Option (String × String × Nat) :=
    match ctx.declaredEncoding with
    | some lbl => encodingMismatchProbe lbl
    | none     => none

  -- Probe 2: webhookSignatureDrift.
  let webhookHit : Option Nat :=
    match ctx.serverBytes with
    | some server => firstArrayDivergence input server
    | none        => none

  -- Probe 3: auditLogReinterpretation.
  let auditHit : Option Nat :=
    match ctx.asWritten with
    | some written => firstArrayDivergence written input
    | none         => none

  -- Probe 4: signedMessageRule.
  let rfcHit : Option (RfcRule × Nat) :=
    match ctx.rfcRule with
    | some rule =>
      match rfcRuleViolation rule input with
      | some pos => some (rule, pos)
      | none     => none
    | none => none

  -- Probe 5: trailingWhitespace.
  let trailingCount := countTrailingWhitespace input

  -- Probe 6: normalizationDrift.
  let nfc       := Unicode.Normalization.NFC.toNFC input
  let nonNfcPos :=
    if input == nfc then none else firstArrayDivergence input nfc

  let classification : Classification :=
    match encodingHit with
    | some (declared, detected, pos) =>
      .hazard (.encodingMismatch declared detected) #[pos]
    | none =>
    match webhookHit with
    | some pos => .hazard (.webhookSignatureDrift pos) #[pos]
    | none =>
    match auditHit with
    | some pos => .hazard (.auditLogReinterpretation pos) #[pos]
    | none =>
    match rfcHit with
    | some (rule, pos) =>
      .hazard (.signedMessageRule rule.tag pos) #[pos]
    | none =>
    if trailingCount > 0 then
      let p := input.size - trailingCount
      .hazard (.trailingWhitespace trailingCount) #[p]
    else match nonNfcPos with
    | some p => .hazard (.normalizationDrift p) #[p]
    | none   => .clear

  { input := input,
    classify := classification,
    stableForm := stable,
    stableSize := stable.size }

/-- Convenience wrapper over `detectWithContext` with the empty
    context — equivalent to running only the two bare-input
    probes (`trailingWhitespace`, `normalizationDrift`).  Used
    by `Unicode.Security.RunAll` and by callers who don't have
    encoding / RFC / paired-bytes context to supply. -/
def detect (input : Array Nat) : Verdict :=
  detectWithContext {} input

-- ═══════════════════════════════════════════════════════════════════════════════
-- §8 Spot-check theorems
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear. -/
theorem detect_empty_clear :
    (detect #[]).classify = .clear := by native_decide

/-- ASCII "abc" is already hash-stable. -/
theorem detect_ascii_idempotent :
    (detect #[0x61, 0x62, 0x63]).classify = .clear := by native_decide

/-- Single trailing space fires `trailingWhitespace` at index
    after the content. -/
theorem detect_trailing_space :
    let v := detect #[0x61, 0x20]
    v.classify.tag = some "TrailingWhitespace"
    ∧ v.stableSize = 1
    ∧ v.classify.positions = #[1] := by native_decide

/-- Trailing CRLF fires `trailingWhitespace` with count = 2. -/
theorem detect_trailing_crlf :
    let v := detect #[0x61, 0x0D, 0x0A]
    v.classify.tag = some "TrailingWhitespace"
    ∧ v.stableSize = 1 := by native_decide

/-- Decomposed é fires `normalizationDrift` at position 0. -/
theorem detect_decomposed_e_acute :
    let v := detect #[0x0065, 0x0301]
    v.classify.tag = some "NormalizationDrift"
    ∧ v.classify.positions = #[0] := by native_decide

/-- Precomposed é is clear. -/
theorem detect_precomposed_e_acute_clear :
    (detect #[0x00E9]).classify = .clear := by native_decide

/-- Priority: trailing whitespace fires before normalization
    drift when both apply.  Input is decomposed "é " — fires
    TrailingWhitespace at position 2, not NormalizationDrift
    at position 0. -/
theorem detect_priority_trailing_over_nfc :
    let v := detect #[0x0065, 0x0301, 0x20]
    v.classify.tag = some "TrailingWhitespace" := by
  native_decide

/-- Internal-only whitespace passes — only TRAILING fires. -/
theorem detect_internal_space_clear :
    (detect #[0x61, 0x20, 0x62]).classify = .clear := by native_decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §9 Context-bearing probe spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- `detectWithContext {}` agrees with `detect` for bare inputs.
    Pinning that the convenience wrapper is genuinely equivalent
    to the context-aware entry point with the empty context.
    Tested via classification + stableSize co-fields (Verdict
    itself doesn't derive DecidableEq because Array Nat doesn't). -/
theorem detectWithContext_default_matches_detect :
    (detectWithContext {} #[0x61, 0x62, 0x63]).classify
      = (detect #[0x61, 0x62, 0x63]).classify
    ∧ (detectWithContext {} #[0x61, 0x62, 0x63]).stableSize
      = (detect #[0x61, 0x62, 0x63]).stableSize
    := by native_decide

/-- `encodingMismatch` fires when declared encoding is not UTF-8.
    Pure-ASCII "abc" labeled "utf-16" reports the mismatch with
    detected = "utf-8". -/
theorem detect_encoding_mismatch_utf16_label :
    let ctx : Context := { declaredEncoding := some "utf-16" }
    let v := detectWithContext ctx #[0x61, 0x62, 0x63]
    v.classify.tag = some "EncodingMismatch"
    ∧ v.classify.positions = #[0] := by native_decide

/-- `encodingMismatch` is case-insensitive on the UTF-8 label —
    "UTF-8" / "UTF8" / "utf-8" / "utf8" all match. -/
theorem detect_encoding_utf8_label_case_insensitive :
    let ctxUpper : Context := { declaredEncoding := some "UTF-8" }
    let ctxLower : Context := { declaredEncoding := some "utf-8" }
    let ctxNoDash : Context := { declaredEncoding := some "UTF8" }
    (detectWithContext ctxUpper #[0x61, 0x62, 0x63]).classify = .clear
    ∧ (detectWithContext ctxLower #[0x61, 0x62, 0x63]).classify = .clear
    ∧ (detectWithContext ctxNoDash #[0x61, 0x62, 0x63]).classify = .clear
    := by native_decide

/-- `signedMessageRule` fires for `pgp4880TrailingWhitespace` on
    a trailing-space input — same condition as
    `trailingWhitespace` but reported under the RFC-specific tag.
    Pinning that the priority order places the RFC-specific
    verdict before the generic one. -/
theorem detect_signed_message_pgp4880 :
    let ctx : Context := { rfcRule := some .pgp4880TrailingWhitespace }
    let v := detectWithContext ctx #[0x61, 0x20]
    v.classify.tag = some "SignedMessageRule"
    ∧ v.classify.positions = #[1] := by native_decide

/-- `signedMessageRule` fires for `pgp9580LineEnding` on a bare
    LF (no preceding CR).  Position points at the LF. -/
theorem detect_signed_message_pgp9580_bare_lf :
    let ctx : Context := { rfcRule := some .pgp9580LineEnding }
    let v := detectWithContext ctx #[0x61, 0x0A, 0x62]
    v.classify.tag = some "SignedMessageRule"
    ∧ v.classify.positions = #[1] := by native_decide

/-- `signedMessageRule` with `pgp9580LineEnding` stays clear on
    proper CRLF. -/
theorem detect_signed_message_pgp9580_crlf_clear_internal :
    let ctx : Context := { rfcRule := some .pgp9580LineEnding }
    -- "abc" CRLF "def" — CRLF is the canonical line ending.
    (detectWithContext ctx
      #[0x61, 0x62, 0x63, 0x0D, 0x0A, 0x64, 0x65, 0x66]).classify
    = .clear := by native_decide

/-- `signedMessageRule` fires for `rfc8785NfcRequirement` on
    decomposed é — same condition as `normalizationDrift` but
    reported under the JSON-canonicalisation tag. -/
theorem detect_signed_message_rfc8785_decomposed :
    let ctx : Context := { rfcRule := some .rfc8785NfcRequirement }
    let v := detectWithContext ctx #[0x0065, 0x0301]
    v.classify.tag = some "SignedMessageRule"
    ∧ v.classify.positions = #[0] := by native_decide

/-- `signedMessageRule` fires for `rfc8259ControlChar` on an
    unescaped control codepoint inside the input.  Position
    points at the first control. -/
theorem detect_signed_message_rfc8259_control :
    let ctx : Context := { rfcRule := some .rfc8259ControlChar }
    -- "a" + U+0001 (Start of Heading) + "b"
    let v := detectWithContext ctx #[0x61, 0x01, 0x62]
    v.classify.tag = some "SignedMessageRule"
    ∧ v.classify.positions = #[1] := by native_decide

/-- `auditLogReinterpretation` fires when `ctx.asWritten`
    differs from `input` at a known position. -/
theorem detect_audit_log_divergence :
    let written : Array Nat := #[0x61, 0x62, 0x63]
    let asRead  : Array Nat := #[0x61, 0x62, 0x64]
    let ctx : Context := { asWritten := some written }
    let v := detectWithContext ctx asRead
    v.classify.tag = some "AuditLogReinterpretation"
    ∧ v.classify.positions = #[2] := by native_decide

/-- `auditLogReinterpretation` stays silent when written and
    read are identical. -/
theorem detect_audit_log_identical_clear :
    let bytes : Array Nat := #[0x61, 0x62, 0x63]
    let ctx : Context := { asWritten := some bytes }
    (detectWithContext ctx bytes).classify = .clear := by native_decide

/-- `webhookSignatureDrift` fires when `ctx.serverBytes` differs
    from the client `input`.  Position is the first divergent
    index. -/
theorem detect_webhook_signature_drift :
    let client : Array Nat := #[0x61, 0x62, 0x63]
    let server : Array Nat := #[0x61, 0x62, 0x64]
    let ctx : Context := { serverBytes := some server }
    let v := detectWithContext ctx client
    v.classify.tag = some "WebhookSignatureDrift"
    ∧ v.classify.positions = #[2] := by native_decide

/-- `webhookSignatureDrift` stays silent when client and server
    bytes are identical. -/
theorem detect_webhook_signature_match_clear :
    let bytes : Array Nat := #[0x61, 0x62, 0x63]
    let ctx : Context := { serverBytes := some bytes }
    (detectWithContext ctx bytes).classify = .clear := by native_decide

/-- Priority pin: `encodingMismatch` fires before all other
    context-bearing probes.  An input with bare LF (would fire
    pgp9580) and decomposed é (would fire rfc8785) labeled
    "utf-16" instead fires encodingMismatch at position 0. -/
theorem detect_priority_encoding_over_rfc :
    let ctx : Context := {
      declaredEncoding := some "utf-16"
      rfcRule := some .pgp9580LineEnding
    }
    let v := detectWithContext ctx #[0x0065, 0x0301, 0x0A]
    v.classify.tag = some "EncodingMismatch" := by native_decide

/-- Priority pin: `webhookSignatureDrift` fires before
    `auditLogReinterpretation` when both diverge.  Pinned by
    setting both fields to diverging arrays. -/
theorem detect_priority_webhook_over_audit :
    let server : Array Nat := #[0x61, 0x62, 0x65]
    let written : Array Nat := #[0x61, 0x62, 0x66]
    let client : Array Nat := #[0x61, 0x62, 0x63]
    let ctx : Context := {
      serverBytes := some server
      asWritten := some written
    }
    let v := detectWithContext ctx client
    v.classify.tag = some "WebhookSignatureDrift" := by native_decide

/-- Priority pin: context-bearing `signedMessageRule` (priority 4)
    fires before generic `trailingWhitespace` (priority 5) when
    both apply.  Input "a" + trailing space + ctx.rfcRule =
    pgp4880TrailingWhitespace — both probes would match; the
    RFC-specific verdict wins. -/
theorem detect_priority_rfc_over_trailing :
    let ctx : Context := { rfcRule := some .pgp4880TrailingWhitespace }
    let v := detectWithContext ctx #[0x61, 0x20]
    v.classify.tag = some "SignedMessageRule" := by native_decide

end Unicode.Security.Crypto.HashInputStability
