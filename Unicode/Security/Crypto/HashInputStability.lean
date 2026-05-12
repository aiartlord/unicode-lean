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

  Sub-threats (priority order, first hit wins):

    1. `trailingWhitespace` — input has trailing ASCII
       whitespace; the trim step changes byte-length.
    2. `normalizationDrift` — input != NFC(input); the NFC step
       changes codepoint content.

  The other four sub-threats listed in
  `docs/specs/security/L6-cryptographic-stability.md` §K2.3
  (`encodingMismatch`, `signedMessageRule`,
  `auditLogReinterpretation`, `webhookSignatureDrift`) require
  context that a codepoint-only detector cannot access:
  declared encoding string, RFC profile choice, persistence-
  boundary state, network-actor identity.  They are declared
  in `K2SubThreat` for future-extension consistency with the
  spec; the v1 detector never emits them.
-/

import Unicode.Security.Calculus
import Unicode.Normalization.NFC

namespace Unicode.Security.Crypto.HashInputStability

open Unicode.Security.Calculus

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Sub-threats K2 can fire.  Names + arguments follow
    `L6-cryptographic-stability.md` §K2.3.  Only the first two
    are emitted by the v1 detector; the remaining four require
    context the codepoint-only API doesn't carry. -/
inductive K2SubThreat where
  | normalizationDrift       (firstDivergentPos : Nat)
  | trailingWhitespace       (count : Nat)
  | encodingMismatch         (declaredEnc : String) (detectedEnc : String)
  | signedMessageRule        (rfcRule : String) (firstPos : Nat)
  | auditLogReinterpretation (firstDivergentPos : Nat)
  | webhookSignatureDrift    (firstPos : Nat)
  deriving DecidableEq, Repr, Inhabited

/-- Top-level K2 classification. -/
inductive K2Classification where
  | clear
  | hazard (sub : K2SubThreat) (positions : Array Nat)
  deriving DecidableEq, Repr, Inhabited

/-- K2 verdict — the structured output of `detect`.
    `stableSize` is the codepoint count of the hash-stable
    canonical form; downstream callers compare it against
    `input.size` to size the byte-drift their hash would see. -/
structure K2Verdict where
  input        : Array Nat
  classify     : K2Classification
  stableForm   : Array Nat
  stableSize   : Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Universal projections (isClear / tag / positions)
-- ═══════════════════════════════════════════════════════════════════════════════

namespace K2Classification

@[inline] def isClear : K2Classification → Bool
  | .clear              => true
  | .hazard sub ps      =>
    Function.const (K2SubThreat × Array Nat) false (sub, ps)

@[inline] def tag : K2Classification → Option String
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

@[inline] def positions : K2Classification → Array Nat
  | .clear              => #[]
  | .hazard sub ps      => Function.const K2SubThreat ps sub

end K2Classification

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
-- §6 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The K2 detection function.

    Priority order (first hit wins):
      1. `trailingWhitespace` — input has trailing ASCII
         whitespace; canonical form differs by the trim.
      2. `normalizationDrift` — input != NFC(input); canonical
         form differs by the NFC normalisation.
      3. clear                — input is already hash-stable.
-/
def detect (input : Array Nat) : K2Verdict :=
  let stable        := hashStable input
  let trailingCount := countTrailingWhitespace input

  let nfc       := Unicode.Normalization.NFC.toNFC input
  let nonNfcPos :=
    if input == nfc then none else firstArrayDivergence input nfc

  let classification : K2Classification :=
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

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 Spot-check theorems
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

end Unicode.Security.Crypto.HashInputStability
