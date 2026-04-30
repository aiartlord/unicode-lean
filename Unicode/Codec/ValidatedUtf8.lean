/-
  Unicode.Codec.ValidatedUtf8

  Refinement type for bytes that have been validated as strict RFC 3629
  UTF-8 by `Unicode.Codec.Utf8.isValidUtf8`. The validity claim is pinned
  at the type level: the only way to construct a `ValidatedUtf8` is via
  the smart constructor `validateUtf8`, which threads through the decoder
  state machine in `Unicode.Codec.Utf8`.

  Rationale: the ingestion layer is security-critical. A plain `String`
  or `ByteArray` field on a codec output type carries no claim about
  its UTF-8 validity — downstream consumers have to either re-validate
  or trust that the producer validated (and hope the producer didn't
  regress). `ValidatedUtf8` makes the claim type-level, so a downstream
  consumer that wants the raw bytes has to *explicitly* unwrap (via
  `ValidatedUtf8.unwrap`), which reads as "I am consuming the
  RFC 3629 claim here".
-/

import Unicode.Codec.Utf8

namespace Unicode.Codec.ValidatedUtf8

open Unicode.Codec.Utf8 (isValidUtf8)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 REFINEMENT TYPE
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A `ByteArray` that has been validated as strict RFC 3629 UTF-8.
    The `valid` field is a proof that the underlying bytes pass
    `Unicode.Codec.Utf8.isValidUtf8`; the smart constructor
    `validateUtf8` below is the only blessed way to build a
    `ValidatedUtf8`. -/
structure ValidatedUtf8 where
  bytes : ByteArray
  valid : isValidUtf8 bytes = true

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 SMART CONSTRUCTOR
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Validate a `ByteArray` and, on success, return a `ValidatedUtf8`
    carrying the RFC 3629 validity proof. Returns `none` when the
    bytes fail the strict state machine (overlong, surrogate,
    > U+10FFFF, invalid start/continuation, truncated).

    The input bytes are stored by reference — no copy, no normalisation. -/
def validateUtf8 (bs : ByteArray) : Option ValidatedUtf8 :=
  if h : isValidUtf8 bs = true then
    some ⟨bs, h⟩
  else
    none

/-- Consume the validity claim, returning the underlying `ByteArray`.
    After this call the validity claim is no longer carried at the
    type level — the caller owns the "these bytes are RFC 3629 valid"
    reasoning from here forward. -/
def ValidatedUtf8.unwrap (v : ValidatedUtf8) : ByteArray :=
  v.bytes

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 VALIDITY THEOREMS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- `validateUtf8` returns `some` iff the input is strict RFC 3629 valid.
    Structural equivalence justifying the smart constructor: validation
    at the `Option` level agrees with validation at the `Bool` predicate
    level. -/
theorem validateUtf8_isSome_iff (bs : ByteArray) :
    (validateUtf8 bs).isSome = true ↔ isValidUtf8 bs = true := by
  unfold validateUtf8
  by_cases h : isValidUtf8 bs = true
  · simp [h]
  · simp [h]

/-- `unwrap` recovers the original bytes. Round-trip fact used by
    downstream codecs that need to serialise a `ValidatedUtf8` back
    to wire format. -/
theorem unwrap_bytes (v : ValidatedUtf8) : v.unwrap = v.bytes := rfl

/-- The validity proof is recoverable from an existing `ValidatedUtf8`.
    Lets downstream proofs appeal to the `valid` field without
    re-running the decoder. -/
theorem unwrap_valid (v : ValidatedUtf8) :
    isValidUtf8 v.unwrap = true := by
  simp [ValidatedUtf8.unwrap, v.valid]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 CONCRETE CONSTRUCTION THEOREMS
-- ═══════════════════════════════════════════════════════════════════════════════

theorem empty_validates : (validateUtf8 ByteArray.empty).isSome = true := by
  native_decide

theorem hello_validates : (validateUtf8 "hello".toUTF8).isSome = true := by
  native_decide

theorem accented_validates : (validateUtf8 "héllo".toUTF8).isSome = true := by
  native_decide

theorem cjk_validates : (validateUtf8 "日本".toUTF8).isSome = true := by
  native_decide

theorem bare_continuation_rejected :
    validateUtf8 (ByteArray.mk #[0x80]) = none := by
  native_decide

end Unicode.Codec.ValidatedUtf8
