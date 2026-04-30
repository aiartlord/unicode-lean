/-
  Unicode.Codec.Utf8

  Strict UTF-8 validator independent of String.fromUTF8?. Rejects overlong
  encodings, surrogate codepoints (U+D800–U+DFFF), codepoints beyond U+10FFFF,
  truncated multi-byte sequences, invalid start bytes, and invalid continuation
  bytes.

  Rationale: the ingestion layer is security-critical; UTF-8 acceptance
  semantics are not deferred to Lean stdlib's internal validator, whose
  strictness on overlong and surrogate inputs is not contractually specified
  for all Lean versions.

  Offset convention for firstInvalidUtf8Offset:
    The returned offset is the index of the byte on which the state machine
    transitioned to reject. For overlongEncoding (detected on emission of a
    multi-byte sequence), this is the START BYTE of the sequence, not the last
    byte consumed.
-/

import Unicode.Codec.Strict

namespace Unicode.Codec.Utf8

open Unicode.Codec.Strict (Utf8RejectKind)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 DECODER STATE
-- ═══════════════════════════════════════════════════════════════════════════════

/-- UTF-8 decoder state. `expectCont remaining accum minCp` means we are in
    the middle of a multi-byte sequence: `remaining` continuation bytes still
    needed, `accum` holds the codepoint accumulated so far, and `minCp` is
    the smallest codepoint a sequence of this start-byte class must decode to
    (used to reject overlong encodings).

    The second parameter is named `accum` rather than `partial` because
    `partial` is a reserved Lean 4 keyword. -/
inductive Utf8State where
  | expectStart
  | expectCont (remaining : Nat) (accum : Nat) (minCp : Nat)
  deriving Repr, DecidableEq

instance : Inhabited Utf8State := ⟨Utf8State.expectStart⟩

/-- A single decoder step produces either a new state, an emitted codepoint
    with a new state, or a rejection. -/
inductive Utf8StepResult where
  | continue (next : Utf8State)
  | emit     (cp : Nat) (next : Utf8State)
  | reject   (kind : Utf8RejectKind)
  deriving DecidableEq

instance : Inhabited Utf8StepResult := ⟨Utf8StepResult.continue Utf8State.expectStart⟩

theorem expectStart_ne_expectCont :
    Utf8State.expectStart ≠ Utf8State.expectCont 1 0 0x80 := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 DECODER STEP
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Process one byte of input given the current state.

    Start-byte ranges (from RFC 3629):
      0x00..0x7F  → 1-byte ASCII, emit directly
      0x80..0xBF  → invalid as start byte (continuation bytes only)
      0xC0..0xC1  → invalid (would encode overlong 2-byte sequences for ASCII)
      0xC2..0xDF  → 2-byte sequence start, minCp = 0x80
      0xE0..0xEF  → 3-byte sequence start, minCp = 0x800
      0xF0..0xF4  → 4-byte sequence start, minCp = 0x10000
      0xF5..0xFF  → invalid (would encode codepoints > U+10FFFF)

    Continuation bytes must be in 0x80..0xBF (high two bits = 10).
    On emission: reject if decoded codepoint < minCp (overlong),
    or in 0xD800..0xDFFF (surrogate), or > 0x10FFFF (beyond max). -/
def utf8DecodeStep (st : Utf8State) (b : UInt8) : Utf8StepResult :=
  let n := b.toNat
  match st with
  | .expectStart =>
      if n < 0x80 then
        .emit n .expectStart
      else if n < 0xC2 then
        .reject .invalidStartByte
      else if n < 0xE0 then
        -- 2-byte start: 110xxxxx; low 5 bits seed partial
        .continue (.expectCont 1 (n &&& 0x1F) 0x80)
      else if n < 0xF0 then
        -- 3-byte start: 1110xxxx; low 4 bits seed partial
        .continue (.expectCont 2 (n &&& 0x0F) 0x800)
      else if n < 0xF5 then
        -- 4-byte start: 11110xxx; low 3 bits seed partial
        .continue (.expectCont 3 (n &&& 0x07) 0x10000)
      else
        .reject .invalidStartByte
  | .expectCont remaining accum minCp =>
      if n < 0x80 ∨ n ≥ 0xC0 then
        -- Not a continuation byte (required: 10xxxxxx = 0x80..0xBF)
        .reject .invalidContinuationByte
      else
        let next := (accum <<< 6) ||| (n &&& 0x3F)
        match remaining with
        | 0 =>
            -- Invariant violation: expectCont should never be reached with remaining = 0.
            -- Treat as invalidContinuationByte for structural totality.
            .reject .invalidContinuationByte
        | 1 =>
            -- Final continuation byte of this sequence; validate and emit.
            if next < minCp then
              .reject .overlongEncoding
            else if 0xD800 ≤ next ∧ next ≤ 0xDFFF then
              .reject .surrogateCodepoint
            else if next > 0x10FFFF then
              .reject .codepointBeyondMax
            else
              .emit next .expectStart
        | m + 1 =>
            .continue (.expectCont m next minCp)

theorem step_ascii_A :
    utf8DecodeStep .expectStart 0x41 = .emit 0x41 .expectStart := by decide

theorem step_ascii_nul :
    utf8DecodeStep .expectStart 0x00 = .emit 0x00 .expectStart := by decide

theorem step_invalid_start_80 :
    utf8DecodeStep .expectStart 0x80 = .reject .invalidStartByte := by decide

theorem step_invalid_start_C0 :
    utf8DecodeStep .expectStart 0xC0 = .reject .invalidStartByte := by decide

theorem step_invalid_start_C1 :
    utf8DecodeStep .expectStart 0xC1 = .reject .invalidStartByte := by decide

theorem step_invalid_start_F5 :
    utf8DecodeStep .expectStart 0xF5 = .reject .invalidStartByte := by decide

theorem step_invalid_start_FF :
    utf8DecodeStep .expectStart 0xFF = .reject .invalidStartByte := by decide

theorem step_2byte_start_C3 :
    utf8DecodeStep .expectStart 0xC3
      = .continue (.expectCont 1 (0xC3 &&& 0x1F) 0x80) := by decide

theorem step_3byte_start_E2 :
    utf8DecodeStep .expectStart 0xE2
      = .continue (.expectCont 2 (0xE2 &&& 0x0F) 0x800) := by decide

theorem step_4byte_start_F0 :
    utf8DecodeStep .expectStart 0xF0
      = .continue (.expectCont 3 (0xF0 &&& 0x07) 0x10000) := by decide

theorem step_cont_with_ascii_rejects :
    utf8DecodeStep (.expectCont 1 0x03 0x80) 0x41
      = .reject .invalidContinuationByte := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 WALKER: firstInvalidUtf8Offset, isValidUtf8
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Fuel-based walker over `bs`. `fuel` is initialized to `bs.size` which is
    always sufficient since we advance `i` by one per step. The `fuel = 0`
    branch is structurally unreachable when entered with `fuel = bs.size` and
    `i ≤ fuel`; it returns `none` defensively. -/
private def firstInvalidUtf8OffsetGo (bs : ByteArray) : Utf8State → Nat → Nat → Nat
    → Option (Nat × Utf8RejectKind)
  | _, _, _, 0 => none
  | st, i, seqStart, f + 1 =>
    if hi : i < bs.size then
      let b := bs[i]'hi
      match utf8DecodeStep st b with
      | .continue next =>
          let newSeqStart := match st with
            | .expectStart => i
            | .expectCont _ _ _ => seqStart
          firstInvalidUtf8OffsetGo bs next (i + 1) newSeqStart f
      | .emit _ next =>
          firstInvalidUtf8OffsetGo bs next (i + 1) (i + 1) f
      | .reject kind =>
          match kind with
          | .overlongEncoding => some (seqStart, kind)
          | other             => some (i, other)
    else
      match st with
      | .expectStart       => none
      | .expectCont _ _ _  => some (i, .truncatedSequence)

/-- Returns `some (offset, kind)` at the first byte where the UTF-8 state
    machine transitions to a reject state, or `none` if the whole array is
    valid UTF-8. Offset for `.overlongEncoding` is the START BYTE of the
    offending sequence; for other reject kinds it is the byte that triggered
    the rejection. Truncated sequences report offset = bs.size. -/
def firstInvalidUtf8Offset (bs : ByteArray) : Option (Nat × Utf8RejectKind) :=
  firstInvalidUtf8OffsetGo bs .expectStart 0 0 (bs.size + 1)

def isValidUtf8 (bs : ByteArray) : Bool := (firstInvalidUtf8Offset bs).isNone

theorem firstInvalidUtf8Offset_none_iff (bs : ByteArray) :
    firstInvalidUtf8Offset bs = none ↔ isValidUtf8 bs = true := by
  unfold isValidUtf8
  cases h : firstInvalidUtf8Offset bs with
  | none => simp
  | some result => simp

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 CONCRETE VALIDATION THEOREMS
-- ═══════════════════════════════════════════════════════════════════════════════

theorem empty_is_valid : isValidUtf8 ByteArray.empty = true := by native_decide

theorem hello_is_valid : isValidUtf8 "hello".toUTF8 = true := by native_decide

theorem ascii_digits_valid : isValidUtf8 "0123456789".toUTF8 = true := by native_decide

theorem accented_is_valid : isValidUtf8 "héllo".toUTF8 = true := by native_decide

theorem cjk_is_valid : isValidUtf8 "日本".toUTF8 = true := by native_decide

theorem bare_continuation_rejected :
    firstInvalidUtf8Offset (ByteArray.mk #[0x80]) = some (0, .invalidStartByte) := by
  native_decide

theorem overlong_nul_rejected :
    firstInvalidUtf8Offset (ByteArray.mk #[0xC0, 0x80]) = some (0, .invalidStartByte) := by
  -- 0xC0 itself is pre-rejected as invalid start (it would be overlong 2-byte).
  native_decide

theorem overlong_3byte_rejected :
    firstInvalidUtf8Offset (ByteArray.mk #[0xE0, 0x80, 0x80]) = some (0, .overlongEncoding) := by
  -- 0xE0 0x80 0x80 decodes to U+0000, minCp for 3-byte is 0x800 → overlongEncoding.
  native_decide

theorem truncated_3byte_rejected :
    firstInvalidUtf8Offset (ByteArray.mk #[0xE2, 0x80]) = some (2, .truncatedSequence) := by
  native_decide

theorem surrogate_rejected :
    firstInvalidUtf8Offset (ByteArray.mk #[0xED, 0xA0, 0x80]) = some (2, .surrogateCodepoint) := by
  native_decide

theorem beyond_max_rejected :
    firstInvalidUtf8Offset (ByteArray.mk #[0xF4, 0x90, 0x80, 0x80])
      = some (3, .codepointBeyondMax) := by
  native_decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 CODEPOINT ITERATION (requires valid UTF-8 for meaningful results)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Fuel-based fold over codepoints with byte-offset tracking.

    On `.emit cp`, calls `f acc seqStart cp` where `seqStart` is the byte
    index at which the emitted codepoint's UTF-8 sequence began. On invalid
    input, folding stops at the first reject and returns the accumulator
    reached so far.

    Requires `isValidUtf8 bs = true` for semantically meaningful results;
    the function is total (returns `acc` on malformed input) but the
    emitted-codepoint sequence has no specified meaning in that case. -/
private def foldCodepointsWithOffsetGo {α : Type}
    (bs : ByteArray) (f : α → Nat → Nat → α)
    : Utf8State → Nat → Nat → α → Nat → α
  | _, _, _, acc, 0 => acc
  | st, i, seqStart, acc, fuel + 1 =>
    if hi : i < bs.size then
      let b := bs[i]'hi
      match utf8DecodeStep st b with
      | .continue next =>
          let newSeqStart := match st with
            | .expectStart => i
            | .expectCont _ _ _ => seqStart
          foldCodepointsWithOffsetGo bs f next (i + 1) newSeqStart acc fuel
      | .emit cp next =>
          foldCodepointsWithOffsetGo bs f next (i + 1) (i + 1) (f acc seqStart cp) fuel
      | .reject _ => acc
    else acc

def foldCodepointsWithOffset {α : Type} (bs : ByteArray) (init : α)
    (f : α → Nat → Nat → α) : α :=
  foldCodepointsWithOffsetGo bs f .expectStart 0 0 init (bs.size + 1)

/-- First codepoint (with byte-offset) satisfying the predicate, or `none`.
    Requires `isValidUtf8 bs = true` for semantically meaningful results. -/
def firstCodepointWhere (bs : ByteArray) (p : Nat → Bool) : Option (Nat × Nat) :=
  foldCodepointsWithOffset bs (Option.none : Option (Nat × Nat))
    (fun acc off cp =>
      match acc with
      | some r => some r
      | none   => if p cp then some (off, cp) else none)

theorem fold_empty_identity {α : Type} (init : α) (f : α → Nat → Nat → α) :
    foldCodepointsWithOffset ByteArray.empty init f = init := by
  unfold foldCodepointsWithOffset foldCodepointsWithOffsetGo
  simp

theorem no_bidi_in_hello :
    firstCodepointWhere "hello".toUTF8
        (fun cp => (0x202A ≤ cp && cp ≤ 0x202E) || (0x2066 ≤ cp && cp ≤ 0x2069)) = none := by
  native_decide

theorem find_bidi_override_in_input :
    -- "a" (0x61) + U+202E (0xE2 0x80 0xAE) + "b" (0x62)
    firstCodepointWhere (ByteArray.mk #[0x61, 0xE2, 0x80, 0xAE, 0x62])
        (fun cp => 0x202A ≤ cp && cp ≤ 0x202E) = some (1, 0x202E) := by
  native_decide

theorem find_bom_in_input :
    -- BOM is 0xEF 0xBB 0xBF
    firstCodepointWhere (ByteArray.mk #[0xEF, 0xBB, 0xBF, 0x61])
        (fun cp => cp == 0xFEFF) = some (0, 0xFEFF) := by
  native_decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 BYTES → STRING (with validity proof)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Decode a byte array to String given a proof that the input is valid UTF-8.

    Uses the codepoint fold rather than Lean's `String.fromUTF8!`. This
    keeps String production consistent with the validator semantics: if
    the validator accepts `bs`, this function produces the exact String that
    corresponds to the codepoints the decoder emits. The validity hypothesis
    `_h` is not used in the body because the fold falls back to the
    accumulator on reject (which cannot fire under valid input); the proof
    documents the intended precondition at the type level.

    Every codepoint the validator emits is in the Unicode scalar range
    (excluding surrogates, ≤ U+10FFFF), so `Char.ofNat cp` always produces
    a valid Char (no silent fallback). -/
def toStringFromValid (bs : ByteArray) (_h : isValidUtf8 bs = true) : String :=
  foldCodepointsWithOffset bs "" (fun acc _ cp => acc.push (Char.ofNat cp))

theorem hello_decodes_to_hello :
    toStringFromValid "hello".toUTF8 (by native_decide) = "hello" := by native_decide

theorem empty_decodes_to_empty :
    toStringFromValid ByteArray.empty (by native_decide) = "" := by native_decide

theorem accented_decodes :
    toStringFromValid "héllo".toUTF8 (by native_decide) = "héllo" := by native_decide

end Unicode.Codec.Utf8
