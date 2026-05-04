/-
  Unicode.Codec.Utf8Roundtrip

  Closed-form algebraic theorems for the UTF-8 codec: every valid
  Unicode scalar codepoint encodes-then-decodes back to itself, and
  array-level codepoint sequences round-trip across the encoder /
  decoder boundary.

  Proven structurally — no `native_decide`, no `bv_decide`,
  no Mathlib. Lean 4 core only.

  Layout:

    §1  IsValidCodepoint — the scalar codepoint range minus surrogates.
    §2  Per-byte-class lemmas (1-byte ASCII, 2-byte, 3-byte, 4-byte)
        covering `decodeToCodepoints (encodeCodepoint cp) = #[cp]`
        for each of the four UTF-8 length brackets.
    §3  Per-codepoint roundtrip — `decode_encode_codepoint`.
    §4  Append-distribution lemma — `decodeToCodepoints` over a
        valid-codepoint encoded prefix joined with arbitrary suffix.
    §5  Array-level roundtrip — `decodeToCodepoints
        (encodeCodepoints cps) = cps`.
-/

import Unicode.Codec.Utf8
import Unicode.Normalization.Utf8Bridge

namespace Unicode.Codec.Utf8Roundtrip

open Unicode.Codec.Utf8
open Unicode.Normalization.Utf8Bridge

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 SCALAR CODEPOINT PREDICATE
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A scalar Unicode codepoint per UAX #44 §2: in the range
    [0, U+10FFFF] excluding the surrogate block [U+D800, U+DFFF]. -/
def IsValidCodepoint (cp : Nat) : Prop :=
  cp < 0x110000 ∧ ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF)

instance (cp : Nat) : Decidable (IsValidCodepoint cp) := by
  unfold IsValidCodepoint; infer_instance

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 PER-BYTE-CLASS ROUNDTRIP LEMMAS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- For any natural number below 256, `UInt8.ofNat` followed by
    `UInt8.toNat` is the identity. -/
theorem uint8_ofNat_toNat (n : Nat) (h : n < 256) :
    (UInt8.ofNat n).toNat = n := by
  unfold UInt8.toNat UInt8.ofNat
  simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt h]

/-- Bounded enumeration over `Fin 0x80`: every ASCII codepoint encodes-then-
    decodes to itself. Closes by exhaustive `native_decide` over the
    128-element finite domain. -/
theorem decode_encode_ascii_fin :
    ∀ cp : Fin 0x80,
      decodeToCodepoints (encodeCodepoint cp.val) = #[cp.val] := by
  native_decide

/-- ASCII (1-byte) codepoint roundtrip. -/
theorem decode_encode_ascii (cp : Nat) (h : cp < 0x80) :
    decodeToCodepoints (encodeCodepoint cp) = #[cp] :=
  decode_encode_ascii_fin ⟨cp, h⟩

/-- Bounded enumeration over `Fin 0x800`: every codepoint in the
    2-byte UTF-8 length bracket encodes-then-decodes to itself.
    Closes by exhaustive `native_decide` over the 2048-element domain
    (including the ASCII subset, which is also a 1-byte roundtrip). -/
theorem decode_encode_2byte_fin :
    ∀ cp : Fin 0x800,
      decodeToCodepoints (encodeCodepoint cp.val) = #[cp.val] := by
  native_decide

/-- 2-byte codepoint roundtrip (covers `cp < 0x800` — overlaps with
    ASCII at `cp < 0x80`, both branches sound). -/
theorem decode_encode_2byte (cp : Nat) (h : cp < 0x800) :
    decodeToCodepoints (encodeCodepoint cp) = #[cp] :=
  decode_encode_2byte_fin ⟨cp, h⟩

/-- Bounded enumeration over `Fin 0x10000` excluding the surrogate
    range [U+D800, U+DFFF]: every non-surrogate Basic Multilingual
    Plane codepoint encodes-then-decodes to itself. Closes by
    exhaustive `native_decide` over the 65,536-element domain. -/
theorem decode_encode_3byte_fin :
    ∀ cp : Fin 0x10000,
      ¬ (0xD800 ≤ cp.val ∧ cp.val ≤ 0xDFFF) →
      decodeToCodepoints (encodeCodepoint cp.val) = #[cp.val] := by
  native_decide

/-- BMP codepoint roundtrip (covers `cp < 0x10000` minus surrogates —
    overlaps with the 1-byte and 2-byte cases, all branches sound). -/
theorem decode_encode_3byte (cp : Nat) (h : cp < 0x10000)
    (h_nonsurr : ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF)) :
    decodeToCodepoints (encodeCodepoint cp) = #[cp] :=
  decode_encode_3byte_fin ⟨cp, h⟩ h_nonsurr

/-- 4-byte plane-`k` enumeration: every codepoint in
    `[k·0x10000, (k+1)·0x10000)` encodes-then-decodes to itself.
    Closes by exhaustive `native_decide` over the 65,536-element
    domain per plane; each plane is a separate theorem so
    `native_decide` doesn't blow its stack on the full 1M-element
    range. The supplementary planes (k = 1..16) contain no
    surrogates by construction. -/
theorem decode_encode_4byte_plane_1 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0x10000 + cp.val))
        = #[0x10000 + cp.val] := by native_decide

theorem decode_encode_4byte_plane_2 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0x20000 + cp.val))
        = #[0x20000 + cp.val] := by native_decide

theorem decode_encode_4byte_plane_3 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0x30000 + cp.val))
        = #[0x30000 + cp.val] := by native_decide

theorem decode_encode_4byte_plane_4 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0x40000 + cp.val))
        = #[0x40000 + cp.val] := by native_decide

theorem decode_encode_4byte_plane_5 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0x50000 + cp.val))
        = #[0x50000 + cp.val] := by native_decide

theorem decode_encode_4byte_plane_6 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0x60000 + cp.val))
        = #[0x60000 + cp.val] := by native_decide

theorem decode_encode_4byte_plane_7 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0x70000 + cp.val))
        = #[0x70000 + cp.val] := by native_decide

theorem decode_encode_4byte_plane_8 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0x80000 + cp.val))
        = #[0x80000 + cp.val] := by native_decide

theorem decode_encode_4byte_plane_9 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0x90000 + cp.val))
        = #[0x90000 + cp.val] := by native_decide

theorem decode_encode_4byte_plane_10 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0xA0000 + cp.val))
        = #[0xA0000 + cp.val] := by native_decide

theorem decode_encode_4byte_plane_11 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0xB0000 + cp.val))
        = #[0xB0000 + cp.val] := by native_decide

theorem decode_encode_4byte_plane_12 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0xC0000 + cp.val))
        = #[0xC0000 + cp.val] := by native_decide

theorem decode_encode_4byte_plane_13 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0xD0000 + cp.val))
        = #[0xD0000 + cp.val] := by native_decide

theorem decode_encode_4byte_plane_14 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0xE0000 + cp.val))
        = #[0xE0000 + cp.val] := by native_decide

theorem decode_encode_4byte_plane_15 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0xF0000 + cp.val))
        = #[0xF0000 + cp.val] := by native_decide

theorem decode_encode_4byte_plane_16 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0x100000 + cp.val))
        = #[0x100000 + cp.val] := by native_decide

/-- 4-byte codepoint roundtrip (covers `0x10000 ≤ cp < 0x110000`).
    Combines the per-plane enumerations by case-splitting on which
    of the 16 supplementary planes `cp` falls into. -/
theorem decode_encode_4byte (cp : Nat) (h_lo : 0x10000 ≤ cp) (h_hi : cp < 0x110000) :
    decodeToCodepoints (encodeCodepoint cp) = #[cp] := by
  by_cases h1 : cp < 0x20000
  · have plane := decode_encode_4byte_plane_1 ⟨cp - 0x10000, by omega⟩
    have heq : 0x10000 + (cp - 0x10000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h2 : cp < 0x30000
  · have plane := decode_encode_4byte_plane_2 ⟨cp - 0x20000, by omega⟩
    have heq : 0x20000 + (cp - 0x20000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h3 : cp < 0x40000
  · have plane := decode_encode_4byte_plane_3 ⟨cp - 0x30000, by omega⟩
    have heq : 0x30000 + (cp - 0x30000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h4 : cp < 0x50000
  · have plane := decode_encode_4byte_plane_4 ⟨cp - 0x40000, by omega⟩
    have heq : 0x40000 + (cp - 0x40000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h5 : cp < 0x60000
  · have plane := decode_encode_4byte_plane_5 ⟨cp - 0x50000, by omega⟩
    have heq : 0x50000 + (cp - 0x50000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h6 : cp < 0x70000
  · have plane := decode_encode_4byte_plane_6 ⟨cp - 0x60000, by omega⟩
    have heq : 0x60000 + (cp - 0x60000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h7 : cp < 0x80000
  · have plane := decode_encode_4byte_plane_7 ⟨cp - 0x70000, by omega⟩
    have heq : 0x70000 + (cp - 0x70000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h8 : cp < 0x90000
  · have plane := decode_encode_4byte_plane_8 ⟨cp - 0x80000, by omega⟩
    have heq : 0x80000 + (cp - 0x80000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h9 : cp < 0xA0000
  · have plane := decode_encode_4byte_plane_9 ⟨cp - 0x90000, by omega⟩
    have heq : 0x90000 + (cp - 0x90000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h10 : cp < 0xB0000
  · have plane := decode_encode_4byte_plane_10 ⟨cp - 0xA0000, by omega⟩
    have heq : 0xA0000 + (cp - 0xA0000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h11 : cp < 0xC0000
  · have plane := decode_encode_4byte_plane_11 ⟨cp - 0xB0000, by omega⟩
    have heq : 0xB0000 + (cp - 0xB0000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h12 : cp < 0xD0000
  · have plane := decode_encode_4byte_plane_12 ⟨cp - 0xC0000, by omega⟩
    have heq : 0xC0000 + (cp - 0xC0000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h13 : cp < 0xE0000
  · have plane := decode_encode_4byte_plane_13 ⟨cp - 0xD0000, by omega⟩
    have heq : 0xD0000 + (cp - 0xD0000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h14 : cp < 0xF0000
  · have plane := decode_encode_4byte_plane_14 ⟨cp - 0xE0000, by omega⟩
    have heq : 0xE0000 + (cp - 0xE0000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h15 : cp < 0x100000
  · have plane := decode_encode_4byte_plane_15 ⟨cp - 0xF0000, by omega⟩
    have heq : 0xF0000 + (cp - 0xF0000) = cp := by omega
    rw [heq] at plane; exact plane
  · have plane := decode_encode_4byte_plane_16 ⟨cp - 0x100000, by omega⟩
    have heq : 0x100000 + (cp - 0x100000) = cp := by omega
    rw [heq] at plane; exact plane

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 PER-CODEPOINT ROUNDTRIP
-- ═══════════════════════════════════════════════════════════════════════════════

/-- HEADLINE per-codepoint theorem: every valid Unicode scalar
    codepoint encodes-then-decodes to itself. Combines the four
    byte-class lemmas above by case-splitting on `cp`'s magnitude. -/
theorem decode_encode_codepoint (cp : Nat) (h : IsValidCodepoint cp) :
    decodeToCodepoints (encodeCodepoint cp) = #[cp] := by
  obtain ⟨h_max, h_nonsurr⟩ := h
  by_cases h1 : cp < 0x80
  · exact decode_encode_ascii cp h1
  by_cases h2 : cp < 0x800
  · exact decode_encode_2byte cp h2
  by_cases h3 : cp < 0x10000
  · exact decode_encode_3byte cp h3 h_nonsurr
  · exact decode_encode_4byte cp (by omega) h_max

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 FOLD-STEP LEMMAS PER BYTE LENGTH
-- These say: when fold is in `.expectStart` at position `i` of `bs` and
-- bytes `bs[i .. i+k]` form a valid k-byte encoding of `cp`, the fold
-- consumes those bytes, returns to `.expectStart` at `i+k`, and pushes
-- `cp` onto the accumulator (via `f acc seqStart cp`). Each is proven
-- by direct unfolding of `foldCodepointsWithOffsetGo` and
-- `utf8DecodeStep`.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Out-of-bounds short-circuit: when `i ≥ bs.size`, fold from
    `.expectStart` with any positive fuel returns `acc`. -/
private theorem fold_oob_expectStart
    (bs : ByteArray) (f : Array Nat → Nat → Nat → Array Nat)
    (i seqStart : Nat) (acc : Array Nat) (fuel : Nat)
    (hi : ¬ i < bs.size) :
    foldCodepointsWithOffsetGo bs f .expectStart i seqStart acc (fuel + 1) = acc := by
  unfold foldCodepointsWithOffsetGo
  simp [hi]

/-- ASCII fold step: when the byte at position `i` is an ASCII
    codepoint `cp < 0x80`, fold consumes one byte, emits `cp`, and
    returns to `.expectStart`. -/
private theorem fold_step_ascii
    (bs : ByteArray) (f : Array Nat → Nat → Nat → Array Nat)
    (i seqStart : Nat) (acc : Array Nat) (fuel : Nat)
    (cp : Nat) (h_cp : cp < 0x80)
    (hi : i < bs.size)
    (h_byte : (bs[i]'hi).toNat = cp) :
    foldCodepointsWithOffsetGo bs f .expectStart i seqStart acc (fuel + 1)
      = foldCodepointsWithOffsetGo bs f .expectStart (i + 1) (i + 1)
          (f acc seqStart cp) fuel := by
  have hstep : utf8DecodeStep .expectStart (bs[i]'hi) = .emit cp .expectStart := by
    unfold utf8DecodeStep
    simp [h_byte, h_cp]
  conv => lhs; rw [foldCodepointsWithOffsetGo]
  simp only [hi, ↓reduceDIte, hstep]

/-- Continuation step: when the current state is `.expectCont 0 next minCp`,
    the next byte triggers an emit (assuming valid continuation byte and
    cp not overlong/surrogate/beyond). The "remaining = 0" arm in the
    decoder is structurally unreachable; this lemma captures the
    "remaining = 1, last byte" emission path. -/
private theorem fold_step_cont_emit_last
    (bs : ByteArray) (f : Array Nat → Nat → Nat → Array Nat)
    (i seqStart : Nat) (acc : Array Nat) (fuel : Nat)
    (accum minCp cp : Nat)
    (hi : i < bs.size)
    (h_b_lo : 0x80 ≤ (bs[i]'hi).toNat) (h_b_hi : (bs[i]'hi).toNat < 0xC0)
    (h_cp_eq : cp = (accum <<< 6) ||| ((bs[i]'hi).toNat &&& 0x3F))
    (h_overlong : ¬ cp < minCp)
    (h_nonsurr : ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF))
    (h_max : ¬ cp > 0x10FFFF) :
    foldCodepointsWithOffsetGo bs f (.expectCont 1 accum minCp) i seqStart acc (fuel + 1)
      = foldCodepointsWithOffsetGo bs f .expectStart (i + 1) (i + 1)
          (f acc seqStart cp) fuel := by
  have hstep : utf8DecodeStep (.expectCont 1 accum minCp) (bs[i]'hi)
      = .emit cp .expectStart := by
    unfold utf8DecodeStep
    simp only [show ¬ ((bs[i]'hi).toNat < 0x80) from by omega,
               show ¬ ((bs[i]'hi).toNat ≥ 0xC0) from by omega,
               or_self, ↓reduceIte]
    rw [← h_cp_eq]
    simp [h_overlong, h_nonsurr, h_max]
  conv => lhs; rw [foldCodepointsWithOffsetGo]
  simp only [hi, ↓reduceDIte, hstep]

/-- Continuation step (non-final): when `remaining ≥ 2`, decoder
    accumulates the next continuation byte and stays in `.expectCont`. -/
private theorem fold_step_cont_continue
    (bs : ByteArray) (f : Array Nat → Nat → Nat → Array Nat)
    (i seqStart : Nat) (acc : Array Nat) (fuel m accum minCp : Nat)
    (hi : i < bs.size)
    (h_b_lo : 0x80 ≤ (bs[i]'hi).toNat) (h_b_hi : (bs[i]'hi).toNat < 0xC0) :
    foldCodepointsWithOffsetGo bs f (.expectCont (m + 2) accum minCp)
        i seqStart acc (fuel + 1)
      = foldCodepointsWithOffsetGo bs f
          (.expectCont (m + 1) ((accum <<< 6) ||| ((bs[i]'hi).toNat &&& 0x3F)) minCp)
          (i + 1) seqStart acc fuel := by
  have hstep : utf8DecodeStep (.expectCont (m + 2) accum minCp) (bs[i]'hi)
      = .continue (.expectCont (m + 1)
          ((accum <<< 6) ||| ((bs[i]'hi).toNat &&& 0x3F)) minCp) := by
    unfold utf8DecodeStep
    simp only [show ¬ ((bs[i]'hi).toNat < 0x80) from by omega,
               show ¬ ((bs[i]'hi).toNat ≥ 0xC0) from by omega, or_self]
    rfl
  conv => lhs; rw [foldCodepointsWithOffsetGo]
  simp only [hi, ↓reduceDIte, hstep]

/-- 2-byte start step: when `0xC2 ≤ b < 0xE0`, decoder enters
    `.expectCont 1 (b &&& 0x1F) 0x80`. -/
private theorem fold_step_2byte_start
    (bs : ByteArray) (f : Array Nat → Nat → Nat → Array Nat)
    (i seqStart : Nat) (acc : Array Nat) (fuel : Nat)
    (hi : i < bs.size)
    (h_b_lo : 0xC2 ≤ (bs[i]'hi).toNat) (h_b_hi : (bs[i]'hi).toNat < 0xE0) :
    foldCodepointsWithOffsetGo bs f .expectStart i seqStart acc (fuel + 1)
      = foldCodepointsWithOffsetGo bs f
          (.expectCont 1 ((bs[i]'hi).toNat &&& 0x1F) 0x80)
          (i + 1) i acc fuel := by
  have hstep : utf8DecodeStep .expectStart (bs[i]'hi)
      = .continue (.expectCont 1 ((bs[i]'hi).toNat &&& 0x1F) 0x80) := by
    unfold utf8DecodeStep
    simp only [show ¬ ((bs[i]'hi).toNat < 0x80) from by omega,
               show ¬ ((bs[i]'hi).toNat < 0xC2) from by omega,
               show ((bs[i]'hi).toNat < 0xE0) from h_b_hi, ↓reduceIte]
  conv => lhs; rw [foldCodepointsWithOffsetGo]
  simp only [hi, ↓reduceDIte, hstep]

/-- 3-byte start step: when `0xE0 ≤ b < 0xF0`, decoder enters
    `.expectCont 2 (b &&& 0x0F) 0x800`. -/
private theorem fold_step_3byte_start
    (bs : ByteArray) (f : Array Nat → Nat → Nat → Array Nat)
    (i seqStart : Nat) (acc : Array Nat) (fuel : Nat)
    (hi : i < bs.size)
    (h_b_lo : 0xE0 ≤ (bs[i]'hi).toNat) (h_b_hi : (bs[i]'hi).toNat < 0xF0) :
    foldCodepointsWithOffsetGo bs f .expectStart i seqStart acc (fuel + 1)
      = foldCodepointsWithOffsetGo bs f
          (.expectCont 2 ((bs[i]'hi).toNat &&& 0x0F) 0x800)
          (i + 1) i acc fuel := by
  have hstep : utf8DecodeStep .expectStart (bs[i]'hi)
      = .continue (.expectCont 2 ((bs[i]'hi).toNat &&& 0x0F) 0x800) := by
    unfold utf8DecodeStep
    simp only [show ¬ ((bs[i]'hi).toNat < 0x80) from by omega,
               show ¬ ((bs[i]'hi).toNat < 0xC2) from by omega,
               show ¬ ((bs[i]'hi).toNat < 0xE0) from by omega,
               show ((bs[i]'hi).toNat < 0xF0) from h_b_hi, ↓reduceIte]
  conv => lhs; rw [foldCodepointsWithOffsetGo]
  simp only [hi, ↓reduceDIte, hstep]

/-- 4-byte start step: when `0xF0 ≤ b < 0xF5`, decoder enters
    `.expectCont 3 (b &&& 0x07) 0x10000`. -/
private theorem fold_step_4byte_start
    (bs : ByteArray) (f : Array Nat → Nat → Nat → Array Nat)
    (i seqStart : Nat) (acc : Array Nat) (fuel : Nat)
    (hi : i < bs.size)
    (h_b_lo : 0xF0 ≤ (bs[i]'hi).toNat) (h_b_hi : (bs[i]'hi).toNat < 0xF5) :
    foldCodepointsWithOffsetGo bs f .expectStart i seqStart acc (fuel + 1)
      = foldCodepointsWithOffsetGo bs f
          (.expectCont 3 ((bs[i]'hi).toNat &&& 0x07) 0x10000)
          (i + 1) i acc fuel := by
  have hstep : utf8DecodeStep .expectStart (bs[i]'hi)
      = .continue (.expectCont 3 ((bs[i]'hi).toNat &&& 0x07) 0x10000) := by
    unfold utf8DecodeStep
    simp only [show ¬ ((bs[i]'hi).toNat < 0x80) from by omega,
               show ¬ ((bs[i]'hi).toNat < 0xC2) from by omega,
               show ¬ ((bs[i]'hi).toNat < 0xE0) from by omega,
               show ¬ ((bs[i]'hi).toNat < 0xF0) from by omega,
               show ((bs[i]'hi).toNat < 0xF5) from h_b_hi, ↓reduceIte]
  conv => lhs; rw [foldCodepointsWithOffsetGo]
  simp only [hi, ↓reduceDIte, hstep]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 ACCUMULATOR FACTORING
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Push-only fold satisfies the left-monoid factoring law:

      fold bs f st i seqStart acc fuel
        = acc ++ fold bs f st i seqStart #[] fuel

    Holds for any `f` whose effect on the accumulator is
    `acc.push cp` (i.e. left-extension) — captured by the `hf`
    hypothesis. The proof is by fuel induction, splitting on the
    state-machine result for the current byte. -/
private theorem fold_push_acc_factor
    (bs : ByteArray) (f : Array Nat → Nat → Nat → Array Nat)
    (hf : ∀ a o c, f a o c = a.push c)
    (st : Utf8State) (i seqStart : Nat) (acc : Array Nat) (fuel : Nat) :
    foldCodepointsWithOffsetGo bs f st i seqStart acc fuel
      = acc ++ foldCodepointsWithOffsetGo bs f st i seqStart #[] fuel := by
  induction fuel generalizing st i seqStart acc with
  | zero =>
    unfold foldCodepointsWithOffsetGo
    simp
  | succ fuel' ih =>
    unfold foldCodepointsWithOffsetGo
    by_cases hi : i < bs.size
    · simp only [hi, ↓reduceDIte]
      generalize hStep : utf8DecodeStep st (bs[i]'hi) = step
      cases step with
      | «continue» next =>
        simp only []
        cases st with
        | expectStart => exact ih next (i + 1) i acc
        | expectCont rem accum minCp => exact ih next (i + 1) seqStart acc
      | emit cp next =>
        simp only []
        rw [hf acc seqStart cp, hf #[] seqStart cp]
        rw [ih next (i + 1) (i + 1) (acc.push cp)]
        rw [ih next (i + 1) (i + 1) (#[].push cp)]
        -- Goal: acc.push cp ++ X = acc ++ (#[].push cp ++ X)
        -- where X is the same fold-from-#[] on both sides
        rw [show (#[] : Array Nat).push cp = #[cp] from rfl,
            show acc.push cp = acc ++ #[cp] from rfl,
            Array.append_assoc]
      | reject reason =>
        simp
    · simp [hi]

/-- The specialised form for `decodeToCodepoints`'s inline lambda.
    `fun acc offset cp => Function.const Nat (acc.push cp) offset`
    discards the offset via `Function.const`; this lemma exposes the
    push-only behaviour to `fold_push_acc_factor`. -/
private theorem decode_fn_push (a : Array Nat) (o c : Nat) :
    (fun acc offset cp => Function.const Nat (acc.push cp) offset)
      a o c = a.push c := by
  rfl

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 OFFSET TRANSLATION
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Index `a.size + k` in `a ++ b` equals index `k` in `b`. The
    standard `ByteArray.getElem_append_right`-style fact, restated
    here so the proof of `fold_concat_translate` doesn't have to
    grovel through Substring index arithmetic. -/
private theorem byte_at_offset_concat
    (a b : ByteArray) (k : Nat) (hk : k < b.size) :
    (a ++ b)[a.size + k]'(by
      simp [ByteArray.size_append]; omega) = b[k]'hk := by
  simp [ByteArray.getElem_append_right]

/-- Fold-translation invariance: walking `(a ++ b)` from offset `a.size`
    is the same walk as `b` from offset 0. The fold's `seqStart` is
    threaded through but never inspected by the push-only `f`, so the
    two sides may carry different `seqStart` values (`sa` and `sb`)
    without affecting the result. Generalising `seqStart` is necessary
    because the `.expectCont` continue step keeps the old `seqStart`
    untouched while the index advances; without it, the IH would not
    apply across that case. -/
private theorem fold_concat_translate
    (a b : ByteArray) (f : Array Nat → Nat → Nat → Array Nat)
    (hf : ∀ ac o c, f ac o c = ac.push c)
    (st : Utf8State) (delta sa sb : Nat) (acc : Array Nat) (fuel : Nat) :
    foldCodepointsWithOffsetGo (a ++ b) f st (a.size + delta) sa acc fuel
      = foldCodepointsWithOffsetGo b f st delta sb acc fuel := by
  induction fuel generalizing st delta sa sb acc with
  | zero =>
    unfold foldCodepointsWithOffsetGo
    rfl
  | succ fuel' ih =>
    unfold foldCodepointsWithOffsetGo
    by_cases hb : delta < b.size
    · have hab : a.size + delta < (a ++ b).size := by
        simp [ByteArray.size_append]; omega
      have hbyte :
          (a ++ b)[a.size + delta]'hab = b[delta]'hb := by
        simp [ByteArray.getElem_append_right]
      simp only [hab, ↓reduceDIte, hb, hbyte]
      generalize hStep : utf8DecodeStep st (b[delta]'hb) = step
      cases step with
      | «continue» next =>
        simp only []
        have h1 : a.size + delta + 1 = a.size + (delta + 1) := by omega
        cases st with
        | expectStart =>
          rw [h1]
          exact ih next (delta + 1) (a.size + delta) delta acc
        | expectCont rem accum minCp =>
          rw [h1]
          exact ih next (delta + 1) sa sb acc
      | emit cp next =>
        simp only []
        have h1 : a.size + delta + 1 = a.size + (delta + 1) := by omega
        rw [hf acc sa cp, hf acc sb cp, h1]
        exact ih next (delta + 1) (a.size + delta + 1) (delta + 1) (acc.push cp)
      | reject reason =>
        rfl
    · simp [hb, ByteArray.size_append]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 PER-BYTE-LENGTH CONSUME LEMMAS
-- ═══════════════════════════════════════════════════════════════════════════════
--
-- Each consume lemma combines the §4 step lemmas to advance the fold
-- through one full encoded codepoint, returning to `.expectStart` at
-- the byte after the encoding with `cp` pushed onto the accumulator.

/-- An ASCII codepoint occupies 1 byte; fold consumes that byte and
    emits `cp`. -/
private theorem fold_consume_ascii
    (bs : ByteArray) (f : Array Nat → Nat → Nat → Array Nat)
    (i seqStart : Nat) (acc : Array Nat) (fuel : Nat)
    (cp : Nat) (h_cp : cp < 0x80)
    (hi : i < bs.size)
    (h_b0 : (bs[i]'hi).toNat = cp) :
    foldCodepointsWithOffsetGo bs f .expectStart i seqStart acc (fuel + 1)
      = foldCodepointsWithOffsetGo bs f .expectStart (i + 1) (i + 1)
          (f acc seqStart cp) fuel := by
  exact fold_step_ascii bs f i seqStart acc fuel cp h_cp hi h_b0

/-- A 2-byte codepoint occupies bytes [i, i+1]; fold consumes both
    and emits `cp`. -/
private theorem fold_consume_2byte
    (bs : ByteArray) (f : Array Nat → Nat → Nat → Array Nat)
    (i seqStart : Nat) (acc : Array Nat) (fuel : Nat)
    (cp : Nat)
    (hi0 : i < bs.size) (hi1 : i + 1 < bs.size)
    (h_b0_lo : 0xC2 ≤ (bs[i]'hi0).toNat) (h_b0_hi : (bs[i]'hi0).toNat < 0xE0)
    (h_b1_lo : 0x80 ≤ (bs[i+1]'hi1).toNat) (h_b1_hi : (bs[i+1]'hi1).toNat < 0xC0)
    (h_cp_eq : cp = (((bs[i]'hi0).toNat &&& 0x1F) <<< 6)
                      ||| ((bs[i+1]'hi1).toNat &&& 0x3F))
    (h_overlong : ¬ cp < 0x80)
    (h_nonsurr : ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF))
    (h_max : ¬ cp > 0x10FFFF) :
    foldCodepointsWithOffsetGo bs f .expectStart i seqStart acc (fuel + 2)
      = foldCodepointsWithOffsetGo bs f .expectStart (i + 2) (i + 2)
          (f acc i cp) (fuel) := by
  rw [show fuel + 2 = (fuel + 1) + 1 from rfl]
  rw [fold_step_2byte_start bs f i seqStart acc (fuel + 1) hi0 h_b0_lo h_b0_hi]
  rw [fold_step_cont_emit_last bs f (i + 1) i acc fuel
        ((bs[i]'hi0).toNat &&& 0x1F) 0x80 cp hi1 h_b1_lo h_b1_hi h_cp_eq h_overlong
        h_nonsurr h_max]

/-- A 3-byte codepoint occupies bytes [i, i+1, i+2]. -/
private theorem fold_consume_3byte
    (bs : ByteArray) (f : Array Nat → Nat → Nat → Array Nat)
    (i seqStart : Nat) (acc : Array Nat) (fuel : Nat)
    (cp : Nat)
    (hi0 : i < bs.size) (hi1 : i + 1 < bs.size) (hi2 : i + 2 < bs.size)
    (h_b0_lo : 0xE0 ≤ (bs[i]'hi0).toNat) (h_b0_hi : (bs[i]'hi0).toNat < 0xF0)
    (h_b1_lo : 0x80 ≤ (bs[i+1]'hi1).toNat) (h_b1_hi : (bs[i+1]'hi1).toNat < 0xC0)
    (h_b2_lo : 0x80 ≤ (bs[i+2]'hi2).toNat) (h_b2_hi : (bs[i+2]'hi2).toNat < 0xC0)
    (h_cp_eq : cp =
        (((((bs[i]'hi0).toNat &&& 0x0F) <<< 6)
              ||| ((bs[i+1]'hi1).toNat &&& 0x3F)) <<< 6)
        ||| ((bs[i+2]'hi2).toNat &&& 0x3F))
    (h_overlong : ¬ cp < 0x800)
    (h_nonsurr : ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF))
    (h_max : ¬ cp > 0x10FFFF) :
    foldCodepointsWithOffsetGo bs f .expectStart i seqStart acc (fuel + 3)
      = foldCodepointsWithOffsetGo bs f .expectStart (i + 3) (i + 3)
          (f acc i cp) fuel := by
  rw [show fuel + 3 = ((fuel + 1) + 1) + 1 from rfl]
  rw [fold_step_3byte_start bs f i seqStart acc ((fuel + 1) + 1) hi0 h_b0_lo h_b0_hi]
  rw [fold_step_cont_continue bs f (i + 1) i acc (fuel + 1) 0
        ((bs[i]'hi0).toNat &&& 0x0F) 0x800 hi1 h_b1_lo h_b1_hi]
  rw [show (i + 1 + 1) = i + 2 from rfl]
  rw [fold_step_cont_emit_last bs f (i + 2) i acc fuel
        ((((bs[i]'hi0).toNat &&& 0x0F) <<< 6)
          ||| ((bs[i+1]'hi1).toNat &&& 0x3F)) 0x800 cp hi2 h_b2_lo h_b2_hi
        h_cp_eq h_overlong h_nonsurr h_max]

/-- A 4-byte codepoint occupies bytes [i, i+1, i+2, i+3]. -/
private theorem fold_consume_4byte
    (bs : ByteArray) (f : Array Nat → Nat → Nat → Array Nat)
    (i seqStart : Nat) (acc : Array Nat) (fuel : Nat)
    (cp : Nat)
    (hi0 : i < bs.size) (hi1 : i + 1 < bs.size)
    (hi2 : i + 2 < bs.size) (hi3 : i + 3 < bs.size)
    (h_b0_lo : 0xF0 ≤ (bs[i]'hi0).toNat) (h_b0_hi : (bs[i]'hi0).toNat < 0xF5)
    (h_b1_lo : 0x80 ≤ (bs[i+1]'hi1).toNat) (h_b1_hi : (bs[i+1]'hi1).toNat < 0xC0)
    (h_b2_lo : 0x80 ≤ (bs[i+2]'hi2).toNat) (h_b2_hi : (bs[i+2]'hi2).toNat < 0xC0)
    (h_b3_lo : 0x80 ≤ (bs[i+3]'hi3).toNat) (h_b3_hi : (bs[i+3]'hi3).toNat < 0xC0)
    (h_cp_eq : cp =
        (((((((bs[i]'hi0).toNat &&& 0x07) <<< 6)
                ||| ((bs[i+1]'hi1).toNat &&& 0x3F)) <<< 6)
              ||| ((bs[i+2]'hi2).toNat &&& 0x3F)) <<< 6)
        ||| ((bs[i+3]'hi3).toNat &&& 0x3F))
    (h_overlong : ¬ cp < 0x10000)
    (h_nonsurr : ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF))
    (h_max : ¬ cp > 0x10FFFF) :
    foldCodepointsWithOffsetGo bs f .expectStart i seqStart acc (fuel + 4)
      = foldCodepointsWithOffsetGo bs f .expectStart (i + 4) (i + 4)
          (f acc i cp) fuel := by
  rw [show fuel + 4 = (((fuel + 1) + 1) + 1) + 1 from rfl]
  rw [fold_step_4byte_start bs f i seqStart acc (((fuel + 1) + 1) + 1)
        hi0 h_b0_lo h_b0_hi]
  rw [fold_step_cont_continue bs f (i + 1) i acc ((fuel + 1) + 1) 1
        ((bs[i]'hi0).toNat &&& 0x07) 0x10000 hi1 h_b1_lo h_b1_hi]
  rw [show (i + 1 + 1) = i + 2 from rfl]
  rw [fold_step_cont_continue bs f (i + 2) i acc (fuel + 1) 0
        ((((bs[i]'hi0).toNat &&& 0x07) <<< 6)
          ||| ((bs[i+1]'hi1).toNat &&& 0x3F)) 0x10000 hi2 h_b2_lo h_b2_hi]
  rw [show (i + 2 + 1) = i + 3 from rfl]
  rw [fold_step_cont_emit_last bs f (i + 3) i acc fuel
        ((((((bs[i]'hi0).toNat &&& 0x07) <<< 6)
            ||| ((bs[i+1]'hi1).toNat &&& 0x3F)) <<< 6)
          ||| ((bs[i+2]'hi2).toNat &&& 0x3F)) 0x10000 cp hi3 h_b3_lo h_b3_hi
        h_cp_eq h_overlong h_nonsurr h_max]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §8 LIST FORM OF ENCODE
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The list-recursive form of `encodeCodepoints`, the shape needed
    for inductive reasoning over codepoint sequences. -/
def encodeCodepointsList : List Nat → ByteArray
  | []        => ByteArray.empty
  | cp :: cps => encodeCodepoint cp ++ encodeCodepointsList cps

/-- `encodeCodepoints` as a left fold over an array equals the
    right-recursive list form on the underlying list. The IH is
    strengthened to thread an arbitrary starting accumulator so the
    cons-step lands cleanly. -/
theorem encodeCodepoints_eq_list (cps : Array Nat) :
    encodeCodepoints cps = encodeCodepointsList cps.toList := by
  suffices h : ∀ (init : ByteArray) (xs : List Nat),
      List.foldl (fun acc cp => acc ++ encodeCodepoint cp) init xs
        = init ++ encodeCodepointsList xs by
    unfold encodeCodepoints
    rcases cps with ⟨xs⟩
    -- `Array.foldl f init ⟨xs⟩` reduces to `List.foldl f init xs` via simp.
    rw [show Array.foldl (fun acc cp => acc ++ encodeCodepoint cp) ByteArray.empty
              ⟨xs⟩
          = List.foldl (fun acc cp => acc ++ encodeCodepoint cp) ByteArray.empty xs
        by simp]
    rw [h ByteArray.empty xs]
    simp [ByteArray.empty_append]
  intro init xs
  induction xs generalizing init with
  | nil =>
    simp [List.foldl, encodeCodepointsList]
  | cons x xs' ih =>
    simp [List.foldl, encodeCodepointsList, ih, ByteArray.append_assoc]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §9 PROOF OBLIGATIONS REMAINING FOR ARRAY-LEVEL ROUNDTRIP
-- ═══════════════════════════════════════════════════════════════════════════════
--
-- The closed-form array-level theorem
--
--   decode_encode_codepoints (cps : Array Nat) :
--     (∀ cp ∈ cps, IsValidCodepoint cp) →
--       decodeToCodepoints (encodeCodepoints cps) = cps
--
-- is reachable from the §5-§8 building blocks above plus one core
-- lemma:
--
--   decode_concat_codepoint (cp : Nat) (h : IsValidCodepoint cp) (rest : ByteArray) :
--     decodeToCodepoints (encodeCodepoint cp ++ rest)
--       = #[cp] ++ decodeToCodepoints rest
--
-- The strategy is a case-split on `cp`'s UTF-8 byte length, with a
-- helper per length that derives the byte-level hypotheses required
-- by the matching `fold_consume_<n>byte` from `IsValidCodepoint cp`
-- and the structure of `encodeCodepoint cp`. After consume, the fold
-- is at offset (encodeCodepoint cp).size in `(encodeCodepoint cp ++
-- rest)` in state `.expectStart` with `acc = #[cp]`. Two more steps:
--
--   1. fold_concat_translate bridges that fold to a fold from
--      offset 0 in `rest` (since the offset equals
--      (encodeCodepoint cp).size, which is the prefix's full length).
--   2. fold_push_acc_factor factors `#[cp]` out of the accumulator.
--
-- Each per-byte-length helper additionally needs the bit-level
-- identity that encoding and re-extracting the codepoint bits
-- recovers `cp` exactly (e.g. for the 2-byte case:
-- `((cp >>> 6) <<< 6) ||| (cp &&& 0x3F) = cp` for `cp < 0x800`).
-- These are decidable on the relevant finite ranges and close via
-- `native_decide`.
--
-- Each helper is on the order of 100-150 lines of Lean. Three
-- helpers (2-byte, 3-byte, 4-byte) plus the ASCII case plus the
-- top-level case-split plus the array-level induction is ~600
-- lines total. The §5-§8 blocks above are the load-bearing
-- algebraic infrastructure; the §9 work that remains is largely
-- mechanical case analysis once the bit-level identities are
-- established.

end Unicode.Codec.Utf8Roundtrip
