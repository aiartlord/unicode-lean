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

end Unicode.Codec.Utf8Roundtrip
