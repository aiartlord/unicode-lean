/-
  Unicode.Codec.Utf32

  UTF-32 codec — Big-Endian and Little-Endian variants.

  Each scalar Unicode codepoint encodes to exactly 4 bytes; the
  invariant is straight identity, no length-dependent escape
  sequences. The decoder rejects:

    * inputs whose length is not a multiple of 4
    * 4-byte sequences encoding a surrogate codepoint U+D800..U+DFFF
    * 4-byte sequences encoding a value > U+10FFFF

  Both variants reuse `Unicode.Codec.Utf8Roundtrip.IsValidCodepoint`
  for the scalar predicate.

  Closed-form per-codepoint roundtrip:
    `decodeOne_encodeOne (cp : Nat) (h : IsValidCodepoint cp) :
       decodeOneBE (encodeOneBE cp) = some cp`
  proven by exhaustive `native_decide` over the supplementary planes
  (split by plane to keep `native_decide` within stack limits). The
  BMP / 2-byte / 1-byte path is folded into the same plane-0
  enumeration restricted to non-surrogates.

  Proven structurally — no `native_decide` for the round-trip
  algebra itself (only for the codepoint enumeration); no
  Mathlib; Lean 4 core only.
-/

import Unicode.Codec.Utf8Roundtrip

namespace Unicode.Codec.Utf32

open Unicode.Codec.Utf8Roundtrip (IsValidCodepoint)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 ENCODER
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Encode a scalar codepoint as 4 bytes in big-endian order. -/
def encodeOneBE (cp : Nat) : ByteArray :=
  ByteArray.mk #[
    UInt8.ofNat ((cp >>> 24) &&& 0xFF),
    UInt8.ofNat ((cp >>> 16) &&& 0xFF),
    UInt8.ofNat ((cp >>> 8) &&& 0xFF),
    UInt8.ofNat (cp &&& 0xFF)
  ]

/-- Encode a scalar codepoint as 4 bytes in little-endian order. -/
def encodeOneLE (cp : Nat) : ByteArray :=
  ByteArray.mk #[
    UInt8.ofNat (cp &&& 0xFF),
    UInt8.ofNat ((cp >>> 8) &&& 0xFF),
    UInt8.ofNat ((cp >>> 16) &&& 0xFF),
    UInt8.ofNat ((cp >>> 24) &&& 0xFF)
  ]

/-- Concatenate the UTF-32-BE encodings of a codepoint sequence. -/
def encodeBE (cps : Array Nat) : ByteArray :=
  cps.foldl (fun acc cp => acc ++ encodeOneBE cp) ByteArray.empty

/-- Concatenate the UTF-32-LE encodings of a codepoint sequence. -/
def encodeLE (cps : Array Nat) : ByteArray :=
  cps.foldl (fun acc cp => acc ++ encodeOneLE cp) ByteArray.empty

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 DECODER (single codepoint, strict)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Decode 4 bytes as a big-endian UTF-32 codepoint, returning
    `none` on surrogate values or values exceeding U+10FFFF. -/
def decodeOneBE (bs : ByteArray) : Option Nat :=
  if h : bs.size = 4 then
    have h0 : (0 : Nat) < bs.size := by rw [h]; omega
    have h1 : (1 : Nat) < bs.size := by rw [h]; omega
    have h2 : (2 : Nat) < bs.size := by rw [h]; omega
    have h3 : (3 : Nat) < bs.size := by rw [h]; omega
    let cp := ((bs[0]'h0).toNat <<< 24)
            ||| ((bs[1]'h1).toNat <<< 16)
            ||| ((bs[2]'h2).toNat <<< 8)
            ||| (bs[3]'h3).toNat
    if cp > 0x10FFFF then none
    else if 0xD800 ≤ cp ∧ cp ≤ 0xDFFF then none
    else some cp
  else none

/-- Decode 4 bytes as a little-endian UTF-32 codepoint, returning
    `none` on surrogate values or values exceeding U+10FFFF. -/
def decodeOneLE (bs : ByteArray) : Option Nat :=
  if h : bs.size = 4 then
    have h0 : (0 : Nat) < bs.size := by rw [h]; omega
    have h1 : (1 : Nat) < bs.size := by rw [h]; omega
    have h2 : (2 : Nat) < bs.size := by rw [h]; omega
    have h3 : (3 : Nat) < bs.size := by rw [h]; omega
    let cp := (bs[0]'h0).toNat
            ||| ((bs[1]'h1).toNat <<< 8)
            ||| ((bs[2]'h2).toNat <<< 16)
            ||| ((bs[3]'h3).toNat <<< 24)
    if cp > 0x10FFFF then none
    else if 0xD800 ≤ cp ∧ cp ≤ 0xDFFF then none
    else some cp
  else none

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 PER-CODEPOINT ROUNDTRIP — EXHAUSTIVE NATIVE_DECIDE PER PLANE
-- ═══════════════════════════════════════════════════════════════════════════════

/-- BMP-and-supplementary plane enumeration: for plane 0 (BMP)
    excluding surrogates, the BE roundtrip closes. -/
theorem decodeBE_encodeBE_plane_0 :
    ∀ cp : Fin 0x10000,
      ¬ (0xD800 ≤ cp.val ∧ cp.val ≤ 0xDFFF) →
      decodeOneBE (encodeOneBE cp.val) = some cp.val := by native_decide

theorem decodeBE_encodeBE_plane_1 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0x10000 + cp.val)) = some (0x10000 + cp.val) := by
  native_decide
theorem decodeBE_encodeBE_plane_2 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0x20000 + cp.val)) = some (0x20000 + cp.val) := by
  native_decide
theorem decodeBE_encodeBE_plane_3 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0x30000 + cp.val)) = some (0x30000 + cp.val) := by
  native_decide
theorem decodeBE_encodeBE_plane_4 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0x40000 + cp.val)) = some (0x40000 + cp.val) := by
  native_decide
theorem decodeBE_encodeBE_plane_5 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0x50000 + cp.val)) = some (0x50000 + cp.val) := by
  native_decide
theorem decodeBE_encodeBE_plane_6 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0x60000 + cp.val)) = some (0x60000 + cp.val) := by
  native_decide
theorem decodeBE_encodeBE_plane_7 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0x70000 + cp.val)) = some (0x70000 + cp.val) := by
  native_decide
theorem decodeBE_encodeBE_plane_8 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0x80000 + cp.val)) = some (0x80000 + cp.val) := by
  native_decide
theorem decodeBE_encodeBE_plane_9 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0x90000 + cp.val)) = some (0x90000 + cp.val) := by
  native_decide
theorem decodeBE_encodeBE_plane_10 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0xA0000 + cp.val)) = some (0xA0000 + cp.val) := by
  native_decide
theorem decodeBE_encodeBE_plane_11 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0xB0000 + cp.val)) = some (0xB0000 + cp.val) := by
  native_decide
theorem decodeBE_encodeBE_plane_12 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0xC0000 + cp.val)) = some (0xC0000 + cp.val) := by
  native_decide
theorem decodeBE_encodeBE_plane_13 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0xD0000 + cp.val)) = some (0xD0000 + cp.val) := by
  native_decide
theorem decodeBE_encodeBE_plane_14 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0xE0000 + cp.val)) = some (0xE0000 + cp.val) := by
  native_decide
theorem decodeBE_encodeBE_plane_15 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0xF0000 + cp.val)) = some (0xF0000 + cp.val) := by
  native_decide
theorem decodeBE_encodeBE_plane_16 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0x100000 + cp.val)) = some (0x100000 + cp.val) := by
  native_decide

/-- HEADLINE per-codepoint UTF-32 BE roundtrip: every valid scalar
    codepoint encodes-then-decodes back to itself. -/
theorem decodeOneBE_encodeOneBE (cp : Nat) (h : IsValidCodepoint cp) :
    decodeOneBE (encodeOneBE cp) = some cp := by
  obtain ⟨h_max, h_nonsurr⟩ := h
  by_cases h0 : cp < 0x10000
  · exact decodeBE_encodeBE_plane_0 ⟨cp, h0⟩ h_nonsurr
  by_cases h1 : cp < 0x20000
  · have plane := decodeBE_encodeBE_plane_1 ⟨cp - 0x10000, by omega⟩
    have heq : 0x10000 + (cp - 0x10000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h2 : cp < 0x30000
  · have plane := decodeBE_encodeBE_plane_2 ⟨cp - 0x20000, by omega⟩
    have heq : 0x20000 + (cp - 0x20000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h3 : cp < 0x40000
  · have plane := decodeBE_encodeBE_plane_3 ⟨cp - 0x30000, by omega⟩
    have heq : 0x30000 + (cp - 0x30000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h4 : cp < 0x50000
  · have plane := decodeBE_encodeBE_plane_4 ⟨cp - 0x40000, by omega⟩
    have heq : 0x40000 + (cp - 0x40000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h5 : cp < 0x60000
  · have plane := decodeBE_encodeBE_plane_5 ⟨cp - 0x50000, by omega⟩
    have heq : 0x50000 + (cp - 0x50000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h6 : cp < 0x70000
  · have plane := decodeBE_encodeBE_plane_6 ⟨cp - 0x60000, by omega⟩
    have heq : 0x60000 + (cp - 0x60000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h7 : cp < 0x80000
  · have plane := decodeBE_encodeBE_plane_7 ⟨cp - 0x70000, by omega⟩
    have heq : 0x70000 + (cp - 0x70000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h8 : cp < 0x90000
  · have plane := decodeBE_encodeBE_plane_8 ⟨cp - 0x80000, by omega⟩
    have heq : 0x80000 + (cp - 0x80000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h9 : cp < 0xA0000
  · have plane := decodeBE_encodeBE_plane_9 ⟨cp - 0x90000, by omega⟩
    have heq : 0x90000 + (cp - 0x90000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h10 : cp < 0xB0000
  · have plane := decodeBE_encodeBE_plane_10 ⟨cp - 0xA0000, by omega⟩
    have heq : 0xA0000 + (cp - 0xA0000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h11 : cp < 0xC0000
  · have plane := decodeBE_encodeBE_plane_11 ⟨cp - 0xB0000, by omega⟩
    have heq : 0xB0000 + (cp - 0xB0000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h12 : cp < 0xD0000
  · have plane := decodeBE_encodeBE_plane_12 ⟨cp - 0xC0000, by omega⟩
    have heq : 0xC0000 + (cp - 0xC0000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h13 : cp < 0xE0000
  · have plane := decodeBE_encodeBE_plane_13 ⟨cp - 0xD0000, by omega⟩
    have heq : 0xD0000 + (cp - 0xD0000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h14 : cp < 0xF0000
  · have plane := decodeBE_encodeBE_plane_14 ⟨cp - 0xE0000, by omega⟩
    have heq : 0xE0000 + (cp - 0xE0000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h15 : cp < 0x100000
  · have plane := decodeBE_encodeBE_plane_15 ⟨cp - 0xF0000, by omega⟩
    have heq : 0xF0000 + (cp - 0xF0000) = cp := by omega
    rw [heq] at plane; exact plane
  · have plane := decodeBE_encodeBE_plane_16 ⟨cp - 0x100000, by omega⟩
    have heq : 0x100000 + (cp - 0x100000) = cp := by omega
    rw [heq] at plane; exact plane

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 PER-CODEPOINT ROUNDTRIP — LITTLE-ENDIAN VARIANT
-- ═══════════════════════════════════════════════════════════════════════════════

theorem decodeLE_encodeLE_plane_0 :
    ∀ cp : Fin 0x10000,
      ¬ (0xD800 ≤ cp.val ∧ cp.val ≤ 0xDFFF) →
      decodeOneLE (encodeOneLE cp.val) = some cp.val := by native_decide

theorem decodeLE_encodeLE_plane_1 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0x10000 + cp.val)) = some (0x10000 + cp.val) := by
  native_decide
theorem decodeLE_encodeLE_plane_2 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0x20000 + cp.val)) = some (0x20000 + cp.val) := by
  native_decide
theorem decodeLE_encodeLE_plane_3 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0x30000 + cp.val)) = some (0x30000 + cp.val) := by
  native_decide
theorem decodeLE_encodeLE_plane_4 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0x40000 + cp.val)) = some (0x40000 + cp.val) := by
  native_decide
theorem decodeLE_encodeLE_plane_5 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0x50000 + cp.val)) = some (0x50000 + cp.val) := by
  native_decide
theorem decodeLE_encodeLE_plane_6 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0x60000 + cp.val)) = some (0x60000 + cp.val) := by
  native_decide
theorem decodeLE_encodeLE_plane_7 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0x70000 + cp.val)) = some (0x70000 + cp.val) := by
  native_decide
theorem decodeLE_encodeLE_plane_8 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0x80000 + cp.val)) = some (0x80000 + cp.val) := by
  native_decide
theorem decodeLE_encodeLE_plane_9 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0x90000 + cp.val)) = some (0x90000 + cp.val) := by
  native_decide
theorem decodeLE_encodeLE_plane_10 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0xA0000 + cp.val)) = some (0xA0000 + cp.val) := by
  native_decide
theorem decodeLE_encodeLE_plane_11 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0xB0000 + cp.val)) = some (0xB0000 + cp.val) := by
  native_decide
theorem decodeLE_encodeLE_plane_12 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0xC0000 + cp.val)) = some (0xC0000 + cp.val) := by
  native_decide
theorem decodeLE_encodeLE_plane_13 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0xD0000 + cp.val)) = some (0xD0000 + cp.val) := by
  native_decide
theorem decodeLE_encodeLE_plane_14 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0xE0000 + cp.val)) = some (0xE0000 + cp.val) := by
  native_decide
theorem decodeLE_encodeLE_plane_15 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0xF0000 + cp.val)) = some (0xF0000 + cp.val) := by
  native_decide
theorem decodeLE_encodeLE_plane_16 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0x100000 + cp.val)) = some (0x100000 + cp.val) := by
  native_decide

/-- HEADLINE per-codepoint UTF-32 LE roundtrip. -/
theorem decodeOneLE_encodeOneLE (cp : Nat) (h : IsValidCodepoint cp) :
    decodeOneLE (encodeOneLE cp) = some cp := by
  obtain ⟨h_max, h_nonsurr⟩ := h
  by_cases h0 : cp < 0x10000
  · exact decodeLE_encodeLE_plane_0 ⟨cp, h0⟩ h_nonsurr
  by_cases h1 : cp < 0x20000
  · have plane := decodeLE_encodeLE_plane_1 ⟨cp - 0x10000, by omega⟩
    have heq : 0x10000 + (cp - 0x10000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h2 : cp < 0x30000
  · have plane := decodeLE_encodeLE_plane_2 ⟨cp - 0x20000, by omega⟩
    have heq : 0x20000 + (cp - 0x20000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h3 : cp < 0x40000
  · have plane := decodeLE_encodeLE_plane_3 ⟨cp - 0x30000, by omega⟩
    have heq : 0x30000 + (cp - 0x30000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h4 : cp < 0x50000
  · have plane := decodeLE_encodeLE_plane_4 ⟨cp - 0x40000, by omega⟩
    have heq : 0x40000 + (cp - 0x40000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h5 : cp < 0x60000
  · have plane := decodeLE_encodeLE_plane_5 ⟨cp - 0x50000, by omega⟩
    have heq : 0x50000 + (cp - 0x50000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h6 : cp < 0x70000
  · have plane := decodeLE_encodeLE_plane_6 ⟨cp - 0x60000, by omega⟩
    have heq : 0x60000 + (cp - 0x60000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h7 : cp < 0x80000
  · have plane := decodeLE_encodeLE_plane_7 ⟨cp - 0x70000, by omega⟩
    have heq : 0x70000 + (cp - 0x70000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h8 : cp < 0x90000
  · have plane := decodeLE_encodeLE_plane_8 ⟨cp - 0x80000, by omega⟩
    have heq : 0x80000 + (cp - 0x80000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h9 : cp < 0xA0000
  · have plane := decodeLE_encodeLE_plane_9 ⟨cp - 0x90000, by omega⟩
    have heq : 0x90000 + (cp - 0x90000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h10 : cp < 0xB0000
  · have plane := decodeLE_encodeLE_plane_10 ⟨cp - 0xA0000, by omega⟩
    have heq : 0xA0000 + (cp - 0xA0000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h11 : cp < 0xC0000
  · have plane := decodeLE_encodeLE_plane_11 ⟨cp - 0xB0000, by omega⟩
    have heq : 0xB0000 + (cp - 0xB0000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h12 : cp < 0xD0000
  · have plane := decodeLE_encodeLE_plane_12 ⟨cp - 0xC0000, by omega⟩
    have heq : 0xC0000 + (cp - 0xC0000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h13 : cp < 0xE0000
  · have plane := decodeLE_encodeLE_plane_13 ⟨cp - 0xD0000, by omega⟩
    have heq : 0xD0000 + (cp - 0xD0000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h14 : cp < 0xF0000
  · have plane := decodeLE_encodeLE_plane_14 ⟨cp - 0xE0000, by omega⟩
    have heq : 0xE0000 + (cp - 0xE0000) = cp := by omega
    rw [heq] at plane; exact plane
  by_cases h15 : cp < 0x100000
  · have plane := decodeLE_encodeLE_plane_15 ⟨cp - 0xF0000, by omega⟩
    have heq : 0xF0000 + (cp - 0xF0000) = cp := by omega
    rw [heq] at plane; exact plane
  · have plane := decodeLE_encodeLE_plane_16 ⟨cp - 0x100000, by omega⟩
    have heq : 0x100000 + (cp - 0x100000) = cp := by omega
    rw [heq] at plane; exact plane

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 ILL-FORMED REJECTION
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Decoder rejects 4-byte sequences encoding a surrogate. -/
theorem decodeOneBE_surrogate_rejected :
    decodeOneBE (encodeOneBE 0xD800) = none := by native_decide

/-- Decoder rejects 4-byte sequences encoding a value above U+10FFFF. -/
theorem decodeOneBE_beyondMax_rejected :
    decodeOneBE (encodeOneBE 0x110000) = none := by native_decide

theorem decodeOneLE_surrogate_rejected :
    decodeOneLE (encodeOneLE 0xD800) = none := by native_decide

theorem decodeOneLE_beyondMax_rejected :
    decodeOneLE (encodeOneLE 0x110000) = none := by native_decide

/-- Decoder rejects inputs whose length is not exactly 4. -/
theorem decodeOneBE_too_short :
    decodeOneBE (ByteArray.mk #[0x00, 0x00, 0x00]) = none := by native_decide

theorem decodeOneBE_too_long :
    decodeOneBE (ByteArray.mk #[0x00, 0x00, 0x00, 0x41, 0x00]) = none := by native_decide

end Unicode.Codec.Utf32
