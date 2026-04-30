/-
  Unicode.Codec.Utf16

  UTF-16 codec — Big-Endian and Little-Endian variants.

  Each scalar Unicode codepoint encodes to either 2 bytes (BMP) or
  4 bytes (supplementary planes via surrogate pair). The supplementary
  pair is constructed as:

    X        = cp - 0x10000           (20-bit value)
    high     = 0xD800 + (X >> 10)     (high surrogate, 0xD800..0xDBFF)
    low      = 0xDC00 + (X & 0x3FF)   (low surrogate, 0xDC00..0xDFFF)

  The decoder rejects:
    * inputs with length not in {2, 4}
    * 2-byte sequences in the surrogate range U+D800..U+DFFF
      (lone surrogate)
    * 4-byte sequences not forming a valid (high, low) surrogate pair

  Closed-form per-codepoint roundtrip:
    decodeOneBE_encodeOneBE (cp : Nat) (h : IsValidCodepoint cp) :
       decodeOneBE (encodeOneBE cp) = some cp
  proven by case-splitting on cp's BMP / supplementary status and
  discharging each via exhaustive `native_decide` per plane.
-/

import Unicode.Codec.Utf8Roundtrip

namespace Unicode.Codec.Utf16

open Unicode.Codec.Utf8Roundtrip (IsValidCodepoint)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 ENCODER
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Encode a scalar codepoint as 2 or 4 bytes in UTF-16 BE. -/
def encodeOneBE (cp : Nat) : ByteArray :=
  if cp < 0x10000 then
    ByteArray.mk #[
      UInt8.ofNat ((cp >>> 8) &&& 0xFF),
      UInt8.ofNat (cp &&& 0xFF)
    ]
  else
    let x    := cp - 0x10000
    let high := 0xD800 + (x >>> 10)
    let low  := 0xDC00 + (x &&& 0x3FF)
    ByteArray.mk #[
      UInt8.ofNat ((high >>> 8) &&& 0xFF),
      UInt8.ofNat (high &&& 0xFF),
      UInt8.ofNat ((low >>> 8) &&& 0xFF),
      UInt8.ofNat (low &&& 0xFF)
    ]

/-- Encode a scalar codepoint as 2 or 4 bytes in UTF-16 LE. -/
def encodeOneLE (cp : Nat) : ByteArray :=
  if cp < 0x10000 then
    ByteArray.mk #[
      UInt8.ofNat (cp &&& 0xFF),
      UInt8.ofNat ((cp >>> 8) &&& 0xFF)
    ]
  else
    let x    := cp - 0x10000
    let high := 0xD800 + (x >>> 10)
    let low  := 0xDC00 + (x &&& 0x3FF)
    ByteArray.mk #[
      UInt8.ofNat (high &&& 0xFF),
      UInt8.ofNat ((high >>> 8) &&& 0xFF),
      UInt8.ofNat (low &&& 0xFF),
      UInt8.ofNat ((low >>> 8) &&& 0xFF)
    ]

/-- Concatenate the UTF-16 BE encodings of a codepoint sequence. -/
def encodeBE (cps : Array Nat) : ByteArray :=
  cps.foldl (fun acc cp => acc ++ encodeOneBE cp) ByteArray.empty

/-- Concatenate the UTF-16 LE encodings of a codepoint sequence. -/
def encodeLE (cps : Array Nat) : ByteArray :=
  cps.foldl (fun acc cp => acc ++ encodeOneLE cp) ByteArray.empty

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 DECODER (single codepoint, strict)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Decode a UTF-16 BE byte sequence as a single codepoint, returning
    `none` on length-mismatch, lone-surrogate, or invalid surrogate
    pair. Accepts byte sequences of length exactly 2 (BMP) or 4
    (supplementary-plane surrogate pair). -/
def decodeOneBE (bs : ByteArray) : Option Nat :=
  if h2 : bs.size = 2 then
    have h0 : (0 : Nat) < bs.size := by rw [h2]; omega
    have h1 : (1 : Nat) < bs.size := by rw [h2]; omega
    let u := ((bs[0]'h0).toNat <<< 8) ||| (bs[1]'h1).toNat
    -- 2-byte path: must NOT be a surrogate.
    if 0xD800 ≤ u ∧ u ≤ 0xDFFF then none else some u
  else if h4 : bs.size = 4 then
    have h0 : (0 : Nat) < bs.size := by rw [h4]; omega
    have h1 : (1 : Nat) < bs.size := by rw [h4]; omega
    have h2' : (2 : Nat) < bs.size := by rw [h4]; omega
    have h3 : (3 : Nat) < bs.size := by rw [h4]; omega
    let high := ((bs[0]'h0).toNat <<< 8) ||| (bs[1]'h1).toNat
    let low  := ((bs[2]'h2').toNat <<< 8) ||| (bs[3]'h3).toNat
    -- 4-byte path: must be a high surrogate followed by a low surrogate.
    if 0xD800 ≤ high ∧ high ≤ 0xDBFF ∧ 0xDC00 ≤ low ∧ low ≤ 0xDFFF then
      some (0x10000 + ((high - 0xD800) <<< 10) + (low - 0xDC00))
    else none
  else none

/-- Decode a UTF-16 LE byte sequence as a single codepoint. -/
def decodeOneLE (bs : ByteArray) : Option Nat :=
  if h2 : bs.size = 2 then
    have h0 : (0 : Nat) < bs.size := by rw [h2]; omega
    have h1 : (1 : Nat) < bs.size := by rw [h2]; omega
    let u := (bs[0]'h0).toNat ||| ((bs[1]'h1).toNat <<< 8)
    if 0xD800 ≤ u ∧ u ≤ 0xDFFF then none else some u
  else if h4 : bs.size = 4 then
    have h0 : (0 : Nat) < bs.size := by rw [h4]; omega
    have h1 : (1 : Nat) < bs.size := by rw [h4]; omega
    have h2' : (2 : Nat) < bs.size := by rw [h4]; omega
    have h3 : (3 : Nat) < bs.size := by rw [h4]; omega
    let high := (bs[0]'h0).toNat ||| ((bs[1]'h1).toNat <<< 8)
    let low  := (bs[2]'h2').toNat ||| ((bs[3]'h3).toNat <<< 8)
    if 0xD800 ≤ high ∧ high ≤ 0xDBFF ∧ 0xDC00 ≤ low ∧ low ≤ 0xDFFF then
      some (0x10000 + ((high - 0xD800) <<< 10) + (low - 0xDC00))
    else none
  else none

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 PER-CODEPOINT ROUNDTRIP — BIG ENDIAN
-- ═══════════════════════════════════════════════════════════════════════════════

/-- BMP plane (excluding surrogates): every non-surrogate BMP
    codepoint encodes-then-decodes back to itself in UTF-16 BE. -/
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

/-- HEADLINE per-codepoint UTF-16 BE roundtrip. -/
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
-- §4 PER-CODEPOINT ROUNDTRIP — LITTLE ENDIAN
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

/-- HEADLINE per-codepoint UTF-16 LE roundtrip. -/
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

/-- Lone high surrogate (no following low surrogate) is rejected. -/
theorem decodeOneBE_lone_high_surrogate :
    decodeOneBE (ByteArray.mk #[0xD8, 0x00]) = none := by native_decide

/-- Lone low surrogate (no preceding high surrogate) is rejected. -/
theorem decodeOneBE_lone_low_surrogate :
    decodeOneBE (ByteArray.mk #[0xDC, 0x00]) = none := by native_decide

/-- High surrogate followed by a non-low-surrogate is rejected. -/
theorem decodeOneBE_high_then_not_low :
    decodeOneBE (ByteArray.mk #[0xD8, 0x00, 0x00, 0x41]) = none := by native_decide

/-- Length not in {2, 4} is rejected. -/
theorem decodeOneBE_length_3 :
    decodeOneBE (ByteArray.mk #[0x00, 0x00, 0x00]) = none := by native_decide
theorem decodeOneBE_length_5 :
    decodeOneBE (ByteArray.mk #[0x00, 0x00, 0x00, 0x00, 0x00]) = none := by native_decide

theorem decodeOneLE_lone_high_surrogate :
    decodeOneLE (ByteArray.mk #[0x00, 0xD8]) = none := by native_decide
theorem decodeOneLE_lone_low_surrogate :
    decodeOneLE (ByteArray.mk #[0x00, 0xDC]) = none := by native_decide

end Unicode.Codec.Utf16
