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
  proven by case-splitting on cp's BMP / supplementary status,
  reconstructing encoded bytes structurally, and using the 20-bit
  surrogate-pair split `(X >>> 10, X &&& 0x3FF)`.
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

theorem decodeOneBE_mk2 (b0 b1 : UInt8) :
    decodeOneBE (ByteArray.mk #[b0, b1]) =
      let u := (b0.toNat <<< 8) ||| b1.toNat
      if 0xD800 ≤ u ∧ u ≤ 0xDFFF then none else some u := by
  rfl

theorem decodeOneBE_mk4 (b0 b1 b2 b3 : UInt8) :
    decodeOneBE (ByteArray.mk #[b0, b1, b2, b3]) =
      let high := (b0.toNat <<< 8) ||| b1.toNat
      let low  := (b2.toNat <<< 8) ||| b3.toNat
      if 0xD800 ≤ high ∧ high ≤ 0xDBFF ∧ 0xDC00 ≤ low ∧ low ≤ 0xDFFF then
        some (0x10000 + ((high - 0xD800) <<< 10) + (low - 0xDC00))
      else none := by
  rfl

theorem decodeOneLE_mk2 (b0 b1 : UInt8) :
    decodeOneLE (ByteArray.mk #[b0, b1]) =
      let u := b0.toNat ||| (b1.toNat <<< 8)
      if 0xD800 ≤ u ∧ u ≤ 0xDFFF then none else some u := by
  rfl

theorem decodeOneLE_mk4 (b0 b1 b2 b3 : UInt8) :
    decodeOneLE (ByteArray.mk #[b0, b1, b2, b3]) =
      let high := b0.toNat ||| (b1.toNat <<< 8)
      let low  := b2.toNat ||| (b3.toNat <<< 8)
      if 0xD800 ≤ high ∧ high ≤ 0xDBFF ∧ 0xDC00 ≤ low ∧ low ≤ 0xDFFF then
        some (0x10000 + ((high - 0xD800) <<< 10) + (low - 0xDC00))
      else none := by
  rfl

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 PER-CODEPOINT ROUNDTRIP — STRUCTURAL BYTE RECONSTRUCTION
-- ═══════════════════════════════════════════════════════════════════════════════

theorem uint8_toNat_ofNat (n : Nat) :
    (UInt8.ofNat n).toNat = n % 256 := by
  unfold UInt8.ofNat UInt8.toNat
  rw [BitVec.toNat_ofNat]

theorem mod256_and_ff (n : Nat) :
    n % 256 &&& 255 = n &&& 255 := by
  rw [← Nat.and_two_pow_sub_one_eq_mod n 8]
  change n &&& 255 &&& 255 = n &&& 255
  rw [Nat.and_assoc, Nat.and_self]

theorem testBit_255 (i : Nat) :
    Nat.testBit 255 i = decide (i < 8) := by
  change Nat.testBit (2^8 - 1) i = decide (i < 8)
  rw [Nat.testBit_two_pow_sub_one]

theorem reconstruct16BE (x : Nat) (h : x < 2^16) :
    ((((x >>> 8) &&& 0xFF) <<< 8) ||| (x &&& 0xFF)) = x := by
  apply Nat.eq_of_testBit_eq
  intro i
  simp only [Nat.testBit_or, Nat.testBit_shiftLeft, Nat.testBit_shiftRight,
    Nat.testBit_and, testBit_255]
  by_cases h16 : i < 16
  · by_cases h8 : i < 8
    · simp [h8, Nat.not_le_of_lt h8]
    · have h8le : 8 ≤ i := Nat.le_of_not_lt h8
      have hSub8 : i - 8 < 8 := by omega
      simp [h8, h8le, hSub8, Nat.add_sub_cancel' h8le]
  · have h16le : 16 ≤ i := Nat.le_of_not_lt h16
    have hx : x.testBit i = false :=
      Nat.testBit_lt_two_pow (x := x) (i := i)
        (Nat.lt_of_lt_of_le h
          (Nat.pow_le_pow_right Nat.zero_lt_two h16le))
    have h8le : 8 ≤ i := by omega
    have hNot8 : ¬ i < 8 := by omega
    have hNotSub8 : ¬ i - 8 < 8 := by omega
    simp [hx, h8le, hNot8, hNotSub8, Nat.add_sub_cancel' h8le]

theorem reconstruct16LE (x : Nat) (h : x < 2^16) :
    ((x &&& 0xFF) ||| (((x >>> 8) &&& 0xFF) <<< 8)) = x := by
  calc
    ((x &&& 0xFF) ||| (((x >>> 8) &&& 0xFF) <<< 8))
        = ((((x >>> 8) &&& 0xFF) <<< 8) ||| (x &&& 0xFF)) := by
          rw [Nat.or_comm]
    ((((x >>> 8) &&& 0xFF) <<< 8) ||| (x &&& 0xFF)) = x :=
      reconstruct16BE x h

theorem split10 (x : Nat) :
    ((x >>> 10) <<< 10) + (x &&& 0x3FF) = x := by
  change ((x >>> 10) <<< 10) + (x &&& (2^10 - 1)) = x
  rw [Nat.shiftRight_eq_div_pow, Nat.shiftLeft_eq,
    Nat.and_two_pow_sub_one_eq_mod]
  rw [Nat.mul_comm]
  exact Nat.div_add_mod x (2^10)

theorem mask10_lt (x : Nat) : x &&& 0x3FF < 0x400 := by
  change x &&& (2^10 - 1) < 2^10
  exact Nat.and_lt_two_pow x (by omega)

theorem d800_lowByte (v : Nat) :
    (0xD800 + v) &&& 0xFF = v &&& 0xFF := by
  change (0xD800 + v) &&& (2^8 - 1) = v &&& (2^8 - 1)
  rw [Nat.and_two_pow_sub_one_eq_mod, Nat.and_two_pow_sub_one_eq_mod]
  change (55296 + v) % 256 = v % 256
  rw [Nat.add_comm]
  change (v + 256 * 216) % 256 = v % 256
  rw [Nat.add_mul_mod_self_left]

theorem dc00_lowByte (v : Nat) :
    (0xDC00 + v) &&& 0xFF = v &&& 0xFF := by
  change (0xDC00 + v) &&& (2^8 - 1) = v &&& (2^8 - 1)
  rw [Nat.and_two_pow_sub_one_eq_mod, Nat.and_two_pow_sub_one_eq_mod]
  change (56320 + v) % 256 = v % 256
  rw [Nat.add_comm]
  change (v + 256 * 220) % 256 = v % 256
  rw [Nat.add_mul_mod_self_left]

theorem mask10_and_ff (x : Nat) :
    (x &&& 0x3FF) &&& 0xFF = x &&& 0xFF := by
  change (x &&& (2^10 - 1)) &&& (2^8 - 1) = x &&& (2^8 - 1)
  repeat rw [Nat.and_two_pow_sub_one_eq_mod]
  change x % 1024 % 256 = x % 256
  exact Nat.mod_mod_of_dvd x ⟨4, by rfl⟩

theorem shiftRight10_lt_of_lt_20 {x : Nat} (h : x < 0x100000) :
    x >>> 10 < 0x400 := by
  rw [Nat.shiftRight_eq_div_pow]
  exact (Nat.div_lt_iff_lt_mul (Nat.two_pow_pos 10)).2 (by omega)

theorem decodeOneBE_encodeOneBE_valid (cp : Nat)
    (hMax : cp < 0x110000)
    (hNonsurr : ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF)) :
    decodeOneBE (encodeOneBE cp) = some cp := by
  by_cases hBmp : cp < 0x10000
  · have hRec := reconstruct16BE cp (by omega)
    unfold encodeOneBE
    simp [hBmp, decodeOneBE_mk2, mod256_and_ff, hRec, hNonsurr]
  · let x := cp - 0x10000
    have hCpLo : 0x10000 ≤ cp := Nat.le_of_not_lt hBmp
    have hxLt : x < 0x100000 := by
      dsimp [x]
      omega
    have hHighLt := shiftRight10_lt_of_lt_20 hxLt
    have hLowLt := mask10_lt x
    have hHighRange :
        0xD800 ≤ 0xD800 + (x >>> 10)
          ∧ 0xD800 + (x >>> 10) ≤ 0xDBFF := by
      omega
    have hLowRange :
        0xDC00 ≤ 0xDC00 + (x &&& 0x3FF)
          ∧ 0xDC00 + (x &&& 0x3FF) ≤ 0xDFFF := by
      omega
    have hHigh16 : 0xD800 + (x >>> 10) < 2^16 := by omega
    have hLow16 : 0xDC00 + (x &&& 0x3FF) < 2^16 := by omega
    have hHighRec := reconstruct16BE (0xD800 + (x >>> 10)) hHigh16
    have hLowRec := reconstruct16BE (0xDC00 + (x &&& 0x3FF)) hLow16
    rw [d800_lowByte] at hHighRec
    rw [dc00_lowByte, mask10_and_ff] at hLowRec
    have hHighSub : 0xD800 + (x >>> 10) - 0xD800 = x >>> 10 :=
      Nat.add_sub_cancel_left 0xD800 (x >>> 10)
    have hLowSub : 0xDC00 + (x &&& 0x3FF) - 0xDC00 = x &&& 0x3FF :=
      Nat.add_sub_cancel_left 0xDC00 (x &&& 0x3FF)
    have hSplit := split10 x
    have hCpEq : 0x10000 + x = cp := by
      dsimp [x]
      omega
    dsimp [x] at hHighRec hLowRec hHighRange hLowRange hHighSub hLowSub hSplit hCpEq
    unfold encodeOneBE
    simp [hBmp, decodeOneBE_mk4, mod256_and_ff, hHighRec, hLowRec,
      hHighRange, hLowRange, hHighSub, hLowSub, Nat.and_assoc, Nat.and_self]
    rw [Nat.add_assoc, hSplit, hCpEq]

theorem decodeOneLE_encodeOneLE_valid (cp : Nat)
    (hMax : cp < 0x110000)
    (hNonsurr : ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF)) :
    decodeOneLE (encodeOneLE cp) = some cp := by
  by_cases hBmp : cp < 0x10000
  · have hRec := reconstruct16LE cp (by omega)
    unfold encodeOneLE
    simp [hBmp, decodeOneLE_mk2, mod256_and_ff, hRec, hNonsurr]
  · let x := cp - 0x10000
    have hCpLo : 0x10000 ≤ cp := Nat.le_of_not_lt hBmp
    have hxLt : x < 0x100000 := by
      dsimp [x]
      omega
    have hHighLt := shiftRight10_lt_of_lt_20 hxLt
    have hLowLt := mask10_lt x
    have hHighRange :
        0xD800 ≤ 0xD800 + (x >>> 10)
          ∧ 0xD800 + (x >>> 10) ≤ 0xDBFF := by
      omega
    have hLowRange :
        0xDC00 ≤ 0xDC00 + (x &&& 0x3FF)
          ∧ 0xDC00 + (x &&& 0x3FF) ≤ 0xDFFF := by
      omega
    have hHigh16 : 0xD800 + (x >>> 10) < 2^16 := by omega
    have hLow16 : 0xDC00 + (x &&& 0x3FF) < 2^16 := by omega
    have hHighRec := reconstruct16LE (0xD800 + (x >>> 10)) hHigh16
    have hLowRec := reconstruct16LE (0xDC00 + (x &&& 0x3FF)) hLow16
    rw [d800_lowByte] at hHighRec
    rw [dc00_lowByte, mask10_and_ff] at hLowRec
    have hHighSub : 0xD800 + (x >>> 10) - 0xD800 = x >>> 10 :=
      Nat.add_sub_cancel_left 0xD800 (x >>> 10)
    have hLowSub : 0xDC00 + (x &&& 0x3FF) - 0xDC00 = x &&& 0x3FF :=
      Nat.add_sub_cancel_left 0xDC00 (x &&& 0x3FF)
    have hSplit := split10 x
    have hCpEq : 0x10000 + x = cp := by
      dsimp [x]
      omega
    dsimp [x] at hHighRec hLowRec hHighRange hLowRange hHighSub hLowSub hSplit hCpEq
    unfold encodeOneLE
    simp [hBmp, decodeOneLE_mk4, mod256_and_ff, hHighRec, hLowRec,
      hHighRange, hLowRange, hHighSub, hLowSub, Nat.and_assoc, Nat.and_self]
    rw [Nat.add_assoc, hSplit, hCpEq]

/-- BMP plane (excluding surrogates): every non-surrogate BMP
    codepoint encodes-then-decodes back to itself in UTF-16 BE. -/
theorem decodeBE_encodeBE_plane_0 :
    ∀ cp : Fin 0x10000,
      ¬ (0xD800 ≤ cp.val ∧ cp.val ≤ 0xDFFF) →
      decodeOneBE (encodeOneBE cp.val) = some cp.val := by
  intro cp hNonsurr
  exact decodeOneBE_encodeOneBE_valid cp.val (by omega) hNonsurr

theorem decodeBE_encodeBE_plane_1 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0x10000 + cp.val)) = some (0x10000 + cp.val) := by
  intro cp
  exact decodeOneBE_encodeOneBE_valid (0x10000 + cp.val) (by omega) (by omega)
theorem decodeBE_encodeBE_plane_2 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0x20000 + cp.val)) = some (0x20000 + cp.val) := by
  intro cp
  exact decodeOneBE_encodeOneBE_valid (0x20000 + cp.val) (by omega) (by omega)
theorem decodeBE_encodeBE_plane_3 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0x30000 + cp.val)) = some (0x30000 + cp.val) := by
  intro cp
  exact decodeOneBE_encodeOneBE_valid (0x30000 + cp.val) (by omega) (by omega)
theorem decodeBE_encodeBE_plane_4 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0x40000 + cp.val)) = some (0x40000 + cp.val) := by
  intro cp
  exact decodeOneBE_encodeOneBE_valid (0x40000 + cp.val) (by omega) (by omega)
theorem decodeBE_encodeBE_plane_5 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0x50000 + cp.val)) = some (0x50000 + cp.val) := by
  intro cp
  exact decodeOneBE_encodeOneBE_valid (0x50000 + cp.val) (by omega) (by omega)
theorem decodeBE_encodeBE_plane_6 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0x60000 + cp.val)) = some (0x60000 + cp.val) := by
  intro cp
  exact decodeOneBE_encodeOneBE_valid (0x60000 + cp.val) (by omega) (by omega)
theorem decodeBE_encodeBE_plane_7 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0x70000 + cp.val)) = some (0x70000 + cp.val) := by
  intro cp
  exact decodeOneBE_encodeOneBE_valid (0x70000 + cp.val) (by omega) (by omega)
theorem decodeBE_encodeBE_plane_8 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0x80000 + cp.val)) = some (0x80000 + cp.val) := by
  intro cp
  exact decodeOneBE_encodeOneBE_valid (0x80000 + cp.val) (by omega) (by omega)
theorem decodeBE_encodeBE_plane_9 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0x90000 + cp.val)) = some (0x90000 + cp.val) := by
  intro cp
  exact decodeOneBE_encodeOneBE_valid (0x90000 + cp.val) (by omega) (by omega)
theorem decodeBE_encodeBE_plane_10 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0xA0000 + cp.val)) = some (0xA0000 + cp.val) := by
  intro cp
  exact decodeOneBE_encodeOneBE_valid (0xA0000 + cp.val) (by omega) (by omega)
theorem decodeBE_encodeBE_plane_11 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0xB0000 + cp.val)) = some (0xB0000 + cp.val) := by
  intro cp
  exact decodeOneBE_encodeOneBE_valid (0xB0000 + cp.val) (by omega) (by omega)
theorem decodeBE_encodeBE_plane_12 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0xC0000 + cp.val)) = some (0xC0000 + cp.val) := by
  intro cp
  exact decodeOneBE_encodeOneBE_valid (0xC0000 + cp.val) (by omega) (by omega)
theorem decodeBE_encodeBE_plane_13 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0xD0000 + cp.val)) = some (0xD0000 + cp.val) := by
  intro cp
  exact decodeOneBE_encodeOneBE_valid (0xD0000 + cp.val) (by omega) (by omega)
theorem decodeBE_encodeBE_plane_14 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0xE0000 + cp.val)) = some (0xE0000 + cp.val) := by
  intro cp
  exact decodeOneBE_encodeOneBE_valid (0xE0000 + cp.val) (by omega) (by omega)
theorem decodeBE_encodeBE_plane_15 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0xF0000 + cp.val)) = some (0xF0000 + cp.val) := by
  intro cp
  exact decodeOneBE_encodeOneBE_valid (0xF0000 + cp.val) (by omega) (by omega)
theorem decodeBE_encodeBE_plane_16 : ∀ cp : Fin 0x10000,
    decodeOneBE (encodeOneBE (0x100000 + cp.val)) = some (0x100000 + cp.val) := by
  intro cp
  exact decodeOneBE_encodeOneBE_valid (0x100000 + cp.val) (by omega) (by omega)

/-- HEADLINE per-codepoint UTF-16 BE roundtrip. -/
theorem decodeOneBE_encodeOneBE (cp : Nat) (h : IsValidCodepoint cp) :
    decodeOneBE (encodeOneBE cp) = some cp := by
  obtain ⟨h_max, h_nonsurr⟩ := h
  exact decodeOneBE_encodeOneBE_valid cp h_max h_nonsurr

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 PER-CODEPOINT ROUNDTRIP — LITTLE ENDIAN
-- ═══════════════════════════════════════════════════════════════════════════════

theorem decodeLE_encodeLE_plane_0 :
    ∀ cp : Fin 0x10000,
      ¬ (0xD800 ≤ cp.val ∧ cp.val ≤ 0xDFFF) →
      decodeOneLE (encodeOneLE cp.val) = some cp.val := by
  intro cp hNonsurr
  exact decodeOneLE_encodeOneLE_valid cp.val (by omega) hNonsurr

theorem decodeLE_encodeLE_plane_1 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0x10000 + cp.val)) = some (0x10000 + cp.val) := by
  intro cp
  exact decodeOneLE_encodeOneLE_valid (0x10000 + cp.val) (by omega) (by omega)
theorem decodeLE_encodeLE_plane_2 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0x20000 + cp.val)) = some (0x20000 + cp.val) := by
  intro cp
  exact decodeOneLE_encodeOneLE_valid (0x20000 + cp.val) (by omega) (by omega)
theorem decodeLE_encodeLE_plane_3 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0x30000 + cp.val)) = some (0x30000 + cp.val) := by
  intro cp
  exact decodeOneLE_encodeOneLE_valid (0x30000 + cp.val) (by omega) (by omega)
theorem decodeLE_encodeLE_plane_4 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0x40000 + cp.val)) = some (0x40000 + cp.val) := by
  intro cp
  exact decodeOneLE_encodeOneLE_valid (0x40000 + cp.val) (by omega) (by omega)
theorem decodeLE_encodeLE_plane_5 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0x50000 + cp.val)) = some (0x50000 + cp.val) := by
  intro cp
  exact decodeOneLE_encodeOneLE_valid (0x50000 + cp.val) (by omega) (by omega)
theorem decodeLE_encodeLE_plane_6 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0x60000 + cp.val)) = some (0x60000 + cp.val) := by
  intro cp
  exact decodeOneLE_encodeOneLE_valid (0x60000 + cp.val) (by omega) (by omega)
theorem decodeLE_encodeLE_plane_7 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0x70000 + cp.val)) = some (0x70000 + cp.val) := by
  intro cp
  exact decodeOneLE_encodeOneLE_valid (0x70000 + cp.val) (by omega) (by omega)
theorem decodeLE_encodeLE_plane_8 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0x80000 + cp.val)) = some (0x80000 + cp.val) := by
  intro cp
  exact decodeOneLE_encodeOneLE_valid (0x80000 + cp.val) (by omega) (by omega)
theorem decodeLE_encodeLE_plane_9 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0x90000 + cp.val)) = some (0x90000 + cp.val) := by
  intro cp
  exact decodeOneLE_encodeOneLE_valid (0x90000 + cp.val) (by omega) (by omega)
theorem decodeLE_encodeLE_plane_10 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0xA0000 + cp.val)) = some (0xA0000 + cp.val) := by
  intro cp
  exact decodeOneLE_encodeOneLE_valid (0xA0000 + cp.val) (by omega) (by omega)
theorem decodeLE_encodeLE_plane_11 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0xB0000 + cp.val)) = some (0xB0000 + cp.val) := by
  intro cp
  exact decodeOneLE_encodeOneLE_valid (0xB0000 + cp.val) (by omega) (by omega)
theorem decodeLE_encodeLE_plane_12 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0xC0000 + cp.val)) = some (0xC0000 + cp.val) := by
  intro cp
  exact decodeOneLE_encodeOneLE_valid (0xC0000 + cp.val) (by omega) (by omega)
theorem decodeLE_encodeLE_plane_13 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0xD0000 + cp.val)) = some (0xD0000 + cp.val) := by
  intro cp
  exact decodeOneLE_encodeOneLE_valid (0xD0000 + cp.val) (by omega) (by omega)
theorem decodeLE_encodeLE_plane_14 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0xE0000 + cp.val)) = some (0xE0000 + cp.val) := by
  intro cp
  exact decodeOneLE_encodeOneLE_valid (0xE0000 + cp.val) (by omega) (by omega)
theorem decodeLE_encodeLE_plane_15 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0xF0000 + cp.val)) = some (0xF0000 + cp.val) := by
  intro cp
  exact decodeOneLE_encodeOneLE_valid (0xF0000 + cp.val) (by omega) (by omega)
theorem decodeLE_encodeLE_plane_16 : ∀ cp : Fin 0x10000,
    decodeOneLE (encodeOneLE (0x100000 + cp.val)) = some (0x100000 + cp.val) := by
  intro cp
  exact decodeOneLE_encodeOneLE_valid (0x100000 + cp.val) (by omega) (by omega)

/-- HEADLINE per-codepoint UTF-16 LE roundtrip. -/
theorem decodeOneLE_encodeOneLE (cp : Nat) (h : IsValidCodepoint cp) :
    decodeOneLE (encodeOneLE cp) = some cp := by
  obtain ⟨h_max, h_nonsurr⟩ := h
  exact decodeOneLE_encodeOneLE_valid cp h_max h_nonsurr

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 ILL-FORMED REJECTION
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Lone high surrogate (no following low surrogate) is rejected. -/
theorem decodeOneBE_lone_high_surrogate :
    decodeOneBE (ByteArray.mk #[0xD8, 0x00]) = none := by decide

/-- Lone low surrogate (no preceding high surrogate) is rejected. -/
theorem decodeOneBE_lone_low_surrogate :
    decodeOneBE (ByteArray.mk #[0xDC, 0x00]) = none := by decide

/-- High surrogate followed by a non-low-surrogate is rejected. -/
theorem decodeOneBE_high_then_not_low :
    decodeOneBE (ByteArray.mk #[0xD8, 0x00, 0x00, 0x41]) = none := by decide

/-- Length not in {2, 4} is rejected. -/
theorem decodeOneBE_length_3 :
    decodeOneBE (ByteArray.mk #[0x00, 0x00, 0x00]) = none := by decide
theorem decodeOneBE_length_5 :
    decodeOneBE (ByteArray.mk #[0x00, 0x00, 0x00, 0x00, 0x00]) = none := by decide

theorem decodeOneLE_lone_high_surrogate :
    decodeOneLE (ByteArray.mk #[0x00, 0xD8]) = none := by decide
theorem decodeOneLE_lone_low_surrogate :
    decodeOneLE (ByteArray.mk #[0x00, 0xDC]) = none := by decide

end Unicode.Codec.Utf16
