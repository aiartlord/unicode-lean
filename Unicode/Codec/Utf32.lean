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
  proven by structural 4-byte reconstruction. The public per-plane
  theorems remain as compatibility witnesses, but they now route
  through the same generic reconstruction proof instead of exhaustive
  `decide` enumeration.
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

theorem decodeOneBE_mk4 (b0 b1 b2 b3 : UInt8) :
    decodeOneBE (ByteArray.mk #[b0, b1, b2, b3]) =
      let cp := (b0.toNat <<< 24)
            ||| (b1.toNat <<< 16)
            ||| (b2.toNat <<< 8)
            ||| b3.toNat
      if cp > 0x10FFFF then none
      else if 0xD800 ≤ cp ∧ cp ≤ 0xDFFF then none
      else some cp := by
  rfl

theorem decodeOneLE_mk4 (b0 b1 b2 b3 : UInt8) :
    decodeOneLE (ByteArray.mk #[b0, b1, b2, b3]) =
      let cp := b0.toNat
            ||| (b1.toNat <<< 8)
            ||| (b2.toNat <<< 16)
            ||| (b3.toNat <<< 24)
      if cp > 0x10FFFF then none
      else if 0xD800 ≤ cp ∧ cp ≤ 0xDFFF then none
      else some cp := by
  rfl

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 PER-CODEPOINT ROUNDTRIP — STRUCTURAL BYTE RECONSTRUCTION
-- ═══════════════════════════════════════════════════════════════════════════════

theorem uint8_toNat_ofNat (n : Nat) :
    (UInt8.ofNat n).toNat = n % 256 := by
  unfold UInt8.ofNat UInt8.toNat
  rw [BitVec.toNat_ofNat]

theorem byteMask_mod (n : Nat) :
    (n &&& 0xFF) % 256 = n &&& 0xFF := by
  apply Nat.mod_eq_of_lt
  change n &&& (2^8 - 1) < 2^8
  exact Nat.and_lt_two_pow n (by omega)

theorem mod256_and_ff (n : Nat) :
    n % 256 &&& 255 = n &&& 255 := by
  rw [← Nat.and_two_pow_sub_one_eq_mod n 8]
  change n &&& 255 &&& 255 = n &&& 255
  rw [Nat.and_assoc, Nat.and_self]

theorem uint8_mask_toNat (n : Nat) :
    (UInt8.ofNat (n &&& 0xFF)).toNat = n &&& 0xFF := by
  rw [uint8_toNat_ofNat, byteMask_mod]

theorem uint8_and_ff_toNat (n : Nat) :
    (UInt8.ofNat n &&& 0xFF).toNat = n &&& 0xFF := by
  rw [UInt8.toNat_and, uint8_toNat_ofNat]
  exact mod256_and_ff n

theorem testBit_255 (i : Nat) :
    Nat.testBit 255 i = decide (i < 8) := by
  change Nat.testBit (2^8 - 1) i = decide (i < 8)
  rw [Nat.testBit_two_pow_sub_one]

theorem reconstruct32BE (cp : Nat) (h : cp < 2^32) :
    ((((cp >>> 24) &&& 0xFF) <<< 24)
      ||| (((cp >>> 16) &&& 0xFF) <<< 16)
      ||| (((cp >>> 8) &&& 0xFF) <<< 8)
      ||| (cp &&& 0xFF)) = cp := by
  apply Nat.eq_of_testBit_eq
  intro i
  simp only [Nat.testBit_or, Nat.testBit_shiftLeft, Nat.testBit_shiftRight,
    Nat.testBit_and, testBit_255]
  by_cases h32 : i < 32
  · by_cases h24 : i < 24
    · by_cases h16 : i < 16
      · by_cases h8 : i < 8
        · simp [h8, Nat.not_le_of_lt h8, Nat.not_le_of_lt h16,
            Nat.not_le_of_lt h24]
        · have h8le : 8 ≤ i := Nat.le_of_not_lt h8
          have hSub8 : i - 8 < 8 := by omega
          simp [h8, h8le, hSub8, Nat.not_le_of_lt h16,
            Nat.not_le_of_lt h24, Nat.add_sub_cancel' h8le]
      · have h16le : 16 ≤ i := Nat.le_of_not_lt h16
        have h8le : 8 ≤ i := by omega
        have hNot8 : ¬ i < 8 := by omega
        have hSub16 : i - 16 < 8 := by omega
        have hNotSub8 : ¬ i - 8 < 8 := by omega
        simp [h16le, h8le, hNot8, hSub16, hNotSub8,
          Nat.not_le_of_lt h24, Nat.add_sub_cancel' h16le,
          Nat.add_sub_cancel' h8le]
    · have h24le : 24 ≤ i := Nat.le_of_not_lt h24
      have h16le : 16 ≤ i := by omega
      have h8le : 8 ≤ i := by omega
      have hNot8 : ¬ i < 8 := by omega
      have hSub24 : i - 24 < 8 := by omega
      have hNotSub16 : ¬ i - 16 < 8 := by omega
      have hNotSub8 : ¬ i - 8 < 8 := by omega
      simp [h24le, h16le, h8le, hNot8, hSub24, hNotSub16,
        hNotSub8, Nat.add_sub_cancel' h24le,
        Nat.add_sub_cancel' h16le, Nat.add_sub_cancel' h8le]
  · have hge32 : 32 ≤ i := Nat.le_of_not_lt h32
    have hcp : cp.testBit i = false :=
      Nat.testBit_lt_two_pow (x := cp) (i := i)
        (Nat.lt_of_lt_of_le h
          (Nat.pow_le_pow_right Nat.zero_lt_two hge32))
    have h24le : 24 ≤ i := by omega
    have h16le : 16 ≤ i := by omega
    have h8le : 8 ≤ i := by omega
    have hNot8 : ¬ i < 8 := by omega
    have hNotSub24 : ¬ i - 24 < 8 := by omega
    have hNotSub16 : ¬ i - 16 < 8 := by omega
    have hNotSub8 : ¬ i - 8 < 8 := by omega
    simp [hcp, h24le, h16le, h8le, hNot8, hNotSub24,
      hNotSub16, hNotSub8, Nat.add_sub_cancel' h24le,
      Nat.add_sub_cancel' h16le, Nat.add_sub_cancel' h8le]

theorem reconstruct32LE (cp : Nat) (h : cp < 2^32) :
    ((cp &&& 0xFF)
      ||| (((cp >>> 8) &&& 0xFF) <<< 8)
      ||| (((cp >>> 16) &&& 0xFF) <<< 16)
      ||| (((cp >>> 24) &&& 0xFF) <<< 24)) = cp := by
  let b0 := ((cp >>> 24) &&& 0xFF) <<< 24
  let b1 := ((cp >>> 16) &&& 0xFF) <<< 16
  let b2 := ((cp >>> 8) &&& 0xFF) <<< 8
  let b3 := cp &&& 0xFF
  have hPerm : (((b3 ||| b2) ||| b1) ||| b0) = (((b0 ||| b1) ||| b2) ||| b3) := by
    apply Nat.eq_of_testBit_eq
    intro i
    simp only [Nat.testBit_or]
    by_cases h0 : b0.testBit i <;> by_cases h1 : b1.testBit i
      <;> by_cases h2 : b2.testBit i <;> by_cases h3 : b3.testBit i
      <;> simp [h0, h1, h2, h3]
  calc
    ((cp &&& 0xFF)
        ||| (((cp >>> 8) &&& 0xFF) <<< 8)
        ||| (((cp >>> 16) &&& 0xFF) <<< 16)
        ||| (((cp >>> 24) &&& 0xFF) <<< 24))
        =
      ((((cp >>> 24) &&& 0xFF) <<< 24)
        ||| (((cp >>> 16) &&& 0xFF) <<< 16)
        ||| (((cp >>> 8) &&& 0xFF) <<< 8)
        ||| (cp &&& 0xFF)) := by
          exact hPerm
    ((((cp >>> 24) &&& 0xFF) <<< 24)
        ||| (((cp >>> 16) &&& 0xFF) <<< 16)
        ||| (((cp >>> 8) &&& 0xFF) <<< 8)
        ||| (cp &&& 0xFF)) = cp := reconstruct32BE cp h

theorem decodeOneBE_encodeOneBE_valid (cp : Nat)
    (hMax : cp < 0x110000)
    (hNonsurr : ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF)) :
    decodeOneBE (encodeOneBE cp) = some cp := by
  have h32 : cp < 2^32 := by omega
  have hRec := reconstruct32BE cp h32
  have hNotBeyond : ¬ cp > 0x10FFFF := by omega
  unfold encodeOneBE
  rw [decodeOneBE_mk4]
  simp [mod256_and_ff, hRec, hNotBeyond, hNonsurr]

theorem decodeOneLE_encodeOneLE_valid (cp : Nat)
    (hMax : cp < 0x110000)
    (hNonsurr : ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF)) :
    decodeOneLE (encodeOneLE cp) = some cp := by
  have h32 : cp < 2^32 := by omega
  have hRec := reconstruct32LE cp h32
  have hNotBeyond : ¬ cp > 0x10FFFF := by omega
  unfold encodeOneLE
  rw [decodeOneLE_mk4]
  simp [mod256_and_ff, hRec, hNotBeyond, hNonsurr]

/-- BMP-and-supplementary plane enumeration: for plane 0 (BMP)
    excluding surrogates, the BE roundtrip closes. -/
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

/-- HEADLINE per-codepoint UTF-32 BE roundtrip: every valid scalar
    codepoint encodes-then-decodes back to itself. -/
theorem decodeOneBE_encodeOneBE (cp : Nat) (h : IsValidCodepoint cp) :
    decodeOneBE (encodeOneBE cp) = some cp := by
  obtain ⟨h_max, h_nonsurr⟩ := h
  exact decodeOneBE_encodeOneBE_valid cp h_max h_nonsurr

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 PER-CODEPOINT ROUNDTRIP — LITTLE-ENDIAN VARIANT
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

/-- HEADLINE per-codepoint UTF-32 LE roundtrip. -/
theorem decodeOneLE_encodeOneLE (cp : Nat) (h : IsValidCodepoint cp) :
    decodeOneLE (encodeOneLE cp) = some cp := by
  obtain ⟨h_max, h_nonsurr⟩ := h
  exact decodeOneLE_encodeOneLE_valid cp h_max h_nonsurr

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 ILL-FORMED REJECTION
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Decoder rejects 4-byte sequences encoding a surrogate. -/
theorem decodeOneBE_surrogate_rejected :
    decodeOneBE (encodeOneBE 0xD800) = none := by decide

/-- Decoder rejects 4-byte sequences encoding a value above U+10FFFF. -/
theorem decodeOneBE_beyondMax_rejected :
    decodeOneBE (encodeOneBE 0x110000) = none := by decide

theorem decodeOneLE_surrogate_rejected :
    decodeOneLE (encodeOneLE 0xD800) = none := by decide

theorem decodeOneLE_beyondMax_rejected :
    decodeOneLE (encodeOneLE 0x110000) = none := by decide

/-- Decoder rejects inputs whose length is not exactly 4. -/
theorem decodeOneBE_too_short :
    decodeOneBE (ByteArray.mk #[0x00, 0x00, 0x00]) = none := by decide

theorem decodeOneBE_too_long :
    decodeOneBE (ByteArray.mk #[0x00, 0x00, 0x00, 0x41, 0x00]) = none := by decide

end Unicode.Codec.Utf32
