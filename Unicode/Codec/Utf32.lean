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
  proven STRUCTURALLY over the whole scalar range: the four encoded
  bytes are `(cp / 2^k) % 256` (via `Nat.and_two_pow_sub_one_eq_mod`
  and `Nat.shiftRight_eq_div_pow`), and the decoder's `|||`/`<<<`
  reassembly recombines them to `cp` (`reassembleBE32` / `reassembleLE32`,
  each a disjoint-OR chain discharged by `Nat.shiftLeft_add_eq_or_of_lt`
  plus `omega`). No enumeration, no `native_decide`; no Mathlib;
  Lean 4 core only.
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
-- §3 BIT-REASSEMBLY HELPERS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Disjoint OR with a high shift: `a ||| b <<< i = a + b <<< i` when `a < 2^i`
    (little-endian byte order peels the low value off the left). -/
private theorem or_lo {a b : Nat} (i : Nat) (ha : a < 2 ^ i) :
    a ||| (b <<< i) = a + b <<< i := by
  rw [Nat.or_comm, ← Nat.shiftLeft_add_eq_or_of_lt ha]; omega

/-- Big-endian 4-byte reassembly: the masked/shifted bytes recombine to `cp`. -/
private theorem reassembleBE32 (cp : Nat) (h : cp < 0x110000) :
    ((((cp / 16777216) % 256) <<< 24 ||| ((cp / 65536) % 256) <<< 16) |||
      ((cp / 256) % 256) <<< 8) ||| (cp % 256) = cp := by
  rw [Nat.or_assoc, Nat.or_assoc,
    ← Nat.shiftLeft_add_eq_or_of_lt (show cp % 256 < 2 ^ 8 by omega),
    ← Nat.shiftLeft_add_eq_or_of_lt
      (show ((cp / 256) % 256) <<< 8 + cp % 256 < 2 ^ 16 by rw [Nat.shiftLeft_eq]; omega),
    ← Nat.shiftLeft_add_eq_or_of_lt
      (show ((cp / 65536) % 256) <<< 16 + (((cp / 256) % 256) <<< 8 + cp % 256) < 2 ^ 24 by
        rw [Nat.shiftLeft_eq, Nat.shiftLeft_eq]; omega),
    Nat.shiftLeft_eq, Nat.shiftLeft_eq, Nat.shiftLeft_eq]
  have dd1 : (cp / 256) / 256 = cp / 65536 := Nat.div_div_eq_div_mul cp 256 256
  have dd2 : (cp / 65536) / 256 = cp / 16777216 := Nat.div_div_eq_div_mul cp 65536 256
  omega

/-- Little-endian 4-byte reassembly: the masked/shifted bytes recombine to `cp`. -/
private theorem reassembleLE32 (cp : Nat) (h : cp < 0x110000) :
    ((cp % 256 ||| ((cp / 256) % 256) <<< 8) ||| ((cp / 65536) % 256) <<< 16) |||
      ((cp / 16777216) % 256) <<< 24 = cp := by
  have h8 : cp % 256 < 2 ^ 8 := by omega
  have h16 : cp % 256 + ((cp / 256) % 256) <<< 8 < 2 ^ 16 := by
    rw [Nat.shiftLeft_eq]; omega
  have h24 : cp % 256 + ((cp / 256) % 256) <<< 8 + ((cp / 65536) % 256) <<< 16 < 2 ^ 24 := by
    rw [Nat.shiftLeft_eq, Nat.shiftLeft_eq]; omega
  rw [or_lo 8 h8, or_lo 16 h16, or_lo 24 h24]
  simp only [Nat.shiftLeft_eq]
  have dd1 : (cp / 256) / 256 = cp / 65536 := Nat.div_div_eq_div_mul cp 256 256
  have dd2 : (cp / 65536) / 256 = cp / 16777216 := Nat.div_div_eq_div_mul cp 65536 256
  omega

/-- HEADLINE per-codepoint UTF-32 BE roundtrip: every valid scalar codepoint
    encodes-then-decodes back to itself — structural, no enumeration. -/
theorem decodeOneBE_encodeOneBE (cp : Nat) (h : IsValidCodepoint cp) :
    decodeOneBE (encodeOneBE cp) = some cp := by
  obtain ⟨h_max, h_nonsurr⟩ := h
  have hb0 : (UInt8.ofNat ((cp >>> 24) &&& 0xFF)).toNat = (cp / 16777216) % 256 := by
    rw [Nat.and_two_pow_sub_one_eq_mod (cp >>> 24) 8, Nat.shiftRight_eq_div_pow cp 24]
    simp [Nat.mod_eq_of_lt (show (cp / 16777216) % 256 < 256 by omega)]
  have hb1 : (UInt8.ofNat ((cp >>> 16) &&& 0xFF)).toNat = (cp / 65536) % 256 := by
    rw [Nat.and_two_pow_sub_one_eq_mod (cp >>> 16) 8, Nat.shiftRight_eq_div_pow cp 16]
    simp [Nat.mod_eq_of_lt (show (cp / 65536) % 256 < 256 by omega)]
  have hb2 : (UInt8.ofNat ((cp >>> 8) &&& 0xFF)).toNat = (cp / 256) % 256 := by
    rw [Nat.and_two_pow_sub_one_eq_mod (cp >>> 8) 8, Nat.shiftRight_eq_div_pow cp 8]
    simp [Nat.mod_eq_of_lt (show (cp / 256) % 256 < 256 by omega)]
  have hb3 : (UInt8.ofNat (cp &&& 0xFF)).toNat = cp % 256 := by
    rw [Nat.and_two_pow_sub_one_eq_mod cp 8]
    simp [Nat.mod_eq_of_lt (show cp % 256 < 256 by omega)]
  unfold decodeOneBE encodeOneBE
  simp only [
    show (⟨#[UInt8.ofNat ((cp >>> 24) &&& 0xFF), UInt8.ofNat ((cp >>> 16) &&& 0xFF), UInt8.ofNat ((cp >>> 8) &&& 0xFF), UInt8.ofNat (cp &&& 0xFF)]⟩ : ByteArray).size = 4 from rfl,
    ByteArray.getElem_eq_getElem_data,
    List.getElem_toArray, List.getElem_cons_zero, List.getElem_cons_succ,
    dif_pos, hb0, hb1, hb2, hb3, reassembleBE32 cp h_max,
    show ¬ (cp > 0x10FFFF) from by omega,
    show ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF) from h_nonsurr,
    if_false]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 PER-CODEPOINT ROUNDTRIP — LITTLE-ENDIAN VARIANT
-- ═══════════════════════════════════════════════════════════════════════════════

/-- HEADLINE per-codepoint UTF-32 LE roundtrip: every valid scalar codepoint
    encodes-then-decodes back to itself — structural, no enumeration. -/
theorem decodeOneLE_encodeOneLE (cp : Nat) (h : IsValidCodepoint cp) :
    decodeOneLE (encodeOneLE cp) = some cp := by
  obtain ⟨h_max, h_nonsurr⟩ := h
  have hb0 : (UInt8.ofNat (cp &&& 0xFF)).toNat = cp % 256 := by
    rw [Nat.and_two_pow_sub_one_eq_mod cp 8]
    simp [Nat.mod_eq_of_lt (show cp % 256 < 256 by omega)]
  have hb1 : (UInt8.ofNat ((cp >>> 8) &&& 0xFF)).toNat = (cp / 256) % 256 := by
    rw [Nat.and_two_pow_sub_one_eq_mod (cp >>> 8) 8, Nat.shiftRight_eq_div_pow cp 8]
    simp [Nat.mod_eq_of_lt (show (cp / 256) % 256 < 256 by omega)]
  have hb2 : (UInt8.ofNat ((cp >>> 16) &&& 0xFF)).toNat = (cp / 65536) % 256 := by
    rw [Nat.and_two_pow_sub_one_eq_mod (cp >>> 16) 8, Nat.shiftRight_eq_div_pow cp 16]
    simp [Nat.mod_eq_of_lt (show (cp / 65536) % 256 < 256 by omega)]
  have hb3 : (UInt8.ofNat ((cp >>> 24) &&& 0xFF)).toNat = (cp / 16777216) % 256 := by
    rw [Nat.and_two_pow_sub_one_eq_mod (cp >>> 24) 8, Nat.shiftRight_eq_div_pow cp 24]
    simp [Nat.mod_eq_of_lt (show (cp / 16777216) % 256 < 256 by omega)]
  unfold decodeOneLE encodeOneLE
  simp only [
    show (⟨#[UInt8.ofNat (cp &&& 0xFF), UInt8.ofNat ((cp >>> 8) &&& 0xFF), UInt8.ofNat ((cp >>> 16) &&& 0xFF), UInt8.ofNat ((cp >>> 24) &&& 0xFF)]⟩ : ByteArray).size = 4 from rfl,
    ByteArray.getElem_eq_getElem_data,
    List.getElem_toArray, List.getElem_cons_zero, List.getElem_cons_succ,
    dif_pos, hb0, hb1, hb2, hb3, reassembleLE32 cp h_max,
    show ¬ (cp > 0x10FFFF) from by omega,
    show ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF) from h_nonsurr,
    if_false]

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
