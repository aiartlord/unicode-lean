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
  Case-split on cp's BMP / supplementary status. In the BMP case the single
  code unit reassembles from its two bytes (`unit16BE` / `unit16LE`); in the
  supplementary case each surrogate reassembles the same way, and
  `0x10000 + (high - 0xD800) <<< 10 + (low - 0xDC00)` inverts the split.
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
-- §3 BIT-REASSEMBLY HELPERS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Disjoint OR with a high shift: `a ||| b <<< i = a + b <<< i` when `a < 2^i`. -/
private theorem or_lo {a b : Nat} (i : Nat) (ha : a < 2 ^ i) :
    a ||| (b <<< i) = a + b <<< i := by
  rw [Nat.or_comm, ← Nat.shiftLeft_add_eq_or_of_lt ha]; omega

/-- `toNat` of the encoded byte carrying bits `[8k, 8k+8)` of a value. -/
private theorem encByte (k u : Nat) :
    (UInt8.ofNat ((u >>> k) &&& 0xFF)).toNat = (u / 2 ^ k) % 256 := by
  rw [Nat.and_two_pow_sub_one_eq_mod (u >>> k) 8, Nat.shiftRight_eq_div_pow u k]
  simp [Nat.mod_eq_of_lt (show (u / 2 ^ k) % 256 < 256 by omega)]

/-- `toNat` of the encoded low byte of a value. -/
private theorem encByte0 (u : Nat) : (UInt8.ofNat (u &&& 0xFF)).toNat = u % 256 := by
  rw [Nat.and_two_pow_sub_one_eq_mod u 8]
  simp [Nat.mod_eq_of_lt (show u % 256 < 256 by omega)]

/-- A 16-bit code unit reassembles from its two big-endian bytes. -/
private theorem unit16BE (u : Nat) (h : u < 0x10000) :
    ((u / 256) % 256) <<< 8 ||| u % 256 = u := by
  rw [← Nat.shiftLeft_add_eq_or_of_lt (show u % 256 < 2 ^ 8 by omega), Nat.shiftLeft_eq]
  have : (u / 256) % 256 = u / 256 := Nat.mod_eq_of_lt (by omega)
  omega

/-- A 16-bit code unit reassembles from its two little-endian bytes. -/
private theorem unit16LE (u : Nat) (h : u < 0x10000) :
    u % 256 ||| ((u / 256) % 256) <<< 8 = u := by
  rw [or_lo 8 (show u % 256 < 2 ^ 8 by omega), Nat.shiftLeft_eq]
  have : (u / 256) % 256 = u / 256 := Nat.mod_eq_of_lt (by omega)
  omega

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 PER-CODEPOINT ROUNDTRIP — BIG ENDIAN
-- ═══════════════════════════════════════════════════════════════════════════════

/-- BMP roundtrip (BE): a non-surrogate code point below U+10000 is a single
    16-bit unit, reassembled from its two bytes by `unit16BE`. -/
private theorem bmpBE (cp : Nat) (hbmp : cp < 0x10000)
    (h_nonsurr : ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF)) :
    decodeOneBE (encodeOneBE cp) = some cp := by
  unfold encodeOneBE
  rw [if_pos hbmp]
  unfold decodeOneBE
  simp only [
    show (⟨#[UInt8.ofNat ((cp >>> 8) &&& 0xFF), UInt8.ofNat (cp &&& 0xFF)]⟩ : ByteArray).size = 2 from rfl,
    ByteArray.getElem_eq_getElem_data, List.getElem_toArray,
    List.getElem_cons_zero, List.getElem_cons_succ, dif_pos,
    encByte 8 cp, encByte0 cp, unit16BE cp hbmp,
    show ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF) from h_nonsurr, if_false]

set_option maxRecDepth 8192 in
/-- Supplementary roundtrip (BE): U+10000..U+10FFFF encodes as a high/low
    surrogate pair; each surrogate is a 16-bit unit, and
    `0x10000 + (high - 0xD800) <<< 10 + (low - 0xDC00)` inverts the split. -/
private theorem suppBE (cp : Nat) (h1 : 0x10000 ≤ cp) (h2 : cp < 0x110000) :
    decodeOneBE (encodeOneBE cp) = some cp := by
  have hmr : (cp - 0x10000) &&& 0x3FF = (cp - 0x10000) % 1024 :=
    Nat.and_two_pow_sub_one_eq_mod (cp - 0x10000) 10
  have hxr : (cp - 0x10000) >>> 10 = (cp - 0x10000) / 1024 :=
    Nat.shiftRight_eq_div_pow (cp - 0x10000) 10
  have hhi : 0xD800 + (cp - 0x10000) >>> 10 < 0x10000 := by rw [hxr]; omega
  have hlo : 0xDC00 + ((cp - 0x10000) &&& 0x3FF) < 0x10000 := by rw [hmr]; omega
  have hrange : 0xD800 ≤ 0xD800 + (cp - 0x10000) >>> 10 ∧
      0xD800 + (cp - 0x10000) >>> 10 ≤ 0xDBFF ∧
      0xDC00 ≤ 0xDC00 + ((cp - 0x10000) &&& 0x3FF) ∧
      0xDC00 + ((cp - 0x10000) &&& 0x3FF) ≤ 0xDFFF :=
    ⟨by omega, by rw [hxr]; omega, by omega, by rw [hmr]; omega⟩
  unfold encodeOneBE
  rw [if_neg (by omega : ¬ cp < 0x10000)]
  unfold decodeOneBE
  simp only [
    show (⟨#[UInt8.ofNat ((0xD800 + (cp - 0x10000) >>> 10) >>> 8 &&& 0xFF),
      UInt8.ofNat ((0xD800 + (cp - 0x10000) >>> 10) &&& 0xFF),
      UInt8.ofNat ((0xDC00 + ((cp - 0x10000) &&& 0x3FF)) >>> 8 &&& 0xFF),
      UInt8.ofNat ((0xDC00 + ((cp - 0x10000) &&& 0x3FF)) &&& 0xFF)]⟩ : ByteArray).size = 4 from rfl,
    ByteArray.getElem_eq_getElem_data, List.getElem_toArray,
    List.getElem_cons_zero, List.getElem_cons_succ, dif_pos,
    encByte 8 (0xD800 + (cp - 0x10000) >>> 10), encByte0 (0xD800 + (cp - 0x10000) >>> 10),
    encByte 8 (0xDC00 + ((cp - 0x10000) &&& 0x3FF)), encByte0 (0xDC00 + ((cp - 0x10000) &&& 0x3FF)),
    unit16BE (0xD800 + (cp - 0x10000) >>> 10) hhi,
    unit16BE (0xDC00 + ((cp - 0x10000) &&& 0x3FF)) hlo,
    show (0xD800 ≤ 0xD800 + (cp - 0x10000) >>> 10 ∧
      0xD800 + (cp - 0x10000) >>> 10 ≤ 0xDBFF ∧
      0xDC00 ≤ 0xDC00 + ((cp - 0x10000) &&& 0x3FF) ∧
      0xDC00 + ((cp - 0x10000) &&& 0x3FF) ≤ 0xDFFF) = True from eq_true hrange,
    if_true]
  split
  · exact absurd (by assumption : (4 : Nat) = 2) (by decide)
  · rw [Option.some.injEq, Nat.shiftLeft_eq, hxr, hmr]
    omega

/-- Per-codepoint UTF-16 BE roundtrip. -/
theorem decodeOneBE_encodeOneBE (cp : Nat) (h : IsValidCodepoint cp) :
    decodeOneBE (encodeOneBE cp) = some cp := by
  obtain ⟨h_max, h_nonsurr⟩ := h
  by_cases hbmp : cp < 0x10000
  · exact bmpBE cp hbmp h_nonsurr
  · exact suppBE cp (by omega) h_max

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 PER-CODEPOINT ROUNDTRIP — LITTLE ENDIAN
-- ═══════════════════════════════════════════════════════════════════════════════

/-- BMP roundtrip (LE): a non-surrogate code point below U+10000 is a single
    16-bit unit, reassembled from its two bytes by `unit16LE`. -/
private theorem bmpLE (cp : Nat) (hbmp : cp < 0x10000)
    (h_nonsurr : ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF)) :
    decodeOneLE (encodeOneLE cp) = some cp := by
  unfold encodeOneLE
  rw [if_pos hbmp]
  unfold decodeOneLE
  simp only [
    show (⟨#[UInt8.ofNat (cp &&& 0xFF), UInt8.ofNat ((cp >>> 8) &&& 0xFF)]⟩ : ByteArray).size = 2 from rfl,
    ByteArray.getElem_eq_getElem_data, List.getElem_toArray,
    List.getElem_cons_zero, List.getElem_cons_succ, dif_pos,
    encByte0 cp, encByte 8 cp, unit16LE cp hbmp,
    show ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF) from h_nonsurr, if_false]

set_option maxRecDepth 8192 in
/-- Supplementary roundtrip (LE): the high/low surrogate pair, little-endian. -/
private theorem suppLE (cp : Nat) (h1 : 0x10000 ≤ cp) (h2 : cp < 0x110000) :
    decodeOneLE (encodeOneLE cp) = some cp := by
  have hmr : (cp - 0x10000) &&& 0x3FF = (cp - 0x10000) % 1024 :=
    Nat.and_two_pow_sub_one_eq_mod (cp - 0x10000) 10
  have hxr : (cp - 0x10000) >>> 10 = (cp - 0x10000) / 1024 :=
    Nat.shiftRight_eq_div_pow (cp - 0x10000) 10
  have hhi : 0xD800 + (cp - 0x10000) >>> 10 < 0x10000 := by rw [hxr]; omega
  have hlo : 0xDC00 + ((cp - 0x10000) &&& 0x3FF) < 0x10000 := by rw [hmr]; omega
  have hrange : 0xD800 ≤ 0xD800 + (cp - 0x10000) >>> 10 ∧
      0xD800 + (cp - 0x10000) >>> 10 ≤ 0xDBFF ∧
      0xDC00 ≤ 0xDC00 + ((cp - 0x10000) &&& 0x3FF) ∧
      0xDC00 + ((cp - 0x10000) &&& 0x3FF) ≤ 0xDFFF :=
    ⟨by omega, by rw [hxr]; omega, by omega, by rw [hmr]; omega⟩
  unfold encodeOneLE
  rw [if_neg (by omega : ¬ cp < 0x10000)]
  unfold decodeOneLE
  simp only [
    show (⟨#[UInt8.ofNat ((0xD800 + (cp - 0x10000) >>> 10) &&& 0xFF),
      UInt8.ofNat ((0xD800 + (cp - 0x10000) >>> 10) >>> 8 &&& 0xFF),
      UInt8.ofNat ((0xDC00 + ((cp - 0x10000) &&& 0x3FF)) &&& 0xFF),
      UInt8.ofNat ((0xDC00 + ((cp - 0x10000) &&& 0x3FF)) >>> 8 &&& 0xFF)]⟩ : ByteArray).size = 4 from rfl,
    ByteArray.getElem_eq_getElem_data, List.getElem_toArray,
    List.getElem_cons_zero, List.getElem_cons_succ, dif_pos,
    encByte0 (0xD800 + (cp - 0x10000) >>> 10), encByte 8 (0xD800 + (cp - 0x10000) >>> 10),
    encByte0 (0xDC00 + ((cp - 0x10000) &&& 0x3FF)), encByte 8 (0xDC00 + ((cp - 0x10000) &&& 0x3FF)),
    unit16LE (0xD800 + (cp - 0x10000) >>> 10) hhi,
    unit16LE (0xDC00 + ((cp - 0x10000) &&& 0x3FF)) hlo,
    show (0xD800 ≤ 0xD800 + (cp - 0x10000) >>> 10 ∧
      0xD800 + (cp - 0x10000) >>> 10 ≤ 0xDBFF ∧
      0xDC00 ≤ 0xDC00 + ((cp - 0x10000) &&& 0x3FF) ∧
      0xDC00 + ((cp - 0x10000) &&& 0x3FF) ≤ 0xDFFF) = True from eq_true hrange,
    if_true]
  split
  · exact absurd (by assumption : (4 : Nat) = 2) (by decide)
  · rw [Option.some.injEq, Nat.shiftLeft_eq, hxr, hmr]
    omega

/-- Per-codepoint UTF-16 LE roundtrip. -/
theorem decodeOneLE_encodeOneLE (cp : Nat) (h : IsValidCodepoint cp) :
    decodeOneLE (encodeOneLE cp) = some cp := by
  obtain ⟨h_max, h_nonsurr⟩ := h
  by_cases hbmp : cp < 0x10000
  · exact bmpLE cp hbmp h_nonsurr
  · exact suppLE cp (by omega) h_max

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 ILL-FORMED REJECTION
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
