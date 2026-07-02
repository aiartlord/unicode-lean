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

/-- ASCII (1-byte) codepoint roundtrip — structural, no enumeration.
    `encodeCodepoint` takes the `cp < 0x80` branch to the single byte
    `UInt8.ofNat cp`; the decode fold runs one `utf8DecodeStep` in
    `.expectStart`, whose `n < 0x80` branch emits `cp`, then terminates. -/
theorem decode_encode_ascii (cp : Nat) (h : cp < 0x80) :
    decodeToCodepoints (encodeCodepoint cp) = #[cp] := by
  have h256 : cp < 256 := by omega
  have hb : (UInt8.ofNat cp).toNat = cp := by
    simp [Nat.mod_eq_of_lt h256]
  unfold decodeToCodepoints encodeCodepoint
  rw [if_pos h]
  simp [Unicode.Codec.Utf8.foldCodepointsWithOffset,
    Unicode.Codec.Utf8.foldCodepointsWithOffsetGo,
    Unicode.Codec.Utf8.utf8DecodeStep,
    ByteArray.getElem_eq_getElem_data,
    show (⟨#[UInt8.ofNat cp]⟩ : ByteArray).size = 1 from rfl,
    hb, h, Function.const]

/-- Bounded `Fin 0x80` restatement of `decode_encode_ascii`. -/
theorem decode_encode_ascii_fin :
    ∀ cp : Fin 0x80,
      decodeToCodepoints (encodeCodepoint cp.val) = #[cp.val] :=
  fun cp => decode_encode_ascii cp.val cp.isLt

-- Bit-reassembly helpers shared by the multi-byte roundtrip proofs. Each
-- recovers the payload bits a UTF-8 byte carries once the byte is written in
-- `const + payload` arithmetic form (the decoder masks with `0x1F`/`0x3F`).

/-- Recover the 5 payload bits of a 2-byte lead byte: `(0xC0 + x) &&& 0x1F = x`. -/
private theorem mask5 (x : Nat) (hx : x < 32) : (192 + x) &&& 0x1F = x := by
  have hxor : 192 + x = 0xC0 ||| x := by
    rw [show (0xC0 : Nat) = 3 <<< 6 from by decide,
      ← Nat.shiftLeft_add_eq_or_of_lt (show x < 2 ^ 6 by omega), Nat.shiftLeft_eq]
  rw [hxor, Nat.and_or_distrib_right, show (0xC0 &&& 0x1F : Nat) = 0 from by decide, Nat.zero_or]
  exact Nat.and_two_pow_sub_one_of_lt_two_pow (n := 5) hx

/-- Recover the 6 payload bits of a continuation byte: `(0x80 + y) &&& 0x3F = y`. -/
private theorem mask6 (y : Nat) (hy : y < 64) : (128 + y) &&& 0x3F = y := by
  have hyor : 128 + y = 0x80 ||| y := by
    rw [show (0x80 : Nat) = 2 <<< 6 from by decide,
      ← Nat.shiftLeft_add_eq_or_of_lt (show y < 2 ^ 6 by omega), Nat.shiftLeft_eq]
  rw [hyor, Nat.and_or_distrib_right, show (0x80 &&& 0x3F : Nat) = 0 from by decide, Nat.zero_or]
  exact Nat.and_two_pow_sub_one_of_lt_two_pow (n := 6) hy

/-- Reassemble a 6-bit split back into `cp`: `(cp / 64) <<< 6 ||| cp % 64 = cp`. -/
private theorem reassemble2 (cp : Nat) : ((cp / 64) <<< 6) ||| (cp % 64) = cp := by
  rw [← Nat.shiftLeft_add_eq_or_of_lt (show cp % 64 < 2 ^ 6 by omega), Nat.shiftLeft_eq]
  omega

/-- Recover the 4 payload bits of a 3-byte lead byte: `(0xE0 + x) &&& 0x0F = x`. -/
private theorem mask4 (x : Nat) (hx : x < 16) : (224 + x) &&& 0x0F = x := by
  have hxor : 224 + x = 0xE0 ||| x := by
    rw [show (0xE0 : Nat) = 7 <<< 5 from by decide,
      ← Nat.shiftLeft_add_eq_or_of_lt (show x < 2 ^ 5 by omega), Nat.shiftLeft_eq]
  rw [hxor, Nat.and_or_distrib_right, show (0xE0 &&& 0x0F : Nat) = 0 from by decide, Nat.zero_or]
  exact Nat.and_two_pow_sub_one_of_lt_two_pow (n := 4) hx

/-- Recover the 3 payload bits of a 4-byte lead byte: `(0xF0 + x) &&& 0x07 = x`. -/
private theorem mask3 (x : Nat) (hx : x < 8) : (240 + x) &&& 0x07 = x := by
  have hxor : 240 + x = 0xF0 ||| x := by
    rw [show (0xF0 : Nat) = 15 <<< 4 from by decide,
      ← Nat.shiftLeft_add_eq_or_of_lt (show x < 2 ^ 4 by omega), Nat.shiftLeft_eq]
  rw [hxor, Nat.and_or_distrib_right, show (0xF0 &&& 0x07 : Nat) = 0 from by decide, Nat.zero_or]
  exact Nat.and_two_pow_sub_one_of_lt_two_pow (n := 3) hx

/-- Reassemble a three-part (4/6/6-bit) split back into `cp`. -/
private theorem reassemble3 (cp : Nat) :
    ((((cp / 4096) <<< 6) ||| ((cp / 64) % 64)) <<< 6) ||| (cp % 64) = cp := by
  rw [← Nat.shiftLeft_add_eq_or_of_lt (show cp % 64 < 2 ^ 6 by omega),
    ← Nat.shiftLeft_add_eq_or_of_lt (show (cp / 64) % 64 < 2 ^ 6 by omega),
    Nat.shiftLeft_eq, Nat.shiftLeft_eq]
  omega

/-- Reassemble a four-part (3/6/6/6-bit) split back into `cp`. -/
private theorem reassemble4 (cp : Nat) :
    ((((((cp / 262144) <<< 6) ||| ((cp / 4096) % 64)) <<< 6) ||| ((cp / 64) % 64)) <<< 6) ||| (cp % 64) = cp := by
  rw [← Nat.shiftLeft_add_eq_or_of_lt (show cp % 64 < 2 ^ 6 by omega),
    ← Nat.shiftLeft_add_eq_or_of_lt (show (cp / 64) % 64 < 2 ^ 6 by omega),
    ← Nat.shiftLeft_add_eq_or_of_lt (show (cp / 4096) % 64 < 2 ^ 6 by omega),
    Nat.shiftLeft_eq, Nat.shiftLeft_eq, Nat.shiftLeft_eq]
  omega

/-- 2-byte codepoint roundtrip (covers `cp < 0x800`) — structural, no
    enumeration. For `cp < 0x80` this is the 1-byte roundtrip; for
    `0x80 ≤ cp` the encoder emits a `110xxxxx 10xxxxxx` pair and the decode
    fold reassembles it via `mask5`/`mask6`/`reassemble2`. -/
theorem decode_encode_2byte (cp : Nat) (h : cp < 0x800) :
    decodeToCodepoints (encodeCodepoint cp) = #[cp] := by
  by_cases h80 : cp < 0x80
  · exact decode_encode_ascii cp h80
  · have ha : cp >>> 6 = cp / 64 := Nat.shiftRight_eq_div_pow cp 6
    have hb : cp &&& 0x3F = cp % 64 := Nat.and_two_pow_sub_one_eq_mod cp 6
    have hor0 : (0xC0 ||| (cp >>> 6)) = 192 + cp / 64 := by
      rw [ha, show (0xC0 : Nat) = 3 <<< 6 from by decide,
        ← Nat.shiftLeft_add_eq_or_of_lt (show cp / 64 < 2 ^ 6 by omega), Nat.shiftLeft_eq]
    have hor1 : (0x80 ||| (cp &&& 0x3F)) = 128 + cp % 64 := by
      rw [hb, show (0x80 : Nat) = 2 <<< 6 from by decide,
        ← Nat.shiftLeft_add_eq_or_of_lt (show cp % 64 < 2 ^ 6 by omega), Nat.shiftLeft_eq]
    have hb0 : (UInt8.ofNat (0xC0 ||| (cp >>> 6))).toNat = 192 + cp / 64 := by
      rw [hor0]; simp [Nat.mod_eq_of_lt (show 192 + cp / 64 < 256 by omega)]
    have hb1 : (UInt8.ofNat (0x80 ||| (cp &&& 0x3F))).toNat = 128 + cp % 64 := by
      rw [hor1]; simp [Nat.mod_eq_of_lt (show 128 + cp % 64 < 256 by omega)]
    unfold decodeToCodepoints encodeCodepoint
    rw [if_neg h80, if_pos h]
    simp only [Unicode.Codec.Utf8.foldCodepointsWithOffset,
      Unicode.Codec.Utf8.foldCodepointsWithOffsetGo,
      Unicode.Codec.Utf8.utf8DecodeStep,
      ByteArray.getElem_eq_getElem_data,
      show (⟨#[UInt8.ofNat (0xC0 ||| (cp >>> 6)), UInt8.ofNat (0x80 ||| (cp &&& 0x3F))]⟩ : ByteArray).size = 2 from rfl,
      List.getElem_toArray, List.getElem_cons_zero, List.getElem_cons_succ,
      if_true, if_false, or_self,
      hb0, hb1,
      show ¬ (192 + cp / 64 < 128) from by omega,
      show ¬ (192 + cp / 64 < 194) from by omega,
      show (192 + cp / 64 < 224) from by omega,
      show ¬ (128 + cp % 64 < 128) from by omega,
      show ¬ (0xC0 ≤ 128 + cp % 64) from by omega,
      mask5 (cp / 64) (by omega), mask6 (cp % 64) (by omega),
      reassemble2 cp,
      show ¬ (cp < 128) from by omega,
      show ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF) from by omega,
      show ¬ (cp > 0x10FFFF) from by omega,
      Function.const]
    rfl

/-- Bounded `Fin 0x800` restatement of `decode_encode_2byte`. -/
theorem decode_encode_2byte_fin :
    ∀ cp : Fin 0x800,
      decodeToCodepoints (encodeCodepoint cp.val) = #[cp.val] :=
  fun cp => decode_encode_2byte cp.val cp.isLt

/-- BMP codepoint roundtrip (covers `cp < 0x10000` minus surrogates) —
    structural, no enumeration. For `cp < 0x800` reduces to the 1/2-byte
    roundtrip; for `0x800 ≤ cp` the encoder emits `1110xxxx 10xxxxxx 10xxxxxx`
    which the decode fold reassembles via `mask4`/`mask6`/`reassemble3`. -/
theorem decode_encode_3byte (cp : Nat) (h : cp < 0x10000)
    (h_nonsurr : ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF)) :
    decodeToCodepoints (encodeCodepoint cp) = #[cp] := by
  by_cases h800 : cp < 0x800
  · exact decode_encode_2byte cp h800
  · have ha12 : cp >>> 12 = cp / 4096 := Nat.shiftRight_eq_div_pow cp 12
    have hm6 : (cp >>> 6) &&& 0x3F = (cp / 64) % 64 := by
      rw [Nat.and_two_pow_sub_one_eq_mod (cp >>> 6) 6, Nat.shiftRight_eq_div_pow cp 6]
    have hb2 : cp &&& 0x3F = cp % 64 := Nat.and_two_pow_sub_one_eq_mod cp 6
    have hor0 : (0xE0 ||| (cp >>> 12)) = 224 + cp / 4096 := by
      rw [ha12, show (0xE0 : Nat) = 7 <<< 5 from by decide,
        ← Nat.shiftLeft_add_eq_or_of_lt (show cp / 4096 < 2 ^ 5 by omega), Nat.shiftLeft_eq]
    have hor1 : (0x80 ||| ((cp >>> 6) &&& 0x3F)) = 128 + (cp / 64) % 64 := by
      rw [hm6, show (0x80 : Nat) = 2 <<< 6 from by decide,
        ← Nat.shiftLeft_add_eq_or_of_lt (show (cp / 64) % 64 < 2 ^ 6 by omega), Nat.shiftLeft_eq]
    have hor2 : (0x80 ||| (cp &&& 0x3F)) = 128 + cp % 64 := by
      rw [hb2, show (0x80 : Nat) = 2 <<< 6 from by decide,
        ← Nat.shiftLeft_add_eq_or_of_lt (show cp % 64 < 2 ^ 6 by omega), Nat.shiftLeft_eq]
    have hb0 : (UInt8.ofNat (0xE0 ||| (cp >>> 12))).toNat = 224 + cp / 4096 := by
      rw [hor0]; simp [Nat.mod_eq_of_lt (show 224 + cp / 4096 < 256 by omega)]
    have hb1 : (UInt8.ofNat (0x80 ||| ((cp >>> 6) &&& 0x3F))).toNat = 128 + (cp / 64) % 64 := by
      rw [hor1]; simp [Nat.mod_eq_of_lt (show 128 + (cp / 64) % 64 < 256 by omega)]
    have hb2t : (UInt8.ofNat (0x80 ||| (cp &&& 0x3F))).toNat = 128 + cp % 64 := by
      rw [hor2]; simp [Nat.mod_eq_of_lt (show 128 + cp % 64 < 256 by omega)]
    unfold decodeToCodepoints encodeCodepoint
    rw [if_neg (by omega : ¬ cp < 0x80), if_neg h800, if_pos h]
    simp only [Unicode.Codec.Utf8.foldCodepointsWithOffset,
      Unicode.Codec.Utf8.foldCodepointsWithOffsetGo,
      Unicode.Codec.Utf8.utf8DecodeStep,
      ByteArray.getElem_eq_getElem_data,
      show (⟨#[UInt8.ofNat (0xE0 ||| (cp >>> 12)), UInt8.ofNat (0x80 ||| ((cp >>> 6) &&& 0x3F)), UInt8.ofNat (0x80 ||| (cp &&& 0x3F))]⟩ : ByteArray).size = 3 from rfl,
      List.getElem_toArray, List.getElem_cons_zero, List.getElem_cons_succ,
      if_true, if_false, or_self,
      hb0, hb1, hb2t,
      show ¬ (224 + cp / 4096 < 128) from by omega,
      show ¬ (224 + cp / 4096 < 194) from by omega,
      show ¬ (224 + cp / 4096 < 224) from by omega,
      show (224 + cp / 4096 < 240) from by omega,
      show ¬ (128 + (cp / 64) % 64 < 128) from by omega,
      show ¬ (0xC0 ≤ 128 + (cp / 64) % 64) from by omega,
      show ¬ (128 + cp % 64 < 128) from by omega,
      show ¬ (0xC0 ≤ 128 + cp % 64) from by omega,
      mask4 (cp / 4096) (by omega), mask6 ((cp / 64) % 64) (by omega),
      mask6 (cp % 64) (by omega),
      reassemble3 cp,
      show ¬ (cp < 0x800) from by omega,
      show ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF) from h_nonsurr,
      show ¬ (cp > 0x10FFFF) from by omega,
      Function.const]
    rfl

/-- Bounded `Fin 0x10000` (non-surrogate) restatement of `decode_encode_3byte`. -/
theorem decode_encode_3byte_fin :
    ∀ cp : Fin 0x10000,
      ¬ (0xD800 ≤ cp.val ∧ cp.val ≤ 0xDFFF) →
      decodeToCodepoints (encodeCodepoint cp.val) = #[cp.val] :=
  fun cp hns => decode_encode_3byte cp.val cp.isLt hns

/-- 4-byte codepoint roundtrip (covers `0x10000 ≤ cp < 0x110000`) —
    structural, no enumeration. The encoder emits
    `11110xxx 10xxxxxx 10xxxxxx 10xxxxxx`; the decode fold reassembles it
    via `mask3`/`mask6`/`reassemble4`. -/
theorem decode_encode_4byte (cp : Nat) (h_lo : 0x10000 ≤ cp) (h_hi : cp < 0x110000) :
    decodeToCodepoints (encodeCodepoint cp) = #[cp] := by
  have ha18 : cp >>> 18 = cp / 262144 := Nat.shiftRight_eq_div_pow cp 18
  have hm12 : (cp >>> 12) &&& 0x3F = (cp / 4096) % 64 := by
    rw [Nat.and_two_pow_sub_one_eq_mod (cp >>> 12) 6, Nat.shiftRight_eq_div_pow cp 12]
  have hm6 : (cp >>> 6) &&& 0x3F = (cp / 64) % 64 := by
    rw [Nat.and_two_pow_sub_one_eq_mod (cp >>> 6) 6, Nat.shiftRight_eq_div_pow cp 6]
  have hb3 : cp &&& 0x3F = cp % 64 := Nat.and_two_pow_sub_one_eq_mod cp 6
  have hor0 : (0xF0 ||| (cp >>> 18)) = 240 + cp / 262144 := by
    rw [ha18, show (0xF0 : Nat) = 15 <<< 4 from by decide,
      ← Nat.shiftLeft_add_eq_or_of_lt (show cp / 262144 < 2 ^ 4 by omega), Nat.shiftLeft_eq]
  have hor1 : (0x80 ||| ((cp >>> 12) &&& 0x3F)) = 128 + (cp / 4096) % 64 := by
    rw [hm12, show (0x80 : Nat) = 2 <<< 6 from by decide,
      ← Nat.shiftLeft_add_eq_or_of_lt (show (cp / 4096) % 64 < 2 ^ 6 by omega), Nat.shiftLeft_eq]
  have hor2 : (0x80 ||| ((cp >>> 6) &&& 0x3F)) = 128 + (cp / 64) % 64 := by
    rw [hm6, show (0x80 : Nat) = 2 <<< 6 from by decide,
      ← Nat.shiftLeft_add_eq_or_of_lt (show (cp / 64) % 64 < 2 ^ 6 by omega), Nat.shiftLeft_eq]
  have hor3 : (0x80 ||| (cp &&& 0x3F)) = 128 + cp % 64 := by
    rw [hb3, show (0x80 : Nat) = 2 <<< 6 from by decide,
      ← Nat.shiftLeft_add_eq_or_of_lt (show cp % 64 < 2 ^ 6 by omega), Nat.shiftLeft_eq]
  have hb0 : (UInt8.ofNat (0xF0 ||| (cp >>> 18))).toNat = 240 + cp / 262144 := by
    rw [hor0]; simp [Nat.mod_eq_of_lt (show 240 + cp / 262144 < 256 by omega)]
  have hb1 : (UInt8.ofNat (0x80 ||| ((cp >>> 12) &&& 0x3F))).toNat = 128 + (cp / 4096) % 64 := by
    rw [hor1]; simp [Nat.mod_eq_of_lt (show 128 + (cp / 4096) % 64 < 256 by omega)]
  have hb2 : (UInt8.ofNat (0x80 ||| ((cp >>> 6) &&& 0x3F))).toNat = 128 + (cp / 64) % 64 := by
    rw [hor2]; simp [Nat.mod_eq_of_lt (show 128 + (cp / 64) % 64 < 256 by omega)]
  have hb3t : (UInt8.ofNat (0x80 ||| (cp &&& 0x3F))).toNat = 128 + cp % 64 := by
    rw [hor3]; simp [Nat.mod_eq_of_lt (show 128 + cp % 64 < 256 by omega)]
  unfold decodeToCodepoints encodeCodepoint
  rw [if_neg (by omega : ¬ cp < 0x80), if_neg (by omega : ¬ cp < 0x800),
    if_neg (by omega : ¬ cp < 0x10000)]
  simp only [Unicode.Codec.Utf8.foldCodepointsWithOffset,
    Unicode.Codec.Utf8.foldCodepointsWithOffsetGo,
    Unicode.Codec.Utf8.utf8DecodeStep,
    ByteArray.getElem_eq_getElem_data,
    show (⟨#[UInt8.ofNat (0xF0 ||| (cp >>> 18)), UInt8.ofNat (0x80 ||| ((cp >>> 12) &&& 0x3F)), UInt8.ofNat (0x80 ||| ((cp >>> 6) &&& 0x3F)), UInt8.ofNat (0x80 ||| (cp &&& 0x3F))]⟩ : ByteArray).size = 4 from rfl,
    List.getElem_toArray, List.getElem_cons_zero, List.getElem_cons_succ,
    if_true, if_false, or_self,
    hb0, hb1, hb2, hb3t,
    show ¬ (240 + cp / 262144 < 128) from by omega,
    show ¬ (240 + cp / 262144 < 194) from by omega,
    show ¬ (240 + cp / 262144 < 224) from by omega,
    show ¬ (240 + cp / 262144 < 240) from by omega,
    show (240 + cp / 262144 < 245) from by omega,
    show ¬ (128 + (cp / 4096) % 64 < 128) from by omega,
    show ¬ (0xC0 ≤ 128 + (cp / 4096) % 64) from by omega,
    show ¬ (128 + (cp / 64) % 64 < 128) from by omega,
    show ¬ (0xC0 ≤ 128 + (cp / 64) % 64) from by omega,
    show ¬ (128 + cp % 64 < 128) from by omega,
    show ¬ (0xC0 ≤ 128 + cp % 64) from by omega,
    mask3 (cp / 262144) (by omega), mask6 ((cp / 4096) % 64) (by omega),
    mask6 ((cp / 64) % 64) (by omega), mask6 (cp % 64) (by omega),
    reassemble4 cp,
    show ¬ (cp < 0x10000) from by omega,
    show ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF) from by omega,
    show ¬ (cp > 0x10FFFF) from by omega,
    Function.const]
  rfl

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
-- §9 BIT-TWIDDLING UTILITIES
-- ═══════════════════════════════════════════════════════════════════════════════
--
-- The per-byte-length consume witnesses below establish:
--
--   1. Each encoded byte lies in the byte-class range expected by the
--      matching `fold_consume_<n>byte` (start byte, continuation byte).
--   2. Re-extracting the codepoint bits from those bytes yields `cp`.
--
-- Both facts rely on a small set of `Nat.testBit` identities that hold
-- for all natural numbers (no upper bound). The proofs go through
-- `Nat.eq_of_testBit_eq` so we never enumerate codepoints — the
-- algebraic structure does the work uniformly across all four byte
-- lengths.

/-- AND-OR distributivity over Nat: `(a ||| b) &&& c = (a &&& c) ||| (b &&& c)`. -/
private theorem nat_land_lor_distrib_right (a b c : Nat) :
    (a ||| b) &&& c = (a &&& c) ||| (b &&& c) := by
  apply Nat.eq_of_testBit_eq
  intro i
  rw [Nat.testBit_and, Nat.testBit_or, Nat.testBit_or, Nat.testBit_and, Nat.testBit_and]
  cases a.testBit i <;> cases b.testBit i <;> cases c.testBit i <;> rfl

/-- `n &&& (2^k - 1) = n % 2^k`. The low-`k`-bit projection in two
    forms; converting between them lets `omega` pick up the residue
    after we have isolated the AND. -/
private theorem nat_and_two_pow_sub_one_eq_mod (n k : Nat) :
    n &&& (2^k - 1) = n % 2^k := by
  apply Nat.eq_of_testBit_eq
  intro i
  rw [Nat.testBit_and, Nat.testBit_two_pow_sub_one, Nat.testBit_mod_two_pow]
  by_cases h : i < k
  · simp [h]
  · simp [h]

/-- A natural number bounded by `2^k` is its own `2^k`-modulus. -/
private theorem nat_mod_two_pow_self (n k : Nat) (h : n < 2^k) :
    n % 2^k = n := Nat.mod_eq_of_lt h

/-- Composite: AND-with-`2^k - 1` is the identity on values bounded by `2^k`. -/
private theorem nat_and_two_pow_sub_one_self (n k : Nat) (h : n < 2^k) :
    n &&& (2^k - 1) = n := by
  rw [nat_and_two_pow_sub_one_eq_mod, nat_mod_two_pow_self n k h]

/-- High-low split at bit `k`: `x = (x >>> k) <<< k ||| (x &&& (2^k - 1))`. -/
private theorem nat_split_at (x k : Nat) :
    x = ((x >>> k) <<< k) ||| (x &&& (2^k - 1)) := by
  apply Nat.eq_of_testBit_eq
  intro i
  rw [Nat.testBit_or, Nat.testBit_shiftLeft, Nat.testBit_shiftRight,
      Nat.testBit_and, Nat.testBit_two_pow_sub_one]
  by_cases h : i < k
  · have hge : ¬ k ≤ i := Nat.not_le_of_lt h
    simp [hge, h]
  · have hge : k ≤ i := Nat.le_of_not_lt h
    have hadd : k + (i - k) = i := by omega
    simp [hge, h, hadd]

/-- Disjoint-mask AND: when `mask` and `flag` have no bits in common
    (i.e. `flag &&& mask = 0`), OR'ing `flag` in then masking with
    `mask` recovers `x &&& mask`. Concrete instance: byte-class
    high-bit prefixes (`0xC0`, `0xE0`, `0xF0`, `0x80`) are disjoint
    from the low-3- and low-6-bit masks (`0x07`, `0x3F`). -/
private theorem nat_lor_flag_and_mask (flag x mask : Nat)
    (h_disjoint : flag &&& mask = 0) :
    (flag ||| x) &&& mask = x &&& mask := by
  rw [nat_land_lor_distrib_right, h_disjoint, Nat.zero_or]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §10 PER-BYTE-LENGTH ENCODE FORM + CONSUME WITNESS
-- ═══════════════════════════════════════════════════════════════════════════════

-- ────────────────────────────────────────────────────────────────────────────
-- 1-byte (ASCII)
-- ────────────────────────────────────────────────────────────────────────────

/-- Closed form of `encodeCodepoint cp` on the ASCII bracket. -/
private theorem encode_ascii_form (cp : Nat) (h : cp < 0x80) :
    encodeCodepoint cp = ByteArray.mk #[UInt8.ofNat cp] := by
  unfold encodeCodepoint; simp [h]

-- ────────────────────────────────────────────────────────────────────────────
-- 2-byte
-- ────────────────────────────────────────────────────────────────────────────

/-- Closed form of `encodeCodepoint cp` on the 2-byte bracket. -/
private theorem encode_2byte_form (cp : Nat) (h_lo : 0x80 ≤ cp) (h_hi : cp < 0x800) :
    encodeCodepoint cp = ByteArray.mk #[
      UInt8.ofNat (0xC0 ||| (cp >>> 6)),
      UInt8.ofNat (0x80 ||| (cp &&& 0x3F))] := by
  unfold encodeCodepoint
  simp [show ¬ (cp < 0x80) from by omega, h_hi]

/-- Closed form of `encodeCodepoint cp` on the 3-byte bracket. -/
private theorem encode_3byte_form (cp : Nat) (h_lo : 0x800 ≤ cp) (h_hi : cp < 0x10000) :
    encodeCodepoint cp = ByteArray.mk #[
      UInt8.ofNat (0xE0 ||| (cp >>> 12)),
      UInt8.ofNat (0x80 ||| ((cp >>> 6) &&& 0x3F)),
      UInt8.ofNat (0x80 ||| (cp &&& 0x3F))] := by
  unfold encodeCodepoint
  simp [show ¬ (cp < 0x80) from by omega,
        show ¬ (cp < 0x800) from by omega, h_hi]

/-- Closed form of `encodeCodepoint cp` on the 4-byte bracket. -/
private theorem encode_4byte_form (cp : Nat) (h_lo : 0x10000 ≤ cp)
    (h_hi : cp < 0x110000) :
    encodeCodepoint cp = ByteArray.mk #[
      UInt8.ofNat (0xF0 ||| (cp >>> 18)),
      UInt8.ofNat (0x80 ||| ((cp >>> 12) &&& 0x3F)),
      UInt8.ofNat (0x80 ||| ((cp >>> 6) &&& 0x3F)),
      UInt8.ofNat (0x80 ||| (cp &&& 0x3F))] := by
  unfold encodeCodepoint
  simp [show ¬ (cp < 0x80) from by omega,
        show ¬ (cp < 0x800) from by omega,
        show ¬ (cp < 0x10000) from by omega]

-- ────────────────────────────────────────────────────────────────────────────
-- Bit-identity bridges: each byte's `&&& mask` collapses to the matching
-- shift of `cp`. These hold for all `cp` (no upper bound on the shift
-- counts; the high-bit prefixes `0xF0` / `0x80` are mask-disjoint
-- regardless of the codepoint's magnitude). The 4-byte case additionally
-- needs `(cp >>> 18) &&& 0x07 = cp >>> 18`, which requires `cp < 2^21`.
-- ────────────────────────────────────────────────────────────────────────────

/-- The low 6 bits of a 0x80-flagged byte equal the masked input. -/
private theorem byte_lor_80_and_3F (x : Nat) :
    (0x80 ||| (x &&& 0x3F)) &&& 0x3F = x &&& 0x3F := by
  rw [nat_lor_flag_and_mask 0x80 (x &&& 0x3F) 0x3F (by decide)]
  rw [Nat.and_assoc, Nat.and_self]

/-- The low 3 bits of a 0xF0-flagged byte equal the masked input. -/
private theorem byte_lor_F0_and_07 (x : Nat) :
    (0xF0 ||| x) &&& 0x07 = x &&& 0x07 :=
  nat_lor_flag_and_mask 0xF0 x 0x07 (by decide)

/-- The low 4 bits of a 0xE0-flagged byte equal the masked input. -/
private theorem byte_lor_E0_and_0F (x : Nat) :
    (0xE0 ||| x) &&& 0x0F = x &&& 0x0F :=
  nat_lor_flag_and_mask 0xE0 x 0x0F (by decide)

/-- The low 5 bits of a 0xC0-flagged byte equal the masked input. -/
private theorem byte_lor_C0_and_1F (x : Nat) :
    (0xC0 ||| x) &&& 0x1F = x &&& 0x1F :=
  nat_lor_flag_and_mask 0xC0 x 0x1F (by decide)

/-- The 4-byte UTF-8 reconstruction: assembling `cp` from its
    encoded bytes recovers `cp` exactly, when `cp < 2^21` (which
    covers the entire `[0, 0x110000)` codepoint space). -/
private theorem encode_4byte_bit_identity (cp : Nat) (h : cp < 0x110000) :
    cp = (((((((0xF0 ||| (cp >>> 18)) &&& 0x07) <<< 6)
            ||| ((0x80 ||| ((cp >>> 12) &&& 0x3F)) &&& 0x3F)) <<< 6)
          ||| ((0x80 ||| ((cp >>> 6) &&& 0x3F)) &&& 0x3F)) <<< 6)
        ||| ((0x80 ||| (cp &&& 0x3F)) &&& 0x3F) := by
  -- Collapse each byte's `&&& mask` to the relevant shift-and-mask of `cp`.
  rw [byte_lor_F0_and_07, byte_lor_80_and_3F, byte_lor_80_and_3F, byte_lor_80_and_3F]
  -- Eliminate `(cp >>> 18) &&& 0x07` using the bound `cp >>> 18 < 8`.
  have h_shr18 : cp >>> 18 < 2^3 := by
    rw [Nat.shiftRight_eq_div_pow]; omega
  rw [show (0x07 : Nat) = 2^3 - 1 from rfl,
      nat_and_two_pow_sub_one_self (cp >>> 18) 3 h_shr18]
  -- Three iterated splits at bit 6, bottom-up.
  rw [show (0x3F : Nat) = 2^6 - 1 from rfl]
  have h12 : cp >>> 12 = (cp >>> 18) <<< 6 ||| ((cp >>> 12) &&& (2^6 - 1)) := by
    rw [show cp >>> 18 = (cp >>> 12) >>> 6 from by
      rw [show (18 : Nat) = 12 + 6 from rfl, Nat.shiftRight_add]]
    exact nat_split_at (cp >>> 12) 6
  have h6 : cp >>> 6 = (cp >>> 12) <<< 6 ||| ((cp >>> 6) &&& (2^6 - 1)) := by
    rw [show cp >>> 12 = (cp >>> 6) >>> 6 from by
      rw [show (12 : Nat) = 6 + 6 from rfl, Nat.shiftRight_add]]
    exact nat_split_at (cp >>> 6) 6
  have hcp : cp = (cp >>> 6) <<< 6 ||| (cp &&& (2^6 - 1)) := nat_split_at cp 6
  rw [← h12, ← h6, ← hcp]

/-- The 3-byte UTF-8 reconstruction. -/
private theorem encode_3byte_bit_identity (cp : Nat) (h : cp < 0x10000) :
    cp = ((((0xE0 ||| (cp >>> 12)) &&& 0x0F) <<< 6)
          ||| ((0x80 ||| ((cp >>> 6) &&& 0x3F)) &&& 0x3F)) <<< 6
        ||| ((0x80 ||| (cp &&& 0x3F)) &&& 0x3F) := by
  rw [byte_lor_E0_and_0F, byte_lor_80_and_3F, byte_lor_80_and_3F]
  have h_shr12 : cp >>> 12 < 2^4 := by
    rw [Nat.shiftRight_eq_div_pow]; omega
  rw [show (0x0F : Nat) = 2^4 - 1 from rfl,
      nat_and_two_pow_sub_one_self (cp >>> 12) 4 h_shr12]
  rw [show (0x3F : Nat) = 2^6 - 1 from rfl]
  have h6 : cp >>> 6 = (cp >>> 12) <<< 6 ||| ((cp >>> 6) &&& (2^6 - 1)) := by
    rw [show cp >>> 12 = (cp >>> 6) >>> 6 from by
      rw [show (12 : Nat) = 6 + 6 from rfl, Nat.shiftRight_add]]
    exact nat_split_at (cp >>> 6) 6
  have hcp : cp = (cp >>> 6) <<< 6 ||| (cp &&& (2^6 - 1)) := nat_split_at cp 6
  rw [← h6, ← hcp]

/-- The 2-byte UTF-8 reconstruction. -/
private theorem encode_2byte_bit_identity (cp : Nat) (h : cp < 0x800) :
    cp = (((0xC0 ||| (cp >>> 6)) &&& 0x1F) <<< 6)
        ||| ((0x80 ||| (cp &&& 0x3F)) &&& 0x3F) := by
  rw [byte_lor_C0_and_1F, byte_lor_80_and_3F]
  have h_shr6 : cp >>> 6 < 2^5 := by
    rw [Nat.shiftRight_eq_div_pow]; omega
  rw [show (0x1F : Nat) = 2^5 - 1 from rfl,
      nat_and_two_pow_sub_one_self (cp >>> 6) 5 h_shr6]
  rw [show (0x3F : Nat) = 2^6 - 1 from rfl]
  exact nat_split_at cp 6

-- ═══════════════════════════════════════════════════════════════════════════════
-- §11 PER-BYTE-LENGTH ENCODED-BYTE VALUE LEMMAS
-- ═══════════════════════════════════════════════════════════════════════════════
--
-- For each byte length, the byte-class start and continuation bytes
-- emitted by `encodeCodepoint` lie in the ranges that the matching
-- `fold_consume_<n>byte` expects, and `(UInt8.ofNat ...).toNat` is
-- the identity (the encoded-byte values are all `< 256`). The lower
-- bounds come from the disjoint OR-add bridge below and the codepoint
-- bracket; the upper bounds combine the same bridge with the
-- shifted-codepoint bound.

/-- Disjoint OR-add bridge: when `y < 2^k`, OR'ing `y` into a value
    shifted left by `k` is the same as adding (the low `k` bits don't
    overlap). Proven by reducing to the unique-base-`2^k` decomposition
    via `nat_split_at`. -/
private theorem nat_lor_shiftLeft_eq_add (high y k : Nat) (h_y : y < 2^k) :
    (high <<< k) ||| y = high * 2^k + y := by
  -- Apply the split-at-k decomposition to (high * 2^k + y), compute its
  -- quotient (= high) and residue (= y) under div by 2^k, then rewrite
  -- the goal's RHS through the resulting OR form.
  have h2k_pos : 0 < 2^k := Nat.two_pow_pos k
  have h_div : (high * 2^k + y) >>> k = high := by
    rw [Nat.shiftRight_eq_div_pow, Nat.mul_comm,
        Nat.mul_add_div h2k_pos, Nat.div_eq_of_lt h_y, Nat.add_zero]
  have h_mod : (high * 2^k + y) &&& (2^k - 1) = y := by
    rw [nat_and_two_pow_sub_one_eq_mod, Nat.mul_comm,
        Nat.mul_add_mod, Nat.mod_eq_of_lt h_y]
  have hsplit : high * 2^k + y
      = ((high * 2^k + y) >>> k) <<< k ||| ((high * 2^k + y) &&& (2^k - 1)) :=
    nat_split_at (high * 2^k + y) k
  rw [h_div, h_mod] at hsplit
  rw [Nat.shiftLeft_eq] at hsplit
  rw [Nat.shiftLeft_eq]
  exact hsplit.symm

-- ────────────────────────────────────────────────────────────────────────────
-- 1-byte (ASCII)
-- ────────────────────────────────────────────────────────────────────────────

/-- ASCII byte 0 — the encoded byte equals `cp` after `toNat`. -/
private theorem encode_ascii_byte0 (cp : Nat) (h : cp < 0x80) :
    (UInt8.ofNat cp).toNat = cp :=
  uint8_ofNat_toNat cp (by omega)

-- ────────────────────────────────────────────────────────────────────────────
-- 2-byte
-- ────────────────────────────────────────────────────────────────────────────

/-- 2-byte byte 0 lies in `[0xC2, 0xE0)` and round-trips through `UInt8`. -/
private theorem encode_2byte_byte0 (cp : Nat) (h_lo : 0x80 ≤ cp) (h_hi : cp < 0x800) :
    (UInt8.ofNat (0xC0 ||| (cp >>> 6))).toNat = 0xC0 ||| (cp >>> 6) ∧
    0xC2 ≤ 0xC0 ||| (cp >>> 6) ∧
    0xC0 ||| (cp >>> 6) < 0xE0 := by
  have h_shr_lt : cp >>> 6 < 2^5 := by rw [Nat.shiftRight_eq_div_pow]; omega
  have h_shr_ge : 2 ≤ cp >>> 6 := by rw [Nat.shiftRight_eq_div_pow]; omega
  have h_eq : (0xC0 : Nat) ||| (cp >>> 6) = 0xC0 + (cp >>> 6) := by
    rw [show (0xC0 : Nat) = 6 <<< 5 from rfl,
        nat_lor_shiftLeft_eq_add 6 (cp >>> 6) 5 h_shr_lt]
    rfl
  have h_lt256 : 0xC0 + (cp >>> 6) < 256 := by omega
  have h_uint : (UInt8.ofNat (0xC0 + (cp >>> 6))).toNat = 0xC0 + (cp >>> 6) :=
    uint8_ofNat_toNat (0xC0 + (cp >>> 6)) h_lt256
  have h_lo_bnd : 0xC2 ≤ 0xC0 + (cp >>> 6) := by omega
  have h_hi_bnd : 0xC0 + (cp >>> 6) < 0xE0 := by omega
  rw [h_eq]
  exact ⟨h_uint, h_lo_bnd, h_hi_bnd⟩

/-- 2-byte byte 1 lies in `[0x80, 0xC0)` and round-trips through `UInt8`. -/
private theorem encode_2byte_byte1 (cp : Nat) :
    (UInt8.ofNat (0x80 ||| (cp &&& 0x3F))).toNat = 0x80 ||| (cp &&& 0x3F) ∧
    0x80 ≤ 0x80 ||| (cp &&& 0x3F) ∧
    0x80 ||| (cp &&& 0x3F) < 0xC0 := by
  have h_and_lt : cp &&& 0x3F < 2^6 := by
    rw [show (0x3F : Nat) = 2^6 - 1 from rfl, nat_and_two_pow_sub_one_eq_mod]
    exact Nat.mod_lt cp (Nat.two_pow_pos 6)
  have h_eq : (0x80 : Nat) ||| (cp &&& 0x3F) = 0x80 + (cp &&& 0x3F) := by
    rw [show (0x80 : Nat) = 2 <<< 6 from rfl,
        nat_lor_shiftLeft_eq_add 2 (cp &&& 0x3F) 6 h_and_lt]
    rfl
  have h_lt256 : 0x80 + (cp &&& 0x3F) < 256 := by omega
  have h_uint : (UInt8.ofNat (0x80 + (cp &&& 0x3F))).toNat = 0x80 + (cp &&& 0x3F) :=
    uint8_ofNat_toNat (0x80 + (cp &&& 0x3F)) h_lt256
  have h_lo_bnd : 0x80 ≤ 0x80 + (cp &&& 0x3F) := by omega
  have h_hi_bnd : 0x80 + (cp &&& 0x3F) < 0xC0 := by omega
  rw [h_eq]
  exact ⟨h_uint, h_lo_bnd, h_hi_bnd⟩

-- ────────────────────────────────────────────────────────────────────────────
-- 3-byte
-- ────────────────────────────────────────────────────────────────────────────

/-- 3-byte byte 0 lies in `[0xE0, 0xF0)`. -/
private theorem encode_3byte_byte0 (cp : Nat) (h_lo : 0x800 ≤ cp) (h_hi : cp < 0x10000) :
    (UInt8.ofNat (0xE0 ||| (cp >>> 12))).toNat = 0xE0 ||| (cp >>> 12) ∧
    0xE0 ≤ 0xE0 ||| (cp >>> 12) ∧
    0xE0 ||| (cp >>> 12) < 0xF0 := by
  have h_shr_lt : cp >>> 12 < 2^4 := by rw [Nat.shiftRight_eq_div_pow]; omega
  have h_eq : (0xE0 : Nat) ||| (cp >>> 12) = 0xE0 + (cp >>> 12) := by
    rw [show (0xE0 : Nat) = 14 <<< 4 from rfl,
        nat_lor_shiftLeft_eq_add 14 (cp >>> 12) 4 h_shr_lt]
    rfl
  have h_lt256 : 0xE0 + (cp >>> 12) < 256 := by omega
  have h_uint : (UInt8.ofNat (0xE0 + (cp >>> 12))).toNat = 0xE0 + (cp >>> 12) :=
    uint8_ofNat_toNat (0xE0 + (cp >>> 12)) h_lt256
  have h_lo_bnd : 0xE0 ≤ 0xE0 + (cp >>> 12) := by omega
  have h_hi_bnd : 0xE0 + (cp >>> 12) < 0xF0 := by omega
  rw [h_eq]
  exact ⟨h_uint, h_lo_bnd, h_hi_bnd⟩

-- (3-byte bytes 1 and 2 share the byte1 lemma above — the form
--  `0x80 ||| (x &&& 0x3F)` is identical, only the input shift changes.)

-- ────────────────────────────────────────────────────────────────────────────
-- 4-byte
-- ────────────────────────────────────────────────────────────────────────────

/-- 4-byte byte 0 lies in `[0xF0, 0xF5)`. -/
private theorem encode_4byte_byte0 (cp : Nat) (h_lo : 0x10000 ≤ cp) (h_hi : cp < 0x110000) :
    (UInt8.ofNat (0xF0 ||| (cp >>> 18))).toNat = 0xF0 ||| (cp >>> 18) ∧
    0xF0 ≤ 0xF0 ||| (cp >>> 18) ∧
    0xF0 ||| (cp >>> 18) < 0xF5 := by
  have h_shr_lt : cp >>> 18 < 2^4 := by rw [Nat.shiftRight_eq_div_pow]; omega
  have h_shr_lt5 : cp >>> 18 < 5 := by rw [Nat.shiftRight_eq_div_pow]; omega
  have h_eq : (0xF0 : Nat) ||| (cp >>> 18) = 0xF0 + (cp >>> 18) := by
    rw [show (0xF0 : Nat) = 15 <<< 4 from rfl,
        nat_lor_shiftLeft_eq_add 15 (cp >>> 18) 4 h_shr_lt]
    rfl
  have h_lt256 : 0xF0 + (cp >>> 18) < 256 := by omega
  have h_uint : (UInt8.ofNat (0xF0 + (cp >>> 18))).toNat = 0xF0 + (cp >>> 18) :=
    uint8_ofNat_toNat (0xF0 + (cp >>> 18)) h_lt256
  have h_lo_bnd : 0xF0 ≤ 0xF0 + (cp >>> 18) := by omega
  have h_hi_bnd : 0xF0 + (cp >>> 18) < 0xF5 := by omega
  rw [h_eq]
  exact ⟨h_uint, h_lo_bnd, h_hi_bnd⟩

-- ═══════════════════════════════════════════════════════════════════════════════
-- §12 PER-BYTE-LENGTH DECODE_CONCAT
-- ═══════════════════════════════════════════════════════════════════════════════
--
-- Prepending an encoded codepoint to `rest` decodes to `#[cp] ++
-- decodeToCodepoints rest`. Each helper advances the fold past the
-- encoding's bytes via `fold_consume_<n>byte`, translates the suffix
-- fold via `fold_concat_translate`, and lifts the leading `#[cp]` out
-- of the accumulator via `fold_push_acc_factor`.

/-- The decode-fold's update function lifts to `acc.push c` after β.
    Used as the `hf` hypothesis for `fold_concat_translate` and
    `fold_push_acc_factor`. -/
private theorem decode_fn_push_eq
    (acc : Array Nat) (offset c : Nat) :
    (fun (a : Array Nat) (o c : Nat) => Function.const Nat (a.push c) o) acc offset c
      = acc.push c := rfl

-- ────────────────────────────────────────────────────────────────────────────
-- 1-byte (ASCII)
-- ────────────────────────────────────────────────────────────────────────────

/-- Prepending an ASCII-encoded codepoint to `rest` decodes to
    `#[cp] ++ decodeToCodepoints rest`. -/
private theorem decode_concat_ascii (cp : Nat) (h_lt : cp < 0x80) (rest : ByteArray) :
    decodeToCodepoints (encodeCodepoint cp ++ rest)
      = #[cp] ++ decodeToCodepoints rest := by
  -- Substitute encodeCodepoint cp with its closed form so its size
  -- (= 1) reduces by `rfl` and indexing is direct.
  rw [encode_ascii_form cp h_lt]
  have h_pfx_size : (ByteArray.mk #[UInt8.ofNat cp] : ByteArray).size = 1 := rfl
  have h_pfx_pos : 0 < (ByteArray.mk #[UInt8.ofNat cp] : ByteArray).size := by
    rw [h_pfx_size]; omega
  have h_total : (ByteArray.mk #[UInt8.ofNat cp] ++ rest).size = rest.size + 1 := by
    rw [ByteArray.size_append, h_pfx_size]; omega
  have h_idx : 0 < (ByteArray.mk #[UInt8.ofNat cp] ++ rest).size := by
    rw [h_total]; omega
  have h_byte0 : ((ByteArray.mk #[UInt8.ofNat cp] ++ rest)[0]'h_idx).toNat = cp := by
    rw [ByteArray.getElem_append_left h_pfx_pos]
    show (UInt8.ofNat cp).toNat = cp
    exact uint8_ofNat_toNat cp (by omega)
  -- Unfold both sides to fold-Go form.
  unfold decodeToCodepoints foldCodepointsWithOffset
  -- Massage the LHS fuel `(pfx ++ rest).size + 1` into `(rest.size + 1) + 1`
  -- so `fold_consume_ascii` can fire its `fuel + 1` pattern.
  rw [show (ByteArray.mk #[UInt8.ofNat cp] ++ rest).size + 1
        = (rest.size + 1) + 1 from by rw [h_total]]
  rw [fold_consume_ascii (ByteArray.mk #[UInt8.ofNat cp] ++ rest)
        (fun a o c => Function.const Nat (a.push c) o)
        0 0 #[] (rest.size + 1) cp h_lt h_idx h_byte0]
  -- After consume: index `0 + 1`, seqStart `0 + 1`, accumulator
  -- `Function.const Nat (#[].push cp) 0`. Bridge index to
  -- `pfx.size + 0` so `fold_concat_translate` matches.
  rw [show (0 : Nat) + 1
        = (ByteArray.mk #[UInt8.ofNat cp] : ByteArray).size + 0 from by
    rw [h_pfx_size]]
  rw [fold_concat_translate (ByteArray.mk #[UInt8.ofNat cp]) rest
        (fun a o c => Function.const Nat (a.push c) o)
        decode_fn_push_eq
        Utf8State.expectStart 0
        ((ByteArray.mk #[UInt8.ofNat cp] : ByteArray).size + 0) 0
        (Function.const Nat ((#[] : Array Nat).push cp) 0) (rest.size + 1)]
  rw [fold_push_acc_factor rest
        (fun a o c => Function.const Nat (a.push c) o)
        decode_fn_push_eq
        Utf8State.expectStart 0 0
        (Function.const Nat ((#[] : Array Nat).push cp) 0) (rest.size + 1)]
  rfl

-- ────────────────────────────────────────────────────────────────────────────
-- 2-byte
-- ────────────────────────────────────────────────────────────────────────────

/-- Prepending a 2-byte-encoded codepoint to `rest` decodes to
    `#[cp] ++ decodeToCodepoints rest`. -/
private theorem decode_concat_2byte (cp : Nat) (h_lo : 0x80 ≤ cp) (h_hi : cp < 0x800)
    (rest : ByteArray) :
    decodeToCodepoints (encodeCodepoint cp ++ rest)
      = #[cp] ++ decodeToCodepoints rest := by
  rw [encode_2byte_form cp h_lo h_hi]
  -- Concrete prefix: 2 bytes long.
  let pfxBytes : ByteArray := ByteArray.mk #[
    UInt8.ofNat (0xC0 ||| (cp >>> 6)),
    UInt8.ofNat (0x80 ||| (cp &&& 0x3F))]
  have h_pfx_size : pfxBytes.size = 2 := rfl
  have h_pfx_pos0 : 0 < pfxBytes.size := by rw [h_pfx_size]; omega
  have h_pfx_pos1 : 1 < pfxBytes.size := by rw [h_pfx_size]; omega
  have h_total : (pfxBytes ++ rest).size = rest.size + 2 := by
    rw [ByteArray.size_append, h_pfx_size]; omega
  have h_idx0 : 0 < (pfxBytes ++ rest).size := by rw [h_total]; omega
  have h_idx1 : 0 + 1 < (pfxBytes ++ rest).size := by rw [h_total]; omega
  -- Byte 0 is the start byte; byte 1 is the continuation byte.
  have h_byte0_eq :
      ((pfxBytes ++ rest)[0]'h_idx0).toNat = 0xC0 ||| (cp >>> 6) := by
    rw [ByteArray.getElem_append_left h_pfx_pos0]
    show (UInt8.ofNat (0xC0 ||| (cp >>> 6))).toNat = 0xC0 ||| (cp >>> 6)
    have h_b0 := encode_2byte_byte0 cp h_lo h_hi
    exact h_b0.left
  have h_byte1_eq :
      ((pfxBytes ++ rest)[0 + 1]'h_idx1).toNat = 0x80 ||| (cp &&& 0x3F) := by
    rw [ByteArray.getElem_append_left h_pfx_pos1]
    show (UInt8.ofNat (0x80 ||| (cp &&& 0x3F))).toNat = 0x80 ||| (cp &&& 0x3F)
    have h_b1 := encode_2byte_byte1 cp
    exact h_b1.left
  -- Byte-class bounds (2-byte start byte + continuation byte).
  have h_b0_lo : 0xC2 ≤ ((pfxBytes ++ rest)[0]'h_idx0).toNat := by
    rw [h_byte0_eq]; exact (encode_2byte_byte0 cp h_lo h_hi).right.left
  have h_b0_hi : ((pfxBytes ++ rest)[0]'h_idx0).toNat < 0xE0 := by
    rw [h_byte0_eq]; exact (encode_2byte_byte0 cp h_lo h_hi).right.right
  have h_b1_lo : 0x80 ≤ ((pfxBytes ++ rest)[0 + 1]'h_idx1).toNat := by
    rw [h_byte1_eq]; exact (encode_2byte_byte1 cp).right.left
  have h_b1_hi : ((pfxBytes ++ rest)[0 + 1]'h_idx1).toNat < 0xC0 := by
    rw [h_byte1_eq]; exact (encode_2byte_byte1 cp).right.right
  -- Bit-reconstruction equality: the encoded bytes recompose to `cp`.
  have h_cp_eq : cp = ((((pfxBytes ++ rest)[0]'h_idx0).toNat &&& 0x1F) <<< 6)
                        ||| (((pfxBytes ++ rest)[0 + 1]'h_idx1).toNat &&& 0x3F) := by
    rw [h_byte0_eq, h_byte1_eq]
    exact encode_2byte_bit_identity cp h_hi
  -- Side conditions for the decoder's emit branch.
  have h_overlong : ¬ cp < 0x80 := by omega
  have h_nonsurr : ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF) := by omega
  have h_max : ¬ cp > 0x10FFFF := by omega
  unfold decodeToCodepoints foldCodepointsWithOffset
  rw [show (pfxBytes ++ rest).size + 1 = (rest.size + 1) + 2 from by
    rw [h_total]]
  rw [fold_consume_2byte (pfxBytes ++ rest)
        (fun a o c => Function.const Nat (a.push c) o)
        0 0 #[] (rest.size + 1) cp h_idx0 h_idx1
        h_b0_lo h_b0_hi h_b1_lo h_b1_hi h_cp_eq h_overlong h_nonsurr h_max]
  rw [show (0 : Nat) + 2 = pfxBytes.size + 0 from by rw [h_pfx_size]]
  rw [fold_concat_translate pfxBytes rest
        (fun a o c => Function.const Nat (a.push c) o)
        decode_fn_push_eq
        Utf8State.expectStart 0 (pfxBytes.size + 0) 0
        (Function.const Nat ((#[] : Array Nat).push cp) 0) (rest.size + 1)]
  rw [fold_push_acc_factor rest
        (fun a o c => Function.const Nat (a.push c) o)
        decode_fn_push_eq
        Utf8State.expectStart 0 0
        (Function.const Nat ((#[] : Array Nat).push cp) 0) (rest.size + 1)]
  rfl

-- ────────────────────────────────────────────────────────────────────────────
-- 3-byte
-- ────────────────────────────────────────────────────────────────────────────

/-- The shared continuation-byte form `0x80 ||| (x &&& 0x3F)` is reused
    at byte positions 1, 2, 3 across the 2-, 3-, 4-byte cases — the
    byte-1 lemma generalises across them. -/
private theorem encode_continuation_bounds (x : Nat) :
    (UInt8.ofNat (0x80 ||| (x &&& 0x3F))).toNat = 0x80 ||| (x &&& 0x3F) ∧
    0x80 ≤ 0x80 ||| (x &&& 0x3F) ∧
    0x80 ||| (x &&& 0x3F) < 0xC0 :=
  encode_2byte_byte1 x

/-- Prepending a 3-byte-encoded codepoint to `rest` decodes to
    `#[cp] ++ decodeToCodepoints rest`. -/
private theorem decode_concat_3byte (cp : Nat) (h_lo : 0x800 ≤ cp) (h_hi : cp < 0x10000)
    (h_nonsurr : ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF))
    (rest : ByteArray) :
    decodeToCodepoints (encodeCodepoint cp ++ rest)
      = #[cp] ++ decodeToCodepoints rest := by
  rw [encode_3byte_form cp h_lo h_hi]
  let pfxBytes : ByteArray := ByteArray.mk #[
    UInt8.ofNat (0xE0 ||| (cp >>> 12)),
    UInt8.ofNat (0x80 ||| ((cp >>> 6) &&& 0x3F)),
    UInt8.ofNat (0x80 ||| (cp &&& 0x3F))]
  have h_pfx_size : pfxBytes.size = 3 := rfl
  have h_pfx_pos0 : 0 < pfxBytes.size := by rw [h_pfx_size]; omega
  have h_pfx_pos1 : 1 < pfxBytes.size := by rw [h_pfx_size]; omega
  have h_pfx_pos2 : 2 < pfxBytes.size := by rw [h_pfx_size]; omega
  have h_total : (pfxBytes ++ rest).size = rest.size + 3 := by
    rw [ByteArray.size_append, h_pfx_size]; omega
  have h_idx0 : 0 < (pfxBytes ++ rest).size := by rw [h_total]; omega
  have h_idx1 : 0 + 1 < (pfxBytes ++ rest).size := by rw [h_total]; omega
  have h_idx2 : 0 + 2 < (pfxBytes ++ rest).size := by rw [h_total]; omega
  have h_byte0_eq :
      ((pfxBytes ++ rest)[0]'h_idx0).toNat = 0xE0 ||| (cp >>> 12) := by
    rw [ByteArray.getElem_append_left h_pfx_pos0]
    show (UInt8.ofNat (0xE0 ||| (cp >>> 12))).toNat = 0xE0 ||| (cp >>> 12)
    exact (encode_3byte_byte0 cp h_lo h_hi).left
  have h_byte1_eq :
      ((pfxBytes ++ rest)[0 + 1]'h_idx1).toNat = 0x80 ||| ((cp >>> 6) &&& 0x3F) := by
    rw [ByteArray.getElem_append_left h_pfx_pos1]
    show (UInt8.ofNat (0x80 ||| ((cp >>> 6) &&& 0x3F))).toNat
        = 0x80 ||| ((cp >>> 6) &&& 0x3F)
    exact (encode_continuation_bounds (cp >>> 6)).left
  have h_byte2_eq :
      ((pfxBytes ++ rest)[0 + 2]'h_idx2).toNat = 0x80 ||| (cp &&& 0x3F) := by
    rw [ByteArray.getElem_append_left h_pfx_pos2]
    show (UInt8.ofNat (0x80 ||| (cp &&& 0x3F))).toNat = 0x80 ||| (cp &&& 0x3F)
    exact (encode_continuation_bounds cp).left
  have h_b0_lo : 0xE0 ≤ ((pfxBytes ++ rest)[0]'h_idx0).toNat := by
    rw [h_byte0_eq]; exact (encode_3byte_byte0 cp h_lo h_hi).right.left
  have h_b0_hi : ((pfxBytes ++ rest)[0]'h_idx0).toNat < 0xF0 := by
    rw [h_byte0_eq]; exact (encode_3byte_byte0 cp h_lo h_hi).right.right
  have h_b1_lo : 0x80 ≤ ((pfxBytes ++ rest)[0 + 1]'h_idx1).toNat := by
    rw [h_byte1_eq]; exact (encode_continuation_bounds (cp >>> 6)).right.left
  have h_b1_hi : ((pfxBytes ++ rest)[0 + 1]'h_idx1).toNat < 0xC0 := by
    rw [h_byte1_eq]; exact (encode_continuation_bounds (cp >>> 6)).right.right
  have h_b2_lo : 0x80 ≤ ((pfxBytes ++ rest)[0 + 2]'h_idx2).toNat := by
    rw [h_byte2_eq]; exact (encode_continuation_bounds cp).right.left
  have h_b2_hi : ((pfxBytes ++ rest)[0 + 2]'h_idx2).toNat < 0xC0 := by
    rw [h_byte2_eq]; exact (encode_continuation_bounds cp).right.right
  have h_cp_eq : cp =
      ((((((pfxBytes ++ rest)[0]'h_idx0).toNat &&& 0x0F) <<< 6)
            ||| (((pfxBytes ++ rest)[0 + 1]'h_idx1).toNat &&& 0x3F)) <<< 6)
        ||| (((pfxBytes ++ rest)[0 + 2]'h_idx2).toNat &&& 0x3F) := by
    rw [h_byte0_eq, h_byte1_eq, h_byte2_eq]
    exact encode_3byte_bit_identity cp h_hi
  have h_overlong : ¬ cp < 0x800 := by omega
  have h_max : ¬ cp > 0x10FFFF := by omega
  unfold decodeToCodepoints foldCodepointsWithOffset
  rw [show (pfxBytes ++ rest).size + 1 = (rest.size + 1) + 3 from by rw [h_total]]
  rw [fold_consume_3byte (pfxBytes ++ rest)
        (fun a o c => Function.const Nat (a.push c) o)
        0 0 #[] (rest.size + 1) cp h_idx0 h_idx1 h_idx2
        h_b0_lo h_b0_hi h_b1_lo h_b1_hi h_b2_lo h_b2_hi
        h_cp_eq h_overlong h_nonsurr h_max]
  rw [show (0 : Nat) + 3 = pfxBytes.size + 0 from by rw [h_pfx_size]]
  rw [fold_concat_translate pfxBytes rest
        (fun a o c => Function.const Nat (a.push c) o)
        decode_fn_push_eq
        Utf8State.expectStart 0 (pfxBytes.size + 0) 0
        (Function.const Nat ((#[] : Array Nat).push cp) 0) (rest.size + 1)]
  rw [fold_push_acc_factor rest
        (fun a o c => Function.const Nat (a.push c) o)
        decode_fn_push_eq
        Utf8State.expectStart 0 0
        (Function.const Nat ((#[] : Array Nat).push cp) 0) (rest.size + 1)]
  rfl

-- ────────────────────────────────────────────────────────────────────────────
-- 4-byte
-- ────────────────────────────────────────────────────────────────────────────

/-- Prepending a 4-byte-encoded codepoint to `rest` decodes to
    `#[cp] ++ decodeToCodepoints rest`. -/
private theorem decode_concat_4byte (cp : Nat) (h_lo : 0x10000 ≤ cp) (h_hi : cp < 0x110000)
    (rest : ByteArray) :
    decodeToCodepoints (encodeCodepoint cp ++ rest)
      = #[cp] ++ decodeToCodepoints rest := by
  rw [encode_4byte_form cp h_lo h_hi]
  let pfxBytes : ByteArray := ByteArray.mk #[
    UInt8.ofNat (0xF0 ||| (cp >>> 18)),
    UInt8.ofNat (0x80 ||| ((cp >>> 12) &&& 0x3F)),
    UInt8.ofNat (0x80 ||| ((cp >>> 6) &&& 0x3F)),
    UInt8.ofNat (0x80 ||| (cp &&& 0x3F))]
  have h_pfx_size : pfxBytes.size = 4 := rfl
  have h_pfx_pos0 : 0 < pfxBytes.size := by rw [h_pfx_size]; omega
  have h_pfx_pos1 : 1 < pfxBytes.size := by rw [h_pfx_size]; omega
  have h_pfx_pos2 : 2 < pfxBytes.size := by rw [h_pfx_size]; omega
  have h_pfx_pos3 : 3 < pfxBytes.size := by rw [h_pfx_size]; omega
  have h_total : (pfxBytes ++ rest).size = rest.size + 4 := by
    rw [ByteArray.size_append, h_pfx_size]; omega
  have h_idx0 : 0 < (pfxBytes ++ rest).size := by rw [h_total]; omega
  have h_idx1 : 0 + 1 < (pfxBytes ++ rest).size := by rw [h_total]; omega
  have h_idx2 : 0 + 2 < (pfxBytes ++ rest).size := by rw [h_total]; omega
  have h_idx3 : 0 + 3 < (pfxBytes ++ rest).size := by rw [h_total]; omega
  have h_byte0_eq :
      ((pfxBytes ++ rest)[0]'h_idx0).toNat = 0xF0 ||| (cp >>> 18) := by
    rw [ByteArray.getElem_append_left h_pfx_pos0]
    show (UInt8.ofNat (0xF0 ||| (cp >>> 18))).toNat = 0xF0 ||| (cp >>> 18)
    exact (encode_4byte_byte0 cp h_lo h_hi).left
  have h_byte1_eq :
      ((pfxBytes ++ rest)[0 + 1]'h_idx1).toNat = 0x80 ||| ((cp >>> 12) &&& 0x3F) := by
    rw [ByteArray.getElem_append_left h_pfx_pos1]
    show (UInt8.ofNat (0x80 ||| ((cp >>> 12) &&& 0x3F))).toNat
        = 0x80 ||| ((cp >>> 12) &&& 0x3F)
    exact (encode_continuation_bounds (cp >>> 12)).left
  have h_byte2_eq :
      ((pfxBytes ++ rest)[0 + 2]'h_idx2).toNat = 0x80 ||| ((cp >>> 6) &&& 0x3F) := by
    rw [ByteArray.getElem_append_left h_pfx_pos2]
    show (UInt8.ofNat (0x80 ||| ((cp >>> 6) &&& 0x3F))).toNat
        = 0x80 ||| ((cp >>> 6) &&& 0x3F)
    exact (encode_continuation_bounds (cp >>> 6)).left
  have h_byte3_eq :
      ((pfxBytes ++ rest)[0 + 3]'h_idx3).toNat = 0x80 ||| (cp &&& 0x3F) := by
    rw [ByteArray.getElem_append_left h_pfx_pos3]
    show (UInt8.ofNat (0x80 ||| (cp &&& 0x3F))).toNat = 0x80 ||| (cp &&& 0x3F)
    exact (encode_continuation_bounds cp).left
  have h_b0_lo : 0xF0 ≤ ((pfxBytes ++ rest)[0]'h_idx0).toNat := by
    rw [h_byte0_eq]; exact (encode_4byte_byte0 cp h_lo h_hi).right.left
  have h_b0_hi : ((pfxBytes ++ rest)[0]'h_idx0).toNat < 0xF5 := by
    rw [h_byte0_eq]; exact (encode_4byte_byte0 cp h_lo h_hi).right.right
  have h_b1_lo : 0x80 ≤ ((pfxBytes ++ rest)[0 + 1]'h_idx1).toNat := by
    rw [h_byte1_eq]; exact (encode_continuation_bounds (cp >>> 12)).right.left
  have h_b1_hi : ((pfxBytes ++ rest)[0 + 1]'h_idx1).toNat < 0xC0 := by
    rw [h_byte1_eq]; exact (encode_continuation_bounds (cp >>> 12)).right.right
  have h_b2_lo : 0x80 ≤ ((pfxBytes ++ rest)[0 + 2]'h_idx2).toNat := by
    rw [h_byte2_eq]; exact (encode_continuation_bounds (cp >>> 6)).right.left
  have h_b2_hi : ((pfxBytes ++ rest)[0 + 2]'h_idx2).toNat < 0xC0 := by
    rw [h_byte2_eq]; exact (encode_continuation_bounds (cp >>> 6)).right.right
  have h_b3_lo : 0x80 ≤ ((pfxBytes ++ rest)[0 + 3]'h_idx3).toNat := by
    rw [h_byte3_eq]; exact (encode_continuation_bounds cp).right.left
  have h_b3_hi : ((pfxBytes ++ rest)[0 + 3]'h_idx3).toNat < 0xC0 := by
    rw [h_byte3_eq]; exact (encode_continuation_bounds cp).right.right
  have h_cp_eq : cp =
      (((((((pfxBytes ++ rest)[0]'h_idx0).toNat &&& 0x07) <<< 6)
              ||| (((pfxBytes ++ rest)[0 + 1]'h_idx1).toNat &&& 0x3F)) <<< 6)
            ||| (((pfxBytes ++ rest)[0 + 2]'h_idx2).toNat &&& 0x3F)) <<< 6
        ||| (((pfxBytes ++ rest)[0 + 3]'h_idx3).toNat &&& 0x3F) := by
    rw [h_byte0_eq, h_byte1_eq, h_byte2_eq, h_byte3_eq]
    exact encode_4byte_bit_identity cp h_hi
  have h_overlong : ¬ cp < 0x10000 := by omega
  have h_nonsurr : ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF) := by omega
  have h_max : ¬ cp > 0x10FFFF := by omega
  unfold decodeToCodepoints foldCodepointsWithOffset
  rw [show (pfxBytes ++ rest).size + 1 = (rest.size + 1) + 4 from by rw [h_total]]
  rw [fold_consume_4byte (pfxBytes ++ rest)
        (fun a o c => Function.const Nat (a.push c) o)
        0 0 #[] (rest.size + 1) cp h_idx0 h_idx1 h_idx2 h_idx3
        h_b0_lo h_b0_hi h_b1_lo h_b1_hi h_b2_lo h_b2_hi h_b3_lo h_b3_hi
        h_cp_eq h_overlong h_nonsurr h_max]
  rw [show (0 : Nat) + 4 = pfxBytes.size + 0 from by rw [h_pfx_size]]
  rw [fold_concat_translate pfxBytes rest
        (fun a o c => Function.const Nat (a.push c) o)
        decode_fn_push_eq
        Utf8State.expectStart 0 (pfxBytes.size + 0) 0
        (Function.const Nat ((#[] : Array Nat).push cp) 0) (rest.size + 1)]
  rw [fold_push_acc_factor rest
        (fun a o c => Function.const Nat (a.push c) o)
        decode_fn_push_eq
        Utf8State.expectStart 0 0
        (Function.const Nat ((#[] : Array Nat).push cp) 0) (rest.size + 1)]
  rfl

-- ────────────────────────────────────────────────────────────────────────────
-- Dispatcher
-- ────────────────────────────────────────────────────────────────────────────

/-- Append distribution for any valid codepoint. The case split on
    `cp`'s UTF-8 byte length picks the matching per-length helper. -/
private theorem decode_concat_codepoint (cp : Nat) (h : IsValidCodepoint cp)
    (rest : ByteArray) :
    decodeToCodepoints (encodeCodepoint cp ++ rest)
      = #[cp] ++ decodeToCodepoints rest := by
  obtain ⟨h_max, h_nonsurr⟩ := h
  by_cases h1 : cp < 0x80
  · exact decode_concat_ascii cp h1 rest
  · by_cases h2 : cp < 0x800
    · exact decode_concat_2byte cp (Nat.le_of_not_lt h1) h2 rest
    · by_cases h3 : cp < 0x10000
      · exact decode_concat_3byte cp (Nat.le_of_not_lt h2) h3 h_nonsurr rest
      · exact decode_concat_4byte cp (Nat.le_of_not_lt h3) h_max rest

-- ═══════════════════════════════════════════════════════════════════════════════
-- §13 ARRAY-LEVEL ROUNDTRIP
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The list-form analogue of `decode_encode_codepoints`: decoding the
    concatenation of UTF-8 encodings of a list of valid codepoints
    yields back the list as an `Array`. Proven by structural induction
    on the codepoint list using `decode_concat_codepoint`. -/
private theorem decode_encodeList (cps : List Nat)
    (h_all : ∀ cp ∈ cps, IsValidCodepoint cp) :
    decodeToCodepoints (encodeCodepointsList cps) = cps.toArray := by
  induction cps with
  | nil =>
    show decodeToCodepoints ByteArray.empty = (#[] : Array Nat)
    unfold decodeToCodepoints foldCodepointsWithOffset foldCodepointsWithOffsetGo
    rfl
  | cons cp tail ih =>
    have h_cp : IsValidCodepoint cp := h_all cp List.mem_cons_self
    have h_tail : ∀ cp' ∈ tail, IsValidCodepoint cp' := fun cp' h_mem =>
      h_all cp' (List.mem_cons_of_mem cp h_mem)
    show decodeToCodepoints (encodeCodepoint cp ++ encodeCodepointsList tail)
        = (cp :: tail).toArray
    rw [decode_concat_codepoint cp h_cp (encodeCodepointsList tail), ih h_tail]
    exact (List.toArray_cons cp tail).symm

/-- **Array-level UTF-8 roundtrip.** Decoding the UTF-8 encoding of an
    array of valid codepoints yields the array back. The inductive
    step is `decode_concat_codepoint`; the base case is the empty
    fold's identity behaviour. -/
theorem decode_encode_codepoints (cps : Array Nat)
    (h_all : ∀ cp ∈ cps, IsValidCodepoint cp) :
    decodeToCodepoints (encodeCodepoints cps) = cps := by
  rw [encodeCodepoints_eq_list cps]
  rw [decode_encodeList cps.toList (fun cp h_mem => h_all cp (Array.mem_def.mpr h_mem))]

end Unicode.Codec.Utf8Roundtrip
