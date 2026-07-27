/-
  Unicode.Codec.Utf8Roundtrip

  Closed-form algebraic theorems for the UTF-8 codec: every valid
  Unicode scalar codepoint encodes-then-decodes back to itself, and
  array-level codepoint sequences round-trip across the encoder /
  decoder boundary.

  The codec round-trip is established by structural induction on the byte
  layout, per scalar-value class.

  Layout:

    §1  IsValidCodepoint — the scalar codepoint range minus surrogates.
    §2  Per-byte-class lemmas (1-byte ASCII, 2-byte, 3-byte, 4-byte)
        covering `decodeToCodepoints (encodeCodepoint cp) = [cp]`
        for each of the four UTF-8 length brackets.
    §3  Per-codepoint roundtrip — `decode_encode_codepoint`.
    §4  Append-distribution lemma — `decodeToCodepoints` over a
        valid-codepoint encoded prefix joined with arbitrary suffix.
    §5  List-level roundtrip — `decodeToCodepoints
        (encodeCodepoints cps) = cps`.
-/

import Unicode.Codec.Utf8
import Unicode.Normalization.Utf8Bridge

namespace Unicode.Codec.Utf8Roundtrip

open Unicode.Codec.Utf8
open Unicode.Normalization.Utf8Bridge

set_option maxRecDepth 100000

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

-- The public per-byte-class theorem names are retained, but their proofs now
-- route through the structural fold theorem below.

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 FOLD-STEP LEMMAS PER BYTE LENGTH
-- These say: when fold is in `.expectStart` at position `i` of `bs` and
-- bytes `bs[i .. i+k]` form a valid k-byte encoding of `cp`, the fold
-- consumes those bytes, returns to `.expectStart` at `i+k`, and pushes
-- `cp` onto the accumulator (via `f acc seqStart cp`). Each is proven
-- by direct unfolding of `foldCodepointsWithOffsetGo` and
-- `utf8DecodeStep`.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Out-of-bounds short-circuit: when `i ≥ bs.length`, fold from
    `.expectStart` with any positive fuel returns `acc`. -/
theorem fold_oob_expectStart
    (bs : List UInt8) (f : List Nat → Nat → Nat → List Nat)
    (i seqStart : Nat) (acc : List Nat) (fuel : Nat)
    (hi : ¬ i < bs.length) :
    foldCodepointsWithOffsetGo bs f .expectStart i seqStart acc (fuel + 1) = acc := by
  unfold foldCodepointsWithOffsetGo
  simp [hi]

/-- ASCII fold step: when the byte at position `i` is an ASCII
    codepoint `cp < 0x80`, fold consumes one byte, emits `cp`, and
    returns to `.expectStart`. -/
theorem fold_step_ascii
    (bs : List UInt8) (f : List Nat → Nat → Nat → List Nat)
    (i seqStart : Nat) (acc : List Nat) (fuel : Nat)
    (cp : Nat) (h_cp : cp < 0x80)
    (hi : i < bs.length)
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
theorem fold_step_cont_emit_last
    (bs : List UInt8) (f : List Nat → Nat → Nat → List Nat)
    (i seqStart : Nat) (acc : List Nat) (fuel : Nat)
    (accum minCp cp : Nat)
    (hi : i < bs.length)
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
theorem fold_step_cont_continue
    (bs : List UInt8) (f : List Nat → Nat → Nat → List Nat)
    (i seqStart : Nat) (acc : List Nat) (fuel m accum minCp : Nat)
    (hi : i < bs.length)
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
  simp

/-- 2-byte start step: when `0xC2 ≤ b < 0xE0`, decoder enters
    `.expectCont 1 (b &&& 0x1F) 0x80`. -/
theorem fold_step_2byte_start
    (bs : List UInt8) (f : List Nat → Nat → Nat → List Nat)
    (i seqStart : Nat) (acc : List Nat) (fuel : Nat)
    (hi : i < bs.length)
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
theorem fold_step_3byte_start
    (bs : List UInt8) (f : List Nat → Nat → Nat → List Nat)
    (i seqStart : Nat) (acc : List Nat) (fuel : Nat)
    (hi : i < bs.length)
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
theorem fold_step_4byte_start
    (bs : List UInt8) (f : List Nat → Nat → Nat → List Nat)
    (i seqStart : Nat) (acc : List Nat) (fuel : Nat)
    (hi : i < bs.length)
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
        = acc ++ fold bs f st i seqStart [] fuel

    Holds for any `f` whose effect on the accumulator is
    `acc ++ [cp]` (i.e. left-extension) — captured by the `hf`
    hypothesis. The proof is by fuel induction, splitting on the
    state-machine result for the current byte. -/
theorem fold_push_acc_factor
    (bs : List UInt8) (f : List Nat → Nat → Nat → List Nat)
    (hf : ∀ a o c, f a o c = a ++ [c])
    (st : Utf8State) (i seqStart : Nat) (acc : List Nat) (fuel : Nat) :
    foldCodepointsWithOffsetGo bs f st i seqStart acc fuel
      = acc ++ foldCodepointsWithOffsetGo bs f st i seqStart [] fuel := by
  induction fuel generalizing st i seqStart acc with
  | zero =>
    unfold foldCodepointsWithOffsetGo
    simp
  | succ fuel' ih =>
    unfold foldCodepointsWithOffsetGo
    by_cases hi : i < bs.length
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
        rw [hf acc seqStart cp, hf [] seqStart cp]
        rw [ih next (i + 1) (i + 1) (acc ++ [cp])]
        rw [ih next (i + 1) (i + 1) ([] ++ [cp])]
        -- Goal: acc ++ [cp] ++ X = acc ++ ([] ++ [cp] ++ X)
        -- where X is the same fold-from-[] on both sides
        rw [show ([] : List Nat) ++ [cp] = [cp] from rfl,
            show acc ++ [cp] = acc ++ [cp] from rfl,
            List.append_assoc]
      | reject reason =>
        simp
    · simp [hi]

/-- The specialised form for `decodeToCodepoints`'s inline lambda.
    `fun acc offset cp => Function.const Nat (acc ++ [cp]) offset`
    discards the offset via `Function.const`; this lemma exposes the
    push-only behaviour to `fold_push_acc_factor`. -/
theorem decode_fn_push (a : List Nat) (o c : Nat) :
    (fun acc offset cp => Function.const Nat (acc ++ [cp]) offset)
      a o c = a ++ [c] := by
  rfl

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 OFFSET TRANSLATION
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Index `a.length + k` in `a ++ b` equals index `k` in `b`. The
    standard `List.getElem_append_right`-style fact, restated
    here so the proof of `fold_concat_translate` doesn't have to
    grovel through Substring index arithmetic. -/
theorem byte_at_offset_concat
    (a b : List UInt8) (k : Nat) (hk : k < b.length) :
    (a ++ b)[a.length + k]'(by
      simp [List.length_append]; omega) = b[k]'hk := by
  simp [List.getElem_append_right]

/-- Fold-translation invariance: walking `(a ++ b)` from offset `a.length`
    is the same walk as `b` from offset 0. The fold's `seqStart` is
    threaded through but never inspected by the push-only `f`, so the
    two sides may carry different `seqStart` values (`sa` and `sb`)
    without affecting the result. Generalising `seqStart` is necessary
    because the `.expectCont` continue step keeps the prior `seqStart`
    untouched while the index advances; without it, the IH would not
    apply across that case. -/
theorem fold_concat_translate
    (a b : List UInt8) (f : List Nat → Nat → Nat → List Nat)
    (hf : ∀ ac o c, f ac o c = ac ++ [c])
    (st : Utf8State) (delta sa sb : Nat) (acc : List Nat) (fuel : Nat) :
    foldCodepointsWithOffsetGo (a ++ b) f st (a.length + delta) sa acc fuel
      = foldCodepointsWithOffsetGo b f st delta sb acc fuel := by
  induction fuel generalizing st delta sa sb acc with
  | zero =>
    unfold foldCodepointsWithOffsetGo
    rfl
  | succ fuel' ih =>
    unfold foldCodepointsWithOffsetGo
    by_cases hb : delta < b.length
    · have hab : a.length + delta < (a ++ b).length := by
        simp [List.length_append]; omega
      have hbyte :
          (a ++ b)[a.length + delta]'hab = b[delta]'hb := by
        simp [List.getElem_append_right]
      simp only [hab, ↓reduceDIte, hb, hbyte]
      generalize hStep : utf8DecodeStep st (b[delta]'hb) = step
      cases step with
      | «continue» next =>
        simp only []
        have h1 : a.length + delta + 1 = a.length + (delta + 1) := by omega
        cases st with
        | expectStart =>
          rw [h1]
          exact ih next (delta + 1) (a.length + delta) delta acc
        | expectCont rem accum minCp =>
          rw [h1]
          exact ih next (delta + 1) sa sb acc
      | emit cp next =>
        simp only []
        have h1 : a.length + delta + 1 = a.length + (delta + 1) := by omega
        rw [hf acc sa cp, hf acc sb cp, h1]
        exact ih next (delta + 1) (a.length + delta + 1) (delta + 1) (acc ++ [cp])
      | reject reason =>
        rfl
    · simp [hb, List.length_append]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 PER-BYTE-LENGTH CONSUME LEMMAS
-- ═══════════════════════════════════════════════════════════════════════════════
--
-- Each consume lemma combines the §4 step lemmas to advance the fold
-- through one full encoded codepoint, returning to `.expectStart` at
-- the byte after the encoding with `cp` pushed onto the accumulator.

/-- An ASCII codepoint occupies 1 byte; fold consumes that byte and
    emits `cp`. -/
theorem fold_consume_ascii
    (bs : List UInt8) (f : List Nat → Nat → Nat → List Nat)
    (i seqStart : Nat) (acc : List Nat) (fuel : Nat)
    (cp : Nat) (h_cp : cp < 0x80)
    (hi : i < bs.length)
    (h_b0 : (bs[i]'hi).toNat = cp) :
    foldCodepointsWithOffsetGo bs f .expectStart i seqStart acc (fuel + 1)
      = foldCodepointsWithOffsetGo bs f .expectStart (i + 1) (i + 1)
          (f acc seqStart cp) fuel := by
  exact fold_step_ascii bs f i seqStart acc fuel cp h_cp hi h_b0

/-- A 2-byte codepoint occupies bytes [i, i+1]; fold consumes both
    and emits `cp`. -/
theorem fold_consume_2byte
    (bs : List UInt8) (f : List Nat → Nat → Nat → List Nat)
    (i seqStart : Nat) (acc : List Nat) (fuel : Nat)
    (cp : Nat)
    (hi0 : i < bs.length) (hi1 : i + 1 < bs.length)
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
theorem fold_consume_3byte
    (bs : List UInt8) (f : List Nat → Nat → Nat → List Nat)
    (i seqStart : Nat) (acc : List Nat) (fuel : Nat)
    (cp : Nat)
    (hi0 : i < bs.length) (hi1 : i + 1 < bs.length) (hi2 : i + 2 < bs.length)
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
theorem fold_consume_4byte
    (bs : List UInt8) (f : List Nat → Nat → Nat → List Nat)
    (i seqStart : Nat) (acc : List Nat) (fuel : Nat)
    (cp : Nat)
    (hi0 : i < bs.length) (hi1 : i + 1 < bs.length)
    (hi2 : i + 2 < bs.length) (hi3 : i + 3 < bs.length)
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
def encodeCodepointsList : List Nat → List UInt8
  | []        => ([] : List UInt8)
  | cp :: cps => encodeCodepoint cp ++ encodeCodepointsList cps

/-- `encodeCodepoints` as a left fold over an array equals the
    right-recursive list form on the underlying list. The IH is
    strengthened to thread an arbitrary starting accumulator so the
    cons-step lands cleanly. -/
theorem encodeCodepoints_eq_list (cps : List Nat) :
    encodeCodepoints cps = encodeCodepointsList cps := by
  suffices h : ∀ (init : List UInt8) (xs : List Nat),
      List.foldl (fun acc cp => acc ++ encodeCodepoint cp) init xs
        = init ++ encodeCodepointsList xs by
    unfold encodeCodepoints
    rw [h ([] : List UInt8) cps]
    simp [List.nil_append]
  intro init xs
  induction xs generalizing init with
  | nil =>
    simp [List.foldl, encodeCodepointsList]
  | cons x xs' ih =>
    simp [List.foldl, encodeCodepointsList, ih, List.append_assoc]

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
theorem nat_land_lor_distrib_right (a b c : Nat) :
    (a ||| b) &&& c = (a &&& c) ||| (b &&& c) := by
  apply Nat.eq_of_testBit_eq
  intro i
  rw [Nat.testBit_and, Nat.testBit_or, Nat.testBit_or, Nat.testBit_and, Nat.testBit_and]
  cases a.testBit i <;> cases b.testBit i <;> cases c.testBit i <;> rfl

/-- `n &&& (2^k - 1) = n % 2^k`. The low-`k`-bit projection in two
    forms; converting between them lets `omega` pick up the residue
    after we have isolated the AND. -/
theorem nat_and_two_pow_sub_one_eq_mod (n k : Nat) :
    n &&& (2^k - 1) = n % 2^k := by
  apply Nat.eq_of_testBit_eq
  intro i
  rw [Nat.testBit_and, Nat.testBit_two_pow_sub_one, Nat.testBit_mod_two_pow]
  by_cases h : i < k
  · simp [h]
  · simp [h]

/-- A natural number bounded by `2^k` is its own `2^k`-modulus. -/
theorem nat_mod_two_pow_self (n k : Nat) (h : n < 2^k) :
    n % 2^k = n := Nat.mod_eq_of_lt h

/-- Composite: AND-with-`2^k - 1` is the identity on values bounded by `2^k`. -/
theorem nat_and_two_pow_sub_one_self (n k : Nat) (h : n < 2^k) :
    n &&& (2^k - 1) = n := by
  rw [nat_and_two_pow_sub_one_eq_mod, nat_mod_two_pow_self n k h]

/-- High-low split at bit `k`: `x = (x >>> k) <<< k ||| (x &&& (2^k - 1))`. -/
theorem nat_split_at (x k : Nat) :
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
theorem nat_lor_flag_and_mask (flag x mask : Nat)
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
theorem encode_ascii_form (cp : Nat) (h : cp < 0x80) :
    encodeCodepoint cp = [UInt8.ofNat cp] := by
  unfold encodeCodepoint; simp [h]

-- ────────────────────────────────────────────────────────────────────────────
-- 2-byte
-- ────────────────────────────────────────────────────────────────────────────

/-- Closed form of `encodeCodepoint cp` on the 2-byte bracket. -/
theorem encode_2byte_form (cp : Nat) (h_lo : 0x80 ≤ cp) (h_hi : cp < 0x800) :
    encodeCodepoint cp = [
      UInt8.ofNat (0xC0 ||| (cp >>> 6)),
      UInt8.ofNat (0x80 ||| (cp &&& 0x3F))] := by
  unfold encodeCodepoint
  simp [show ¬ (cp < 0x80) from by omega, h_hi]

/-- Closed form of `encodeCodepoint cp` on the 3-byte bracket. -/
theorem encode_3byte_form (cp : Nat) (h_lo : 0x800 ≤ cp) (h_hi : cp < 0x10000) :
    encodeCodepoint cp = [
      UInt8.ofNat (0xE0 ||| (cp >>> 12)),
      UInt8.ofNat (0x80 ||| ((cp >>> 6) &&& 0x3F)),
      UInt8.ofNat (0x80 ||| (cp &&& 0x3F))] := by
  unfold encodeCodepoint
  simp [show ¬ (cp < 0x80) from by omega,
        show ¬ (cp < 0x800) from by omega, h_hi]

/-- Closed form of `encodeCodepoint cp` on the 4-byte bracket. -/
theorem encode_4byte_form (cp : Nat) (h_lo : 0x10000 ≤ cp)
    (h_hi : cp < 0x110000) :
    encodeCodepoint cp = [
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
theorem byte_lor_80_and_3F (x : Nat) :
    (0x80 ||| (x &&& 0x3F)) &&& 0x3F = x &&& 0x3F := by
  rw [nat_lor_flag_and_mask 0x80 (x &&& 0x3F) 0x3F (by decide)]
  rw [Nat.and_assoc, Nat.and_self]

/-- The low 3 bits of a 0xF0-flagged byte equal the masked input. -/
theorem byte_lor_F0_and_07 (x : Nat) :
    (0xF0 ||| x) &&& 0x07 = x &&& 0x07 :=
  nat_lor_flag_and_mask 0xF0 x 0x07 (by decide)

/-- The low 4 bits of a 0xE0-flagged byte equal the masked input. -/
theorem byte_lor_E0_and_0F (x : Nat) :
    (0xE0 ||| x) &&& 0x0F = x &&& 0x0F :=
  nat_lor_flag_and_mask 0xE0 x 0x0F (by decide)

/-- The low 5 bits of a 0xC0-flagged byte equal the masked input. -/
theorem byte_lor_C0_and_1F (x : Nat) :
    (0xC0 ||| x) &&& 0x1F = x &&& 0x1F :=
  nat_lor_flag_and_mask 0xC0 x 0x1F (by decide)

/-- The 4-byte UTF-8 reconstruction: assembling `cp` from its
    encoded bytes recovers `cp` exactly, when `cp < 2^21` (which
    covers the entire `[0, 0x110000)` codepoint space). -/
theorem encode_4byte_bit_identity (cp : Nat) (h : cp < 0x110000) :
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
theorem encode_3byte_bit_identity (cp : Nat) (h : cp < 0x10000) :
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
theorem encode_2byte_bit_identity (cp : Nat) (h : cp < 0x800) :
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
theorem nat_lor_shiftLeft_eq_add (high y k : Nat) (h_y : y < 2^k) :
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
theorem encode_ascii_byte0 (cp : Nat) (h : cp < 0x80) :
    (UInt8.ofNat cp).toNat = cp :=
  uint8_ofNat_toNat cp (by omega)

-- ────────────────────────────────────────────────────────────────────────────
-- 2-byte
-- ────────────────────────────────────────────────────────────────────────────

/-- 2-byte byte 0 lies in `[0xC2, 0xE0)` and round-trips through `UInt8`. -/
theorem encode_2byte_byte0 (cp : Nat) (h_lo : 0x80 ≤ cp) (h_hi : cp < 0x800) :
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
theorem encode_2byte_byte1 (cp : Nat) :
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
theorem encode_3byte_byte0 (cp : Nat) (h_lo : 0x800 ≤ cp) (h_hi : cp < 0x10000) :
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
theorem encode_4byte_byte0 (cp : Nat) (h_lo : 0x10000 ≤ cp) (h_hi : cp < 0x110000) :
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
-- Prepending an encoded codepoint to `rest` decodes to `[cp] ++
-- decodeToCodepoints rest`. Each helper advances the fold past the
-- encoding's bytes via `fold_consume_<n>byte`, translates the suffix
-- fold via `fold_concat_translate`, and lifts the leading `[cp]` out
-- of the accumulator via `fold_push_acc_factor`.

/-- The decode-fold's update function lifts to `acc ++ [c]` after β.
    Used as the `hf` hypothesis for `fold_concat_translate` and
    `fold_push_acc_factor`. -/
theorem decode_fn_push_eq
    (acc : List Nat) (offset c : Nat) :
    (fun (a : List Nat) (o c : Nat) => Function.const Nat (a ++ [c]) o) acc offset c
      = acc ++ [c] := rfl

-- ────────────────────────────────────────────────────────────────────────────
-- 1-byte (ASCII)
-- ────────────────────────────────────────────────────────────────────────────

/-- Prepending an ASCII-encoded codepoint to `rest` decodes to
    `[cp] ++ decodeToCodepoints rest`. -/
theorem decode_concat_ascii (cp : Nat) (h_lt : cp < 0x80) (rest : List UInt8) :
    decodeToCodepoints (encodeCodepoint cp ++ rest)
      = [cp] ++ decodeToCodepoints rest := by
  -- Substitute encodeCodepoint cp with its closed form so its size
  -- (= 1) reduces by `rfl` and indexing is direct.
  rw [encode_ascii_form cp h_lt]
  have h_pfx_size : ([UInt8.ofNat cp] : List UInt8).length = 1 := rfl
  have h_pfx_pos : 0 < ([UInt8.ofNat cp] : List UInt8).length := by
    rw [h_pfx_size]; omega
  have h_total : ([UInt8.ofNat cp] ++ rest).length = rest.length + 1 := by
    rw [List.length_append, h_pfx_size]; omega
  have h_idx : 0 < ([UInt8.ofNat cp] ++ rest).length := by
    rw [h_total]; omega
  have h_byte0 : (([UInt8.ofNat cp] ++ rest)[0]'h_idx).toNat = cp := by
    rw [List.getElem_append_left h_pfx_pos]
    show (UInt8.ofNat cp).toNat = cp
    exact uint8_ofNat_toNat cp (by omega)
  -- Unfold both sides to fold-Go form.
  unfold decodeToCodepoints foldCodepointsWithOffset
  -- Massage the LHS fuel `(pfx ++ rest).length + 1` into `(rest.length + 1) + 1`
  -- so `fold_consume_ascii` can fire its `fuel + 1` pattern.
  rw [show ([UInt8.ofNat cp] ++ rest).length + 1
        = (rest.length + 1) + 1 from by rw [h_total]]
  rw [fold_consume_ascii ([UInt8.ofNat cp] ++ rest)
        (fun a o c => Function.const Nat (a ++ [c]) o)
        0 0 [] (rest.length + 1) cp h_lt h_idx h_byte0]
  -- After consume: index `0 + 1`, seqStart `0 + 1`, accumulator
  -- `Function.const Nat ([] ++ [cp]) 0`. Bridge index to
  -- `pfx.length + 0` so `fold_concat_translate` matches.
  rw [show (0 : Nat) + 1
        = ([UInt8.ofNat cp] : List UInt8).length + 0 from by
    rw [h_pfx_size]]
  rw [fold_concat_translate ([UInt8.ofNat cp]) rest
        (fun a o c => Function.const Nat (a ++ [c]) o)
        decode_fn_push_eq
        Utf8State.expectStart 0
        (([UInt8.ofNat cp] : List UInt8).length + 0) 0
        (Function.const Nat (([] : List Nat) ++ [cp]) 0) (rest.length + 1)]
  rw [fold_push_acc_factor rest
        (fun a o c => Function.const Nat (a ++ [c]) o)
        decode_fn_push_eq
        Utf8State.expectStart 0 0
        (Function.const Nat (([] : List Nat) ++ [cp]) 0) (rest.length + 1)]
  rfl

-- ────────────────────────────────────────────────────────────────────────────
-- 2-byte
-- ────────────────────────────────────────────────────────────────────────────

/-- Prepending a 2-byte-encoded codepoint to `rest` decodes to
    `[cp] ++ decodeToCodepoints rest`. -/
theorem decode_concat_2byte (cp : Nat) (h_lo : 0x80 ≤ cp) (h_hi : cp < 0x800)
    (rest : List UInt8) :
    decodeToCodepoints (encodeCodepoint cp ++ rest)
      = [cp] ++ decodeToCodepoints rest := by
  rw [encode_2byte_form cp h_lo h_hi]
  -- Concrete prefix: 2 bytes long.
  let pfxBytes : List UInt8 := [
    UInt8.ofNat (0xC0 ||| (cp >>> 6)),
    UInt8.ofNat (0x80 ||| (cp &&& 0x3F))]
  have h_pfx_size : pfxBytes.length = 2 := rfl
  have h_pfx_pos0 : 0 < pfxBytes.length := by rw [h_pfx_size]; omega
  have h_pfx_pos1 : 1 < pfxBytes.length := by rw [h_pfx_size]; omega
  have h_total : (pfxBytes ++ rest).length = rest.length + 2 := by
    rw [List.length_append, h_pfx_size]; omega
  have h_idx0 : 0 < (pfxBytes ++ rest).length := by rw [h_total]; omega
  have h_idx1 : 0 + 1 < (pfxBytes ++ rest).length := by rw [h_total]; omega
  -- Byte 0 is the start byte; byte 1 is the continuation byte.
  have h_byte0_eq :
      ((pfxBytes ++ rest)[0]'h_idx0).toNat = 0xC0 ||| (cp >>> 6) := by
    rw [List.getElem_append_left h_pfx_pos0]
    show (UInt8.ofNat (0xC0 ||| (cp >>> 6))).toNat = 0xC0 ||| (cp >>> 6)
    have h_b0 := encode_2byte_byte0 cp h_lo h_hi
    exact h_b0.left
  have h_byte1_eq :
      ((pfxBytes ++ rest)[0 + 1]'h_idx1).toNat = 0x80 ||| (cp &&& 0x3F) := by
    rw [List.getElem_append_left h_pfx_pos1]
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
  rw [show (pfxBytes ++ rest).length + 1 = (rest.length + 1) + 2 from by
    rw [h_total]]
  rw [fold_consume_2byte (pfxBytes ++ rest)
        (fun a o c => Function.const Nat (a ++ [c]) o)
        0 0 [] (rest.length + 1) cp h_idx0 h_idx1
        h_b0_lo h_b0_hi h_b1_lo h_b1_hi h_cp_eq h_overlong h_nonsurr h_max]
  rw [show (0 : Nat) + 2 = pfxBytes.length + 0 from by rw [h_pfx_size]]
  rw [fold_concat_translate pfxBytes rest
        (fun a o c => Function.const Nat (a ++ [c]) o)
        decode_fn_push_eq
        Utf8State.expectStart 0 (pfxBytes.length + 0) 0
        (Function.const Nat (([] : List Nat) ++ [cp]) 0) (rest.length + 1)]
  rw [fold_push_acc_factor rest
        (fun a o c => Function.const Nat (a ++ [c]) o)
        decode_fn_push_eq
        Utf8State.expectStart 0 0
        (Function.const Nat (([] : List Nat) ++ [cp]) 0) (rest.length + 1)]
  rfl

-- ────────────────────────────────────────────────────────────────────────────
-- 3-byte
-- ────────────────────────────────────────────────────────────────────────────

/-- The shared continuation-byte form `0x80 ||| (x &&& 0x3F)` is reused
    at byte positions 1, 2, 3 across the 2-, 3-, 4-byte cases — the
    byte-1 lemma generalises across them. -/
theorem encode_continuation_bounds (x : Nat) :
    (UInt8.ofNat (0x80 ||| (x &&& 0x3F))).toNat = 0x80 ||| (x &&& 0x3F) ∧
    0x80 ≤ 0x80 ||| (x &&& 0x3F) ∧
    0x80 ||| (x &&& 0x3F) < 0xC0 :=
  encode_2byte_byte1 x

/-- Prepending a 3-byte-encoded codepoint to `rest` decodes to
    `[cp] ++ decodeToCodepoints rest`. -/
theorem decode_concat_3byte (cp : Nat) (h_lo : 0x800 ≤ cp) (h_hi : cp < 0x10000)
    (h_nonsurr : ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF))
    (rest : List UInt8) :
    decodeToCodepoints (encodeCodepoint cp ++ rest)
      = [cp] ++ decodeToCodepoints rest := by
  rw [encode_3byte_form cp h_lo h_hi]
  let pfxBytes : List UInt8 := [
    UInt8.ofNat (0xE0 ||| (cp >>> 12)),
    UInt8.ofNat (0x80 ||| ((cp >>> 6) &&& 0x3F)),
    UInt8.ofNat (0x80 ||| (cp &&& 0x3F))]
  have h_pfx_size : pfxBytes.length = 3 := rfl
  have h_pfx_pos0 : 0 < pfxBytes.length := by rw [h_pfx_size]; omega
  have h_pfx_pos1 : 1 < pfxBytes.length := by rw [h_pfx_size]; omega
  have h_pfx_pos2 : 2 < pfxBytes.length := by rw [h_pfx_size]; omega
  have h_total : (pfxBytes ++ rest).length = rest.length + 3 := by
    rw [List.length_append, h_pfx_size]; omega
  have h_idx0 : 0 < (pfxBytes ++ rest).length := by rw [h_total]; omega
  have h_idx1 : 0 + 1 < (pfxBytes ++ rest).length := by rw [h_total]; omega
  have h_idx2 : 0 + 2 < (pfxBytes ++ rest).length := by rw [h_total]; omega
  have h_byte0_eq :
      ((pfxBytes ++ rest)[0]'h_idx0).toNat = 0xE0 ||| (cp >>> 12) := by
    rw [List.getElem_append_left h_pfx_pos0]
    show (UInt8.ofNat (0xE0 ||| (cp >>> 12))).toNat = 0xE0 ||| (cp >>> 12)
    exact (encode_3byte_byte0 cp h_lo h_hi).left
  have h_byte1_eq :
      ((pfxBytes ++ rest)[0 + 1]'h_idx1).toNat = 0x80 ||| ((cp >>> 6) &&& 0x3F) := by
    rw [List.getElem_append_left h_pfx_pos1]
    show (UInt8.ofNat (0x80 ||| ((cp >>> 6) &&& 0x3F))).toNat
        = 0x80 ||| ((cp >>> 6) &&& 0x3F)
    exact (encode_continuation_bounds (cp >>> 6)).left
  have h_byte2_eq :
      ((pfxBytes ++ rest)[0 + 2]'h_idx2).toNat = 0x80 ||| (cp &&& 0x3F) := by
    rw [List.getElem_append_left h_pfx_pos2]
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
  rw [show (pfxBytes ++ rest).length + 1 = (rest.length + 1) + 3 from by rw [h_total]]
  rw [fold_consume_3byte (pfxBytes ++ rest)
        (fun a o c => Function.const Nat (a ++ [c]) o)
        0 0 [] (rest.length + 1) cp h_idx0 h_idx1 h_idx2
        h_b0_lo h_b0_hi h_b1_lo h_b1_hi h_b2_lo h_b2_hi
        h_cp_eq h_overlong h_nonsurr h_max]
  rw [show (0 : Nat) + 3 = pfxBytes.length + 0 from by rw [h_pfx_size]]
  rw [fold_concat_translate pfxBytes rest
        (fun a o c => Function.const Nat (a ++ [c]) o)
        decode_fn_push_eq
        Utf8State.expectStart 0 (pfxBytes.length + 0) 0
        (Function.const Nat (([] : List Nat) ++ [cp]) 0) (rest.length + 1)]
  rw [fold_push_acc_factor rest
        (fun a o c => Function.const Nat (a ++ [c]) o)
        decode_fn_push_eq
        Utf8State.expectStart 0 0
        (Function.const Nat (([] : List Nat) ++ [cp]) 0) (rest.length + 1)]
  rfl

-- ────────────────────────────────────────────────────────────────────────────
-- 4-byte
-- ────────────────────────────────────────────────────────────────────────────

/-- Prepending a 4-byte-encoded codepoint to `rest` decodes to
    `[cp] ++ decodeToCodepoints rest`. -/
theorem decode_concat_4byte (cp : Nat) (h_lo : 0x10000 ≤ cp) (h_hi : cp < 0x110000)
    (rest : List UInt8) :
    decodeToCodepoints (encodeCodepoint cp ++ rest)
      = [cp] ++ decodeToCodepoints rest := by
  rw [encode_4byte_form cp h_lo h_hi]
  let pfxBytes : List UInt8 := [
    UInt8.ofNat (0xF0 ||| (cp >>> 18)),
    UInt8.ofNat (0x80 ||| ((cp >>> 12) &&& 0x3F)),
    UInt8.ofNat (0x80 ||| ((cp >>> 6) &&& 0x3F)),
    UInt8.ofNat (0x80 ||| (cp &&& 0x3F))]
  have h_pfx_size : pfxBytes.length = 4 := rfl
  have h_pfx_pos0 : 0 < pfxBytes.length := by rw [h_pfx_size]; omega
  have h_pfx_pos1 : 1 < pfxBytes.length := by rw [h_pfx_size]; omega
  have h_pfx_pos2 : 2 < pfxBytes.length := by rw [h_pfx_size]; omega
  have h_pfx_pos3 : 3 < pfxBytes.length := by rw [h_pfx_size]; omega
  have h_total : (pfxBytes ++ rest).length = rest.length + 4 := by
    rw [List.length_append, h_pfx_size]; omega
  have h_idx0 : 0 < (pfxBytes ++ rest).length := by rw [h_total]; omega
  have h_idx1 : 0 + 1 < (pfxBytes ++ rest).length := by rw [h_total]; omega
  have h_idx2 : 0 + 2 < (pfxBytes ++ rest).length := by rw [h_total]; omega
  have h_idx3 : 0 + 3 < (pfxBytes ++ rest).length := by rw [h_total]; omega
  have h_byte0_eq :
      ((pfxBytes ++ rest)[0]'h_idx0).toNat = 0xF0 ||| (cp >>> 18) := by
    rw [List.getElem_append_left h_pfx_pos0]
    show (UInt8.ofNat (0xF0 ||| (cp >>> 18))).toNat = 0xF0 ||| (cp >>> 18)
    exact (encode_4byte_byte0 cp h_lo h_hi).left
  have h_byte1_eq :
      ((pfxBytes ++ rest)[0 + 1]'h_idx1).toNat = 0x80 ||| ((cp >>> 12) &&& 0x3F) := by
    rw [List.getElem_append_left h_pfx_pos1]
    show (UInt8.ofNat (0x80 ||| ((cp >>> 12) &&& 0x3F))).toNat
        = 0x80 ||| ((cp >>> 12) &&& 0x3F)
    exact (encode_continuation_bounds (cp >>> 12)).left
  have h_byte2_eq :
      ((pfxBytes ++ rest)[0 + 2]'h_idx2).toNat = 0x80 ||| ((cp >>> 6) &&& 0x3F) := by
    rw [List.getElem_append_left h_pfx_pos2]
    show (UInt8.ofNat (0x80 ||| ((cp >>> 6) &&& 0x3F))).toNat
        = 0x80 ||| ((cp >>> 6) &&& 0x3F)
    exact (encode_continuation_bounds (cp >>> 6)).left
  have h_byte3_eq :
      ((pfxBytes ++ rest)[0 + 3]'h_idx3).toNat = 0x80 ||| (cp &&& 0x3F) := by
    rw [List.getElem_append_left h_pfx_pos3]
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
  rw [show (pfxBytes ++ rest).length + 1 = (rest.length + 1) + 4 from by rw [h_total]]
  rw [fold_consume_4byte (pfxBytes ++ rest)
        (fun a o c => Function.const Nat (a ++ [c]) o)
        0 0 [] (rest.length + 1) cp h_idx0 h_idx1 h_idx2 h_idx3
        h_b0_lo h_b0_hi h_b1_lo h_b1_hi h_b2_lo h_b2_hi h_b3_lo h_b3_hi
        h_cp_eq h_overlong h_nonsurr h_max]
  rw [show (0 : Nat) + 4 = pfxBytes.length + 0 from by rw [h_pfx_size]]
  rw [fold_concat_translate pfxBytes rest
        (fun a o c => Function.const Nat (a ++ [c]) o)
        decode_fn_push_eq
        Utf8State.expectStart 0 (pfxBytes.length + 0) 0
        (Function.const Nat (([] : List Nat) ++ [cp]) 0) (rest.length + 1)]
  rw [fold_push_acc_factor rest
        (fun a o c => Function.const Nat (a ++ [c]) o)
        decode_fn_push_eq
        Utf8State.expectStart 0 0
        (Function.const Nat (([] : List Nat) ++ [cp]) 0) (rest.length + 1)]
  rfl

-- ────────────────────────────────────────────────────────────────────────────
-- Dispatcher
-- ────────────────────────────────────────────────────────────────────────────

/-- Append distribution for any valid codepoint. The case split on
    `cp`'s UTF-8 byte length picks the matching per-length helper. -/
theorem decode_concat_codepoint (cp : Nat) (h : IsValidCodepoint cp)
    (rest : List UInt8) :
    decodeToCodepoints (encodeCodepoint cp ++ rest)
      = [cp] ++ decodeToCodepoints rest := by
  obtain ⟨h_max, h_nonsurr⟩ := h
  by_cases h1 : cp < 0x80
  · exact decode_concat_ascii cp h1 rest
  · by_cases h2 : cp < 0x800
    · exact decode_concat_2byte cp (Nat.le_of_not_lt h1) h2 rest
    · by_cases h3 : cp < 0x10000
      · exact decode_concat_3byte cp (Nat.le_of_not_lt h2) h3 h_nonsurr rest
      · exact decode_concat_4byte cp (Nat.le_of_not_lt h3) h_max rest

-- ═══════════════════════════════════════════════════════════════════════════════
-- §13 PER-CODEPOINT ROUNDTRIP ALIASES
-- ═══════════════════════════════════════════════════════════════════════════════

/-- HEADLINE per-codepoint theorem: every valid Unicode scalar
    codepoint encodes-then-decodes to itself. -/
theorem decode_encode_codepoint (cp : Nat) (h : IsValidCodepoint cp) :
    decodeToCodepoints (encodeCodepoint cp) = [cp] := by
  have hConcat := decode_concat_codepoint cp h ([] : List UInt8)
  have hNil : decodeToCodepoints ([] : List UInt8) = [] := by
    unfold decodeToCodepoints foldCodepointsWithOffset foldCodepointsWithOffsetGo
    rfl
  simpa [List.append_nil, hNil] using hConcat

/-- ASCII (1-byte) codepoint roundtrip. -/
theorem decode_encode_ascii (cp : Nat) (h : cp < 0x80) :
    decodeToCodepoints (encodeCodepoint cp) = [cp] :=
  decode_encode_codepoint cp ⟨by omega, by omega⟩

/-- 2-byte codepoint roundtrip. -/
theorem decode_encode_2byte (cp : Nat) (h : cp < 0x800) :
    decodeToCodepoints (encodeCodepoint cp) = [cp] :=
  decode_encode_codepoint cp ⟨by omega, by omega⟩

/-- BMP codepoint roundtrip, excluding surrogates. -/
theorem decode_encode_3byte (cp : Nat) (h : cp < 0x10000)
    (h_nonsurr : ¬ (0xD800 ≤ cp ∧ cp ≤ 0xDFFF)) :
    decodeToCodepoints (encodeCodepoint cp) = [cp] :=
  decode_encode_codepoint cp ⟨by omega, h_nonsurr⟩

/-- 4-byte codepoint roundtrip. -/
theorem decode_encode_4byte (cp : Nat)
    (h_lo : 0x10000 ≤ cp) (h_hi : cp < 0x110000) :
    decodeToCodepoints (encodeCodepoint cp) = [cp] :=
  decode_encode_codepoint cp ⟨h_hi, by omega⟩

/-- Finite-domain ASCII roundtrip alias. -/
theorem decode_encode_ascii_fin :
    ∀ cp : Fin 0x80,
      decodeToCodepoints (encodeCodepoint cp.val) = [cp.val] := by
  intro cp
  exact decode_encode_ascii cp.val cp.isLt

/-- Finite-domain 2-byte bracket roundtrip alias. -/
theorem decode_encode_2byte_fin :
    ∀ cp : Fin 0x800,
      decodeToCodepoints (encodeCodepoint cp.val) = [cp.val] := by
  intro cp
  exact decode_encode_2byte cp.val cp.isLt

/-- Finite-domain BMP roundtrip alias, excluding surrogates. -/
theorem decode_encode_3byte_fin :
    ∀ cp : Fin 0x10000,
      ¬ (0xD800 ≤ cp.val ∧ cp.val ≤ 0xDFFF) →
      decodeToCodepoints (encodeCodepoint cp.val) = [cp.val] := by
  intro cp h_nonsurr
  exact decode_encode_3byte cp.val cp.isLt h_nonsurr

/-- 4-byte plane aliases retained for compatibility with the public proof layout. -/
theorem decode_encode_4byte_plane_1 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0x10000 + cp.val))
        = [0x10000 + cp.val] := by
  intro cp
  exact decode_encode_4byte (0x10000 + cp.val) (by omega) (by omega)

theorem decode_encode_4byte_plane_2 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0x20000 + cp.val))
        = [0x20000 + cp.val] := by
  intro cp
  exact decode_encode_4byte (0x20000 + cp.val) (by omega) (by omega)

theorem decode_encode_4byte_plane_3 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0x30000 + cp.val))
        = [0x30000 + cp.val] := by
  intro cp
  exact decode_encode_4byte (0x30000 + cp.val) (by omega) (by omega)

theorem decode_encode_4byte_plane_4 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0x40000 + cp.val))
        = [0x40000 + cp.val] := by
  intro cp
  exact decode_encode_4byte (0x40000 + cp.val) (by omega) (by omega)

theorem decode_encode_4byte_plane_5 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0x50000 + cp.val))
        = [0x50000 + cp.val] := by
  intro cp
  exact decode_encode_4byte (0x50000 + cp.val) (by omega) (by omega)

theorem decode_encode_4byte_plane_6 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0x60000 + cp.val))
        = [0x60000 + cp.val] := by
  intro cp
  exact decode_encode_4byte (0x60000 + cp.val) (by omega) (by omega)

theorem decode_encode_4byte_plane_7 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0x70000 + cp.val))
        = [0x70000 + cp.val] := by
  intro cp
  exact decode_encode_4byte (0x70000 + cp.val) (by omega) (by omega)

theorem decode_encode_4byte_plane_8 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0x80000 + cp.val))
        = [0x80000 + cp.val] := by
  intro cp
  exact decode_encode_4byte (0x80000 + cp.val) (by omega) (by omega)

theorem decode_encode_4byte_plane_9 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0x90000 + cp.val))
        = [0x90000 + cp.val] := by
  intro cp
  exact decode_encode_4byte (0x90000 + cp.val) (by omega) (by omega)

theorem decode_encode_4byte_plane_10 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0xA0000 + cp.val))
        = [0xA0000 + cp.val] := by
  intro cp
  exact decode_encode_4byte (0xA0000 + cp.val) (by omega) (by omega)

theorem decode_encode_4byte_plane_11 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0xB0000 + cp.val))
        = [0xB0000 + cp.val] := by
  intro cp
  exact decode_encode_4byte (0xB0000 + cp.val) (by omega) (by omega)

theorem decode_encode_4byte_plane_12 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0xC0000 + cp.val))
        = [0xC0000 + cp.val] := by
  intro cp
  exact decode_encode_4byte (0xC0000 + cp.val) (by omega) (by omega)

theorem decode_encode_4byte_plane_13 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0xD0000 + cp.val))
        = [0xD0000 + cp.val] := by
  intro cp
  exact decode_encode_4byte (0xD0000 + cp.val) (by omega) (by omega)

theorem decode_encode_4byte_plane_14 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0xE0000 + cp.val))
        = [0xE0000 + cp.val] := by
  intro cp
  exact decode_encode_4byte (0xE0000 + cp.val) (by omega) (by omega)

theorem decode_encode_4byte_plane_15 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0xF0000 + cp.val))
        = [0xF0000 + cp.val] := by
  intro cp
  exact decode_encode_4byte (0xF0000 + cp.val) (by omega) (by omega)

theorem decode_encode_4byte_plane_16 :
    ∀ cp : Fin 0x10000,
      decodeToCodepoints (encodeCodepoint (0x100000 + cp.val))
        = [0x100000 + cp.val] := by
  intro cp
  exact decode_encode_4byte (0x100000 + cp.val) (by omega) (by omega)


-- ═══════════════════════════════════════════════════════════════════════════════
-- §14 ARRAY-LEVEL ROUNDTRIP
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The list-form analogue of `decode_encode_codepoints`: decoding the
    concatenation of UTF-8 encodings of a list of valid codepoints
    yields back the list. Proven by structural induction
    on the codepoint list using `decode_concat_codepoint`. -/
theorem decode_encodeList (cps : List Nat)
    (h_all : ∀ cp ∈ cps, IsValidCodepoint cp) :
    decodeToCodepoints (encodeCodepointsList cps) = cps := by
  induction cps with
  | nil =>
    show decodeToCodepoints ([] : List UInt8) = ([] : List Nat)
    unfold decodeToCodepoints foldCodepointsWithOffset foldCodepointsWithOffsetGo
    rfl
  | cons cp tail ih =>
    have h_cp : IsValidCodepoint cp := h_all cp List.mem_cons_self
    have h_tail : ∀ cp' ∈ tail, IsValidCodepoint cp' := fun cp' h_mem =>
      h_all cp' (List.mem_cons_of_mem cp h_mem)
    show decodeToCodepoints (encodeCodepoint cp ++ encodeCodepointsList tail)
        = (cp :: tail)
    rw [decode_concat_codepoint cp h_cp (encodeCodepointsList tail), ih h_tail,
      List.singleton_append]

/-- **List-level UTF-8 roundtrip.** Decoding the UTF-8 encoding of a
    list of valid codepoints yields the list back. The inductive
    step is `decode_concat_codepoint`; the base case is the empty
    fold's identity behaviour. -/
theorem decode_encode_codepoints (cps : List Nat)
    (h_all : ∀ cp ∈ cps, IsValidCodepoint cp) :
    decodeToCodepoints (encodeCodepoints cps) = cps := by
  rw [encodeCodepoints_eq_list cps]
  rw [decode_encodeList cps h_all]

end Unicode.Codec.Utf8Roundtrip
