/-
  Unicode.Normalization.QuickCheckHangulFacts

  Hangul / jamo CCC = 0 facts in support of `isNFCQuickCheck` soundness
  (UAX #15 §A.1).

  Four `decide` tables live here:

    * `lJamo_ccc_zero`         — 19 L-jamo codepoints have CCC = 0.
    * `vJamo_ccc_zero`         — 21 V-jamo codepoints have CCC = 0.
    * `tJamo_ccc_zero`         — 27 T-jamo codepoints have CCC = 0
                                 (indexed from `TBase + 1`; `TBase + 0`
                                 is the "no T" sentinel).
    * `hangulSyllable_ccc_zero` — every one of the 11172 precomposed
                                  Hangul syllables has CCC = 0.

  The three tables together discharge "Hangul composition never fires
  with a nonstarter trailing element" — the lemma the Fact 3 per-codepoint
  lift in `QuickCheckSoundness` depends on.

  Placed in its own module so the heavy compilation (especially the
  11172-element Hangul-syllable scan) isolates cleanly under
  `LEAN_NUM_THREADS=1`. Parallel to `QuickCheckFacts`'s split.
-/

import Unicode.Normalization.Hangul
import Unicode.Normalization.Lookup

namespace Unicode.Normalization.QuickCheckHangulFacts

open Unicode.Normalization

set_option maxRecDepth 100000

/-- Every L-jamo (leading consonant jamo, range `0x1100..0x1112`) has
    CCC = 0. Narrow `decide` over 19 codepoints. -/
theorem lJamo_ccc_zero :
    (List.range Hangul.LCount).all
      (fun i => Lookup.canonicalCombiningClass (Hangul.LBase + i) = 0) = true := by
  decide

/-- Every V-jamo (vowel jamo, range `0x1161..0x1175`) has CCC = 0.
    Narrow `decide` over 21 codepoints. -/
theorem vJamo_ccc_zero :
    (List.range Hangul.VCount).all
      (fun i => Lookup.canonicalCombiningClass (Hangul.VBase + i) = 0) = true := by
  decide

/-- Every T-jamo (trailing jamo, range `0x11A8..0x11C2`) has CCC = 0.
    Narrow `decide` over 27 codepoints. Indexes from `TBase + 1`
    because `TBase + 0` is the "no T" sentinel in `decomposeSyllable?`. -/
theorem tJamo_ccc_zero :
    (List.range (Hangul.TCount - 1)).all
      (fun i => Lookup.canonicalCombiningClass (Hangul.TBase + 1 + i) = 0) = true := by
  decide

/-- The pinned NFC-relevant UnicodeData rows omit precomposed Hangul syllables;
    those decompose algorithmically instead of via the row table. -/
theorem rows_omit_hangul_syllables :
    Unicode.Generated.UnicodeData.rowsList.all (fun r =>
      decide (¬ (Hangul.SBase ≤ r.codepoint ∧ r.codepoint ≤ Hangul.SBase + Hangul.SCount - 1))) = true := by
  decide +kernel

/-- Every precomposed Hangul syllable (range `0xAC00..0xD7A3`) has
    CCC = 0. Table-scale `decide` over 11172 codepoints. -/
theorem hangulSyllable_ccc_zero :
    (List.range Hangul.SCount).all
      (fun i => Lookup.canonicalCombiningClass (Hangul.SBase + i) = 0) = true := by
  rw [List.all_eq_true]
  intro i hi
  have hiLt : i < Hangul.SCount := List.mem_range.mp hi
  have hiLtNorm : i < 11172 := by
    simpa [Hangul.SCount, Hangul.LCount, Hangul.NCount, Hangul.VCount, Hangul.TCount] using hiLt
  have hRange : 0xAC00 ≤ Hangul.SBase + i ∧ Hangul.SBase + i < 0xAC00 + 11172 := by
    simp [Hangul.SBase]
    omega
  have hNone : Lookup.lookupRow (Hangul.SBase + i) = none :=
    Lookup.lookupRow_none_of_all_outside Hangul.SBase (Hangul.SBase + Hangul.SCount - 1)
      (Hangul.SBase + i) rows_omit_hangul_syllables (by omega) (by omega)
  exact decide_eq_true
    (Lookup.canonicalCombiningClass_of_lookupRow_none (Hangul.SBase + i) hNone)

end Unicode.Normalization.QuickCheckHangulFacts
