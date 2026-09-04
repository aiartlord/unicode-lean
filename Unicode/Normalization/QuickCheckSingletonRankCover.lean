/-
  Unicode.Normalization.QuickCheckSingletonRankCover

  The two table-coverage facts of the generated singleton-rank data: every
  `UnicodeData` row is either irrelevant to QC=Y starter singletons (a
  non-starter, a Hangul syllable, not `NFC_QC = Y`, or without a
  decomposition) or is carried by a rank row. Proven per 64-row chunk with
  the cheap row tests ordered before the quick-check range walk, so the
  kernel evaluates that walk only for the rows no cheap test settles and its
  working set is one chunk's rows; the chunks combine along the right-nested
  `rowsList` without evaluating anything, and the statements the soundness
  proofs consume are recovered pointwise.
-/

import Unicode.Normalization.QuickCheckSingletonRankData

namespace Unicode.Normalization.QuickCheckSingletonRankCover

open Unicode.Normalization
open Unicode.Normalization.NFC (nfcQCValue)
open Unicode.Normalization.QuickCheckSingletonRankData (rows)
open Unicode.Generated

/-- The coverage predicate as its consumers state it. -/
def cover (row : UnicodeData.UnicodeDataRow) : Bool :=
  decide (row.canonicalCombiningClass ≠ 0) ||
  decide (Hangul.isHangulSyllable row.codepoint = true) ||
  decide (nfcQCValue row.codepoint ≠ .Y) ||
  decide (row.canonicalDecomposition.length = 0) ||
  rows.any (fun entry => decide (entry.codepoint = row.codepoint))

/-- The same predicate in evaluation order: the range walk last, the rank
    membership by `Nat.beq`. -/
def coverFast (row : UnicodeData.UnicodeDataRow) : Bool :=
  decide (row.canonicalCombiningClass ≠ 0) ||
  decide (Hangul.isHangulSyllable row.codepoint = true) ||
  decide (row.canonicalDecomposition.length = 0) ||
  rows.any (fun entry => Nat.beq entry.codepoint row.codepoint) ||
  decide (nfcQCValue row.codepoint ≠ .Y)

/-- The coverage predicate through the row lookup, as its consumers state it. -/
def coverLookup (row : UnicodeData.UnicodeDataRow) : Bool :=
  decide (Lookup.canonicalCombiningClass row.codepoint ≠ 0) ||
  decide (Hangul.isHangulSyllable row.codepoint = true) ||
  decide (nfcQCValue row.codepoint ≠ .Y) ||
  decide (row.canonicalDecomposition.length = 0) ||
  rows.any (fun entry => decide (entry.codepoint = row.codepoint))

/-- `coverLookup` in evaluation order. -/
def coverLookupFast (row : UnicodeData.UnicodeDataRow) : Bool :=
  decide (Lookup.canonicalCombiningClass row.codepoint ≠ 0) ||
  decide (Hangul.isHangulSyllable row.codepoint = true) ||
  decide (row.canonicalDecomposition.length = 0) ||
  rows.any (fun entry => Nat.beq entry.codepoint row.codepoint) ||
  decide (nfcQCValue row.codepoint ≠ .Y)

private theorem decide_eq_beq (a b : Nat) : decide (a = b) = Nat.beq a b := by
  cases hb : Nat.beq a b
  · exact decide_eq_false (Nat.ne_of_beq_eq_false hb)
  · exact decide_eq_true (Nat.eq_of_beq_eq_true hb)

private theorem rows_any_decide_eq_beq (cp : Nat) :
    rows.any (fun entry => decide (entry.codepoint = cp))
      = rows.any (fun entry => Nat.beq entry.codepoint cp) := by
  congr 1
  funext entry
  exact decide_eq_beq entry.codepoint cp

theorem cover_eq_fast : cover = coverFast := by
  funext row
  unfold cover coverFast
  rw [rows_any_decide_eq_beq]
  cases decide (row.canonicalCombiningClass ≠ 0) <;>
    cases decide (Hangul.isHangulSyllable row.codepoint = true) <;>
    cases decide (nfcQCValue row.codepoint ≠ .Y) <;>
    cases decide (row.canonicalDecomposition.length = 0) <;>
    cases rows.any (fun entry => Nat.beq entry.codepoint row.codepoint) <;>
    rfl

theorem coverLookup_eq_fast : coverLookup = coverLookupFast := by
  funext row
  unfold coverLookup coverLookupFast
  rw [rows_any_decide_eq_beq]
  cases decide (Lookup.canonicalCombiningClass row.codepoint ≠ 0) <;>
    cases decide (Hangul.isHangulSyllable row.codepoint = true) <;>
    cases decide (nfcQCValue row.codepoint ≠ .Y) <;>
    cases decide (row.canonicalDecomposition.length = 0) <;>
    cases rows.any (fun entry => Nat.beq entry.codepoint row.codepoint) <;>
    rfl

theorem cover_c0 : UnicodeData.rowsChunk0.all coverFast = true := by
  decide +kernel
theorem cover_c1 : UnicodeData.rowsChunk1.all coverFast = true := by
  decide +kernel
theorem cover_c2 : UnicodeData.rowsChunk2.all coverFast = true := by
  decide +kernel
theorem cover_c3 : UnicodeData.rowsChunk3.all coverFast = true := by
  decide +kernel
theorem cover_c4 : UnicodeData.rowsChunk4.all coverFast = true := by
  decide +kernel
theorem cover_c5 : UnicodeData.rowsChunk5.all coverFast = true := by
  decide +kernel
theorem cover_c6 : UnicodeData.rowsChunk6.all coverFast = true := by
  decide +kernel
theorem cover_c7 : UnicodeData.rowsChunk7.all coverFast = true := by
  decide +kernel
theorem cover_c8 : UnicodeData.rowsChunk8.all coverFast = true := by
  decide +kernel
theorem cover_c9 : UnicodeData.rowsChunk9.all coverFast = true := by
  decide +kernel
theorem cover_c10 : UnicodeData.rowsChunk10.all coverFast = true := by
  decide +kernel
theorem cover_c11 : UnicodeData.rowsChunk11.all coverFast = true := by
  decide +kernel
theorem cover_c12 : UnicodeData.rowsChunk12.all coverFast = true := by
  decide +kernel
theorem cover_c13 : UnicodeData.rowsChunk13.all coverFast = true := by
  decide +kernel
theorem cover_c14 : UnicodeData.rowsChunk14.all coverFast = true := by
  decide +kernel
theorem cover_c15 : UnicodeData.rowsChunk15.all coverFast = true := by
  decide +kernel
theorem cover_c16 : UnicodeData.rowsChunk16.all coverFast = true := by
  decide +kernel
theorem cover_c17 : UnicodeData.rowsChunk17.all coverFast = true := by
  decide +kernel
theorem cover_c18 : UnicodeData.rowsChunk18.all coverFast = true := by
  decide +kernel
theorem cover_c19 : UnicodeData.rowsChunk19.all coverFast = true := by
  decide +kernel
theorem cover_c20 : UnicodeData.rowsChunk20.all coverFast = true := by
  decide +kernel
theorem cover_c21 : UnicodeData.rowsChunk21.all coverFast = true := by
  decide +kernel
theorem cover_c22 : UnicodeData.rowsChunk22.all coverFast = true := by
  decide +kernel
theorem cover_c23 : UnicodeData.rowsChunk23.all coverFast = true := by
  decide +kernel
theorem cover_c24 : UnicodeData.rowsChunk24.all coverFast = true := by
  decide +kernel
theorem cover_c25 : UnicodeData.rowsChunk25.all coverFast = true := by
  decide +kernel
theorem cover_c26 : UnicodeData.rowsChunk26.all coverFast = true := by
  decide +kernel
theorem cover_c27 : UnicodeData.rowsChunk27.all coverFast = true := by
  decide +kernel
theorem cover_c28 : UnicodeData.rowsChunk28.all coverFast = true := by
  decide +kernel
theorem cover_c29 : UnicodeData.rowsChunk29.all coverFast = true := by
  decide +kernel
theorem cover_c30 : UnicodeData.rowsChunk30.all coverFast = true := by
  decide +kernel
theorem cover_c31 : UnicodeData.rowsChunk31.all coverFast = true := by
  decide +kernel
theorem cover_c32 : UnicodeData.rowsChunk32.all coverFast = true := by
  decide +kernel
theorem cover_c33 : UnicodeData.rowsChunk33.all coverFast = true := by
  decide +kernel
theorem cover_c34 : UnicodeData.rowsChunk34.all coverFast = true := by
  decide +kernel
theorem cover_c35 : UnicodeData.rowsChunk35.all coverFast = true := by
  decide +kernel
theorem cover_c36 : UnicodeData.rowsChunk36.all coverFast = true := by
  decide +kernel
theorem cover_c37 : UnicodeData.rowsChunk37.all coverFast = true := by
  decide +kernel
theorem cover_c38 : UnicodeData.rowsChunk38.all coverFast = true := by
  decide +kernel
theorem cover_c39 : UnicodeData.rowsChunk39.all coverFast = true := by
  decide +kernel
theorem cover_c40 : UnicodeData.rowsChunk40.all coverFast = true := by
  decide +kernel
theorem cover_c41 : UnicodeData.rowsChunk41.all coverFast = true := by
  decide +kernel
theorem cover_c42 : UnicodeData.rowsChunk42.all coverFast = true := by
  decide +kernel
theorem cover_c43 : UnicodeData.rowsChunk43.all coverFast = true := by
  decide +kernel
theorem cover_c44 : UnicodeData.rowsChunk44.all coverFast = true := by
  decide +kernel
theorem cover_c45 : UnicodeData.rowsChunk45.all coverFast = true := by
  decide +kernel
theorem cover_c46 : UnicodeData.rowsChunk46.all coverFast = true := by
  decide +kernel
theorem cover_c47 : UnicodeData.rowsChunk47.all coverFast = true := by
  decide +kernel

theorem coverLookup_c0 : UnicodeData.rowsChunk0.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c1 : UnicodeData.rowsChunk1.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c2 : UnicodeData.rowsChunk2.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c3 : UnicodeData.rowsChunk3.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c4 : UnicodeData.rowsChunk4.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c5 : UnicodeData.rowsChunk5.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c6 : UnicodeData.rowsChunk6.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c7 : UnicodeData.rowsChunk7.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c8 : UnicodeData.rowsChunk8.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c9 : UnicodeData.rowsChunk9.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c10 : UnicodeData.rowsChunk10.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c11 : UnicodeData.rowsChunk11.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c12 : UnicodeData.rowsChunk12.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c13 : UnicodeData.rowsChunk13.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c14 : UnicodeData.rowsChunk14.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c15 : UnicodeData.rowsChunk15.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c16 : UnicodeData.rowsChunk16.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c17 : UnicodeData.rowsChunk17.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c18 : UnicodeData.rowsChunk18.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c19 : UnicodeData.rowsChunk19.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c20 : UnicodeData.rowsChunk20.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c21 : UnicodeData.rowsChunk21.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c22 : UnicodeData.rowsChunk22.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c23 : UnicodeData.rowsChunk23.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c24 : UnicodeData.rowsChunk24.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c25 : UnicodeData.rowsChunk25.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c26 : UnicodeData.rowsChunk26.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c27 : UnicodeData.rowsChunk27.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c28 : UnicodeData.rowsChunk28.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c29 : UnicodeData.rowsChunk29.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c30 : UnicodeData.rowsChunk30.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c31 : UnicodeData.rowsChunk31.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c32 : UnicodeData.rowsChunk32.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c33 : UnicodeData.rowsChunk33.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c34 : UnicodeData.rowsChunk34.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c35 : UnicodeData.rowsChunk35.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c36 : UnicodeData.rowsChunk36.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c37 : UnicodeData.rowsChunk37.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c38 : UnicodeData.rowsChunk38.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c39 : UnicodeData.rowsChunk39.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c40 : UnicodeData.rowsChunk40.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c41 : UnicodeData.rowsChunk41.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c42 : UnicodeData.rowsChunk42.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c43 : UnicodeData.rowsChunk43.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c44 : UnicodeData.rowsChunk44.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c45 : UnicodeData.rowsChunk45.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c46 : UnicodeData.rowsChunk46.all coverLookupFast = true := by
  decide +kernel
theorem coverLookup_c47 : UnicodeData.rowsChunk47.all coverLookupFast = true := by
  decide +kernel

theorem rowsList_all_coverFast : UnicodeData.rowsList.all coverFast = true := by
  unfold UnicodeData.rowsList
  simp only [List.all_append, cover_c0, cover_c1, cover_c2, cover_c3, cover_c4, cover_c5, cover_c6, cover_c7, cover_c8, cover_c9, cover_c10, cover_c11, cover_c12, cover_c13, cover_c14, cover_c15, cover_c16, cover_c17, cover_c18, cover_c19, cover_c20, cover_c21, cover_c22, cover_c23, cover_c24, cover_c25, cover_c26, cover_c27, cover_c28, cover_c29, cover_c30, cover_c31, cover_c32, cover_c33, cover_c34, cover_c35, cover_c36, cover_c37, cover_c38, cover_c39, cover_c40, cover_c41, cover_c42, cover_c43, cover_c44, cover_c45, cover_c46, cover_c47, Bool.and_self]

theorem rowsList_all_coverLookupFast : UnicodeData.rowsList.all coverLookupFast = true := by
  unfold UnicodeData.rowsList
  simp only [List.all_append, coverLookup_c0, coverLookup_c1, coverLookup_c2, coverLookup_c3, coverLookup_c4, coverLookup_c5, coverLookup_c6, coverLookup_c7, coverLookup_c8, coverLookup_c9, coverLookup_c10, coverLookup_c11, coverLookup_c12, coverLookup_c13, coverLookup_c14, coverLookup_c15, coverLookup_c16, coverLookup_c17, coverLookup_c18, coverLookup_c19, coverLookup_c20, coverLookup_c21, coverLookup_c22, coverLookup_c23, coverLookup_c24, coverLookup_c25, coverLookup_c26, coverLookup_c27, coverLookup_c28, coverLookup_c29, coverLookup_c30, coverLookup_c31, coverLookup_c32, coverLookup_c33, coverLookup_c34, coverLookup_c35, coverLookup_c36, coverLookup_c37, coverLookup_c38, coverLookup_c39, coverLookup_c40, coverLookup_c41, coverLookup_c42, coverLookup_c43, coverLookup_c44, coverLookup_c45, coverLookup_c46, coverLookup_c47, Bool.and_self]

/-- Every row is irrelevant to QC=Y starter singletons or carried by a rank
    row (row fields). -/
theorem relevant_rows_covered :
    UnicodeData.rowsList.all (fun row =>
      decide (row.canonicalCombiningClass ≠ 0) ||
      decide (Hangul.isHangulSyllable row.codepoint = true) ||
      decide (nfcQCValue row.codepoint ≠ .Y) ||
      decide (row.canonicalDecomposition.length = 0) ||
      rows.any (fun entry => decide (entry.codepoint = row.codepoint))) = true := by
  show UnicodeData.rowsList.all cover = true
  rw [cover_eq_fast]
  exact rowsList_all_coverFast

/-- Every row is irrelevant to QC=Y starter singletons or carried by a rank
    row (through the row lookup). -/
theorem relevant_lookup_rows_covered :
    UnicodeData.rowsList.all (fun row =>
      decide (Lookup.canonicalCombiningClass row.codepoint ≠ 0) ||
      decide (Hangul.isHangulSyllable row.codepoint = true) ||
      decide (nfcQCValue row.codepoint ≠ .Y) ||
      decide (row.canonicalDecomposition.length = 0) ||
      rows.any (fun entry => decide (entry.codepoint = row.codepoint))) = true := by
  show UnicodeData.rowsList.all coverLookup = true
  rw [coverLookup_eq_fast]
  exact rowsList_all_coverLookupFast

end Unicode.Normalization.QuickCheckSingletonRankCover
