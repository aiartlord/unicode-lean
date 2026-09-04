/-
  Unicode.Normalization.QuickCheckFactsRows

  Per-chunk kernel facts behind `QuickCheckFacts` facts 2 and 3. Each fact
  filters a 64-row `UnicodeData` chunk by its cheap row conditions and
  evaluates the pairs lookup or the quick-check range walk only on the rows
  that pass. One chunk is one declaration, so the kernel's working set is one
  chunk's walk rather than the whole table's; `rows_fact2` and `rows_fact3`
  combine the chunks along the right-nested `rowsList` without evaluating
  anything.
-/

import Unicode.Normalization.Compose
import Unicode.Normalization.NFC

namespace Unicode.Normalization.QuickCheckFactsRows

open Unicode.Normalization
open Unicode.Generated

/-- Fact 2's row filter: a starter with a two-element canonical
    decomposition. -/
def guard2 (r : UnicodeData.UnicodeDataRow) : Bool :=
  decide (r.canonicalDecomposition.length = 2) &&
  decide (r.canonicalCombiningClass = 0)

/-- Fact 2's claim on a filtered row: it recomposes through the pairs
    lookup, or it is not `NFC_QC = Y`. The lookup is tried first, so the
    range walk runs only for the excluded rows. -/
def body2 (r : UnicodeData.UnicodeDataRow) : Bool :=
  decide (Compose.primaryCompositePairs?
            (r.canonicalDecomposition[0]!)
            (r.canonicalDecomposition[1]!) = some r.codepoint) ||
  ! decide (NFC.nfcQCValue r.codepoint = .Y)

/-- Fact 3's row filter: a two-element canonical decomposition. -/
def guard3 (r : UnicodeData.UnicodeDataRow) : Bool :=
  decide (r.canonicalDecomposition.length = 2)

/-- Fact 3's claim on a filtered row: a full composition exclusion, or a
    trailing element that is not `NFC_QC = Y`. -/
def body3 (r : UnicodeData.UnicodeDataRow) : Bool :=
  decide (Lookup.isFullCompositionExclusion r.codepoint = true) ||
  (! decide (NFC.nfcQCValue (r.canonicalDecomposition[1]!) = .Y))

theorem fact2_c0 : (UnicodeData.rowsChunk0.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c1 : (UnicodeData.rowsChunk1.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c2 : (UnicodeData.rowsChunk2.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c3 : (UnicodeData.rowsChunk3.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c4 : (UnicodeData.rowsChunk4.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c5 : (UnicodeData.rowsChunk5.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c6 : (UnicodeData.rowsChunk6.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c7 : (UnicodeData.rowsChunk7.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c8 : (UnicodeData.rowsChunk8.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c9 : (UnicodeData.rowsChunk9.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c10 : (UnicodeData.rowsChunk10.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c11 : (UnicodeData.rowsChunk11.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c12 : (UnicodeData.rowsChunk12.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c13 : (UnicodeData.rowsChunk13.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c14 : (UnicodeData.rowsChunk14.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c15 : (UnicodeData.rowsChunk15.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c16 : (UnicodeData.rowsChunk16.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c17 : (UnicodeData.rowsChunk17.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c18 : (UnicodeData.rowsChunk18.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c19 : (UnicodeData.rowsChunk19.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c20 : (UnicodeData.rowsChunk20.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c21 : (UnicodeData.rowsChunk21.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c22 : (UnicodeData.rowsChunk22.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c23 : (UnicodeData.rowsChunk23.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c24 : (UnicodeData.rowsChunk24.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c25 : (UnicodeData.rowsChunk25.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c26 : (UnicodeData.rowsChunk26.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c27 : (UnicodeData.rowsChunk27.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c28 : (UnicodeData.rowsChunk28.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c29 : (UnicodeData.rowsChunk29.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c30 : (UnicodeData.rowsChunk30.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c31 : (UnicodeData.rowsChunk31.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c32 : (UnicodeData.rowsChunk32.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c33 : (UnicodeData.rowsChunk33.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c34 : (UnicodeData.rowsChunk34.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c35 : (UnicodeData.rowsChunk35.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c36 : (UnicodeData.rowsChunk36.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c37 : (UnicodeData.rowsChunk37.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c38 : (UnicodeData.rowsChunk38.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c39 : (UnicodeData.rowsChunk39.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c40 : (UnicodeData.rowsChunk40.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c41 : (UnicodeData.rowsChunk41.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c42 : (UnicodeData.rowsChunk42.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c43 : (UnicodeData.rowsChunk43.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c44 : (UnicodeData.rowsChunk44.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c45 : (UnicodeData.rowsChunk45.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c46 : (UnicodeData.rowsChunk46.filter guard2).all body2 = true := by
  decide +kernel
theorem fact2_c47 : (UnicodeData.rowsChunk47.filter guard2).all body2 = true := by
  decide +kernel

theorem fact3_c0 : (UnicodeData.rowsChunk0.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c1 : (UnicodeData.rowsChunk1.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c2 : (UnicodeData.rowsChunk2.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c3 : (UnicodeData.rowsChunk3.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c4 : (UnicodeData.rowsChunk4.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c5 : (UnicodeData.rowsChunk5.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c6 : (UnicodeData.rowsChunk6.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c7 : (UnicodeData.rowsChunk7.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c8 : (UnicodeData.rowsChunk8.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c9 : (UnicodeData.rowsChunk9.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c10 : (UnicodeData.rowsChunk10.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c11 : (UnicodeData.rowsChunk11.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c12 : (UnicodeData.rowsChunk12.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c13 : (UnicodeData.rowsChunk13.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c14 : (UnicodeData.rowsChunk14.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c15 : (UnicodeData.rowsChunk15.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c16 : (UnicodeData.rowsChunk16.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c17 : (UnicodeData.rowsChunk17.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c18 : (UnicodeData.rowsChunk18.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c19 : (UnicodeData.rowsChunk19.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c20 : (UnicodeData.rowsChunk20.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c21 : (UnicodeData.rowsChunk21.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c22 : (UnicodeData.rowsChunk22.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c23 : (UnicodeData.rowsChunk23.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c24 : (UnicodeData.rowsChunk24.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c25 : (UnicodeData.rowsChunk25.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c26 : (UnicodeData.rowsChunk26.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c27 : (UnicodeData.rowsChunk27.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c28 : (UnicodeData.rowsChunk28.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c29 : (UnicodeData.rowsChunk29.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c30 : (UnicodeData.rowsChunk30.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c31 : (UnicodeData.rowsChunk31.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c32 : (UnicodeData.rowsChunk32.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c33 : (UnicodeData.rowsChunk33.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c34 : (UnicodeData.rowsChunk34.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c35 : (UnicodeData.rowsChunk35.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c36 : (UnicodeData.rowsChunk36.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c37 : (UnicodeData.rowsChunk37.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c38 : (UnicodeData.rowsChunk38.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c39 : (UnicodeData.rowsChunk39.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c40 : (UnicodeData.rowsChunk40.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c41 : (UnicodeData.rowsChunk41.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c42 : (UnicodeData.rowsChunk42.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c43 : (UnicodeData.rowsChunk43.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c44 : (UnicodeData.rowsChunk44.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c45 : (UnicodeData.rowsChunk45.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c46 : (UnicodeData.rowsChunk46.filter guard3).all body3 = true := by
  decide +kernel
theorem fact3_c47 : (UnicodeData.rowsChunk47.filter guard3).all body3 = true := by
  decide +kernel

theorem rows_fact2 : (UnicodeData.rowsList.filter guard2).all body2 = true := by
  unfold UnicodeData.rowsList
  simp only [List.filter_append, List.all_append, fact2_c0, fact2_c1, fact2_c2, fact2_c3, fact2_c4, fact2_c5, fact2_c6, fact2_c7, fact2_c8, fact2_c9, fact2_c10, fact2_c11, fact2_c12, fact2_c13, fact2_c14, fact2_c15, fact2_c16, fact2_c17, fact2_c18, fact2_c19, fact2_c20, fact2_c21, fact2_c22, fact2_c23, fact2_c24, fact2_c25, fact2_c26, fact2_c27, fact2_c28, fact2_c29, fact2_c30, fact2_c31, fact2_c32, fact2_c33, fact2_c34, fact2_c35, fact2_c36, fact2_c37, fact2_c38, fact2_c39, fact2_c40, fact2_c41, fact2_c42, fact2_c43, fact2_c44, fact2_c45, fact2_c46, fact2_c47, Bool.and_self]

theorem rows_fact3 : (UnicodeData.rowsList.filter guard3).all body3 = true := by
  unfold UnicodeData.rowsList
  simp only [List.filter_append, List.all_append, fact3_c0, fact3_c1, fact3_c2, fact3_c3, fact3_c4, fact3_c5, fact3_c6, fact3_c7, fact3_c8, fact3_c9, fact3_c10, fact3_c11, fact3_c12, fact3_c13, fact3_c14, fact3_c15, fact3_c16, fact3_c17, fact3_c18, fact3_c19, fact3_c20, fact3_c21, fact3_c22, fact3_c23, fact3_c24, fact3_c25, fact3_c26, fact3_c27, fact3_c28, fact3_c29, fact3_c30, fact3_c31, fact3_c32, fact3_c33, fact3_c34, fact3_c35, fact3_c36, fact3_c37, fact3_c38, fact3_c39, fact3_c40, fact3_c41, fact3_c42, fact3_c43, fact3_c44, fact3_c45, fact3_c46, fact3_c47, Bool.and_self]

end Unicode.Normalization.QuickCheckFactsRows
