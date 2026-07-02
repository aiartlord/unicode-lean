/-
  Unicode.Normalization.QuickCheckFacts

  UCD-derived facts supporting `isNFCQuickCheck` soundness (UAX #15 §A.1).

  The quick-check algorithm returns `true` on sequences where every
  codepoint has `NFC_QC = Y` and canonical combining classes are
  non-decreasing within non-starter runs. Proving that this implies
  `toNFC cps = cps` requires three structural UCD facts, each provable
  by enumerating `UnicodeData.rows` together with the `NFC_QC` and
  Full_Composition_Exclusion tables:

    * **Fact 1** — Every `NFC_QC = Y` row with non-zero CCC has an
      empty canonical decomposition. (QC=Y non-starters have no
      canonical decomposition.)

    * **Fact 2** — Every `NFC_QC = Y` row with CCC = 0 and a
      two-element canonical decomposition satisfies
      `primaryComposite? d e = some cp`. (QC=Y starters with a
      two-element decomp recompose to themselves.)

    * **Fact 3** — Every row with a two-element canonical
      decomposition either is a full composition exclusion or has
      `NFC_QC ≠ Y` on its trailing element. (QC=Y non-starters are
      never the composable second-half of a primary composite.)

  These row-level facts lift pointwise to per-codepoint form in the
  companion `QuickCheckSoundness` module by case-analysis on
  `Lookup.lookupRow`.

  Placed in its own module so the heavy `decide` compilation
  isolates cleanly under `LEAN_NUM_THREADS=1`, matching the
  `Unicode.Precis.ZsPreservation` split pattern.
-/

import Unicode.Normalization.Compose
import Unicode.Normalization.NFC

namespace Unicode.Normalization.QuickCheckFacts

open Unicode.Normalization
open Unicode.Generated

set_option maxRecDepth 100000

/-- Row-level fact 1: every `UnicodeData` row with `NFC_QC = Y` and
    non-zero CCC has an empty canonical decomposition. -/
theorem qcY_nonstarter_rows_no_decomp :
    UnicodeData.rows.all (fun r =>
      (! (decide (NFC.nfcQCValue r.codepoint = .Y) &&
          decide (r.canonicalCombiningClass > 0))) ||
      decide (r.canonicalDecomposition = #[])) = true := by
  decide

/-- Row-level fact 2: every `UnicodeData` row with `NFC_QC = Y`,
    CCC = 0, and a two-element canonical decomposition recomposes via
    `primaryComposite?` back to its codepoint. -/
theorem qcY_starter_2decomp_rows_compose :
    UnicodeData.rows.all (fun r =>
      (! (decide (NFC.nfcQCValue r.codepoint = .Y) &&
          decide (r.canonicalCombiningClass = 0) &&
          decide (r.canonicalDecomposition.size = 2))) ||
      decide (Compose.primaryComposite?
                (r.canonicalDecomposition[0]!)
                (r.canonicalDecomposition[1]!) = some r.codepoint)) = true := by
  native_decide

/-- Row-level fact 3: every `UnicodeData` row with a two-element
    canonical decomposition that is NOT a full composition exclusion
    has an `NFC_QC ≠ Y` trailing element. Composition-excluded rows
    (e.g., BENGALI LETTER RRA: `primaryComposite?` returns `none` for
    them) may have QC=Y trailing elements without issue; they do not
    contribute compose paths. -/
theorem qcY_nonstarter_not_decomp_target :
    UnicodeData.rows.all (fun r =>
      (! decide (r.canonicalDecomposition.size = 2)) ||
      decide (Lookup.isFullCompositionExclusion r.codepoint = true) ||
      (! decide (NFC.nfcQCValue (r.canonicalDecomposition[1]!) = .Y))) = true := by
  native_decide

theorem lookupRow_codepoint
    (cp : Nat) (row : UnicodeData.UnicodeDataRow)
    (hLookup : Lookup.lookupRow cp = some row) :
    row.codepoint = cp := by
  unfold Lookup.lookupRow at hLookup
  have hFind := Array.find?_eq_some_iff_getElem.mp hLookup
  obtain ⟨hPred, _hIdxLt, _hAllPriorFalse⟩ := hFind
  exact of_decide_eq_true hPred

theorem lookupRow_generated_fields
    (cp : Nat) (row : UnicodeData.UnicodeDataRow)
    (hLookup : Lookup.lookupRow cp = some row) :
    Lookup.canonicalCombiningClass cp = row.canonicalCombiningClass ∧
      Lookup.canonicalDecomposition cp = row.canonicalDecomposition := by
  simp [Lookup.canonicalCombiningClass, Lookup.canonicalDecomposition, hLookup]

theorem no_row_of_lookupRow_none
    (cp : Nat) (hLookup : Lookup.lookupRow cp = none) :
    ¬ ∃ row, row ∈ UnicodeData.rows ∧ row.codepoint = cp := by
  unfold Lookup.lookupRow at hLookup
  rw [Array.find?_eq_none] at hLookup
  intro hRow
  rcases hRow with ⟨row, hMem, hCp⟩
  have hFalse := hLookup row hMem
  simp [hCp] at hFalse

theorem canonicalDecomposition_empty_of_lookupRow_none
    (cp : Nat) (hLookup : Lookup.lookupRow cp = none) :
    Lookup.canonicalDecomposition cp = #[] := by
  simp [Lookup.canonicalDecomposition, hLookup]

-- ═══════════════════════════════════════════════════════════════════════════════
-- LIFTED PER-CODEPOINT FACTS
--
-- Each row-level `Array.all` decomposes into a per-row implication via
-- `Array.all_eq_true`, then lifts to a per-codepoint claim by case-analysis
-- on `Lookup.lookupRow`. The actual generated lookup implementation is
-- connected to the row table by the definitions in `Lookup`.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Per-codepoint fact 1: QC=Y non-starters have no canonical
    decomposition. Lifted from `qcY_nonstarter_rows_no_decomp`. -/
theorem qcY_nonstarter_cp_no_decomp
    (cp : Nat) (hQC : NFC.nfcQCValue cp = .Y)
    (hCcc : Lookup.canonicalCombiningClass cp > 0) :
    Lookup.canonicalDecomposition cp = #[] := by
  cases hLookup : Lookup.lookupRow cp with
  | none =>
    exact canonicalDecomposition_empty_of_lookupRow_none cp hLookup
  | some r =>
    have hRowCp : r.codepoint = cp := lookupRow_codepoint cp r hLookup
    have hFields := lookupRow_generated_fields cp r hLookup
    have hRccc : r.canonicalCombiningClass > 0 := by
      rw [← hFields.1]
      exact hCcc
    have hRQC : NFC.nfcQCValue r.codepoint = .Y := by rw [hRowCp]; exact hQC
    have hMem : r ∈ UnicodeData.rows := Array.mem_of_find?_eq_some hLookup
    have hAll : UnicodeData.rows.all (fun r =>
      (! (decide (NFC.nfcQCValue r.codepoint = .Y) &&
          decide (r.canonicalCombiningClass > 0))) ||
      decide (r.canonicalDecomposition = #[])) = true :=
      qcY_nonstarter_rows_no_decomp
    rw [Array.all_eq_true] at hAll
    rcases Array.getElem_of_mem hMem with ⟨i, hi, hIEq⟩
    have hThis := hAll i hi
    rw [hIEq] at hThis
    simp only [Bool.or_eq_true] at hThis
    rcases hThis with hNot | hEmpty
    · -- hNot contradicts the QC=Y and nonstarter premises.
      exfalso
      have h1 : decide (NFC.nfcQCValue r.codepoint = .Y) = true :=
        decide_eq_true hRQC
      have h2 : decide (r.canonicalCombiningClass > 0) = true :=
        decide_eq_true hRccc
      rw [h1, h2] at hNot
      exact Bool.noConfusion hNot
    ·
      rw [hFields.2]
      exact of_decide_eq_true hEmpty

/-- Per-codepoint fact 2: QC=Y starters with a two-element canonical
    decomposition `[d, e]` satisfy `primaryComposite? d e = some cp`.
    Lifted from `qcY_starter_2decomp_rows_compose`. -/
theorem qcY_starter_2decomp_cp_composes
    (cp : Nat) (hQC : NFC.nfcQCValue cp = .Y)
    (hCcc : Lookup.canonicalCombiningClass cp = 0)
    (hSize : (Lookup.canonicalDecomposition cp).size = 2) :
    Compose.primaryComposite?
      (Lookup.canonicalDecomposition cp)[0]!
      (Lookup.canonicalDecomposition cp)[1]! = some cp := by
  cases hLookup : Lookup.lookupRow cp with
  | none =>
    have hEmpty := canonicalDecomposition_empty_of_lookupRow_none cp hLookup
    rw [hEmpty] at hSize
    exact absurd hSize (by decide)
  | some r =>
    have hFields := lookupRow_generated_fields cp r hLookup
    rw [hFields.2] at hSize ⊢
    have hRowCp : r.codepoint = cp := lookupRow_codepoint cp r hLookup
    have hRccc : r.canonicalCombiningClass = 0 := by
      rw [← hFields.1]
      exact hCcc
    have hRQC : NFC.nfcQCValue r.codepoint = .Y := by rw [hRowCp]; exact hQC
    have hMem : r ∈ UnicodeData.rows := Array.mem_of_find?_eq_some hLookup
    have hAll : UnicodeData.rows.all (fun r =>
      (! (decide (NFC.nfcQCValue r.codepoint = .Y) &&
          decide (r.canonicalCombiningClass = 0) &&
          decide (r.canonicalDecomposition.size = 2))) ||
      decide (Compose.primaryComposite?
                (r.canonicalDecomposition[0]!)
                (r.canonicalDecomposition[1]!) = some r.codepoint)) = true :=
      qcY_starter_2decomp_rows_compose
    rw [Array.all_eq_true] at hAll
    rcases Array.getElem_of_mem hMem with ⟨i, hi, hIEq⟩
    have hThis := hAll i hi
    rw [hIEq] at hThis
    simp only [Bool.or_eq_true] at hThis
    rcases hThis with hNot | hGood
    · -- hNot is the negated conjunction; derive contradiction directly
      -- by rewriting each decide-arm to `true` via the proofs at hand.
      exfalso
      have h1 : decide (NFC.nfcQCValue r.codepoint = .Y) = true :=
        decide_eq_true hRQC
      have h2 : decide (r.canonicalCombiningClass = 0) = true :=
        decide_eq_true hRccc
      have h3 : decide (r.canonicalDecomposition.size = 2) = true :=
        decide_eq_true hSize
      rw [h1, h2, h3] at hNot
      exact Bool.noConfusion hNot
    · rw [hRowCp] at hGood
      exact of_decide_eq_true hGood

end Unicode.Normalization.QuickCheckFacts
