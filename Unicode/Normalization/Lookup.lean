/-
  Unicode.Normalization.Lookup

  Thin accessors that bridge the generated UnicodeData row table and
  the NFC algorithms in this Normalization/* namespace. Keeps table-shape
  concerns out of the algorithm implementations.

  Lookup is row-backed: codepoints absent from the pinned NFC-relevant
  subset use the Unicode @missing defaults (`CCC = 0`, no canonical
  decomposition).
-/

import Unicode.Generated.UnicodeData
import Unicode.Generated.CompositionExclusions
import Unicode.Generated.DerivedNormalizationProps

namespace Unicode.Normalization.Lookup

open Unicode.Generated

set_option maxRecDepth 100000

/-- Find the `UnicodeDataRow` for a codepoint, if one is present in the
    pinned NFC-relevant subset. Returns `none` for codepoints that are
    both `CCC = 0` and have no canonical decomposition. -/
def lookupRow (cp : Nat) : Option UnicodeData.UnicodeDataRow :=
  UnicodeData.rows.find? (fun row => row.codepoint = cp)

/-- Canonical_Combining_Class for a codepoint. Unlisted codepoints have
    `CCC = 0` per the UCD's implicit default for the NFC-relevant
    filter. -/
def canonicalCombiningClass (cp : Nat) : Nat :=
  match lookupRow cp with
  | some row => row.canonicalCombiningClass
  | none => 0

/-- Canonical decomposition target sequence for a codepoint. Returns
    the empty array when the codepoint has no canonical decomposition
    (every codepoint outside the pinned subset, and many inside it). -/
def canonicalDecomposition (cp : Nat) : Array Nat :=
  match lookupRow cp with
  | some row => row.canonicalDecomposition
  | none => #[]

/-- Whether a codepoint appears in CompositionExclusions.txt. When
    `true`, the codepoint decomposes canonically but must NOT recompose
    during NFC synthesis. -/
def isCompositionExclusion (cp : Nat) : Bool :=
  CompositionExclusions.codepoints.toList.any (fun candidate => candidate == cp)

/-- Whether a codepoint is marked `Full_Composition_Exclusion` in
    DerivedNormalizationProps. Strictly broader than
    `isCompositionExclusion`: includes singleton and non-starter
    decompositions in addition to the CompositionExclusions set. The
    NFC algorithm uses this broader test when deciding which canonical
    decompositions may recompose. -/
def isFullCompositionExclusion (cp : Nat) : Bool :=
  DerivedNormalizationProps.fullCompositionExclusion.toList.any
    (fun ⟨min, max⟩ => decide (min ≤ cp ∧ cp ≤ max))

-- ─────────────────────────────────────────────────────────────────────────────
--                                              // lookup // fact-transport
-- ─────────────────────────────────────────────────────────────────────────────

-- Evaluating an accessor at a concrete codepoint must never happen by
-- reducing the row scan: `List.find?` reduction over the pinned table is
-- catastrophically expensive in every reduction engine, at every scan
-- depth. Concrete-codepoint facts are instead witnessed by linear
-- `List.all` / `List.any` passes over `rowsList` — the only table
-- traversals the kernel checks at flat cost — and transported to the
-- accessors here. The lemmas are parametric in `cp` on purpose: with a
-- variable scrutinee, `unfold` rewrites the accessor's match without
-- evaluating the row scan.

/-- A codepoint no row carries is a `lookupRow` miss. The `List.all`
    hypothesis is the kernel-checkable witness of absence — one linear
    pass over the row list. -/
theorem lookupRow_none_of_all_ne (cp : Nat)
    (hAll : UnicodeData.rowsList.all
      (fun r => decide (r.codepoint ≠ cp)) = true) :
    lookupRow cp = none := by
  unfold lookupRow
  simp only [UnicodeData.rows, List.find?_toArray]
  rw [List.find?_eq_none]
  intro x hx
  have hNe : x.codepoint ≠ cp :=
    of_decide_eq_true (List.all_eq_true.mp hAll x hx)
  intro hEq
  exact hNe (of_decide_eq_true hEq)

/-- Every codepoint of an interval no row touches is a `lookupRow`
    miss. One linear pass witnesses absence for the WHOLE interval, so
    per-codepoint facts over ranges (e.g. the 195 Hangul jamo) need
    one traversal, not one scan per codepoint. -/
theorem lookupRow_none_of_all_outside (lo hi cp : Nat)
    (hAll : UnicodeData.rowsList.all
      (fun r => decide (¬ (lo ≤ r.codepoint ∧ r.codepoint ≤ hi))) = true)
    (hLo : lo ≤ cp) (hHi : cp ≤ hi) :
    lookupRow cp = none := by
  unfold lookupRow
  simp only [UnicodeData.rows, List.find?_toArray]
  rw [List.find?_eq_none]
  intro x hx
  have hOut : ¬ (lo ≤ x.codepoint ∧ x.codepoint ≤ hi) :=
    of_decide_eq_true (List.all_eq_true.mp hAll x hx)
  intro hEq
  have hEqCp : x.codepoint = cp := of_decide_eq_true hEq
  exact hOut (by omega)

/-- A `lookupRow` miss has the CCC default: codepoints outside the
    pinned NFC-relevant subset have `CCC = 0` per the UCD's implicit
    default. -/
theorem canonicalCombiningClass_of_lookupRow_none (cp : Nat)
    (h : lookupRow cp = none) :
    canonicalCombiningClass cp = 0 := by
  unfold canonicalCombiningClass
  rw [h]

/-- A `lookupRow` miss has no canonical decomposition: codepoints outside
    the pinned NFC-relevant subset decompose to themselves. -/
theorem canonicalDecomposition_of_lookupRow_none (cp : Nat)
    (h : lookupRow cp = none) :
    canonicalDecomposition cp = #[] := by
  unfold canonicalDecomposition
  rw [h]

/-- CCC of a codepoint PRESENT in the table, without reducing the scan.
    `hAny` witnesses that some row carries `cp`; `hAll` pins the CCC field
    of every row carrying `cp`. Whichever row the scan selects, it is a
    member matching `cp`, so `hAll` applies to it. -/
theorem canonicalCombiningClass_of_hit (cp ccc : Nat)
    (hAny : UnicodeData.rowsList.any
      (fun r => decide (r.codepoint = cp)) = true)
    (hAll : UnicodeData.rowsList.all
      (fun r => decide (r.codepoint = cp →
        r.canonicalCombiningClass = ccc)) = true) :
    canonicalCombiningClass cp = ccc := by
  unfold canonicalCombiningClass
  cases hL : lookupRow cp with
  | none =>
    exfalso
    unfold lookupRow at hL
    simp only [UnicodeData.rows, List.find?_toArray] at hL
    rw [List.find?_eq_none] at hL
    rw [List.any_eq_true] at hAny
    obtain ⟨r, hrMem, hrEq⟩ := hAny
    exact (hL r hrMem) hrEq
  | some row =>
    unfold lookupRow at hL
    simp only [UnicodeData.rows, List.find?_toArray] at hL
    have hMem : row ∈ UnicodeData.rowsList := List.mem_of_find?_eq_some hL
    have hCp : row.codepoint = cp :=
      of_decide_eq_true
        (List.find?_some
          (p := fun (r : UnicodeData.UnicodeDataRow) =>
            decide (r.codepoint = cp)) hL)
    have hImp : row.codepoint = cp → row.canonicalCombiningClass = ccc :=
      of_decide_eq_true (List.all_eq_true.mp hAll row hMem)
    exact hImp hCp

/-- Canonical decomposition of a codepoint PRESENT in the table, without
    reducing the scan. Same transport shape as
    `canonicalCombiningClass_of_hit`. -/
theorem canonicalDecomposition_of_hit (cp : Nat) (target : Array Nat)
    (hAny : UnicodeData.rowsList.any
      (fun r => decide (r.codepoint = cp)) = true)
    (hAll : UnicodeData.rowsList.all
      (fun r => decide (r.codepoint = cp →
        r.canonicalDecomposition = target)) = true) :
    canonicalDecomposition cp = target := by
  unfold canonicalDecomposition
  cases hL : lookupRow cp with
  | none =>
    exfalso
    unfold lookupRow at hL
    simp only [UnicodeData.rows, List.find?_toArray] at hL
    rw [List.find?_eq_none] at hL
    rw [List.any_eq_true] at hAny
    obtain ⟨r, hrMem, hrEq⟩ := hAny
    exact (hL r hrMem) hrEq
  | some row =>
    unfold lookupRow at hL
    simp only [UnicodeData.rows, List.find?_toArray] at hL
    have hMem : row ∈ UnicodeData.rowsList := List.mem_of_find?_eq_some hL
    have hCp : row.codepoint = cp :=
      of_decide_eq_true
        (List.find?_some
          (p := fun (r : UnicodeData.UnicodeDataRow) =>
            decide (r.codepoint = cp)) hL)
    have hImp : row.codepoint = cp → row.canonicalDecomposition = target :=
      of_decide_eq_true (List.all_eq_true.mp hAll row hMem)
    exact hImp hCp

end Unicode.Normalization.Lookup
