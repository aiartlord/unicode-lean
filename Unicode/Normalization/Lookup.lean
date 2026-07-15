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
import Unicode.Generated.UnicodeDataIndexFacts
import Unicode.Generated.CompositionExclusions
import Unicode.Generated.DerivedNormalizationProps

namespace Unicode.Normalization.Lookup

open Unicode.Generated

set_option maxRecDepth 100000

/-- Find the `UnicodeDataRow` for a codepoint, if one is present in the
    pinned NFC-relevant subset. Returns `none` for codepoints that are
    both `CCC = 0` and have no canonical decomposition. -/
def lookupRow (cp : Nat) : Option UnicodeData.UnicodeDataRow :=
  UnicodeDataIndex.lookupRow? cp

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

-- Evaluating an accessor at a concrete codepoint must never reduce a full
-- row scan. `lookupRow` uses the generated low-byte index; concrete facts are
-- still witnessed over `rowsList` and transported through the generated
-- index support/coverage lemmas.

/-- A codepoint no row carries is a `lookupRow` miss. The `List.all`
    hypothesis is the kernel-checkable witness of absence — one linear
    pass over the row list. -/
theorem lookupRow_none_of_all_ne (cp : Nat)
    (hAll : UnicodeData.rowsList.all
      (fun r => decide (r.codepoint ≠ cp)) = true) :
    lookupRow cp = none := by
  unfold lookupRow
  cases hL : UnicodeDataIndex.lookupRow? cp with
  | none => rfl
  | some row =>
    exfalso
    have hCp := UnicodeDataIndex.lookupRow?_codepoint hL
    obtain ⟨src, hSrcMem, hSrcCp, _hSrcCcc, _hSrcDecomp⟩ :=
      UnicodeDataIndex.lookupRow?_supported_rowsList hL
    have hNe : src.codepoint ≠ cp :=
      of_decide_eq_true (List.all_eq_true.mp hAll src hSrcMem)
    exact hNe (hSrcCp.trans hCp)

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
  cases hL : UnicodeDataIndex.lookupRow? cp with
  | none => rfl
  | some row =>
    exfalso
    have hCp := UnicodeDataIndex.lookupRow?_codepoint hL
    obtain ⟨src, hSrcMem, hSrcCp, _hSrcCcc, _hSrcDecomp⟩ :=
      UnicodeDataIndex.lookupRow?_supported_rowsList hL
    have hOut : ¬ (lo ≤ src.codepoint ∧ src.codepoint ≤ hi) :=
      of_decide_eq_true (List.all_eq_true.mp hAll src hSrcMem)
    have hSrcEqCp : src.codepoint = cp := hSrcCp.trans hCp
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
    rw [List.any_eq_true] at hAny
    obtain ⟨r, hrMem, hrEq⟩ := hAny
    exact UnicodeDataIndex.lookupRow?_none_no_rowsList_codepoint hL hrMem
      (of_decide_eq_true hrEq)
  | some row =>
    obtain ⟨src, hSrcMem, hSrcCp, hSrcCcc, _hSrcDecomp⟩ :=
      UnicodeDataIndex.lookupRow?_supported_rowsList hL
    have hCp : row.codepoint = cp :=
      UnicodeDataIndex.lookupRow?_codepoint hL
    have hImp : src.codepoint = cp → src.canonicalCombiningClass = ccc :=
      of_decide_eq_true (List.all_eq_true.mp hAll src hSrcMem)
    exact hSrcCcc.symm.trans (hImp (hSrcCp.trans hCp))

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
    rw [List.any_eq_true] at hAny
    obtain ⟨r, hrMem, hrEq⟩ := hAny
    exact UnicodeDataIndex.lookupRow?_none_no_rowsList_codepoint hL hrMem
      (of_decide_eq_true hrEq)
  | some row =>
    obtain ⟨src, hSrcMem, hSrcCp, _hSrcCcc, hSrcDecomp⟩ :=
      UnicodeDataIndex.lookupRow?_supported_rowsList hL
    have hCp : row.codepoint = cp :=
      UnicodeDataIndex.lookupRow?_codepoint hL
    have hImp : src.codepoint = cp → src.canonicalDecomposition = target :=
      of_decide_eq_true (List.all_eq_true.mp hAll src hSrcMem)
    exact hSrcDecomp.symm.trans (hImp (hSrcCp.trans hCp))

end Unicode.Normalization.Lookup
