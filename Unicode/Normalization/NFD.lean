/-
  Unicode.Normalization.NFD

  NFD idempotence and structural properties. `toNFD = reorder ∘
  decomposeSequence`; this module establishes:

    * `decomposeSequence` is the identity on `IsFullyDecomposed` input.
    * `toNFD` output satisfies `IsHSR` (from `reorder_output_HasSortedRuns`)
      and `IsFullyDecomposed` (from `decomposeSequence_fullyDecomposed`).
    * `toNFD` is idempotent.

  These are foundational: NFD idempotence is strictly simpler than NFC
  idempotence (no primary-composition step) and is a direct consequence
  of the Decomposability + Reorder output invariants landed.
-/

import Unicode.Normalization.NFC
import Unicode.Normalization.Decomposability
import Unicode.Invariants

namespace Unicode.Normalization.NFD

open Unicode.Normalization
open Unicode.Invariants

-- ═══════════════════════════════════════════════════════════════════════════════
-- DECOMPOSE ON FULLY-DECOMPOSED INPUT
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Pointwise: `fullCanonicalDecompose` returns `#[cp]` when `cp` has no
    canonical decomposition and is not a Hangul syllable. -/
theorem fullCanonicalDecompose_id_of_nonDecomposable
    (cp : Nat)
    (hDecomp : Lookup.canonicalDecomposition cp = #[])
    (hNotHangul : Hangul.isHangulSyllable cp = false) :
    Decompose.fullCanonicalDecompose cp = #[cp] := by
  have hDsyl : Hangul.decomposeSyllable? cp = none := by
    unfold Hangul.decomposeSyllable?
    rw [hNotHangul]
    simp
  show Decompose.fullCanonicalDecomposeFuel Decompose.maxDepth cp = #[cp]
  unfold Decompose.maxDepth
  unfold Decompose.fullCanonicalDecomposeFuel
  rw [hDsyl]
  simp [hDecomp]

/-- Array.foldl with concat on a sequence where every element `f cp = #[cp]`
    returns the sequence unchanged. Generic helper; does not depend on
    any specific UCD facts. -/
theorem foldl_concat_id_of_all_singleton
    (f : Nat → Array Nat) (cps : Array Nat)
    (h : ∀ cp ∈ cps, f cp = #[cp]) :
    cps.foldl (fun acc cp => acc ++ f cp) #[] = cps := by
  rw [← Array.foldl_toList]
  have hAllList : ∀ cp ∈ cps.toList, f cp = #[cp] :=
    fun cp hMem => h cp (by simpa using hMem)
  have key : ∀ (l : List Nat) (init : Array Nat),
      (∀ cp ∈ l, f cp = #[cp]) →
      l.foldl (fun acc cp => acc ++ f cp) init = init ++ l.toArray := by
    intro l
    induction l with
    | nil => intro init hH; simp
    | cons hd tl ih =>
      intro init hH
      have hHd : f hd = #[hd] := hH hd (by simp)
      have hTl : ∀ cp ∈ tl, f cp = #[cp] := fun cp hMem => hH cp (by simp [hMem])
      simp only [List.foldl_cons, hHd]
      rw [ih (init ++ #[hd]) hTl]
      simp
  rw [key cps.toList #[] hAllList]
  simp

/-- `decomposeSequence` is the identity on `IsFullyDecomposed` input. -/
theorem decomposeSequence_id_on_FullyDecomposed (cps : Array Nat)
    (h : IsFullyDecomposed cps) :
    Decompose.decomposeSequence cps = cps := by
  unfold Decompose.decomposeSequence
  apply foldl_concat_id_of_all_singleton Decompose.fullCanonicalDecompose
  intro cp hMem
  obtain ⟨hDecomp, hNotHangul⟩ := h cp hMem
  exact fullCanonicalDecompose_id_of_nonDecomposable cp hDecomp hNotHangul

-- ═══════════════════════════════════════════════════════════════════════════════
-- TONFD OUTPUT INVARIANT
-- ═══════════════════════════════════════════════════════════════════════════════

/-- `toNFD` output satisfies both `IsHSR` (sorted non-starter runs) and
    `IsFullyDecomposed` (no further canonical decomposition). -/
theorem toNFD_output_HSR_and_FullyDecomposed (cps : Array Nat) :
    IsHSR (NFC.toNFD cps) ∧ IsFullyDecomposed (NFC.toNFD cps) := by
  refine ⟨?nfdHsr, ?nfdFullyDec⟩
  · unfold NFC.toNFD
    exact Reorder.reorder_output_HasSortedRuns (Decompose.decomposeSequence cps)
  · intro cp hMem
    unfold NFC.toNFD at hMem
    have hReorderMem : cp ∈ Reorder.reorder (Decompose.decomposeSequence cps) := hMem
    -- Reorder preserves set membership; every element of reorder output
    -- appears in the input to reorder, which is decomposeSequence cps.
    have hSrc : cp ∈ Decompose.decomposeSequence cps := by
      have hR := Reorder.reorder_preserves_all
                   (fun x => decide (x ∈ Decompose.decomposeSequence cps))
                   (Decompose.decomposeSequence cps)
      have hAllSrc : ∀ x ∈ Decompose.decomposeSequence cps,
          (fun x => decide (x ∈ Decompose.decomposeSequence cps)) x = true := by
        intro x hx
        exact decide_eq_true hx
      have := hR hAllSrc cp hMem
      exact of_decide_eq_true this
    exact Decomposability.decomposeSequence_fullyDecomposed cps cp hSrc

-- ═══════════════════════════════════════════════════════════════════════════════
-- REORDER IS IDENTITY ON HSR + FULLY-DECOMPOSED (NFD FORM)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- **NFD idempotence.** Applying `toNFD` twice equals applying it once.
    Proof: `toNFD x` is HSR (so `reorder` is identity) and
    `IsFullyDecomposed` (so `decomposeSequence` is identity); composing
    both identities gives the claim. -/
theorem toNFD_idempotent (cps : Array Nat) :
    NFC.toNFD (NFC.toNFD cps) = NFC.toNFD cps := by
  obtain ⟨hHSR, hFD⟩ := toNFD_output_HSR_and_FullyDecomposed cps
  -- Unfold hHSR, hFD to match the unfolded toNFD goal shape.
  unfold NFC.toNFD at hHSR hFD ⊢
  show Reorder.reorder (Decompose.decomposeSequence
         (Reorder.reorder (Decompose.decomposeSequence cps))) =
       Reorder.reorder (Decompose.decomposeSequence cps)
  rw [decomposeSequence_id_on_FullyDecomposed
        (Reorder.reorder (Decompose.decomposeSequence cps)) hFD]
  exact Reorder.reorder_id_on_HasSortedRuns
    (Reorder.reorder (Decompose.decomposeSequence cps)) hHSR

-- ═══════════════════════════════════════════════════════════════════════════════
-- NFC-NFD CONGRUENCE (glue)
--
-- Since `toNFC = compose ∘ toNFD`, two inputs with equal `toNFD` produce
-- equal `toNFC`. Trivial unfold + rewrite. Used downstream to transport
-- NFD-level equalities into NFC-level equalities — in particular to close
-- `CaseFoldNfcRoundtripFixed` without unfolding the compose step.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- `toNFC` is determined by `toNFD`: if two arrays canonicalize to the
    same NFD form, they canonicalize to the same NFC form. -/
theorem toNFC_eq_of_toNFD_eq {x y : Array Nat} (h : NFC.toNFD x = NFC.toNFD y) :
    NFC.toNFC x = NFC.toNFC y := by
  unfold NFC.toNFC
  rw [h]

-- ═══════════════════════════════════════════════════════════════════════════════
-- NFD QUICK CHECK
--
-- Two-valued NFD_QC table (Y / N) is pinned in
-- `Unicode.Generated.DerivedNormalizationProps`. The quick check passes
-- when every codepoint has `NFD_QC = Y` AND combining marks are in
-- canonical CCC order. Reuses `NFC.hasSortedRunsBool` for the HSR check
-- because the canonical reorder stage is identical between NFD and NFC.
-- ═══════════════════════════════════════════════════════════════════════════════

open Unicode.Generated

/-- Look up a codepoint's `NFD_QuickCheck` value. Falls back to the
    source file's `@missing` default (`Y`). -/
def nfdQCValue (cp : Nat) : DerivedNormalizationProps.NFC_QC :=
  if cp < 0x00C0 then
    DerivedNormalizationProps.defaultNfdQC
  else if decide (0x00C0 ≤ cp ∧ cp ≤ 0x00C5) then
    .N
  else
    match DerivedNormalizationProps.nfdQC.findSome?
            (fun ⟨min, max, v⟩ => if min ≤ cp ∧ cp ≤ max then some v else none) with
    | some v => v
    | none   => DerivedNormalizationProps.defaultNfdQC

theorem nfdQCValue_below_first_range (cp : Nat) (h : cp < 0x00C0) :
    nfdQCValue cp = DerivedNormalizationProps.defaultNfdQC := by
  unfold nfdQCValue
  simp [h]

theorem nfdQCValue_first_range_N (cp : Nat)
    (hLo : 0x00C0 ≤ cp) (hHi : cp ≤ 0x00C5) :
    nfdQCValue cp = .N := by
  unfold nfdQCValue
  have hNotLt : ¬ cp < 0x00C0 := Nat.not_lt_of_ge hLo
  have hRange : (decide (0x00C0 ≤ cp ∧ cp ≤ 0x00C5)) = true :=
    decide_eq_true ⟨hLo, hHi⟩
  simp [hNotLt, hRange]

/-- Every pinned row below U+0300 records `CCC = 0` — the sub-U+0300
    rows exist only for their canonical decompositions. One linear
    kernel pass over the row list. -/
theorem rows_ccc_zero_below_0x0300 :
    UnicodeData.rowsList.all (fun r =>
      decide (r.codepoint < 0x0300 →
        r.canonicalCombiningClass = 0)) = true := by
  decide +kernel

theorem ccc_below_first_nonzero_range (cp : Nat) (h : cp < 0x0300) :
    Lookup.canonicalCombiningClass cp = 0 := by
  unfold Lookup.canonicalCombiningClass
  cases hL : Lookup.lookupRow cp with
  | none => rfl
  | some row =>
    obtain ⟨src, hSrcMem, hSrcCp, hSrcCcc, _hSrcDecomp⟩ :=
      Unicode.Generated.UnicodeDataIndex.lookupRow?_supported_rowsList hL
    have hImp : src.codepoint < 0x0300 → src.canonicalCombiningClass = 0 :=
      of_decide_eq_true
        (List.all_eq_true.mp rows_ccc_zero_below_0x0300 src hSrcMem)
    have hCp : row.codepoint = cp :=
      Unicode.Generated.UnicodeDataIndex.lookupRow?_codepoint hL
    exact hSrcCcc.symm.trans (hImp (by omega))

/-- Quick check per UAX #15 §A.1 NFD: a sequence is guaranteed to be in
    NFD when every codepoint has `NFD_QC = Y` AND combining marks are
    non-decreasing in CCC within non-starter runs. -/
def isNFDQuickCheck (cps : Array Nat) : Bool :=
  cps.all (fun cp => decide (nfdQCValue cp = .Y)) &&
  NFC.hasSortedRunsBool cps.toList

/-- Definitive NFD check: a sequence is in NFD iff applying the NFD
    pipeline is a no-op. -/
def isNFD (cps : Array Nat) : Bool :=
  NFC.toNFD cps = cps

-- ═══════════════════════════════════════════════════════════════════════════════
-- TEST VECTORS
-- ═══════════════════════════════════════════════════════════════════════════════

theorem isNFDQuickCheck_empty : isNFDQuickCheck #[] = true := by
  unfold isNFDQuickCheck NFC.hasSortedRunsBool
  simp

theorem isNFDQuickCheck_ascii :
    isNFDQuickCheck #[0x0048, 0x0069] = true := by
  have hH : nfdQCValue 0x0048 = .Y :=
    nfdQCValue_below_first_range 0x0048 (by decide)
  have hI : nfdQCValue 0x0069 = .Y :=
    nfdQCValue_below_first_range 0x0069 (by decide)
  have hHccc : Lookup.canonicalCombiningClass 0x0048 = 0 :=
    ccc_below_first_nonzero_range 0x0048 (by decide)
  have hIccc : Lookup.canonicalCombiningClass 0x0069 = 0 :=
    ccc_below_first_nonzero_range 0x0069 (by decide)
  have hSorted : NFC.hasSortedRunsBool [0x0048, 0x0069] = true := by
    unfold NFC.hasSortedRunsBool
    simp [hHccc, hIccc]
  unfold isNFDQuickCheck
  simp [hH, hI, hSorted]

/-- LATIN CAPITAL LETTER A WITH GRAVE has `NFD_QC = N` (it decomposes). -/
theorem isNFDQuickCheck_A_grave : isNFDQuickCheck #[0x00C0] = false := by
  have hN : nfdQCValue 0x00C0 = .N :=
    nfdQCValue_first_range_N 0x00C0 (by decide) (by decide)
  simp [isNFDQuickCheck, hN]

theorem nfdQC_default_ascii : nfdQCValue 0x0041 = .Y :=
  nfdQCValue_below_first_range 0x0041 (by decide)

theorem nfdQC_explicit_N : nfdQCValue 0x00C0 = .N :=
  nfdQCValue_first_range_N 0x00C0 (by decide) (by decide)

end Unicode.Normalization.NFD
