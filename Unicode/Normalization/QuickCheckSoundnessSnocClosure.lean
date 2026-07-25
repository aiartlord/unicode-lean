/-
  Unicode.Normalization.QuickCheckSoundnessSnocClosure

  Closes the master soundness theorem of `isNFCQuickCheck` (UAX
  #15 §A.1) via a two-shape dispatcher over the snoc element's CCC
  class.

    * Starter (CCC = 0): `nfc_snoc_qcY_starter` — `singleton_sound`
      gives `toNFC [cp] = [cp]` for any QC=Y starter regardless
      of decomposition shape (atomic, Hangul, size-2, or
      recursively-chained size-2);
      `compose_qcY_starter_block_additive` factors `compose` over
      the snoc boundary; `reorder_append_starter_middle` factors
      `toNFD` over the same boundary.
    * Non-starter (CCC > 0):
      `nfc_snoc_qcY_nonstarter_structural` — `compose_slide_qcY`
      (`ComposeNonstarterSlide`) discharges the swap step via state-
      machine equivariance; the buffer-bound
      `compose_buffer_ccc_bound` and chain-validity
      `chain_fires_via_buffer_bound` come from
      `ComposeBufferStructure`.

  The starter branch needs a structural premise: for any QC=Y starter
  `cp`, the head of `decomposeSequence [cp]` is a starter and the head of
  `toNFD [cp]` is a QC=Y starter.  This module proves that premise by
  dispatching over the same semantic cases as singleton soundness:
  atomic, Hangul, and generated rank-certificate rows.
-/

import Unicode.Normalization.QuickCheckSoundness
import Unicode.Normalization.QuickCheckSoundnessMaster
import Unicode.Normalization.QuickCheckSoundnessHangul
import Unicode.Normalization.QuickCheckSoundnessSingletonRank
import Unicode.Normalization.ComposeBlockAdditive
import Unicode.Normalization.ComposeNonstarterSlide
import Unicode.Normalization.ComposeBufferStructure
import Unicode.Normalization.ComposeKernelSupport
import Unicode.Normalization.NFC
import Unicode.Normalization.ReorderAppend
import Unicode.Normalization.Distribute
import Unicode.Generated.UnicodeData

namespace Unicode.Normalization.QuickCheckSoundnessSnocClosure

open Unicode.Normalization
open Unicode.Normalization.NFC (toNFC toNFD isNFCQuickCheck nfcQCValue)
open Unicode.Normalization.QuickCheckSoundness
  (qcY_nonstarter_cp_no_decomp hangulSyllable_ccc_zero_cp)
open Unicode.Normalization.QuickCheckSoundnessMaster (singleton_sound)
open Unicode.Normalization.ComposeBlockAdditive
  (compose_qcY_starter_block_additive compose_qcY_linear)
open Unicode.Normalization.ComposeNonstarterSlide
  (PrimaryFiresChain compose_slide_qcY)
open Unicode.Normalization.ComposeBufferStructure
  (compose_buffer_ccc_bound chain_fires_via_buffer_bound)
open Unicode.Normalization.ComposeKernelSupport
  (foldl_stepCompose_starter_isSome_persists
   foldl_stepCompose_starter_isSome_of_member
   getLast?_concat_singleton
   decomp_atomic_id
   trailingLow trailingHigh
   trailingLow_append_trailingHigh
   trailingHigh_all_gt
   trailingHigh_all_pos
   trailingLow_last_le_when_high_nonempty
   HasSortedRuns_left_of_concat
   HasSortedRuns_right_of_concat
   HasSortedRuns_append_singleton
   HasSortedRuns_concat
   trailingHigh_nonempty_in_swap_case
   lowL_has_starter_in_swap_case
   nfc_snoc_atomic_nonstarter_hsr_preserves)
open Unicode.Generated

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 PER-CODEPOINT STARTER-HEAD LIFT
-- ═══════════════════════════════════════════════════════════════════════════════

/-- For any QC=Y starter `cp`, `decomposeSequence [cp]` is non-empty
    and starter-led, and `toNFD [cp]` is non-empty with a QC=Y starter
    head. Atomic rows reduce directly, Hangul syllables use Hangul
    arithmetic, and non-empty non-Hangul row decompositions route through
    the generated singleton-rank certificate. -/
theorem qcY_starter_toNFD_head
    (cp : Nat)
    (hQC : nfcQCValue cp = .Y)
    (hCcc : Lookup.canonicalCombiningClass cp = 0) :
    Lookup.canonicalCombiningClass
        (Decompose.decomposeSequence [cp])[0]! = 0 ∧
    Lookup.canonicalCombiningClass (toNFD [cp])[0]! = 0 ∧
    nfcQCValue (toNFD [cp])[0]! = .Y ∧
    (Decompose.decomposeSequence [cp]).length > 0 ∧
    (toNFD [cp]).length > 0 := by
  by_cases hHangul : Hangul.isHangulSyllable cp = true
  · exact QuickCheckSoundnessHangul.hangul_singleton_toNFD_head cp hHangul
  · have hNotHangul : Hangul.isHangulSyllable cp = false := by
      cases hH : Hangul.isHangulSyllable cp
      · rfl
      · exact absurd hH hHangul
    cases hLookup : Lookup.lookupRow cp with
    | none =>
      have hDecomp : Lookup.canonicalDecomposition cp = #[] := by
        unfold Lookup.canonicalDecomposition; rw [hLookup]
      have hDsyl : Hangul.decomposeSyllable? cp = none := by
        unfold Hangul.decomposeSyllable?
        rw [hNotHangul]
        simp
      have hFCD : Decompose.fullCanonicalDecompose cp = #[cp] := by
        show Decompose.fullCanonicalDecomposeFuel Decompose.maxDepth cp = #[cp]
        unfold Decompose.maxDepth Decompose.fullCanonicalDecomposeFuel
        rw [hDsyl]
        simp [hDecomp]
      have hDS : Decompose.decomposeSequence [cp] = [cp] := by
        rw [Distribute.decomposeSequence_singleton, hFCD]
      have hToNFD : toNFD [cp] = [cp] := by
        unfold toNFD
        rw [hDS]
        apply Reorder.reorder_id_on_HasSortedRuns
        rw [Reorder.HasSortedRuns_singleton]
        exact True.intro
      have hDsHead :
          Lookup.canonicalCombiningClass
            (Decompose.decomposeSequence [cp])[0]! = 0 := by
        rw [hDS]; simpa using hCcc
      have hNfdHead :
          Lookup.canonicalCombiningClass (toNFD [cp])[0]! = 0 := by
        rw [hToNFD]; simpa using hCcc
      have hNfdQC : nfcQCValue (toNFD [cp])[0]! = .Y := by
        rw [hToNFD]; simpa using hQC
      have hDsNonEmpty : (Decompose.decomposeSequence [cp]).length > 0 := by
        rw [hDS]; simp
      have hNfdNonEmpty : (toNFD [cp]).length > 0 := by
        rw [hToNFD]; simp
      exact And.intro hDsHead
        (And.intro hNfdHead
          (And.intro hNfdQC
            (And.intro hDsNonEmpty hNfdNonEmpty)))
    | some row =>
      have hRowCp : row.codepoint = cp := by
        exact Unicode.Generated.UnicodeDataIndex.lookupRow?_codepoint hLookup
      obtain ⟨src, hSrcMem, hSrcCp, _hSrcCcc, hSrcDecomp⟩ :=
        Unicode.Generated.UnicodeDataIndex.lookupRow?_supported_rowsList hLookup
      have hSrcCpEq : src.codepoint = cp := hSrcCp.trans hRowCp
      by_cases hEmpty : Lookup.canonicalDecomposition cp = #[]
      · have hDsyl : Hangul.decomposeSyllable? cp = none := by
          unfold Hangul.decomposeSyllable?
          rw [hNotHangul]
          simp
        have hFCD : Decompose.fullCanonicalDecompose cp = #[cp] := by
          show Decompose.fullCanonicalDecomposeFuel Decompose.maxDepth cp = #[cp]
          unfold Decompose.maxDepth Decompose.fullCanonicalDecomposeFuel
          rw [hDsyl]
          simp [hEmpty]
        have hDS : Decompose.decomposeSequence [cp] = [cp] := by
          rw [Distribute.decomposeSequence_singleton, hFCD]
        have hToNFD : toNFD [cp] = [cp] := by
          unfold toNFD
          rw [hDS]
          apply Reorder.reorder_id_on_HasSortedRuns
          trivial
        have hDsHead :
            Lookup.canonicalCombiningClass
              (Decompose.decomposeSequence [cp])[0]! = 0 := by
          rw [hDS]; simpa using hCcc
        have hNfdHead :
            Lookup.canonicalCombiningClass (toNFD [cp])[0]! = 0 := by
          rw [hToNFD]; simpa using hCcc
        have hNfdQC : nfcQCValue (toNFD [cp])[0]! = .Y := by
          rw [hToNFD]; simpa using hQC
        have hDsNonEmpty : (Decompose.decomposeSequence [cp]).length > 0 := by
          rw [hDS]; simp
        have hNfdNonEmpty : (toNFD [cp]).length > 0 := by
          rw [hToNFD]; simp
        exact And.intro hDsHead
          (And.intro hNfdHead
            (And.intro hNfdQC
              (And.intro hDsNonEmpty hNfdNonEmpty)))
      · have hCovered :=
          List.all_eq_true.mp
            QuickCheckSingletonRankData.relevant_lookup_rows_covered src hSrcMem
        have hCccDecide :
            decide (Lookup.canonicalCombiningClass src.codepoint ≠ 0) = false := by
          rw [hSrcCpEq]
          simp [hCcc]
        have hHangulDecide :
            decide (Hangul.isHangulSyllable src.codepoint = true) = false := by
          rw [hSrcCpEq]
          simp [hNotHangul]
        have hQCDecide : decide (nfcQCValue src.codepoint ≠ .Y) = false := by
          rw [hSrcCpEq]
          simp [hQC]
        have hRowDecomp :
            src.canonicalDecomposition = Lookup.canonicalDecomposition cp := by
          unfold Lookup.canonicalDecomposition
          rw [hLookup]
          exact hSrcDecomp
        have hSizeDecide :
            decide (src.canonicalDecomposition.size = 0) = false := by
          rw [hRowDecomp]
          have hSizeNonzero : (Lookup.canonicalDecomposition cp).size ≠ 0 := by
            intro hZero
            apply hEmpty
            exact Array.eq_empty_of_size_eq_zero hZero
          simp [hSizeNonzero]
        have hAny :
            QuickCheckSingletonRankData.rows.any
              (fun entry => decide (entry.codepoint = cp)) = true := by
          rw [hCccDecide, hHangulDecide, hQCDecide, hSizeDecide] at hCovered
          simp only [Bool.false_or] at hCovered
          rw [hSrcCpEq] at hCovered
          exact hCovered
        exact QuickCheckSoundnessSingletonRank.toNFD_head_of_rank_rows_any cp hAny

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 REORDER FACTORS OVER A STARTER-LED RIGHT BLOCK
-- ═══════════════════════════════════════════════════════════════════════════════

/-- `reorder` distributes over `X ++ Y` when `Y` is non-empty with a
    starter head: factoring `Y = [Y[0]] ++ Y_tail` and applying
    `reorder_append_starter_middle` once to the (X, head, tail)
    triple and once to the (∅, head, tail) triple. -/
theorem reorder_append_starter_led
    (X : List Nat) (head : Nat) (tail : List Nat)
    (hHead : Lookup.canonicalCombiningClass head = 0) :
    Reorder.reorder (X ++ (head :: tail)) =
      Reorder.reorder X ++ Reorder.reorder (head :: tail) := by
  -- The right block reorder factors at its leading starter.
  have hReorderRight :
      Reorder.reorder (head :: tail)
        = [head] ++ Reorder.reorder tail := by
    have hStep := ReorderAppend.reorder_append_starter_middle
                    ([] : List Nat) head tail hHead
    -- hStep: reorder ([] ++ [head] ++ tail)
    --        = reorder [] ++ [head] ++ reorder tail.
    simpa [show Reorder.reorder ([] : List Nat) = [] from rfl] using hStep
  have hYEq : X ++ (head :: tail) = X ++ [head] ++ tail := by simp
  rw [hYEq, ReorderAppend.reorder_append_starter_middle X head tail hHead,
      hReorderRight, List.append_assoc]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 toNFD DISTRIBUTES OVER SNOC AT A STARTER BOUNDARY
-- ═══════════════════════════════════════════════════════════════════════════════

/-- For any QC=Y starter `cp`, `toNFD` distributes over the snoc-
    extension boundary: the decomposition+reorder of `xs ++ [cp]`
    factors as `toNFD xs ++ toNFD [cp]`. The factoring uses
    `decomposeSequence_append` (decomposition is list-additive) and
    `reorder_append_starter_led` (starter-led right block). -/
theorem toNFD_snoc_qcY_starter
    (xs : List Nat) (cp : Nat)
    (hQC : nfcQCValue cp = .Y)
    (hCcc : Lookup.canonicalCombiningClass cp = 0) :
    toNFD (xs ++ [cp]) = toNFD xs ++ toNFD [cp] := by
  have hLift := qcY_starter_toNFD_head cp hQC hCcc
  have hDsHead := hLift.1
  have hDsNonEmpty := hLift.2.2.2.1
  cases hL : Decompose.decomposeSequence [cp] with
  | nil =>
    exfalso
    rw [hL] at hDsNonEmpty
    simp at hDsNonEmpty
  | cons head tail =>
    have hHeadCcc : Lookup.canonicalCombiningClass head = 0 := by
      rw [hL] at hDsHead
      simpa using hDsHead
    unfold toNFD
    rw [Distribute.decomposeSequence_append xs [cp]]
    rw [hL]
    exact reorder_append_starter_led (Decompose.decomposeSequence xs)
            head tail hHeadCcc

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 STARTER SNOC CLOSURE
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Snoc closure for any QC=Y starter `cp` (regardless of decomposition
    shape: atomic, Hangul, size-2, or chained). Uses `toNFD_snoc_qcY_starter`
    to factor `toNFD` over the boundary, then `compose_qcY_starter_block_additive`
    to factor `compose`, and finally `singleton_sound` for the singleton
    round-trip. -/
theorem nfc_snoc_qcY_starter
    (xs : List Nat) (cp : Nat)
    (hQC : nfcQCValue cp = .Y)
    (hCcc : Lookup.canonicalCombiningClass cp = 0)
    (hPrefix : toNFC xs = xs) :
    toNFC (xs ++ [cp]) = xs ++ [cp] := by
  have hLift := qcY_starter_toNFD_head cp hQC hCcc
  have hNfdHead := hLift.2.1
  have hNfdQC := hLift.2.2.1
  have hNfdNonEmpty := hLift.2.2.2.2
  have hSingleton : toNFC [cp] = [cp] := singleton_sound cp hQC
  have hToNFDSnoc : toNFD (xs ++ [cp]) = toNFD xs ++ toNFD [cp] :=
    toNFD_snoc_qcY_starter xs cp hQC hCcc
  cases hL : toNFD [cp] with
  | nil =>
    exfalso
    rw [hL] at hNfdNonEmpty
    simp at hNfdNonEmpty
  | cons head tail =>
    have hHeadCcc0 : Lookup.canonicalCombiningClass head = 0 := by
      rw [hL] at hNfdHead
      simpa using hNfdHead
    have hHeadQC : nfcQCValue head = .Y := by
      rw [hL] at hNfdQC
      simpa using hNfdQC
    show Compose.compose (toNFD (xs ++ [cp])) = xs ++ [cp]
    rw [hToNFDSnoc, hL]
    rw [compose_qcY_starter_block_additive (toNFD xs) (head :: tail)
          (by simp) hHeadCcc0 hHeadQC]
    rw [← hL]
    show toNFC xs ++ toNFC [cp] = xs ++ [cp]
    rw [hPrefix, hSingleton]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §8 STRUCTURAL ATOMIC-NONSTARTER SNOC
-- ═══════════════════════════════════════════════════════════════════════════════

/-- **Atomic-nonstarter snoc closure.** The slide step
    `compose (lowL ++ [cp] ++ highL) = compose (lowL ++ highL ++
    [cp])` is discharged by `compose_slide_qcY`
    (`ComposeNonstarterSlide`); chain validity for the high part is
    derived from the buffer-bound on `lowL ++ highL` via
    `chain_fires_via_buffer_bound` (`ComposeBufferStructure`). -/
theorem nfc_snoc_qcY_nonstarter_structural
    (xs : List Nat) (cp : Nat)
    (hQC : nfcQCValue cp = .Y)
    (hCp_ccc_pos : 0 < Lookup.canonicalCombiningClass cp)
    (hDecomp : Lookup.canonicalDecomposition cp = #[])
    (hNotHangul : Hangul.isHangulSyllable cp = false)
    (hPrefix : toNFC xs = xs)
    (hQCSnoc : NFC.isNFCQuickCheck (xs ++ [cp]) = true) :
    toNFC (xs ++ [cp]) = xs ++ [cp] := by
  have hHSR_outer : NFC.hasSortedRunsBool (xs ++ [cp]) = true := by
    unfold NFC.isNFCQuickCheck at hQCSnoc
    rw [Bool.and_eq_true] at hQCSnoc
    exact hQCSnoc.2
  by_cases hHSR_inner : NFC.hasSortedRunsBool (toNFD xs ++ [cp]) = true
  · have hHSR_prop : Reorder.HasSortedRuns (toNFD xs ++ [cp]) :=
      (NFC.hasSortedRunsBool_iff_HasSortedRuns
        (toNFD xs ++ [cp])).mp hHSR_inner
    exact nfc_snoc_atomic_nonstarter_hsr_preserves
      xs cp hQC hCp_ccc_pos hDecomp hNotHangul hHSR_prop hPrefix
  · -- Swap variant: partition `toNFD xs` at the cp-CCC threshold,
    -- derive chain validity for the high part, and apply the slide.
    have hCpCcc : Lookup.canonicalCombiningClass cp ≠ 0 :=
      Nat.pos_iff_ne_zero.mp hCp_ccc_pos
    have hFCD : Decompose.fullCanonicalDecompose cp = #[cp] :=
      decomp_atomic_id cp hDecomp hNotHangul
    have hZ_HSR : Reorder.HasSortedRuns (toNFD xs) :=
      (NFD.toNFD_output_HSR_and_FullyDecomposed xs).1
    obtain ⟨lowL, hLowEq⟩ :
        ∃ lowL, lowL =
          trailingLow (toNFD xs) (Lookup.canonicalCombiningClass cp) :=
      ⟨trailingLow (toNFD xs) (Lookup.canonicalCombiningClass cp), rfl⟩
    obtain ⟨highL, hHighEq⟩ :
        ∃ highL, highL =
          trailingHigh (toNFD xs) (Lookup.canonicalCombiningClass cp) :=
      ⟨trailingHigh (toNFD xs) (Lookup.canonicalCombiningClass cp), rfl⟩
    have hPartition : toNFD xs = lowL ++ highL := by
      rw [hLowEq, hHighEq]
      exact (trailingLow_append_trailingHigh
              (toNFD xs) (Lookup.canonicalCombiningClass cp)).symm
    have hHighNonEmpty : highL ≠ [] := by
      rw [hHighEq]
      exact trailingHigh_nonempty_in_swap_case
              xs cp hHSR_inner
    have hHighPos : ∀ b ∈ highL, 0 < Lookup.canonicalCombiningClass b := by
      intros b hb
      rw [hHighEq] at hb
      exact trailingHigh_all_pos
              (toNFD xs) (Lookup.canonicalCombiningClass cp) b hb
    have hHighGt : ∀ b ∈ highL,
                      Lookup.canonicalCombiningClass cp
                        < Lookup.canonicalCombiningClass b := by
      intros b hb
      rw [hHighEq] at hb
      exact trailingHigh_all_gt
              (toNFD xs) (Lookup.canonicalCombiningClass cp) b hb
    have hLowHasStarter : ∃ s ∈ lowL, Lookup.canonicalCombiningClass s = 0 := by
      rw [hLowEq]
      exact lowL_has_starter_in_swap_case
              xs cp hCp_ccc_pos hPrefix hHSR_outer hHSR_inner
    have hLowStarter :
        (lowL.foldl Compose.stepCompose Compose.initialState).starter.isSome
          = true :=
      foldl_stepCompose_starter_isSome_of_member
        lowL Compose.initialState hLowHasStarter
    -- Reshape `toNFD xs ++ [cp]` to `lowL ++ highL ++ [cp]`, then
    -- commute `cp` past `highL` via reorder's strict-max-multi
    -- lemma so that `reorder` becomes the identity on the inserted
    -- `lowL ++ [cp] ++ highL`.
    show Compose.compose (toNFD (xs ++ [cp])) = xs ++ [cp]
    have hToNFD_snoc : toNFD (xs ++ [cp])
                      = Reorder.reorder (toNFD xs ++ [cp]) := by
      unfold toNFD
      rw [Distribute.decomposeSequence_append xs [cp]]
      rw [Distribute.decomposeSequence_singleton, hFCD]
      exact ReorderAppend.reorder_append_absorbing_nonstarter
              (Decompose.decomposeSequence xs) cp hCp_ccc_pos
    rw [hToNFD_snoc]
    have hZsnocReshape : toNFD xs ++ [cp]
                       = lowL ++ highL ++ [cp] := by
      rw [hPartition]
    rw [hZsnocReshape]
    have hCpPos :
        ∀ y ∈ ([cp] : List Nat), 0 < Lookup.canonicalCombiningClass y := by
      intro y hy
      have hYcp : y = cp := by simpa using hy
      rw [hYcp]; exact hCp_ccc_pos
    have hStrictGt :
        ∀ c ∈ highL, ∀ y ∈ ([cp] : List Nat),
          Lookup.canonicalCombiningClass y
            < Lookup.canonicalCombiningClass c := by
      intros c hc y hy
      have hYcp : y = cp := by simpa using hy
      rw [hYcp]
      exact hHighGt c hc
    have hCommute :
        Reorder.reorder (lowL ++ [cp] ++ highL)
          = Reorder.reorder (lowL ++ highL ++ [cp]) :=
      ReorderAppend.reorder_commutes_strict_max_multi
        lowL ([cp] : List Nat) highL
        hHighPos hCpPos hStrictGt
    rw [← hCommute]
    -- HSR for the inserted form makes `reorder` the identity.
    have hHSR_partitioned : Reorder.HasSortedRuns (lowL ++ highL) :=
      hPartition ▸ hZ_HSR
    have hHSR_lowL :=
      HasSortedRuns_left_of_concat
        lowL highL hHSR_partitioned
    have hHSR_highL :=
      HasSortedRuns_right_of_concat
        lowL highL hHSR_partitioned
    have hSeam_lowL_cp :
        0 < Lookup.canonicalCombiningClass cp
        → ∀ a, lowL.getLast? = some a
            → Lookup.canonicalCombiningClass a
                ≤ Lookup.canonicalCombiningClass cp := by
      intros hCpPosArg a hLast
      clear hCpPosArg
      rw [hLowEq] at hLast
      exact trailingLow_last_le_when_high_nonempty
              (toNFD xs) (Lookup.canonicalCombiningClass cp) a hLast
    have hHSR_lowL_cp : Reorder.HasSortedRuns (lowL ++ [cp]) :=
      HasSortedRuns_append_singleton
        lowL cp hHSR_lowL hSeam_lowL_cp
    have hSeam_lowLcp_highL :
        ∀ a b, (lowL ++ [cp]).getLast? = some a → highL.head? = some b
            → 0 < Lookup.canonicalCombiningClass b
            → Lookup.canonicalCombiningClass a
                ≤ Lookup.canonicalCombiningClass b := by
      intros a b hLast hHead hBpos
      clear hBpos
      have hLastEq : (lowL ++ [cp]).getLast? = some cp :=
        getLast?_concat_singleton lowL cp
      rw [hLastEq] at hLast
      have hAcp : a = cp := ((Option.some.injEq cp a).mp hLast).symm
      rw [hAcp]
      have hBmem : b ∈ highL := by
        cases hHigh : highL with
        | nil => exact absurd hHigh hHighNonEmpty
        | cons hd tl =>
          rw [hHigh] at hHead
          have hHeadVal : (hd :: tl).head? = some hd := rfl
          rw [hHeadVal] at hHead
          have hBeq : hd = b := (Option.some.injEq hd b).mp hHead
          rw [← hBeq]
          exact List.mem_cons_self
      have hLt := hHighGt b hBmem
      omega
    have hHSR_inserted : Reorder.HasSortedRuns (lowL ++ [cp] ++ highL) :=
      HasSortedRuns_concat
        (lowL ++ [cp]) highL hHSR_lowL_cp hHSR_highL hSeam_lowLcp_highL
    rw [Reorder.reorder_id_on_HasSortedRuns
      (lowL ++ [cp] ++ highL) hHSR_inserted]
    -- Apply the slide. Chain validity is derived from the buffer-
    -- bound on `compose (lowL ++ highL)`.
    have hCompZ : Compose.compose (lowL ++ highL) = xs := by
      rw [← hPartition]; show toNFC xs = xs; exact hPrefix
    have hFinalStarter :
        ((lowL ++ highL).foldl
            Compose.stepCompose Compose.initialState).starter.isSome
          = true := by
      rw [List.foldl_append]
      exact foldl_stepCompose_starter_isSome_persists
              highL
              (lowL.foldl Compose.stepCompose Compose.initialState)
              hLowStarter
    have hHSR_postCompose :
        NFC.hasSortedRunsBool
          (Compose.compose (lowL ++ highL) ++ [cp])
            = true := by
      rw [hCompZ]; exact hHSR_outer
    -- Buffer-bound (`compose_buffer_ccc_bound`) via the trailing-
    -- run-of-output characterization.
    have hFinalBufBound :
        ∀ y ∈ ((lowL ++ highL).foldl
                  Compose.stepCompose Compose.initialState).buffer,
          Lookup.canonicalCombiningClass y
            ≤ Lookup.canonicalCombiningClass cp :=
      compose_buffer_ccc_bound (lowL ++ highL) cp
        hCp_ccc_pos hFinalStarter hHSR_postCompose
    -- Chain validity (`chain_fires_via_buffer_bound`) via the
    -- buffer-bound + buffer-or-fire dichotomy.
    have hChainFresh : PrimaryFiresChain
          (lowL.foldl Compose.stepCompose Compose.initialState) highL :=
      chain_fires_via_buffer_bound highL lowL cp hHighPos hHighGt
        hLowStarter hFinalBufBound
    obtain ⟨stLow, hStLow⟩ :=
      Option.isSome_iff_exists.mp hLowStarter
    have hSlide : Compose.compose
                    (lowL ++ [cp] ++ highL)
                  = Compose.compose
                    (lowL ++ highL ++ [cp]) :=
      compose_slide_qcY lowL cp highL stLow hStLow hQC hCp_ccc_pos
        hHighGt hChainFresh
    rw [hSlide]
    rw [compose_qcY_linear
          (lowL ++ highL) cp hQC]
    rw [hCompZ]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §9 UNIFIED SNOC DISPATCHER
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Closes the snoc-induction step of the master soundness theorem.
    Dispatches on `cp`'s CCC class:

      * Starter (CCC = 0): `nfc_snoc_qcY_starter` — handles all
        decomposition shapes uniformly via
        `compose_qcY_starter_block_additive`.
      * Non-starter (CCC > 0): `nfc_snoc_qcY_nonstarter_structural`
        — the swap analysis discharged via `compose_slide_qcY` in
        `ComposeNonstarterSlide`. The empty-decomposition and
        not-Hangul premises derive from Fact 1 and
        `hangulSyllable_ccc_zero`. -/
theorem nfc_snoc_qcY
    (xs : List Nat) (cp : Nat)
    (hQC : nfcQCValue cp = .Y)
    (hPrefix : toNFC xs = xs)
    (hSnocQC : isNFCQuickCheck (xs ++ [cp]) = true) :
    toNFC (xs ++ [cp]) = xs ++ [cp] := by
  by_cases hCcc : Lookup.canonicalCombiningClass cp = 0
  · exact nfc_snoc_qcY_starter xs cp hQC hCcc hPrefix
  · have hCccPos : 0 < Lookup.canonicalCombiningClass cp :=
      Nat.pos_of_ne_zero hCcc
    have hDecomp : Lookup.canonicalDecomposition cp = #[] :=
      qcY_nonstarter_cp_no_decomp cp hQC hCccPos
    have hNotHangul : Hangul.isHangulSyllable cp = false := by
      cases hH : Hangul.isHangulSyllable cp with
      | false => rfl
      | true =>
        exfalso
        have hHangulCcc := hangulSyllable_ccc_zero_cp cp hH
        omega
    exact nfc_snoc_qcY_nonstarter_structural xs cp hQC hCccPos hDecomp
      hNotHangul hPrefix hSnocQC

end Unicode.Normalization.QuickCheckSoundnessSnocClosure
