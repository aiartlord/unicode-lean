/-
  Unicode.Normalization.QuickCheckSoundnessHangul

  Structural Hangul singleton NFC soundness for the quick-check master proof.
  This proves the full precomposed-syllable range by UAX #15 Hangul arithmetic:
  decompose a syllable into L+V(+T), reorder the starter-only jamo sequence as
  identity, then compose L+V and optional LV+T back to the original syllable.
-/

import Unicode.Normalization.NFC
import Unicode.Normalization.Decompose
import Unicode.Normalization.Reorder
import Unicode.Normalization.Compose
import Unicode.Normalization.Hangul
import Unicode.Normalization.Distribute
import Unicode.Normalization.QuickCheckHangulFacts

namespace Unicode.Normalization.QuickCheckSoundnessHangul

open Unicode.Normalization
open Unicode.Normalization.NFC (toNFC toNFD nfcQCValue)

theorem lJamo_ccc_zero_at (i : Nat) (hi : i < Hangul.LCount) :
    Lookup.canonicalCombiningClass (Hangul.LBase + i) = 0 := by
  have hAll := QuickCheckHangulFacts.lJamo_ccc_zero
  rw [List.all_eq_true] at hAll
  exact of_decide_eq_true (hAll i (List.mem_range.mpr hi))

/-- Every L-jamo emitted at the head of a Hangul syllable decomposition has
    NFC_QC=Y. Narrow `decide` over the 19 leading-consonant jamo. -/
theorem lJamo_qcY :
    (List.range Hangul.LCount).all
      (fun i => nfcQCValue (Hangul.LBase + i) = .Y) = true := by
  decide

theorem lJamo_qcY_at (i : Nat) (hi : i < Hangul.LCount) :
    nfcQCValue (Hangul.LBase + i) = .Y := by
  have hAll := lJamo_qcY
  rw [List.all_eq_true] at hAll
  exact of_decide_eq_true (hAll i (List.mem_range.mpr hi))

theorem vJamo_ccc_zero_at (i : Nat) (hi : i < Hangul.VCount) :
    Lookup.canonicalCombiningClass (Hangul.VBase + i) = 0 := by
  have hAll := QuickCheckHangulFacts.vJamo_ccc_zero
  rw [List.all_eq_true] at hAll
  exact of_decide_eq_true (hAll i (List.mem_range.mpr hi))

theorem tJamo_ccc_zero_at (i : Nat) (hiPos : 0 < i) (hi : i < Hangul.TCount) :
    Lookup.canonicalCombiningClass (Hangul.TBase + i) = 0 := by
  have hAll := QuickCheckHangulFacts.tJamo_ccc_zero
  rw [List.all_eq_true] at hAll
  have hIdx : i - 1 < Hangul.TCount - 1 := by omega
  have hAt := hAll (i - 1) (List.mem_range.mpr hIdx)
  have hEq : Hangul.TBase + 1 + (i - 1) = Hangul.TBase + i := by omega
  exact of_decide_eq_true (by simpa [hEq] using hAt)

theorem composePair_LV_of_indices
    (li vi : Nat) (hli : li < Hangul.LCount) (hvi : vi < Hangul.VCount) :
    Hangul.composePair? (Hangul.LBase + li) (Hangul.VBase + vi) =
      some (Hangul.SBase + (li * Hangul.VCount + vi) * Hangul.TCount) := by
  have hL : Hangul.isLJamo (Hangul.LBase + li) = true := by
    unfold Hangul.isLJamo
    exact decide_eq_true (by
      simp only [Hangul.LBase, Hangul.LCount] at hli ⊢
      omega)
  have hV : Hangul.isVJamo (Hangul.VBase + vi) = true := by
    unfold Hangul.isVJamo
    exact decide_eq_true (by
      simp only [Hangul.VBase, Hangul.VCount] at hvi ⊢
      omega)
  unfold Hangul.composePair?
  rw [hL, hV]
  have hSubL : Hangul.LBase + li - Hangul.LBase = li := by omega
  have hSubV : Hangul.VBase + vi - Hangul.VBase = vi := by omega
  simp [hSubL, hSubV]

theorem composePair_LVT_of_indices
    (li vi ti : Nat)
    (hli : li < Hangul.LCount) (hvi : vi < Hangul.VCount)
    (htiPos : 0 < ti) (hti : ti < Hangul.TCount) :
    Hangul.composePair?
        (Hangul.SBase + (li * Hangul.VCount + vi) * Hangul.TCount)
        (Hangul.TBase + ti) =
      some (Hangul.SBase + (li * Hangul.VCount + vi) * Hangul.TCount + ti) := by
  let lv := Hangul.SBase + (li * Hangul.VCount + vi) * Hangul.TCount
  let t := Hangul.TBase + ti
  have hNotL : Hangul.isLJamo lv = false := by
    unfold Hangul.isLJamo
    exact decide_eq_false (by
      simp only [lv, Hangul.SBase, Hangul.LBase, Hangul.LCount,
        Hangul.VCount, Hangul.TCount]
      omega)
  have hLV : Hangul.isHangulSyllable lv = true := by
    unfold Hangul.isHangulSyllable
    exact decide_eq_true (by
      simp only [lv, Hangul.SBase, Hangul.SCount, Hangul.LCount,
        Hangul.NCount, Hangul.VCount, Hangul.TCount] at hli hvi ⊢
      omega)
  have hT : Hangul.isTJamo t = true := by
    unfold Hangul.isTJamo
    exact decide_eq_true (by
      simp only [t, Hangul.TBase, Hangul.TCount] at hti htiPos ⊢
      omega)
  have hMod : (lv - Hangul.SBase) % Hangul.TCount = 0 := by
    have hSub :
        lv - Hangul.SBase = (li * Hangul.VCount + vi) * Hangul.TCount := by
      simp only [lv]
      omega
    rw [hSub]
    rw [Nat.mul_comm]
    exact Nat.mul_mod_right Hangul.TCount (li * Hangul.VCount + vi)
  unfold Hangul.composePair?
  simp [hNotL, hLV, hT, lv, t]

/-- The generated Hangul L/V/T jamo sequence for a precomposed syllable is
    already in canonical order, because every emitted jamo has CCC 0. -/
theorem hangul_jamo_HasSortedRuns
    (l v : Nat) :
    Lookup.canonicalCombiningClass l = 0 →
    Lookup.canonicalCombiningClass v = 0 →
    Reorder.HasSortedRuns [l, v] := by
  intro hL hV
  refine ⟨?head, ?tail⟩
  · intro hPos
    rw [hL, hV]
    exact Nat.le_refl 0
  · trivial

theorem hangul_jamo3_HasSortedRuns
    (l v t : Nat) :
    Lookup.canonicalCombiningClass l = 0 →
    Lookup.canonicalCombiningClass v = 0 →
    Lookup.canonicalCombiningClass t = 0 →
    Reorder.HasSortedRuns [l, v, t] := by
  intro hL hV hT
  refine ⟨?head, ?tail⟩
  · intro _hPos
    rw [hL, hV]
    exact Nat.le_refl 0
  · refine ⟨?head2, ?tail2⟩
    · intro _hPos
      rw [hV, hT]
      exact Nat.le_refl 0
    · trivial

theorem compose_LV_array
    (li vi : Nat) (hli : li < Hangul.LCount) (hvi : vi < Hangul.VCount) :
    Compose.compose [Hangul.LBase + li, Hangul.VBase + vi] =
      [Hangul.SBase + (li * Hangul.VCount + vi) * Hangul.TCount] := by
  have hLcc := lJamo_ccc_zero_at li hli
  have hVcc := vJamo_ccc_zero_at vi hvi
  have hPC := composePair_LV_of_indices li vi hli hvi
  unfold Compose.compose
  simp only [List.foldl_cons, List.foldl_nil]
  have hStep1 :
      Compose.stepCompose Compose.initialState (Hangul.LBase + li) =
        { emitted := [], starter := some (Hangul.LBase + li), buffer := [],
          maxCCC := 0 } := by
    rw [Compose.stepCompose.eq_def]
    unfold Compose.initialState
    simp [hLcc]
  have hStep2 :
      Compose.stepCompose
        { emitted := [], starter := some (Hangul.LBase + li), buffer := [],
          maxCCC := 0 } (Hangul.VBase + vi) =
        { emitted := [], starter := some
            (Hangul.SBase + (li * Hangul.VCount + vi) * Hangul.TCount),
          buffer := [], maxCCC := 0 } := by
    have hPrimary :
        Compose.primaryComposite? (Hangul.LBase + li) (Hangul.VBase + vi) =
          some (Hangul.SBase + (li * Hangul.VCount + vi) * Hangul.TCount) := by
      unfold Compose.primaryComposite?
      rw [hPC]
    rw [Compose.stepCompose.eq_def]
    simp [hVcc, hPrimary]
  rw [hStep1, hStep2]
  unfold Compose.flushCompose
  rfl

theorem compose_LVT_array
    (li vi ti : Nat)
    (hli : li < Hangul.LCount) (hvi : vi < Hangul.VCount)
    (htiPos : 0 < ti) (hti : ti < Hangul.TCount) :
    Compose.compose [Hangul.LBase + li, Hangul.VBase + vi, Hangul.TBase + ti] =
      [Hangul.SBase + (li * Hangul.VCount + vi) * Hangul.TCount + ti] := by
  have hLcc := lJamo_ccc_zero_at li hli
  have hVcc := vJamo_ccc_zero_at vi hvi
  have hTcc := tJamo_ccc_zero_at ti htiPos hti
  have hPC1 := composePair_LV_of_indices li vi hli hvi
  have hPC2 := composePair_LVT_of_indices li vi ti hli hvi htiPos hti
  unfold Compose.compose
  simp only [List.foldl_cons, List.foldl_nil]
  have hStep1 :
      Compose.stepCompose Compose.initialState (Hangul.LBase + li) =
        { emitted := [], starter := some (Hangul.LBase + li), buffer := [],
          maxCCC := 0 } := by
    rw [Compose.stepCompose.eq_def]
    unfold Compose.initialState
    simp [hLcc]
  have hStep2 :
      Compose.stepCompose
        { emitted := [], starter := some (Hangul.LBase + li), buffer := [],
          maxCCC := 0 } (Hangul.VBase + vi) =
        { emitted := [], starter := some
            (Hangul.SBase + (li * Hangul.VCount + vi) * Hangul.TCount),
          buffer := [], maxCCC := 0 } := by
    have hPrimary :
        Compose.primaryComposite? (Hangul.LBase + li) (Hangul.VBase + vi) =
          some (Hangul.SBase + (li * Hangul.VCount + vi) * Hangul.TCount) := by
      unfold Compose.primaryComposite?
      rw [hPC1]
    rw [Compose.stepCompose.eq_def]
    simp [hVcc, hPrimary]
  have hStep3 :
      Compose.stepCompose
        { emitted := [], starter := some
            (Hangul.SBase + (li * Hangul.VCount + vi) * Hangul.TCount),
          buffer := [], maxCCC := 0 } (Hangul.TBase + ti) =
        { emitted := [], starter := some
            (Hangul.SBase + (li * Hangul.VCount + vi) * Hangul.TCount + ti),
          buffer := [], maxCCC := 0 } := by
    have hPrimary :
        Compose.primaryComposite?
            (Hangul.SBase + (li * Hangul.VCount + vi) * Hangul.TCount)
            (Hangul.TBase + ti) =
          some (Hangul.SBase + (li * Hangul.VCount + vi) * Hangul.TCount + ti) := by
      unfold Compose.primaryComposite?
      rw [hPC2]
    rw [Compose.stepCompose.eq_def]
    simp [hTcc, hPrimary]
  rw [hStep1, hStep2, hStep3]
  unfold Compose.flushCompose
  rfl

/-- For every precomposed Hangul syllable, both `decomposeSequence [cp]` and
    `toNFD [cp]` are non-empty and headed by the L-jamo, which is a QC=Y
    starter. -/
theorem hangul_singleton_toNFD_head
    (cp : Nat) (hHangul : Hangul.isHangulSyllable cp = true) :
    Lookup.canonicalCombiningClass
        (Decompose.decomposeSequence [cp])[0]! = 0 ∧
    Lookup.canonicalCombiningClass (toNFD [cp])[0]! = 0 ∧
    nfcQCValue (toNFD [cp])[0]! = .Y ∧
    (Decompose.decomposeSequence [cp]).length > 0 ∧
    (toNFD [cp]).length > 0 := by
  have hRange : Hangul.SBase ≤ cp ∧ cp < Hangul.SBase + Hangul.SCount := by
    unfold Hangul.isHangulSyllable at hHangul
    exact of_decide_eq_true hHangul
  have hsLt : cp - Hangul.SBase < Hangul.SCount := by omega
  have hNPos : 0 < Hangul.NCount := by
    decide
  have hTPos : 0 < Hangul.TCount := by
    decide
  let sIndex := cp - Hangul.SBase
  let li := sIndex / Hangul.NCount
  let vi := (sIndex % Hangul.NCount) / Hangul.TCount
  let ti := sIndex % Hangul.TCount
  have hli : li < Hangul.LCount := by
    exact (Nat.div_lt_iff_lt_mul hNPos).2 (by
      simp only [sIndex, Hangul.SCount, Hangul.NCount] at hsLt ⊢
      omega)
  have hModNLt : sIndex % Hangul.NCount < Hangul.NCount :=
    Nat.mod_lt sIndex hNPos
  have hvi : vi < Hangul.VCount := by
    exact (Nat.div_lt_iff_lt_mul hTPos).2 (by
      simp only [Hangul.NCount, Hangul.VCount, Hangul.TCount] at hModNLt ⊢
      omega)
  have hti : ti < Hangul.TCount := by
    exact Nat.mod_lt sIndex hTPos
  have hDecompSyllable :
      Hangul.decomposeSyllable? cp =
        if ti = 0 then
          some [Hangul.LBase + li, Hangul.VBase + vi]
        else
          some [Hangul.LBase + li, Hangul.VBase + vi, Hangul.TBase + ti] := by
    unfold Hangul.decomposeSyllable?
    rw [hHangul]
    simp [sIndex, li, vi, ti]
  have hLcc := lJamo_ccc_zero_at li hli
  have hLqc := lJamo_qcY_at li hli
  by_cases htiZero : ti = 0
  · have hFCD :
        Decompose.fullCanonicalDecompose cp =
          [Hangul.LBase + li, Hangul.VBase + vi] := by
      show Decompose.fullCanonicalDecomposeFuel Decompose.maxDepth cp =
        [Hangul.LBase + li, Hangul.VBase + vi]
      simp [Decompose.maxDepth, Decompose.fullCanonicalDecomposeFuel,
        hDecompSyllable, htiZero]
    have hDS :
        Decompose.decomposeSequence [cp] =
          [Hangul.LBase + li, Hangul.VBase + vi] := by
      rw [Distribute.decomposeSequence_singleton, hFCD]
    have hVcc := vJamo_ccc_zero_at vi hvi
    have hR :
        Reorder.reorder [Hangul.LBase + li, Hangul.VBase + vi] =
          [Hangul.LBase + li, Hangul.VBase + vi] := by
      apply Reorder.reorder_id_on_HasSortedRuns
      exact hangul_jamo_HasSortedRuns
              (Hangul.LBase + li) (Hangul.VBase + vi) hLcc hVcc
    have hToNFD :
        toNFD [cp] = [Hangul.LBase + li, Hangul.VBase + vi] := by
      unfold toNFD
      rw [hDS, hR]
    have hDsHead :
        Lookup.canonicalCombiningClass
          (Decompose.decomposeSequence [cp])[0]! = 0 := by
      rw [hDS]; simpa using hLcc
    have hNfdHead :
        Lookup.canonicalCombiningClass (toNFD [cp])[0]! = 0 := by
      rw [hToNFD]; simpa using hLcc
    have hNfdQC :
        nfcQCValue (toNFD [cp])[0]! = .Y := by
      rw [hToNFD]; simpa using hLqc
    have hDsNonEmpty : (Decompose.decomposeSequence [cp]).length > 0 := by
      rw [hDS]; simp
    have hNfdNonEmpty : (toNFD [cp]).length > 0 := by
      rw [hToNFD]; simp
    exact And.intro hDsHead
      (And.intro hNfdHead
        (And.intro hNfdQC
          (And.intro hDsNonEmpty hNfdNonEmpty)))
  · have htiPos : 0 < ti := by omega
    have hFCD :
        Decompose.fullCanonicalDecompose cp =
          [Hangul.LBase + li, Hangul.VBase + vi, Hangul.TBase + ti] := by
      show Decompose.fullCanonicalDecomposeFuel Decompose.maxDepth cp =
        [Hangul.LBase + li, Hangul.VBase + vi, Hangul.TBase + ti]
      simp [Decompose.maxDepth, Decompose.fullCanonicalDecomposeFuel,
        hDecompSyllable, htiZero]
    have hDS :
        Decompose.decomposeSequence [cp] =
          [Hangul.LBase + li, Hangul.VBase + vi, Hangul.TBase + ti] := by
      rw [Distribute.decomposeSequence_singleton, hFCD]
    have hVcc := vJamo_ccc_zero_at vi hvi
    have hTcc := tJamo_ccc_zero_at ti htiPos hti
    have hR :
        Reorder.reorder [Hangul.LBase + li, Hangul.VBase + vi, Hangul.TBase + ti] =
          [Hangul.LBase + li, Hangul.VBase + vi, Hangul.TBase + ti] := by
      apply Reorder.reorder_id_on_HasSortedRuns
      exact hangul_jamo3_HasSortedRuns
              (Hangul.LBase + li) (Hangul.VBase + vi) (Hangul.TBase + ti)
              hLcc hVcc hTcc
    have hToNFD :
        toNFD [cp] =
          [Hangul.LBase + li, Hangul.VBase + vi, Hangul.TBase + ti] := by
      unfold toNFD
      rw [hDS, hR]
    have hDsHead :
        Lookup.canonicalCombiningClass
          (Decompose.decomposeSequence [cp])[0]! = 0 := by
      rw [hDS]; simpa using hLcc
    have hNfdHead :
        Lookup.canonicalCombiningClass (toNFD [cp])[0]! = 0 := by
      rw [hToNFD]; simpa using hLcc
    have hNfdQC :
        nfcQCValue (toNFD [cp])[0]! = .Y := by
      rw [hToNFD]; simpa using hLqc
    have hDsNonEmpty : (Decompose.decomposeSequence [cp]).length > 0 := by
      rw [hDS]; simp
    have hNfdNonEmpty : (toNFD [cp]).length > 0 := by
      rw [hToNFD]; simp
    exact And.intro hDsHead
      (And.intro hNfdHead
        (And.intro hNfdQC
          (And.intro hDsNonEmpty hNfdNonEmpty)))

/-- Every precomposed Hangul syllable is unchanged by the NFC singleton
    pipeline. -/
theorem singleton_sound_hangul (cp : Nat)
    (hHangul : Hangul.isHangulSyllable cp = true) :
    toNFC [cp] = [cp] := by
  have hRange : Hangul.SBase ≤ cp ∧ cp < Hangul.SBase + Hangul.SCount := by
    unfold Hangul.isHangulSyllable at hHangul
    exact of_decide_eq_true hHangul
  have hsLt : cp - Hangul.SBase < Hangul.SCount := by omega
  have hNPos : 0 < Hangul.NCount := by
    decide
  have hTPos : 0 < Hangul.TCount := by
    decide
  let sIndex := cp - Hangul.SBase
  let li := sIndex / Hangul.NCount
  let vi := (sIndex % Hangul.NCount) / Hangul.TCount
  let ti := sIndex % Hangul.TCount
  have hli : li < Hangul.LCount := by
    exact (Nat.div_lt_iff_lt_mul hNPos).2 (by
      simp only [sIndex, Hangul.SCount, Hangul.NCount] at hsLt ⊢
      omega)
  have hModNLt : sIndex % Hangul.NCount < Hangul.NCount :=
    Nat.mod_lt sIndex hNPos
  have hvi : vi < Hangul.VCount := by
    exact (Nat.div_lt_iff_lt_mul hTPos).2 (by
      simp only [Hangul.NCount, Hangul.VCount, Hangul.TCount] at hModNLt ⊢
      omega)
  have hti : ti < Hangul.TCount := by
    exact Nat.mod_lt sIndex hTPos
  have hCpEq : Hangul.SBase + sIndex = cp := by
    simp only [sIndex]
    omega
  have hModMod :
      (sIndex % Hangul.NCount) % Hangul.TCount = ti := by
    have hDvd : Hangul.TCount ∣ Hangul.NCount := by
      simp [Hangul.NCount, Hangul.VCount, Hangul.TCount]
    simpa [ti] using Nat.mod_mod_of_dvd sIndex hDvd
  have hModN :
      sIndex % Hangul.NCount = vi * Hangul.TCount + ti := by
    have hDivMod := Nat.div_add_mod (sIndex % Hangul.NCount) Hangul.TCount
    rw [hModMod] at hDivMod
    have hDivMod' :
        vi * Hangul.TCount + ti = sIndex % Hangul.NCount := by
      dsimp [vi]
      rw [Nat.mul_comm]
      exact hDivMod
    exact hDivMod'.symm
  have hDecompSyllable :
      Hangul.decomposeSyllable? cp =
        if ti = 0 then
          some [Hangul.LBase + li, Hangul.VBase + vi]
        else
          some [Hangul.LBase + li, Hangul.VBase + vi, Hangul.TBase + ti] := by
    unfold Hangul.decomposeSyllable?
    rw [hHangul]
    simp [sIndex, li, vi, ti]
  by_cases htiZero : ti = 0
  · have hFCD :
        Decompose.fullCanonicalDecompose cp =
          [Hangul.LBase + li, Hangul.VBase + vi] := by
      show Decompose.fullCanonicalDecomposeFuel Decompose.maxDepth cp =
        [Hangul.LBase + li, Hangul.VBase + vi]
      simp [Decompose.maxDepth, Decompose.fullCanonicalDecomposeFuel,
        hDecompSyllable, htiZero]
    have hDS :
        Decompose.decomposeSequence [cp] =
          [Hangul.LBase + li, Hangul.VBase + vi] := by
      rw [Distribute.decomposeSequence_singleton, hFCD]
    have hLcc := lJamo_ccc_zero_at li hli
    have hVcc := vJamo_ccc_zero_at vi hvi
    have hR :
        Reorder.reorder [Hangul.LBase + li, Hangul.VBase + vi] =
          [Hangul.LBase + li, Hangul.VBase + vi] := by
      apply Reorder.reorder_id_on_HasSortedRuns
      exact hangul_jamo_HasSortedRuns
              (Hangul.LBase + li) (Hangul.VBase + vi) hLcc hVcc
    have hCompose := compose_LV_array li vi hli hvi
    have hLvEq :
        Hangul.SBase + (li * Hangul.VCount + vi) * Hangul.TCount = cp := by
      have hDivModS := Nat.div_add_mod sIndex Hangul.NCount
      simp only [li, Hangul.NCount, Hangul.VCount, Hangul.TCount] at hDivModS hModN hCpEq ⊢
      omega
    unfold toNFC toNFD
    rw [hDS, hR, hCompose, hLvEq]
  · have htiPos : 0 < ti := by omega
    have hFCD :
        Decompose.fullCanonicalDecompose cp =
          [Hangul.LBase + li, Hangul.VBase + vi, Hangul.TBase + ti] := by
      show Decompose.fullCanonicalDecomposeFuel Decompose.maxDepth cp =
        [Hangul.LBase + li, Hangul.VBase + vi, Hangul.TBase + ti]
      simp [Decompose.maxDepth, Decompose.fullCanonicalDecomposeFuel,
        hDecompSyllable, htiZero]
    have hDS :
        Decompose.decomposeSequence [cp] =
          [Hangul.LBase + li, Hangul.VBase + vi, Hangul.TBase + ti] := by
      rw [Distribute.decomposeSequence_singleton, hFCD]
    have hLcc := lJamo_ccc_zero_at li hli
    have hVcc := vJamo_ccc_zero_at vi hvi
    have hTcc := tJamo_ccc_zero_at ti htiPos hti
    have hR :
        Reorder.reorder [Hangul.LBase + li, Hangul.VBase + vi, Hangul.TBase + ti] =
          [Hangul.LBase + li, Hangul.VBase + vi, Hangul.TBase + ti] := by
      apply Reorder.reorder_id_on_HasSortedRuns
      exact hangul_jamo3_HasSortedRuns
              (Hangul.LBase + li) (Hangul.VBase + vi) (Hangul.TBase + ti)
              hLcc hVcc hTcc
    have hCompose := compose_LVT_array li vi ti hli hvi htiPos hti
    have hLvtEq :
        Hangul.SBase + (li * Hangul.VCount + vi) * Hangul.TCount + ti = cp := by
      have hDivModS := Nat.div_add_mod sIndex Hangul.NCount
      simp only [li, Hangul.NCount, Hangul.VCount, Hangul.TCount] at hDivModS hModN hCpEq ⊢
      omega
    unfold toNFC toNFD
    rw [hDS, hR, hCompose, hLvtEq]

end Unicode.Normalization.QuickCheckSoundnessHangul
