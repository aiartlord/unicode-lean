/-
  Unicode.Normalization.QuickCheckSoundnessSingletonPair

  Singleton NFC soundness for QC=Y starters with two-element canonical
  decompositions.  This module keeps the structural compose proof separate
  from table facts that identify which rows have this shape.
-/

import Unicode.Normalization.NFC
import Unicode.Normalization.Decompose
import Unicode.Normalization.Reorder
import Unicode.Normalization.Compose
import Unicode.Normalization.Hangul
import Unicode.Normalization.Distribute
import Unicode.Normalization.QuickCheckFacts

namespace Unicode.Normalization.QuickCheckSoundnessSingletonPair

open Unicode.Normalization
open Unicode.Normalization.NFC (toNFC toNFD nfcQCValue)
open Unicode.Normalization.QuickCheckFacts
  (qcY_starter_2decomp_cp_composes)

/-- A QC=Y starter whose canonical decomposition is `[d, e]` recomposes
    through `primaryComposite? d e = some cp`. -/
theorem singleton_sound_pair
    (cp d e : Nat)
    (hQC : nfcQCValue cp = .Y)
    (hCcc : Lookup.canonicalCombiningClass cp = 0)
    (hDecomp : Lookup.canonicalDecomposition cp = [d, e]) :
    Compose.primaryComposite? d e = some cp := by
  have hSize : (Lookup.canonicalDecomposition cp).length = 2 := by
    rw [hDecomp]; rfl
  have hLift := qcY_starter_2decomp_cp_composes cp hQC hCcc hSize
  rw [hDecomp] at hLift
  have h0 : ([d, e] : List Nat)[0]! = d := by simp
  have h1 : ([d, e] : List Nat)[1]! = e := by simp
  rw [h0, h1] at hLift
  exact hLift

/-- A QC=Y starter with a two-element canonical decomposition whose
    components are atomic recomposes back to itself under the full NFC
    singleton pipeline. -/
theorem singleton_sound_pair_full
    (cp d e : Nat)
    (hQC : nfcQCValue cp = .Y)
    (hCcc : Lookup.canonicalCombiningClass cp = 0)
    (hDecomp : Lookup.canonicalDecomposition cp = [d, e])
    (hDStarter : Lookup.canonicalCombiningClass d = 0)
    (hENonStarter : 0 < Lookup.canonicalCombiningClass e)
    (hNotHangul : Hangul.isHangulSyllable cp = false)
    (hDDecompEmpty : Lookup.canonicalDecomposition d = [])
    (hEDecompEmpty : Lookup.canonicalDecomposition e = [])
    (hDNotHangul : Hangul.isHangulSyllable d = false)
    (hENotHangul : Hangul.isHangulSyllable e = false) :
    toNFC [cp] = [cp] := by
  have hPC := singleton_sound_pair cp d e hQC hCcc hDecomp
  have hDsylCp : Hangul.decomposeSyllable? cp = none := by
    unfold Hangul.decomposeSyllable?; rw [hNotHangul]; simp
  have hDsylD : Hangul.decomposeSyllable? d = none := by
    unfold Hangul.decomposeSyllable?; rw [hDNotHangul]; simp
  have hDsylE : Hangul.decomposeSyllable? e = none := by
    unfold Hangul.decomposeSyllable?; rw [hENotHangul]; simp
  have hFCD_d_31 : Decompose.fullCanonicalDecomposeFuel 31 d = [d] := by
    unfold Decompose.fullCanonicalDecomposeFuel
    rw [hDsylD]; simp [hDDecompEmpty]
  have hFCD_e_31 : Decompose.fullCanonicalDecomposeFuel 31 e = [e] := by
    unfold Decompose.fullCanonicalDecomposeFuel
    rw [hDsylE]; simp [hEDecompEmpty]
  have hFCD_cp : Decompose.fullCanonicalDecompose cp = [d, e] := by
    show Decompose.fullCanonicalDecomposeFuel Decompose.maxDepth cp = [d, e]
    unfold Decompose.maxDepth
    show Decompose.fullCanonicalDecomposeFuel 32 cp = [d, e]
    unfold Decompose.fullCanonicalDecomposeFuel
    rw [hDsylCp]
    simp only []
    rw [hDecomp]
    show (([d, e] : List Nat).foldl
            (fun acc cp' => acc ++ Decompose.fullCanonicalDecomposeFuel 31 cp') [])
        = [d, e]
    have hFold : ([d, e] : List Nat).foldl
            (fun acc cp' => acc ++ Decompose.fullCanonicalDecomposeFuel 31 cp') []
          = ([] ++ Decompose.fullCanonicalDecomposeFuel 31 d) ++
              Decompose.fullCanonicalDecomposeFuel 31 e := rfl
    rw [hFold, hFCD_d_31, hFCD_e_31]
    rfl
  have hDS : Decompose.decomposeSequence [cp] = [d, e] := by
    rw [Distribute.decomposeSequence_singleton, hFCD_cp]
  have hHSR : Reorder.HasSortedRuns [d, e] := by
    refine ⟨?starterImplication, ?singletonRun⟩
    · intro hENs
      clear hENs
      rw [hDStarter]
      exact Nat.zero_le (Lookup.canonicalCombiningClass e)
    · rw [Reorder.HasSortedRuns_singleton]
      exact True.intro
  have hR : Reorder.reorder [d, e] = [d, e] := by
    apply Reorder.reorder_id_on_HasSortedRuns
    exact hHSR
  show Compose.compose (toNFD [cp]) = [cp]
  unfold toNFD
  rw [hDS, hR]
  show (Compose.flushCompose
          (([d, e] : List Nat).foldl Compose.stepCompose Compose.initialState))
      = [cp]
  have hFold2 : ([d, e] : List Nat).foldl Compose.stepCompose Compose.initialState
              = Compose.stepCompose (Compose.stepCompose Compose.initialState d) e := by
    simp only [List.foldl_cons, List.foldl_nil]
  rw [hFold2]
  have hStep1 : Compose.stepCompose Compose.initialState d
              = { emitted := [], starter := some d, buffer := [], maxCCC := 0 } := by
    rw [Compose.stepCompose.eq_def]
    unfold Compose.initialState
    simp [hDStarter]
  rw [hStep1]
  have hENotZero : Lookup.canonicalCombiningClass e ≠ 0 := Nat.ne_of_gt hENonStarter
  have hENotLeMax : ¬ (Lookup.canonicalCombiningClass e ≤ 0) := by
    intro hLe; omega
  have hStep2 : Compose.stepCompose
                  { emitted := [], starter := some d, buffer := [], maxCCC := 0 } e
              = { emitted := [], starter := some cp, buffer := [], maxCCC := 0 } := by
    rw [Compose.stepCompose.eq_def]
    simp only [hENotZero, ↓reduceIte, hENotLeMax, hPC]
  rw [hStep2]
  unfold Compose.flushCompose
  rfl

end Unicode.Normalization.QuickCheckSoundnessSingletonPair
