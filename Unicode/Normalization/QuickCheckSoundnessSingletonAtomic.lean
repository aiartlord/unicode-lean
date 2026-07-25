/-
  Unicode.Normalization.QuickCheckSoundnessSingletonAtomic

  Atomic singleton NFC soundness for QC=Y starters with empty canonical
  decomposition.  This is split out of the older snoc-support file so
  the singleton dispatcher can depend on a small current-shape proof.
-/

import Unicode.Normalization.NFC
import Unicode.Normalization.Decompose
import Unicode.Normalization.Reorder
import Unicode.Normalization.Compose
import Unicode.Normalization.Hangul
import Unicode.Normalization.Distribute

namespace Unicode.Normalization.QuickCheckSoundnessSingletonAtomic

open Unicode.Normalization
open Unicode.Normalization.NFC (toNFC toNFD)

/-- A QC=Y starter whose canonical decomposition is empty and that is not a
    Hangul precomposed syllable is in NFC unchanged. -/
theorem singleton_sound_atomic
    (cp : Nat)
    (hCcc : Lookup.canonicalCombiningClass cp = 0)
    (hDecomp : Lookup.canonicalDecomposition cp = #[])
    (hNotHangul : Hangul.isHangulSyllable cp = false) :
    toNFC [cp] = [cp] := by
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
  have hR : Reorder.reorder [cp] = [cp] := by
    apply Reorder.reorder_id_on_HasSortedRuns
    rw [Reorder.HasSortedRuns_singleton]
    exact True.intro
  show Compose.compose (toNFD [cp]) = [cp]
  unfold toNFD
  rw [hDS, hR]
  show (Compose.flushCompose
          (([cp] : List Nat).foldl Compose.stepCompose Compose.initialState)).toList
      = [cp]
  simp only [List.foldl_cons, List.foldl_nil]
  rw [Compose.stepCompose.eq_def]
  unfold Compose.flushCompose Compose.initialState
  simp [hCcc]

end Unicode.Normalization.QuickCheckSoundnessSingletonAtomic
