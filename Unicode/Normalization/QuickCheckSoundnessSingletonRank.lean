/-
  Unicode.Normalization.QuickCheckSoundnessSingletonRank

  Structural support for replacing the old singleton `toNFC` row-table reducer
  with the generated canonical-decomposition rank certificate.
-/

import Unicode.Normalization.NFC
import Unicode.Normalization.QuickCheckSingletonRankData
import Unicode.Normalization.QuickCheckSoundnessSingletonPair

namespace Unicode.Normalization.QuickCheckSoundnessSingletonRank

open Unicode.Normalization
open Unicode.Normalization.NFC (toNFC toNFD nfcQCValue)

/-- The composition fold state for an already-normalized singleton starter. -/
def singletonState (cp : Nat) : Compose.ComposeState :=
  { emitted := #[], starter := some cp, buffer := [], maxCCC := 0 }

/-- Flushing an active singleton starter produces the singleton array. -/
theorem flush_singletonState (cp : Nat) :
    Compose.flushCompose (singletonState cp) = #[cp] := by
  unfold singletonState Compose.flushCompose
  rfl

/-- If the active starter and the next codepoint primary-compose with no
    buffered blockers, `stepCompose` updates only the active starter. This covers
    both ordinary starter/starter Hangul-style composition and starter/nonstarter
    canonical composition. -/
theorem stepCompose_empty_buffer_primary
    (st cp p : Nat)
    (hPC : Compose.primaryComposite? st cp = some p) :
    Compose.stepCompose (singletonState st) cp = singletonState p := by
  unfold singletonState Compose.stepCompose
  by_cases hCcc : Lookup.canonicalCombiningClass cp = 0
  · simp [hCcc, hPC]
  · have hNotLe : ¬ Lookup.canonicalCombiningClass cp ≤ 0 := by
      omega
    simp [hCcc, hNotLe, hPC]

/-- Append one composing codepoint to an input whose composition fold is already
    a singleton active starter. -/
theorem foldl_append_singleton_primary
    (xs : Array Nat) (left right cp : Nat)
    (hFold : xs.foldl Compose.stepCompose Compose.initialState =
      singletonState left)
    (hPC : Compose.primaryComposite? left right = some cp) :
    (xs ++ #[right]).foldl Compose.stepCompose Compose.initialState =
      singletonState cp := by
  rw [Array.foldl_append, hFold]
  rw [← Array.foldl_toList]
  simp [stepCompose_empty_buffer_primary left right cp hPC]

/-- A folded `toNFD` singleton state is enough to prove singleton NFC identity. -/
theorem toNFC_of_toNFD_foldl_singletonState
    (cp : Nat)
    (hFold : (toNFD #[cp]).foldl Compose.stepCompose Compose.initialState =
      singletonState cp) :
    toNFC #[cp] = #[cp] := by
  unfold toNFC Compose.compose
  rw [hFold]
  exact flush_singletonState cp

/-- Raw composition over a singleton starter produces the active singleton
    state. -/
theorem foldl_singleton_starter
    (cp : Nat)
    (hCcc : Lookup.canonicalCombiningClass cp = 0) :
    (#[cp] : Array Nat).foldl Compose.stepCompose Compose.initialState =
      singletonState cp := by
  rw [← Array.foldl_toList]
  simp only [List.foldl_cons, List.foldl_nil]
  rw [Compose.stepCompose.eq_def]
  unfold Compose.initialState singletonState
  simp [hCcc]

/-- A QC=Y starter row with two-element canonical decomposition primary-composes
    from its generated rank-entry components back to its codepoint. -/
theorem entry_primaryComposite
    (entry : QuickCheckSingletonRankData.SingletonRankRow)
    (hQC : nfcQCValue entry.codepoint = .Y)
    (hCcc : Lookup.canonicalCombiningClass entry.codepoint = 0)
    (hDecomp :
      Lookup.canonicalDecomposition entry.codepoint =
        #[entry.left, entry.right]) :
    Compose.primaryComposite? entry.left entry.right = some entry.codepoint :=
  QuickCheckSoundnessSingletonPair.singleton_sound_pair
    entry.codepoint entry.left entry.right hQC hCcc hDecomp

/-- Prop-level view of the shared generated facts for one singleton-rank
    entry. -/
structure EntryCommonFacts
    (entry : QuickCheckSingletonRankData.SingletonRankRow) : Prop where
  hQC : nfcQCValue entry.codepoint = .Y
  hNotHangul : Hangul.isHangulSyllable entry.codepoint = false
  hCcc : Lookup.canonicalCombiningClass entry.codepoint = 0
  hDecomp :
    Lookup.canonicalDecomposition entry.codepoint =
      #[entry.left, entry.right]
  hLeftCcc : Lookup.canonicalCombiningClass entry.left = 0
  hLeftQC : nfcQCValue entry.left = .Y
  hLeftNotHangul : Hangul.isHangulSyllable entry.left = false
  hRightDecompEmpty : Lookup.canonicalDecomposition entry.right = #[]
  hRightNotHangul : Hangul.isHangulSyllable entry.right = false
  hHangulPairNone : Hangul.composePair? entry.left entry.right = none

/-- The common generated rank-entry validity predicate exposes the row facts
    needed by the structural singleton proof. -/
theorem entryCommonValid_facts
    (entry : QuickCheckSingletonRankData.SingletonRankRow)
    (h : QuickCheckSingletonRankData.entryCommonValid entry = true) :
    EntryCommonFacts entry := by
  unfold QuickCheckSingletonRankData.entryCommonValid at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  rcases h with ⟨h, hHangulPairNone⟩
  rcases h with ⟨h, hRightNotHangul⟩
  rcases h with ⟨h, hRightDecompEmpty⟩
  rcases h with ⟨h, hLeftNotHangul⟩
  rcases h with ⟨h, hLeftQC⟩
  rcases h with ⟨h, hLeftCcc⟩
  rcases h with ⟨h, hDecomp⟩
  rcases h with ⟨h, hCcc⟩
  rcases h with ⟨h, hNotHangul⟩
  rcases h with ⟨_hRow, hQC⟩
  exact
    { hQC := hQC
      hNotHangul := hNotHangul
      hCcc := hCcc
      hDecomp := hDecomp
      hLeftCcc := hLeftCcc
      hLeftQC := hLeftQC
      hLeftNotHangul := hLeftNotHangul
      hRightDecompEmpty := hRightDecompEmpty
      hRightNotHangul := hRightNotHangul
      hHangulPairNone := hHangulPairNone }

/-- Rank validity includes common validity. -/
theorem entryRankValid_common
    (entry : QuickCheckSingletonRankData.SingletonRankRow)
    (h : QuickCheckSingletonRankData.entryRankValid entry = true) :
    QuickCheckSingletonRankData.entryCommonValid entry = true := by
  unfold QuickCheckSingletonRankData.entryRankValid at h
  rw [Bool.and_eq_true] at h
  exact h.1

/-- A generated valid rank entry primary-composes from its recorded components
    back to its codepoint. -/
theorem entryRankValid_primaryComposite
    (entry : QuickCheckSingletonRankData.SingletonRankRow)
    (h : QuickCheckSingletonRankData.entryRankValid entry = true) :
    Compose.primaryComposite? entry.left entry.right = some entry.codepoint := by
  have hCommon := entryRankValid_common entry h
  have facts := entryCommonValid_facts entry hCommon
  exact entry_primaryComposite entry facts.hQC facts.hCcc facts.hDecomp

/-- For rank-1 entries, rank validity certifies that the left component is
    atomic. -/
theorem entryRankValid_rank1_left_empty
    (entry : QuickCheckSingletonRankData.SingletonRankRow)
    (h : QuickCheckSingletonRankData.entryRankValid entry = true)
    (hRank : entry.rank = 1) :
    Lookup.canonicalDecomposition entry.left = #[] := by
  unfold QuickCheckSingletonRankData.entryRankValid at h
  rw [Bool.and_eq_true] at h
  have hRankBranch := h.2
  rw [hRank] at hRankBranch
  exact of_decide_eq_true hRankBranch

end Unicode.Normalization.QuickCheckSoundnessSingletonRank
