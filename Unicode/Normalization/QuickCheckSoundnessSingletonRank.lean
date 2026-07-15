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

end Unicode.Normalization.QuickCheckSoundnessSingletonRank
