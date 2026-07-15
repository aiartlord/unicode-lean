/-
  Unicode.Normalization.QuickCheckSoundnessSingletonRank

  Structural support for replacing the old singleton `toNFC` row-table reducer
  with the generated canonical-decomposition rank certificate.
-/

import Unicode.Normalization.NFC
import Unicode.Normalization.Distribute
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

/-- Atomic non-Hangul starters are unchanged by `toNFD`. -/
theorem atomic_starter_toNFD_singleton
    (cp : Nat)
    (hDecomp : Lookup.canonicalDecomposition cp = #[])
    (hNotHangul : Hangul.isHangulSyllable cp = false) :
    toNFD #[cp] = #[cp] := by
  have hDsyl : Hangul.decomposeSyllable? cp = none := by
    unfold Hangul.decomposeSyllable?
    rw [hNotHangul]
    simp
  have hFCD : Decompose.fullCanonicalDecompose cp = #[cp] := by
    show Decompose.fullCanonicalDecomposeFuel Decompose.maxDepth cp = #[cp]
    unfold Decompose.maxDepth Decompose.fullCanonicalDecomposeFuel
    rw [hDsyl]
    simp [hDecomp]
  have hDS : Decompose.decomposeSequence #[cp] = #[cp] := by
    rw [Distribute.decomposeSequence_singleton]
    exact hFCD
  have hR : Reorder.reorder #[cp] = #[cp] := by
    apply Reorder.reorder_id_on_HasSortedRuns
    show Reorder.HasSortedRuns [cp]
    trivial
  unfold toNFD
  rw [hDS, hR]

/-- Atomic non-Hangul starters fold through `toNFD` and `stepCompose` to an
    active singleton starter state. -/
theorem atomic_starter_toNFD_foldl_singletonState
    (cp : Nat)
    (hCcc : Lookup.canonicalCombiningClass cp = 0)
    (hDecomp : Lookup.canonicalDecomposition cp = #[])
    (hNotHangul : Hangul.isHangulSyllable cp = false) :
    (toNFD #[cp]).foldl Compose.stepCompose Compose.initialState =
      singletonState cp := by
  rw [atomic_starter_toNFD_singleton cp hDecomp hNotHangul]
  exact foldl_singleton_starter cp hCcc

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

/-- Rank-1 entries have a structurally proven singleton state for their left
    component. -/
theorem entryRank1_left_toNFD_foldl_singletonState
    (entry : QuickCheckSingletonRankData.SingletonRankRow)
    (h : QuickCheckSingletonRankData.entryRankValid entry = true)
    (hRank : entry.rank = 1) :
    (toNFD #[entry.left]).foldl Compose.stepCompose Compose.initialState =
      singletonState entry.left := by
  have hCommon := entryRankValid_common entry h
  have facts := entryCommonValid_facts entry hCommon
  have hLeftEmpty := entryRankValid_rank1_left_empty entry h hRank
  exact atomic_starter_toNFD_foldl_singletonState
    entry.left facts.hLeftCcc hLeftEmpty facts.hLeftNotHangul

/-- Rank-1 entries fold through `toNFD` and `stepCompose` to their own active
    singleton state. -/
theorem entryRank1_toNFD_foldl_singletonState
    (entry : QuickCheckSingletonRankData.SingletonRankRow)
    (h : QuickCheckSingletonRankData.entryRankValid entry = true)
    (hRank : entry.rank = 1) :
    (toNFD #[entry.codepoint]).foldl Compose.stepCompose Compose.initialState =
      singletonState entry.codepoint := by
  have hCommon := entryRankValid_common entry h
  have facts := entryCommonValid_facts entry hCommon
  have hLeftEmpty := entryRankValid_rank1_left_empty entry h hRank
  have hDsylCp : Hangul.decomposeSyllable? entry.codepoint = none := by
    unfold Hangul.decomposeSyllable?
    rw [facts.hNotHangul]
    simp
  have hDsylLeft : Hangul.decomposeSyllable? entry.left = none := by
    unfold Hangul.decomposeSyllable?
    rw [facts.hLeftNotHangul]
    simp
  have hDsylRight : Hangul.decomposeSyllable? entry.right = none := by
    unfold Hangul.decomposeSyllable?
    rw [facts.hRightNotHangul]
    simp
  have hFCDLeft31 :
      Decompose.fullCanonicalDecomposeFuel 31 entry.left = #[entry.left] := by
    unfold Decompose.fullCanonicalDecomposeFuel
    rw [hDsylLeft]
    simp [hLeftEmpty]
  have hFCDRight31 :
      Decompose.fullCanonicalDecomposeFuel 31 entry.right = #[entry.right] := by
    unfold Decompose.fullCanonicalDecomposeFuel
    rw [hDsylRight]
    simp [facts.hRightDecompEmpty]
  have hFCD :
      Decompose.fullCanonicalDecompose entry.codepoint =
        #[entry.left, entry.right] := by
    show Decompose.fullCanonicalDecomposeFuel Decompose.maxDepth entry.codepoint =
      #[entry.left, entry.right]
    unfold Decompose.maxDepth
    show Decompose.fullCanonicalDecomposeFuel 32 entry.codepoint =
      #[entry.left, entry.right]
    unfold Decompose.fullCanonicalDecomposeFuel
    rw [hDsylCp]
    simp only []
    rw [facts.hDecomp]
    show ((#[entry.left, entry.right] : Array Nat).foldl
        (fun acc cp' => acc ++ Decompose.fullCanonicalDecomposeFuel 31 cp') #[])
      = #[entry.left, entry.right]
    have hFold :
        (#[entry.left, entry.right] : Array Nat).foldl
          (fun acc cp' => acc ++ Decompose.fullCanonicalDecomposeFuel 31 cp') #[]
        = (#[] ++ Decompose.fullCanonicalDecomposeFuel 31 entry.left) ++
            Decompose.fullCanonicalDecomposeFuel 31 entry.right := rfl
    rw [hFold, hFCDLeft31, hFCDRight31]
    rfl
  have hDS :
      Decompose.decomposeSequence #[entry.codepoint] =
        #[entry.left, entry.right] := by
    rw [Distribute.decomposeSequence_singleton]
    exact hFCD
  have hR : Reorder.reorder #[entry.left, entry.right] =
      #[entry.left, entry.right] := by
    apply Reorder.reorder_id_on_HasSortedRuns
    show Reorder.HasSortedRuns [entry.left, entry.right]
    refine ⟨?starterImplication, ?singletonRun⟩
    · intro _hRightNonstarter
      rw [facts.hLeftCcc]
      exact Nat.zero_le (Lookup.canonicalCombiningClass entry.right)
    · trivial
  have hToNFD :
      toNFD #[entry.codepoint] = #[entry.left, entry.right] := by
    unfold toNFD
    rw [hDS, hR]
  rw [hToNFD]
  rw [← Array.foldl_toList]
  simp only [List.foldl_cons, List.foldl_nil]
  have hStepLeft :
      Compose.stepCompose Compose.initialState entry.left =
        singletonState entry.left := by
    change (#[entry.left] : Array Nat).foldl
        Compose.stepCompose Compose.initialState = singletonState entry.left
    exact foldl_singleton_starter entry.left facts.hLeftCcc
  rw [hStepLeft]
  exact stepCompose_empty_buffer_primary
    entry.left entry.right entry.codepoint
    (entryRankValid_primaryComposite entry h)

/-- Rank-1 entries are singleton-NFC identities. -/
theorem entryRank1_toNFC_singleton
    (entry : QuickCheckSingletonRankData.SingletonRankRow)
    (h : QuickCheckSingletonRankData.entryRankValid entry = true)
    (hRank : entry.rank = 1) :
    toNFC #[entry.codepoint] = #[entry.codepoint] :=
  toNFC_of_toNFD_foldl_singletonState entry.codepoint
    (entryRank1_toNFD_foldl_singletonState entry h hRank)

/-- For rank-2 entries, rank validity points the left component at a valid
    rank-1 parent entry. -/
theorem entryRankValid_rank2_left_parent
    (entry : QuickCheckSingletonRankData.SingletonRankRow)
    (h : QuickCheckSingletonRankData.entryRankValid entry = true)
    (hRank : entry.rank = 2) :
    ∃ parent ∈ QuickCheckSingletonRankData.rowsRank1,
      parent.codepoint = entry.left ∧
      QuickCheckSingletonRankData.entryRankValid parent = true := by
  unfold QuickCheckSingletonRankData.entryRankValid at h
  rw [Bool.and_eq_true] at h
  have hRankBranch := h.2
  rw [hRank] at hRankBranch
  have h21 : ¬ (2 : Nat) = 1 := by decide
  simp [h21] at hRankBranch
  obtain ⟨parent, hMem, hCodepoint⟩ := hRankBranch
  have hParentValid :=
    List.all_eq_true.mp QuickCheckSingletonRankData.rowsRank1_valid parent hMem
  exact ⟨parent, hMem, hCodepoint, hParentValid⟩

/-- For rank-3 entries, rank validity points the left component at a valid
    rank-2 parent entry. -/
theorem entryRankValid_rank3_left_parent
    (entry : QuickCheckSingletonRankData.SingletonRankRow)
    (h : QuickCheckSingletonRankData.entryRankValid entry = true)
    (hRank : entry.rank = 3) :
    ∃ parent ∈ QuickCheckSingletonRankData.rowsRank2,
      parent.codepoint = entry.left ∧
      QuickCheckSingletonRankData.entryRankValid parent = true := by
  unfold QuickCheckSingletonRankData.entryRankValid at h
  rw [Bool.and_eq_true] at h
  have hRankBranch := h.2
  rw [hRank] at hRankBranch
  have h31 : ¬ (3 : Nat) = 1 := by decide
  have h32 : ¬ (3 : Nat) = 2 := by decide
  simp [h31, h32] at hRankBranch
  obtain ⟨parent, hMem, hCodepoint⟩ := hRankBranch
  have hParentValid :=
    List.all_eq_true.mp QuickCheckSingletonRankData.rowsRank2_valid parent hMem
  exact ⟨parent, hMem, hCodepoint, hParentValid⟩

theorem rowsRank1_member_rank
    (entry : QuickCheckSingletonRankData.SingletonRankRow)
    (hMem : entry ∈ QuickCheckSingletonRankData.rowsRank1) :
    entry.rank = 1 :=
  of_decide_eq_true
    (List.all_eq_true.mp QuickCheckSingletonRankData.rowsRank1_rank entry hMem)

theorem rowsRank2_member_rank
    (entry : QuickCheckSingletonRankData.SingletonRankRow)
    (hMem : entry ∈ QuickCheckSingletonRankData.rowsRank2) :
    entry.rank = 2 :=
  of_decide_eq_true
    (List.all_eq_true.mp QuickCheckSingletonRankData.rowsRank2_rank entry hMem)

theorem rowsRank3_member_rank
    (entry : QuickCheckSingletonRankData.SingletonRankRow)
    (hMem : entry ∈ QuickCheckSingletonRankData.rowsRank3) :
    entry.rank = 3 :=
  of_decide_eq_true
    (List.all_eq_true.mp QuickCheckSingletonRankData.rowsRank3_rank entry hMem)

/-- Rank-2 rows carry the parent/right CCC ordering needed for the
    three-codepoint full decomposition to already be sorted. -/
theorem rowsRank2_parent_right_order
    (entry : QuickCheckSingletonRankData.SingletonRankRow)
    (hMem : entry ∈ QuickCheckSingletonRankData.rowsRank2) :
    ∃ parent ∈ QuickCheckSingletonRankData.rowsRank1,
      parent.codepoint = entry.left ∧
      parent.rank = 1 ∧
      QuickCheckSingletonRankData.entryRankValid parent = true ∧
      (Lookup.canonicalCombiningClass entry.right = 0 ∨
        Lookup.canonicalCombiningClass parent.right ≤
          Lookup.canonicalCombiningClass entry.right) := by
  have hOrder :=
    List.all_eq_true.mp
      QuickCheckSingletonRankData.rowsRank2_parentRightOrder_valid entry hMem
  unfold QuickCheckSingletonRankData.parentRightOrderValid at hOrder
  rw [List.any_eq_true] at hOrder
  obtain ⟨parent, hParentMem, hParentFacts⟩ := hOrder
  obtain ⟨hCodepoint, hOrderRel⟩ := of_decide_eq_true hParentFacts
  have hParentValid :=
    List.all_eq_true.mp QuickCheckSingletonRankData.rowsRank1_valid parent hParentMem
  have hParentRank := rowsRank1_member_rank parent hParentMem
  exact ⟨parent, hParentMem, hCodepoint, hParentRank, hParentValid, hOrderRel⟩

/-- Rank-3 rows carry the parent/right CCC ordering needed to append the final
    right component after the rank-2 parent's full decomposition. -/
theorem rowsRank3_parent_right_order
    (entry : QuickCheckSingletonRankData.SingletonRankRow)
    (hMem : entry ∈ QuickCheckSingletonRankData.rowsRank3) :
    ∃ parent ∈ QuickCheckSingletonRankData.rowsRank2,
      parent.codepoint = entry.left ∧
      parent.rank = 2 ∧
      QuickCheckSingletonRankData.entryRankValid parent = true ∧
      (Lookup.canonicalCombiningClass entry.right = 0 ∨
        Lookup.canonicalCombiningClass parent.right ≤
          Lookup.canonicalCombiningClass entry.right) := by
  have hOrder :=
    List.all_eq_true.mp
      QuickCheckSingletonRankData.rowsRank3_parentRightOrder_valid entry hMem
  unfold QuickCheckSingletonRankData.parentRightOrderValid at hOrder
  rw [List.any_eq_true] at hOrder
  obtain ⟨parent, hParentMem, hParentFacts⟩ := hOrder
  obtain ⟨hCodepoint, hOrderRel⟩ := of_decide_eq_true hParentFacts
  have hParentValid :=
    List.all_eq_true.mp QuickCheckSingletonRankData.rowsRank2_valid parent hParentMem
  have hParentRank := rowsRank2_member_rank parent hParentMem
  exact ⟨parent, hParentMem, hCodepoint, hParentRank, hParentValid, hOrderRel⟩

/-- Rank-2 entries fold through `toNFD` and `stepCompose` to their own active
    singleton state. -/
theorem entryRank2_toNFD_foldl_singletonState
    (entry : QuickCheckSingletonRankData.SingletonRankRow)
    (hMem : entry ∈ QuickCheckSingletonRankData.rowsRank2) :
    (toNFD #[entry.codepoint]).foldl Compose.stepCompose Compose.initialState =
      singletonState entry.codepoint := by
  have hValid :=
    List.all_eq_true.mp QuickCheckSingletonRankData.rowsRank2_valid entry hMem
  have facts := entryCommonValid_facts entry (entryRankValid_common entry hValid)
  obtain ⟨parent, _hParentMem, hParentCp, hParentRank, hParentValid, hOrderRel⟩ :=
    rowsRank2_parent_right_order entry hMem
  have parentFacts := entryCommonValid_facts parent
    (entryRankValid_common parent hParentValid)
  have hParentLeftEmpty :=
    entryRankValid_rank1_left_empty parent hParentValid hParentRank
  have hDsylCp : Hangul.decomposeSyllable? entry.codepoint = none := by
    unfold Hangul.decomposeSyllable?
    rw [facts.hNotHangul]
    simp
  have hDsylParentCp : Hangul.decomposeSyllable? parent.codepoint = none := by
    unfold Hangul.decomposeSyllable?
    rw [parentFacts.hNotHangul]
    simp
  have hDsylParentLeft : Hangul.decomposeSyllable? parent.left = none := by
    unfold Hangul.decomposeSyllable?
    rw [parentFacts.hLeftNotHangul]
    simp
  have hDsylParentRight : Hangul.decomposeSyllable? parent.right = none := by
    unfold Hangul.decomposeSyllable?
    rw [parentFacts.hRightNotHangul]
    simp
  have hDsylRight : Hangul.decomposeSyllable? entry.right = none := by
    unfold Hangul.decomposeSyllable?
    rw [facts.hRightNotHangul]
    simp
  have hFCDParentLeft30 :
      Decompose.fullCanonicalDecomposeFuel 30 parent.left = #[parent.left] := by
    unfold Decompose.fullCanonicalDecomposeFuel
    rw [hDsylParentLeft]
    simp [hParentLeftEmpty]
  have hFCDParentRight30 :
      Decompose.fullCanonicalDecomposeFuel 30 parent.right = #[parent.right] := by
    unfold Decompose.fullCanonicalDecomposeFuel
    rw [hDsylParentRight]
    simp [parentFacts.hRightDecompEmpty]
  have hFCDParent31AtParent :
      Decompose.fullCanonicalDecomposeFuel 31 parent.codepoint =
        #[parent.left, parent.right] := by
    unfold Decompose.fullCanonicalDecomposeFuel
    rw [hDsylParentCp]
    simp only []
    rw [parentFacts.hDecomp]
    show ((#[parent.left, parent.right] : Array Nat).foldl
        (fun acc cp' => acc ++ Decompose.fullCanonicalDecomposeFuel 30 cp') #[])
      = #[parent.left, parent.right]
    have hFold :
        (#[parent.left, parent.right] : Array Nat).foldl
          (fun acc cp' => acc ++ Decompose.fullCanonicalDecomposeFuel 30 cp') #[]
        = (#[] ++ Decompose.fullCanonicalDecomposeFuel 30 parent.left) ++
            Decompose.fullCanonicalDecomposeFuel 30 parent.right := rfl
    rw [hFold, hFCDParentLeft30, hFCDParentRight30]
    rfl
  have hFCDLeft31 :
      Decompose.fullCanonicalDecomposeFuel 31 entry.left =
        #[parent.left, parent.right] := by
    rw [← hParentCp]
    exact hFCDParent31AtParent
  have hFCDRight31 :
      Decompose.fullCanonicalDecomposeFuel 31 entry.right = #[entry.right] := by
    unfold Decompose.fullCanonicalDecomposeFuel
    rw [hDsylRight]
    simp [facts.hRightDecompEmpty]
  have hFCD :
      Decompose.fullCanonicalDecompose entry.codepoint =
        #[parent.left, parent.right, entry.right] := by
    show Decompose.fullCanonicalDecomposeFuel Decompose.maxDepth entry.codepoint =
      #[parent.left, parent.right, entry.right]
    unfold Decompose.maxDepth
    show Decompose.fullCanonicalDecomposeFuel 32 entry.codepoint =
      #[parent.left, parent.right, entry.right]
    unfold Decompose.fullCanonicalDecomposeFuel
    rw [hDsylCp]
    simp only []
    rw [facts.hDecomp]
    show ((#[entry.left, entry.right] : Array Nat).foldl
        (fun acc cp' => acc ++ Decompose.fullCanonicalDecomposeFuel 31 cp') #[])
      = #[parent.left, parent.right, entry.right]
    have hFold :
        (#[entry.left, entry.right] : Array Nat).foldl
          (fun acc cp' => acc ++ Decompose.fullCanonicalDecomposeFuel 31 cp') #[]
        = (#[] ++ Decompose.fullCanonicalDecomposeFuel 31 entry.left) ++
            Decompose.fullCanonicalDecomposeFuel 31 entry.right := rfl
    rw [hFold, hFCDLeft31, hFCDRight31]
    rfl
  have hDS :
      Decompose.decomposeSequence #[entry.codepoint] =
        #[parent.left, parent.right, entry.right] := by
    rw [Distribute.decomposeSequence_singleton]
    exact hFCD
  have hR :
      Reorder.reorder #[parent.left, parent.right, entry.right] =
        #[parent.left, parent.right, entry.right] := by
    apply Reorder.reorder_id_on_HasSortedRuns
    show Reorder.HasSortedRuns [parent.left, parent.right, entry.right]
    refine ⟨?leftToParentRight, ?tailSorted⟩
    · intro _hParentRightNonstarter
      rw [parentFacts.hLeftCcc]
      exact Nat.zero_le (Lookup.canonicalCombiningClass parent.right)
    · refine ⟨?parentRightToEntryRight, ?single⟩
      · intro hEntryRightNonstarter
        cases hOrderRel with
        | inl hEntryRightStarter =>
            omega
        | inr hLe =>
            exact hLe
      · trivial
  have hToNFD :
      toNFD #[entry.codepoint] =
        #[parent.left, parent.right, entry.right] := by
    unfold toNFD
    rw [hDS, hR]
  rw [hToNFD]
  rw [← Array.foldl_toList]
  simp only [List.foldl_cons, List.foldl_nil]
  have hStepParentLeft :
      Compose.stepCompose Compose.initialState parent.left =
        singletonState parent.left := by
    change (#[parent.left] : Array Nat).foldl
        Compose.stepCompose Compose.initialState = singletonState parent.left
    exact foldl_singleton_starter parent.left parentFacts.hLeftCcc
  rw [hStepParentLeft]
  rw [stepCompose_empty_buffer_primary
    parent.left parent.right parent.codepoint
    (entryRankValid_primaryComposite parent hParentValid)]
  rw [hParentCp]
  exact stepCompose_empty_buffer_primary
    entry.left entry.right entry.codepoint
    (entryRankValid_primaryComposite entry hValid)

/-- Rank-2 entries are singleton-NFC identities. -/
theorem entryRank2_toNFC_singleton
    (entry : QuickCheckSingletonRankData.SingletonRankRow)
    (hMem : entry ∈ QuickCheckSingletonRankData.rowsRank2) :
    toNFC #[entry.codepoint] = #[entry.codepoint] :=
  toNFC_of_toNFD_foldl_singletonState entry.codepoint
    (entryRank2_toNFD_foldl_singletonState entry hMem)

/-- Rank-3 entries fold through `toNFD` and `stepCompose` to their own active
    singleton state. -/
theorem entryRank3_toNFD_foldl_singletonState
    (entry : QuickCheckSingletonRankData.SingletonRankRow)
    (hMem : entry ∈ QuickCheckSingletonRankData.rowsRank3) :
    (toNFD #[entry.codepoint]).foldl Compose.stepCompose Compose.initialState =
      singletonState entry.codepoint := by
  have hValid :=
    List.all_eq_true.mp QuickCheckSingletonRankData.rowsRank3_valid entry hMem
  have facts := entryCommonValid_facts entry (entryRankValid_common entry hValid)
  obtain ⟨parent, hParentMem, hParentCp, _hParentRank, hParentValid, hParentOrderRel⟩ :=
    rowsRank3_parent_right_order entry hMem
  have parentFacts := entryCommonValid_facts parent
    (entryRankValid_common parent hParentValid)
  obtain ⟨grand, _hGrandMem, hGrandCp, hGrandRank, hGrandValid, hGrandOrderRel⟩ :=
    rowsRank2_parent_right_order parent hParentMem
  have grandFacts := entryCommonValid_facts grand
    (entryRankValid_common grand hGrandValid)
  have hGrandLeftEmpty :=
    entryRankValid_rank1_left_empty grand hGrandValid hGrandRank
  have hDsylCp : Hangul.decomposeSyllable? entry.codepoint = none := by
    unfold Hangul.decomposeSyllable?
    rw [facts.hNotHangul]
    simp
  have hDsylParentCp : Hangul.decomposeSyllable? parent.codepoint = none := by
    unfold Hangul.decomposeSyllable?
    rw [parentFacts.hNotHangul]
    simp
  have hDsylGrandCp : Hangul.decomposeSyllable? grand.codepoint = none := by
    unfold Hangul.decomposeSyllable?
    rw [grandFacts.hNotHangul]
    simp
  have hDsylGrandLeft : Hangul.decomposeSyllable? grand.left = none := by
    unfold Hangul.decomposeSyllable?
    rw [grandFacts.hLeftNotHangul]
    simp
  have hDsylGrandRight : Hangul.decomposeSyllable? grand.right = none := by
    unfold Hangul.decomposeSyllable?
    rw [grandFacts.hRightNotHangul]
    simp
  have hDsylParentRight : Hangul.decomposeSyllable? parent.right = none := by
    unfold Hangul.decomposeSyllable?
    rw [parentFacts.hRightNotHangul]
    simp
  have hDsylRight : Hangul.decomposeSyllable? entry.right = none := by
    unfold Hangul.decomposeSyllable?
    rw [facts.hRightNotHangul]
    simp
  have hFCDGrandLeft29 :
      Decompose.fullCanonicalDecomposeFuel 29 grand.left = #[grand.left] := by
    unfold Decompose.fullCanonicalDecomposeFuel
    rw [hDsylGrandLeft]
    simp [hGrandLeftEmpty]
  have hFCDGrandRight29 :
      Decompose.fullCanonicalDecomposeFuel 29 grand.right = #[grand.right] := by
    unfold Decompose.fullCanonicalDecomposeFuel
    rw [hDsylGrandRight]
    simp [grandFacts.hRightDecompEmpty]
  have hFCDGrand30AtGrand :
      Decompose.fullCanonicalDecomposeFuel 30 grand.codepoint =
        #[grand.left, grand.right] := by
    unfold Decompose.fullCanonicalDecomposeFuel
    rw [hDsylGrandCp]
    simp only []
    rw [grandFacts.hDecomp]
    show ((#[grand.left, grand.right] : Array Nat).foldl
        (fun acc cp' => acc ++ Decompose.fullCanonicalDecomposeFuel 29 cp') #[])
      = #[grand.left, grand.right]
    have hFold :
        (#[grand.left, grand.right] : Array Nat).foldl
          (fun acc cp' => acc ++ Decompose.fullCanonicalDecomposeFuel 29 cp') #[]
        = (#[] ++ Decompose.fullCanonicalDecomposeFuel 29 grand.left) ++
            Decompose.fullCanonicalDecomposeFuel 29 grand.right := rfl
    rw [hFold, hFCDGrandLeft29, hFCDGrandRight29]
    rfl
  have hFCDParentLeft30 :
      Decompose.fullCanonicalDecomposeFuel 30 parent.left =
        #[grand.left, grand.right] := by
    rw [← hGrandCp]
    exact hFCDGrand30AtGrand
  have hFCDParentRight30 :
      Decompose.fullCanonicalDecomposeFuel 30 parent.right = #[parent.right] := by
    unfold Decompose.fullCanonicalDecomposeFuel
    rw [hDsylParentRight]
    simp [parentFacts.hRightDecompEmpty]
  have hFCDParent31AtParent :
      Decompose.fullCanonicalDecomposeFuel 31 parent.codepoint =
        #[grand.left, grand.right, parent.right] := by
    unfold Decompose.fullCanonicalDecomposeFuel
    rw [hDsylParentCp]
    simp only []
    rw [parentFacts.hDecomp]
    show ((#[parent.left, parent.right] : Array Nat).foldl
        (fun acc cp' => acc ++ Decompose.fullCanonicalDecomposeFuel 30 cp') #[])
      = #[grand.left, grand.right, parent.right]
    have hFold :
        (#[parent.left, parent.right] : Array Nat).foldl
          (fun acc cp' => acc ++ Decompose.fullCanonicalDecomposeFuel 30 cp') #[]
        = (#[] ++ Decompose.fullCanonicalDecomposeFuel 30 parent.left) ++
            Decompose.fullCanonicalDecomposeFuel 30 parent.right := rfl
    rw [hFold, hFCDParentLeft30, hFCDParentRight30]
    rfl
  have hFCDLeft31 :
      Decompose.fullCanonicalDecomposeFuel 31 entry.left =
        #[grand.left, grand.right, parent.right] := by
    rw [← hParentCp]
    exact hFCDParent31AtParent
  have hFCDRight31 :
      Decompose.fullCanonicalDecomposeFuel 31 entry.right = #[entry.right] := by
    unfold Decompose.fullCanonicalDecomposeFuel
    rw [hDsylRight]
    simp [facts.hRightDecompEmpty]
  have hFCD :
      Decompose.fullCanonicalDecompose entry.codepoint =
        #[grand.left, grand.right, parent.right, entry.right] := by
    show Decompose.fullCanonicalDecomposeFuel Decompose.maxDepth entry.codepoint =
      #[grand.left, grand.right, parent.right, entry.right]
    unfold Decompose.maxDepth
    show Decompose.fullCanonicalDecomposeFuel 32 entry.codepoint =
      #[grand.left, grand.right, parent.right, entry.right]
    unfold Decompose.fullCanonicalDecomposeFuel
    rw [hDsylCp]
    simp only []
    rw [facts.hDecomp]
    show ((#[entry.left, entry.right] : Array Nat).foldl
        (fun acc cp' => acc ++ Decompose.fullCanonicalDecomposeFuel 31 cp') #[])
      = #[grand.left, grand.right, parent.right, entry.right]
    have hFold :
        (#[entry.left, entry.right] : Array Nat).foldl
          (fun acc cp' => acc ++ Decompose.fullCanonicalDecomposeFuel 31 cp') #[]
        = (#[] ++ Decompose.fullCanonicalDecomposeFuel 31 entry.left) ++
            Decompose.fullCanonicalDecomposeFuel 31 entry.right := rfl
    rw [hFold, hFCDLeft31, hFCDRight31]
    rfl
  have hDS :
      Decompose.decomposeSequence #[entry.codepoint] =
        #[grand.left, grand.right, parent.right, entry.right] := by
    rw [Distribute.decomposeSequence_singleton]
    exact hFCD
  have hR :
      Reorder.reorder #[grand.left, grand.right, parent.right, entry.right] =
        #[grand.left, grand.right, parent.right, entry.right] := by
    apply Reorder.reorder_id_on_HasSortedRuns
    show Reorder.HasSortedRuns [grand.left, grand.right, parent.right, entry.right]
    refine ⟨?leftToGrandRight, ?tailSorted⟩
    · intro _hGrandRightNonstarter
      rw [grandFacts.hLeftCcc]
      exact Nat.zero_le (Lookup.canonicalCombiningClass grand.right)
    · refine ⟨?grandRightToParentRight, ?tailTailSorted⟩
      · intro hParentRightNonstarter
        cases hGrandOrderRel with
        | inl hParentRightStarter =>
            omega
        | inr hLe =>
            exact hLe
      · refine ⟨?parentRightToEntryRight, ?single⟩
        · intro hEntryRightNonstarter
          cases hParentOrderRel with
          | inl hEntryRightStarter =>
              omega
          | inr hLe =>
              exact hLe
        · trivial
  have hToNFD :
      toNFD #[entry.codepoint] =
        #[grand.left, grand.right, parent.right, entry.right] := by
    unfold toNFD
    rw [hDS, hR]
  rw [hToNFD]
  rw [← Array.foldl_toList]
  simp only [List.foldl_cons, List.foldl_nil]
  have hStepGrandLeft :
      Compose.stepCompose Compose.initialState grand.left =
        singletonState grand.left := by
    change (#[grand.left] : Array Nat).foldl
        Compose.stepCompose Compose.initialState = singletonState grand.left
    exact foldl_singleton_starter grand.left grandFacts.hLeftCcc
  rw [hStepGrandLeft]
  rw [stepCompose_empty_buffer_primary
    grand.left grand.right grand.codepoint
    (entryRankValid_primaryComposite grand hGrandValid)]
  rw [hGrandCp]
  rw [stepCompose_empty_buffer_primary
    parent.left parent.right parent.codepoint
    (entryRankValid_primaryComposite parent hParentValid)]
  rw [hParentCp]
  exact stepCompose_empty_buffer_primary
    entry.left entry.right entry.codepoint
    (entryRankValid_primaryComposite entry hValid)

/-- Rank-3 entries are singleton-NFC identities. -/
theorem entryRank3_toNFC_singleton
    (entry : QuickCheckSingletonRankData.SingletonRankRow)
    (hMem : entry ∈ QuickCheckSingletonRankData.rowsRank3) :
    toNFC #[entry.codepoint] = #[entry.codepoint] :=
  toNFC_of_toNFD_foldl_singletonState entry.codepoint
    (entryRank3_toNFD_foldl_singletonState entry hMem)

theorem rowsRank1_singletonNFC :
    QuickCheckSingletonRankData.rowsRank1.all
      (fun entry => decide (toNFC #[entry.codepoint] = #[entry.codepoint])) = true := by
  rw [List.all_eq_true]
  intro entry hMem
  have hValid :=
    List.all_eq_true.mp QuickCheckSingletonRankData.rowsRank1_valid entry hMem
  exact decide_eq_true
    (entryRank1_toNFC_singleton entry hValid (rowsRank1_member_rank entry hMem))

theorem rowsRank2_singletonNFC :
    QuickCheckSingletonRankData.rowsRank2.all
      (fun entry => decide (toNFC #[entry.codepoint] = #[entry.codepoint])) = true := by
  rw [List.all_eq_true]
  intro entry hMem
  exact decide_eq_true (entryRank2_toNFC_singleton entry hMem)

theorem rowsRank3_singletonNFC :
    QuickCheckSingletonRankData.rowsRank3.all
      (fun entry => decide (toNFC #[entry.codepoint] = #[entry.codepoint])) = true := by
  rw [List.all_eq_true]
  intro entry hMem
  exact decide_eq_true (entryRank3_toNFC_singleton entry hMem)

/-- Every generated singleton-rank entry is in NFC as a singleton. -/
theorem rows_singletonNFC :
    QuickCheckSingletonRankData.rows.all
      (fun entry => decide (toNFC #[entry.codepoint] = #[entry.codepoint])) = true := by
  unfold QuickCheckSingletonRankData.rows
  simp [rowsRank1_singletonNFC, rowsRank2_singletonNFC, rowsRank3_singletonNFC]

/-- Any row codepoint covered by the generated singleton-rank table inherits the
    singleton NFC identity. -/
theorem singletonNFC_of_rank_rows_any
    (cp : Nat)
    (hAny : QuickCheckSingletonRankData.rows.any
      (fun entry => decide (entry.codepoint = cp)) = true) :
    toNFC #[cp] = #[cp] := by
  rw [List.any_eq_true] at hAny
  obtain ⟨entry, hMem, hCodepoint⟩ := hAny
  have hEntry :=
    List.all_eq_true.mp rows_singletonNFC entry hMem
  have hSingleton := of_decide_eq_true hEntry
  have hCp := of_decide_eq_true hCodepoint
  rw [hCp] at hSingleton
  exact hSingleton

end Unicode.Normalization.QuickCheckSoundnessSingletonRank
