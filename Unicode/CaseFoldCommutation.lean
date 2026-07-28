/-
  Unicode.CaseFoldCommutation

  The UCD design invariant that powers `CaseFoldNfcRoundtripFixed`:
  Unicode case folding commutes with canonical decomposition modulo
  canonical-ordering of non-starter runs. Explicitly:

      toNFD (caseFold x) = toNFD (caseFold (toNFD x))

  for every codepoint sequence x, where `toNFD = reorder ∘
  decomposeSequence`. The pointwise version is a `decide` check
  over the 1585 case-fold entries in CaseFolding.txt; the sequence-level
  lift chains through the fold-foldl pattern.

  The consequence (`caseFoldNfcRoundtripFixed`) closes the PRECIS
  round-trip hypothesis and, via `precis_idempotent_given_roundtrip`,
  gives unconditional PRECIS Preparation idempotence (RFC 8264/8265 §7).

  Architectural note: the commutation does NOT hold at the stage level
  in isolation — `caseFold(toNFC x)` can differ from `caseFold(x)` for
  the U+01F0 family. The claim holds at the round-trip / NFC-equivalence
  level, which is the structural fixed point that PRECIS relies on.
-/

import Unicode.Normalization.NFC
import Unicode.Normalization.NFD
import Unicode.Normalization.Decomposability
import Unicode.Normalization.Distribute
import Unicode.Normalization.ReorderAppend
import Unicode.Normalization.ToNFDAppend
import Unicode.Invariants
import Unicode.Precis.CaseMapping
import Unicode.CaseFoldCommutationSource
import Unicode.CaseFoldDecompositionFacts

namespace Unicode.CaseFoldCommutation

open Unicode.Normalization
open Unicode.Generated
open Unicode.Precis.CaseMapping
  (caseFold caseFoldCodepoint lookupCaseFolding? isCaseFoldSource
   caseFold_id_of_all_non_source)

set_option maxRecDepth 1000000

-- ═══════════════════════════════════════════════════════════════════════════════
-- TABLE-LEVEL WITNESS
--
-- The pointwise commutation check over every `CaseFolding.foldings`
-- entry. For each (src, tgt):
--
--   toNFD tgt = toNFD (caseFold (toNFD [src]))
--
-- Checked by `decide`. If this closes, the sequence-level lift
-- follows by a standard structural argument mirroring the width-compat
-- preservation chain.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- **Per-codepoint case-fold / canonical-decomposition commutation.**
    For every case-fold entry `(src, tgt)` in CaseFolding.txt, the full
    canonical decomposition of `tgt` equals the full canonical
    decomposition of the case-fold of the full canonical decomposition
    of `[src]`. This is Unicode's design property: case folding is
    defined to commute with canonical decomposition at the
    NFD-equivalence level. -/
theorem caseFold_commutes_with_NFD_pointwise :
    CaseFolding.foldings.all (fun entry =>
      decide (NFC.toNFD entry.2 =
              NFC.toNFD (caseFold (NFC.toNFD [entry.1])))) = true := by
  unfold CaseFolding.foldings
  simpa [sourcePointwiseP] using sourcePointwise_foldingsList

/-- Decomposed-form case-fold targets: for every fold entry, applying
    `toNFD` to the target is its own NFD form (idempotent restriction).
    This is the structural property that makes the pointwise commutation
    `decide`-able uniformly. Slightly weaker than "targets are
    fully decomposed" — some fold targets contain codepoints with
    non-trivial canonical decomposition, so the stronger claim fails. -/
theorem caseFoldTargets_NFD_idempotent :
    CaseFolding.foldings.all (fun entry =>
      decide (NFC.toNFD (NFC.toNFD entry.2) = NFC.toNFD entry.2)) = true := by
  rw [List.all_eq_true]
  intro entry hEntry
  exact decide_eq_true (NFD.toNFD_idempotent entry.2)

/-- **Per-codepoint commutation over CaseFolding sources, direct form.**
    Parallel to `caseFold_commutes_with_NFD_pointwise` but states the
    commutation in direct `caseFold [entry.1]` form — matching the
    shape of `caseFold_commutes_with_NFD_UnicodeData_rows` and
    `caseFold_commutes_with_NFD_Hangul_range`. Lets the downstream
    per-codepoint lift handle all three categories uniformly without
    routing through `lookupCaseFolding?` semantics. -/
theorem caseFold_commutes_with_NFD_sources :
    CaseFolding.foldings.all (fun entry =>
      decide (NFC.toNFD (caseFold [entry.1]) =
              NFC.toNFD (caseFold (NFC.toNFD [entry.1])))) = true := by
  unfold CaseFolding.foldings
  simpa [sourceCommP] using sourceComm_foldingsList

-- ═══════════════════════════════════════════════════════════════════════════════
-- UNIFIED PER-CODEPOINT LIFT
-- ═══════════════════════════════════════════════════════════════════════════════

/-- `caseFold [cp] = [cp]` for non-case-fold-source codepoints.
    Thin wrapper around the existing public
    `caseFold_id_of_all_non_source`. -/
theorem caseFold_singleton_non_source (cp : Nat)
    (h : isCaseFoldSource cp = false) :
    caseFold [cp] = [cp] := by
  apply caseFold_id_of_all_non_source
  intro x hMem
  have hxEq : x = cp := by simp at hMem; exact hMem
  rw [hxEq]
  exact h

/-- Every Hangul jamo codepoint emitted by algorithmic Hangul decomposition is
    not a case-fold source. -/
theorem hangulJamo_non_caseFoldSource :
    ((List.range 195).map (fun i => 0x1100 + i)).all
      (fun cp => !isCaseFoldSource cp) = true := by decide

theorem hangulJamo_non_caseFoldSource_point
    (j : Nat) (hLo : 0x1100 ≤ j) (hHi : j < 0x1100 + 195) :
    isCaseFoldSource j = false := by
  have hAll := hangulJamo_non_caseFoldSource
  rw [List.all_eq_true] at hAll
  have hi : j - 0x1100 ∈ List.range 195 := List.mem_range.mpr (by omega)
  have hMem : 0x1100 + (j - 0x1100) ∈
      (List.range 195).map (fun i => 0x1100 + i) := by
    exact List.mem_map.mpr ⟨j - 0x1100, hi, rfl⟩
  have hAt := hAll (0x1100 + (j - 0x1100)) hMem
  have hEq : 0x1100 + (j - 0x1100) = j := by omega
  rw [hEq] at hAt
  simpa using hAt

theorem decomposeSyllable_output_non_caseFoldSource
    (cp : Nat) (arr : List Nat)
    (h : Hangul.decomposeSyllable? cp = some arr) (j : Nat) (hj : j ∈ arr) :
    isCaseFoldSource j = false := by
  unfold Hangul.decomposeSyllable? at h
  split at h
  · next hSyl =>
    have hRange : 0xAC00 ≤ cp ∧ cp < 0xAC00 + 11172 := by
      unfold Hangul.isHangulSyllable Hangul.SBase Hangul.SCount
             Hangul.LCount Hangul.NCount Hangul.VCount Hangul.TCount
        at hSyl
      exact of_decide_eq_true hSyl
    have hsLt : cp - 0xAC00 < 11172 := by omega
    have hNPos : 0 < 588 := by decide
    have hTPos : 0 < 28 := by decide
    have hLIndexLt : (cp - 0xAC00) / 588 < 19 := by
      exact (Nat.div_lt_iff_lt_mul hNPos).2 (by omega)
    have hModNLt : (cp - 0xAC00) % 588 < 588 :=
      Nat.mod_lt (cp - 0xAC00) hNPos
    have hVIndexLt : ((cp - 0xAC00) % 588) / 28 < 21 := by
      exact (Nat.div_lt_iff_lt_mul hTPos).2 (by omega)
    have hTIndexLt : (cp - 0xAC00) % 28 < 28 :=
      Nat.mod_lt (cp - 0xAC00) hTPos
    simp only [Hangul.SBase, Hangul.LBase, Hangul.VBase, Hangul.TBase,
      Hangul.VCount, Hangul.TCount, Hangul.NCount] at h
    split at h
    · next hTZero =>
      simp only [Option.some.injEq] at h
      rw [← h] at hj
      simp only [List.mem_cons] at hj
      rcases hj with hJL | hRest
      · rw [hJL]
        apply hangulJamo_non_caseFoldSource_point <;> omega
      · rcases hRest with hJV | hEmpty
        · rw [hJV]
          apply hangulJamo_non_caseFoldSource_point <;> omega
        · cases hEmpty
    · next hTNonzero =>
      simp only [Option.some.injEq] at h
      rw [← h] at hj
      simp only [List.mem_cons] at hj
      have hTIndexPos : 0 < (cp - 0xAC00) % 28 := by omega
      rcases hj with hJL | hRest
      · rw [hJL]
        apply hangulJamo_non_caseFoldSource_point <;> omega
      · rcases hRest with hJV | hRest
        · rw [hJV]
          apply hangulJamo_non_caseFoldSource_point <;> omega
        · rcases hRest with hJT | hEmpty
          · rw [hJT]
            apply hangulJamo_non_caseFoldSource_point <;> omega
          · cases hEmpty
  · cases h

theorem canonicalDecomposition_output_non_caseFoldSource
    (cp : Nat) (hCp : isCaseFoldSource cp = false)
    (j : Nat) (hj : j ∈ Lookup.canonicalDecomposition cp) :
    isCaseFoldSource j = false := by
  unfold Lookup.canonicalDecomposition at hj
  split at hj
  · next row hRow =>
    obtain ⟨src, hSrcMem, hSrcCp, _hSrcCcc, hSrcDecomp⟩ :=
      Unicode.Generated.UnicodeDataIndex.lookupRow?_supported_rowsList hRow
    have hRowCp : row.codepoint = cp :=
      Unicode.Generated.UnicodeDataIndex.lookupRow?_codepoint hRow
    have hSrcRows : src ∈ UnicodeData.rows := by
      simpa [UnicodeData.rows] using hSrcMem
    have hSrcCpToInput : src.codepoint = cp := hSrcCp.trans hRowCp
    have hTable := nonCaseFoldSource_decomp_all_nonSource
    rw [List.all_eq_true] at hTable
    have hEntry := hTable src hSrcRows
    simp only [Bool.or_eq_true] at hEntry
    rcases hEntry with hSrcCFS | hTgtAllNonSrc
    · rw [hSrcCpToInput, hCp] at hSrcCFS
      exact Bool.noConfusion hSrcCFS
    · rw [List.all_eq_true] at hTgtAllNonSrc
      rw [← hSrcDecomp] at hj
      have hBool := hTgtAllNonSrc j hj
      simpa using hBool
  · simp at hj

theorem mem_foldl_append (f : Nat → List Nat) (cps : List Nat) (cp : Nat)
    (hMem : cp ∈ cps.foldl (fun acc x => acc ++ f x) []) :
    ∃ x ∈ cps, cp ∈ f x := by
  have key : ∀ (l : List Nat) (init : List Nat),
      cp ∈ l.foldl (fun acc x => acc ++ f x) init →
      cp ∈ init ∨ ∃ x ∈ l, cp ∈ f x := by
    intro l
    induction l with
    | nil => intro init hM; left; simpa using hM
    | cons hd tl ih =>
      intro init hM
      simp only [List.foldl_cons] at hM
      rcases ih (init ++ f hd) hM with hInit | ⟨x, hxM, hxF⟩
      · rcases List.mem_append.mp hInit with h1 | h2
        · left; exact h1
        · right; exact ⟨hd, by simp, h2⟩
      · right; exact ⟨x, by simp [hxM], hxF⟩
  rcases key cps [] hMem with hEmpty | ⟨x, hxM, hxF⟩
  · simp at hEmpty
  · exact ⟨x, hxM, hxF⟩

theorem fullCanonicalDecomposeFuel_preserves_non_caseFoldSource (fuel : Nat) :
    ∀ cp, isCaseFoldSource cp = false →
    ∀ j ∈ Decompose.fullCanonicalDecomposeFuel fuel cp, isCaseFoldSource j = false := by
  induction fuel with
  | zero =>
    intro cp hCp j hj
    unfold Decompose.fullCanonicalDecomposeFuel at hj
    simp at hj
  | succ fuel ih =>
    intro cp hCp j hj
    unfold Decompose.fullCanonicalDecomposeFuel at hj
    split at hj
    · next arr hSome =>
      exact decomposeSyllable_output_non_caseFoldSource cp arr hSome j hj
    · next hNone =>
      generalize hStep : Lookup.canonicalDecomposition cp = step at hj
      change j ∈ (if step.isEmpty = true then [cp]
                  else step.foldl (fun acc cp' =>
                        acc ++ Decompose.fullCanonicalDecomposeFuel fuel cp') []) at hj
      split at hj
      · next hEmpty =>
        simp at hj
        rw [hj]
        exact hCp
      · next hNotEmpty =>
        obtain ⟨x, hxIn, hxF⟩ :=
          mem_foldl_append (Decompose.fullCanonicalDecomposeFuel fuel) step j hj
        rw [← hStep] at hxIn
        have hxNonSource : isCaseFoldSource x = false :=
          canonicalDecomposition_output_non_caseFoldSource cp hCp x hxIn
        exact ih x hxNonSource j hxF

theorem fullCanonicalDecompose_preserves_non_caseFoldSource
    (cp : Nat) (h : isCaseFoldSource cp = false) :
    ∀ j ∈ Decompose.fullCanonicalDecompose cp, isCaseFoldSource j = false := by
  unfold Decompose.fullCanonicalDecompose
  exact fullCanonicalDecomposeFuel_preserves_non_caseFoldSource Decompose.maxDepth cp h

theorem decomposeSequence_preserves_non_caseFoldSource
    (cps : List Nat) (h : ∀ cp ∈ cps, isCaseFoldSource cp = false) :
    ∀ j ∈ Decompose.decomposeSequence cps, isCaseFoldSource j = false := by
  intro j hj
  unfold Decompose.decomposeSequence at hj
  obtain ⟨x, hxIn, hxF⟩ := List.mem_flatMap.mp hj
  exact fullCanonicalDecompose_preserves_non_caseFoldSource x (h x hxIn) j hxF

theorem toNFD_preserves_non_caseFoldSource
    (cps : List Nat) (h : ∀ cp ∈ cps, isCaseFoldSource cp = false) :
    ∀ j ∈ NFC.toNFD cps, isCaseFoldSource j = false := by
  unfold NFC.toNFD
  intro j hj
  have hDecAll : ∀ cp ∈ Decompose.decomposeSequence cps,
                   (fun x => !isCaseFoldSource x) cp = true := by
    intro cp hcp
    have := decomposeSequence_preserves_non_caseFoldSource cps h cp hcp
    simpa using this
  have hR := Reorder.reorder_preserves_all (fun x => !isCaseFoldSource x)
               (Decompose.decomposeSequence cps) hDecAll j hj
  simpa using hR

/-- `toNFD [cp] = [cp]` for non-decomposable non-Hangul codepoints.
    Goes via `NFD.decomposeSequence_id_on_FullyDecomposed` and
    `Reorder.reorder_id_on_HasSortedRuns` — both already in
    their respective modules, so this wrapper stays thin. -/
theorem toNFD_singleton_trivial (cp : Nat)
    (hDecomp : Lookup.canonicalDecomposition cp = [])
    (hNotHangul : Hangul.isHangulSyllable cp = false) :
    NFC.toNFD [cp] = [cp] := by
  have hFD : Invariants.IsFullyDecomposed [cp] := by
    intro c hMem
    simp at hMem
    subst hMem
    exact ⟨hDecomp, hNotHangul⟩
  have hHSR : Reorder.HasSortedRuns [cp] := by
    exact True.intro
  unfold NFC.toNFD
  rw [NFD.decomposeSequence_id_on_FullyDecomposed [cp] hFD]
  exact Reorder.reorder_id_on_HasSortedRuns [cp] hHSR

/-- **Successful lookup branch.** If the public case-fold lookup returns a
    target, the bounded source-column certificate applies to the raw table
    entry selected by that lookup. -/
theorem caseFold_commutes_with_NFD_lookup_case
    (cp : Nat) (target : List Nat)
    (hLookup : lookupCaseFolding? cp = some target) :
    NFC.toNFD (caseFold [cp]) =
    NFC.toNFD (caseFold (NFC.toNFD [cp])) := by
  unfold lookupCaseFolding? at hLookup
  unfold CaseFolding.lookup? at hLookup
  split at hLookup
  · cases hRaw : CaseFolding.lookupRaw? cp with
    | none =>
        rw [hRaw] at hLookup
        cases hLookup
    | some found =>
        rw [hRaw] at hLookup
        cases hLookup
        have hEntryPair : (cp, target) ∈ CaseFolding.foldingsList :=
          CaseFolding.lookupRaw_mem_foldingsList cp target hRaw
        have hAll := sourceComm_foldingsList
        rw [List.all_eq_true] at hAll
        have hAt := of_decide_eq_true (hAll (cp, target) hEntryPair)
        simpa [sourceCommP] using hAt
  · cases hLookup

/-- **Non-source branch.** If a codepoint has no case-fold mapping, case
    folding is identity on the singleton, and `toNFD` preserves the
    non-source property through canonical decomposition and reordering. -/
theorem caseFold_commutes_with_NFD_non_source
    (cp : Nat) (hNotCFS : isCaseFoldSource cp = false) :
    NFC.toNFD (caseFold [cp]) =
    NFC.toNFD (caseFold (NFC.toNFD [cp])) := by
  have hCF : caseFold [cp] = [cp] :=
    caseFold_singleton_non_source cp hNotCFS
  have hNFDStable : ∀ d ∈ NFC.toNFD [cp], isCaseFoldSource d = false := by
    apply toNFD_preserves_non_caseFoldSource
    intro x hx
    simp at hx
    rw [hx]
    exact hNotCFS
  have hCaseFoldNFD : caseFold (NFC.toNFD [cp]) = NFC.toNFD [cp] :=
    caseFold_id_of_all_non_source (NFC.toNFD [cp]) hNFDStable
  rw [hCF, hCaseFoldNFD]
  exact (NFD.toNFD_idempotent [cp]).symm

/-- **Unified per-codepoint commutation.** For every codepoint `cp`,
    `toNFD (caseFold [cp]) = toNFD (caseFold (toNFD [cp]))`. Dispatches
    to the successful-lookup and non-source structural branches. -/
theorem caseFold_commutes_with_NFD_singleton (cp : Nat) :
    NFC.toNFD (caseFold [cp]) =
    NFC.toNFD (caseFold (NFC.toNFD [cp])) := by
  cases hLookup : lookupCaseFolding? cp with
  | some target =>
      exact caseFold_commutes_with_NFD_lookup_case cp target hLookup
  | none =>
      have hNotCFS : isCaseFoldSource cp = false :=
        Unicode.Precis.CaseMapping.non_source_of_lookupCaseFolding_none cp hLookup
      exact caseFold_commutes_with_NFD_non_source cp hNotCFS

/-- **Per-codepoint commutation over UnicodeData rows.** Kept as an aggregate
    export, now derived from the universal singleton theorem instead of a
    whole-table reducer. -/
theorem caseFold_commutes_with_NFD_UnicodeData_rows :
    UnicodeData.rows.all (fun row =>
      decide (NFC.toNFD (caseFold [row.codepoint]) =
              NFC.toNFD (caseFold (NFC.toNFD [row.codepoint])))) = true := by
  rw [List.all_eq_true]
  intro row hRow
  exact decide_eq_true
    (caseFold_commutes_with_NFD_singleton row.codepoint)

/-- **Per-codepoint commutation over Hangul syllables.** Kept as an aggregate
    export, now derived from the universal singleton theorem rather than
    evaluating 11172 syllables directly. -/
theorem caseFold_commutes_with_NFD_Hangul_range :
    (List.range 11172).all (fun i =>
      decide (NFC.toNFD (caseFold [0xAC00 + i]) =
              NFC.toNFD (caseFold (NFC.toNFD [0xAC00 + i])))) = true := by
  rw [List.all_eq_true]
  intro i hi
  exact decide_eq_true (caseFold_commutes_with_NFD_singleton (0xAC00 + i))

/-- Compatibility wrapper preserving the Hangul branch entry point. -/
theorem caseFold_commutes_with_NFD_hangul_case
    (cp : Nat) (_hHangul : Hangul.isHangulSyllable cp = true) :
    NFC.toNFD (caseFold [cp]) =
    NFC.toNFD (caseFold (NFC.toNFD [cp])) :=
  caseFold_commutes_with_NFD_singleton cp

/-- Compatibility wrapper preserving the UnicodeData-row branch entry point. -/
theorem caseFold_commutes_with_NFD_rows_case
    (cp : Nat) (_hRow : ∃ row, row ∈ UnicodeData.rows ∧ row.codepoint = cp) :
    NFC.toNFD (caseFold [cp]) =
    NFC.toNFD (caseFold (NFC.toNFD [cp])) :=
  caseFold_commutes_with_NFD_singleton cp

/-- Compatibility wrapper preserving the case-fold-source branch entry point. -/
theorem caseFold_commutes_with_NFD_cfs_case
    (cp : Nat) (_hCFS : isCaseFoldSource cp = true) :
    NFC.toNFD (caseFold [cp]) =
    NFC.toNFD (caseFold (NFC.toNFD [cp])) :=
  caseFold_commutes_with_NFD_singleton cp

/-- Compatibility wrapper preserving the trivial branch entry point. -/
theorem caseFold_commutes_with_NFD_trivial_case
    (cp : Nat)
    (_hNotHangul : Hangul.isHangulSyllable cp = false)
    (_hNotRow : ¬ ∃ row, row ∈ UnicodeData.rows ∧ row.codepoint = cp)
    (_hNotCFS : isCaseFoldSource cp = false) :
    NFC.toNFD (caseFold [cp]) =
    NFC.toNFD (caseFold (NFC.toNFD [cp])) :=
  caseFold_commutes_with_NFD_singleton cp

end Unicode.CaseFoldCommutation
