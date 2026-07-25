/-
  Unicode.Normalization.Decomposability

  Structural witness that `fullCanonicalDecompose` output is fully
  decomposed — every resulting codepoint has no further canonical
  decomposition and is not a Hangul syllable. Upstream, this establishes
  `IsFullyDecomposed` on `decomposeSequence` output, the key precondition
  for feeding `compose` (pillar 2 of NFC idempotence).

  Architecture: the two `decide` table facts here cover the
  interesting codepoints — rows of `UnicodeData` (3045 cases) and Hangul
  syllables (11172 cases). Codepoints outside both sets decompose
  trivially to themselves, and the non-decomposability of the trivial
  case is established structurally.
-/

import Unicode.Normalization.Decompose

namespace Unicode.Normalization.Decomposability

open Unicode.Normalization
open Unicode.Generated

set_option maxRecDepth 100000
-- ═══════════════════════════════════════════════════════════════════════════════
-- SMALL TERMINAL WITNESSES
-- ═══════════════════════════════════════════════════════════════════════════════

/-- No pinned row carries a codepoint in the Hangul jamo band used by
    the algorithmic decomposition. One linear kernel pass witnesses
    absence for the whole band at once. -/
theorem rows_omit_hangulJamo :
    UnicodeData.rowsList.all (fun r =>
      decide (¬ (0x1100 ≤ r.codepoint ∧ r.codepoint ≤ 0x11C2))) = true := by
  decide +kernel

/-- Hangul jamo used by the algorithmic decomposition are terminal for
    canonical decomposition. This is the small Hangul atom: 195 jamo
    codepoints, not 11172 syllables. -/
theorem hangulJamo_terminal
    (j : Nat) (hLo : 0x1100 ≤ j) (hHi : j < 0x1100 + 195) :
    Lookup.canonicalDecomposition j = #[] ∧ Hangul.isHangulSyllable j = false := by
  constructor
  · exact Lookup.canonicalDecomposition_of_lookupRow_none j
      (Lookup.lookupRow_none_of_all_outside 0x1100 0x11C2 j
        rows_omit_hangulJamo hLo (by omega))
  · have hNot : ¬ (Hangul.SBase ≤ j ∧ j < Hangul.SBase + Hangul.SCount) := by
      simp only [Hangul.SBase, Hangul.SCount, Hangul.LCount, Hangul.NCount,
                 Hangul.VCount, Hangul.TCount]
      omega
    unfold Hangul.isHangulSyllable
    exact decide_eq_false hNot

/-- The enumerated form of `hangulJamo_terminal`, index-driven over the
    195-codepoint band. -/
theorem hangulJamo_terminal_checked :
    (List.range 195).all (fun i =>
      decide (Lookup.canonicalDecomposition (0x1100 + i) = #[]
              ∧ Hangul.isHangulSyllable (0x1100 + i) = false)) = true := by
  rw [List.all_eq_true]
  intro i hi
  have hiLt : i < 195 := List.mem_range.mp hi
  exact decide_eq_true (hangulJamo_terminal (0x1100 + i) (by omega) (by omega))

theorem decomposeSyllable_output_terminal
    (cp : Nat) (arr : Array Nat)
    (h : Hangul.decomposeSyllable? cp = some arr) (j : Nat) (hj : j ∈ arr) :
    Lookup.canonicalDecomposition j = #[] ∧ Hangul.isHangulSyllable j = false := by
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
      simp only [Array.mem_def, List.mem_cons] at hj
      rcases hj with hJL | hRest
      · rw [hJL]
        apply hangulJamo_terminal <;> omega
      · rcases hRest with hJV | hEmpty
        · rw [hJV]
          apply hangulJamo_terminal <;> omega
        · cases hEmpty
    · next hTNonzero =>
      simp only [Option.some.injEq] at h
      rw [← h] at hj
      simp only [Array.mem_def, List.mem_cons] at hj
      have hTIndexPos : 0 < (cp - 0xAC00) % 28 := by omega
      rcases hj with hJL | hRest
      · rw [hJL]
        apply hangulJamo_terminal <;> omega
      · rcases hRest with hJV | hRest
        · rw [hJV]
          apply hangulJamo_terminal <;> omega
        · rcases hRest with hJT | hEmpty
          · rw [hJT]
            apply hangulJamo_terminal <;> omega
          · cases hEmpty
  · cases h

-- ═══════════════════════════════════════════════════════════════════════════════
-- SEQUENCE-LEVEL WITNESS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Generic: membership in a `foldl`-with-append over an array factors
    through one of the source elements. (Local copy of the private helper
    from `Decompose`; kept here to avoid modifying that module.) -/
theorem mem_foldl_append (f : Nat → Array Nat) (cps : Array Nat) (cp : Nat)
    (hMem : cp ∈ cps.foldl (fun acc x => acc ++ f x) #[]) :
    ∃ x ∈ cps, cp ∈ f x := by
  rw [← Array.foldl_toList] at hMem
  have key : ∀ (l : List Nat) (init : Array Nat),
      cp ∈ l.foldl (fun acc x => acc ++ f x) init →
      cp ∈ init ∨ ∃ x ∈ l, cp ∈ f x := by
    intro l
    induction l with
    | nil => intro init hM; left; simpa using hM
    | cons hd tl ih =>
      intro init hM
      simp only [List.foldl_cons] at hM
      rcases ih (init ++ f hd) hM with hInit | ⟨x, hxM, hxF⟩
      · rcases Array.mem_append.mp hInit with h1 | h2
        · left; exact h1
        · right; exact ⟨hd, by simp, h2⟩
      · right; exact ⟨x, by simp [hxM], hxF⟩
  rcases key cps.toList #[] hMem with hEmpty | ⟨x, hxM, hxF⟩
  · simp at hEmpty
  · exact ⟨x, by simpa using hxM, hxF⟩

theorem array_eq_empty_of_isEmpty_true
    (a : Array Nat) (h : a.isEmpty = true) : a = #[] := by
  cases a with
  | mk xs =>
    cases xs with
    | nil => rfl
    | cons _ _ =>
      simp [Array.isEmpty] at h

theorem not_hangul_of_decomposeSyllable_none
    (cp : Nat) (h : Hangul.decomposeSyllable? cp = none) :
    Hangul.isHangulSyllable cp = false := by
  by_cases hHangul : Hangul.isHangulSyllable cp = true
  · unfold Hangul.decomposeSyllable? at h
    by_cases hT : (cp - Hangul.SBase) % Hangul.TCount = 0
    · simp [hHangul, hT] at h
    · simp [hHangul, hT] at h
  · exact Bool.not_eq_true (Hangul.isHangulSyllable cp) |>.mp hHangul

/-- Fuel-bounded decomposition output is fully decomposed. The proof is
    structural in the fuel because the exhausted-fuel branch in
    `fullCanonicalDecomposeFuel` emits no codepoints. -/
theorem fullCanonicalDecomposeFuel_fullyDecomposed (fuel : Nat) :
    ∀ cp, ∀ j ∈ Decompose.fullCanonicalDecomposeFuel fuel cp,
      Lookup.canonicalDecomposition j = #[] ∧ Hangul.isHangulSyllable j = false := by
  induction fuel with
  | zero =>
    intro cp j hj
    unfold Decompose.fullCanonicalDecomposeFuel at hj
    simp at hj
  | succ fuel ih =>
    intro cp j hj
    unfold Decompose.fullCanonicalDecomposeFuel at hj
    split at hj
    · next arr hSome =>
      exact decomposeSyllable_output_terminal cp arr hSome j hj
    · next hNone =>
      generalize hStep : Lookup.canonicalDecomposition cp = step at hj
      change j ∈ (if step.isEmpty then #[cp]
                  else step.foldl
                    (fun acc cp' => acc ++ Decompose.fullCanonicalDecomposeFuel fuel cp')
                    #[]) at hj
      split at hj
      · next hEmpty =>
        have hDecomp : Lookup.canonicalDecomposition cp = #[] := by
          rw [hStep]
          exact array_eq_empty_of_isEmpty_true step hEmpty
        have hNotHangul : Hangul.isHangulSyllable cp = false :=
          not_hangul_of_decomposeSyllable_none cp hNone
        simp at hj
        rw [hj]
        exact ⟨hDecomp, hNotHangul⟩
      · next _hNotEmpty =>
        obtain ⟨x, _hxIn, hxF⟩ :=
          mem_foldl_append (Decompose.fullCanonicalDecomposeFuel fuel) step j hj
        exact ih x j hxF

/-- Pointwise: for any codepoint `cp`, every element of
    `fullCanonicalDecompose cp` has no further canonical decomposition
    and is not a Hangul syllable. -/
theorem fullCanonicalDecompose_fullyDecomposed (cp : Nat) :
    ∀ j ∈ Decompose.fullCanonicalDecompose cp,
      Lookup.canonicalDecomposition j = #[] ∧ Hangul.isHangulSyllable j = false := by
  unfold Decompose.fullCanonicalDecompose
  exact fullCanonicalDecomposeFuel_fullyDecomposed Decompose.maxDepth cp

/-- `decomposeSequence` output is fully decomposed. Lifted from the
    per-codepoint witness through the flattened per-codepoint expansion. -/
theorem decomposeSequence_fullyDecomposed (cps : List Nat) :
    ∀ j ∈ Decompose.decomposeSequence cps,
      Lookup.canonicalDecomposition j = #[] ∧ Hangul.isHangulSyllable j = false := by
  intro j hj
  unfold Decompose.decomposeSequence at hj
  simp only [List.mem_flatMap] at hj
  obtain ⟨x, _hxInCps, hxF⟩ := hj
  exact fullCanonicalDecompose_fullyDecomposed x j (by simpa using hxF)

end Unicode.Normalization.Decomposability
