/-
  Unicode.Precis.ZsPreservation

  Pre-compiled `decide` facts and structural preservation
  lemmas for the "no non-ASCII Zs" predicate, factored out of
  `Unicode.Precis.OpaqueString` so that the heavy UCD-table
  compilation costs stay isolated to one olean. `OpaqueString.lean`
  imports this module's pre-compiled oleans without reloading the
  underlying tables during its own `decide` evaluation.

  Exports:

    * `nonAsciiZsCodepoints`, `isNonAsciiZs` — the 16 hardcoded Zs
      codepoints and predicate.
    * `remapZsToAscii` — RFC 8265 §4.2.2 remap to U+0020.
    * `remapZsToAscii_output_no_nonAsciiZs`,
      `remapZsToAscii_id_of_no_nonAsciiZs` — remap invariants.
    * `decomposeSequence_preserves_no_nonAsciiZs`,
      `toNFD_preserves_no_nonAsciiZs`,
      `toNFC_preserves_no_nonAsciiZs` — structural preservation
      through the normalization pipeline.

  Deliberately does NOT import `Unicode.Precis.Categories` or
  `Unicode.Precis.BidiRule`; doing so would pull
  `DerivedGeneralCategory` and `DerivedBidiClass` into the
  `decide` compilation closure here, which is what caused the
  M5 build to exhaust WSL memory.
-/

import Unicode.Normalization.NFC
import Unicode.Normalization.Decompose
import Unicode.Normalization.Decomposability
import Unicode.Normalization.Hangul
import Unicode.Normalization.ComposeInversion
import Unicode.CaseFoldRoundtrip
import Unicode.Precis.ZsMapping
import Unicode.Precis.ZsPreservationFacts

namespace Unicode.Precis.ZsPreservation

open Unicode.Normalization
open Unicode.Normalization.NFC (toNFC)
open Unicode.Generated

-- The table facts below reduce large UCD ranges (all rows, 11172 Hangul
-- syllables, per-codepoint `fullCanonicalDecompose`); kernel reduction needs a
-- deeper recursion bound than the elaboration default.
set_option maxRecDepth 1000000

-- Runtime definitions (`nonAsciiZsCodepoints`, `isNonAsciiZs`,
-- `remapZsToAscii`) live in `ZsMapping`.

/-- `remapZsToAscii` output contains no non-ASCII Zs codepoints. -/
theorem remapZsToAscii_output_no_nonAsciiZs (cps : Array Nat) :
    ∀ cp ∈ remapZsToAscii cps, isNonAsciiZs cp = false := by
  intro cp hcp
  unfold remapZsToAscii at hcp
  rw [Array.mem_map] at hcp
  obtain ⟨a, hMem, ha⟩ := hcp
  clear hMem
  by_cases hAZs : isNonAsciiZs a = true
  · rw [if_pos hAZs] at ha
    rw [← ha]
    exact isNonAsciiZs_ascii_space
  · rw [if_neg hAZs] at ha
    rw [← ha]
    simpa using hAZs

/-- `remapZsToAscii` is the identity on inputs that already have no
    non-ASCII Zs. -/
theorem remapZsToAscii_id_of_no_nonAsciiZs (cps : Array Nat)
    (h : ∀ cp ∈ cps, isNonAsciiZs cp = false) :
    remapZsToAscii cps = cps := by
  unfold remapZsToAscii
  have hAllEq : cps.map (fun cp => if isNonAsciiZs cp then 0x0020 else cp) =
                cps.map id := by
    apply Array.map_congr_left
    intro a ha
    have hA : isNonAsciiZs a = false := h a ha
    simp [hA]
  rw [hAllEq, Array.map_id]

-- ═══════════════════════════════════════════════════════════════════════════════
-- NON-ASCII Zs DECOMPOSITION FACTS
-- ═══════════════════════════════════════════════════════════════════════════════

-- The two genuine table facts — `nonNonAsciiZs_decomp_no_nonAsciiZs` (over the
-- `List` mirror `rowsList`) and `nonAsciiZs_fullDecompose_contains_nonAsciiZs`
-- (16 codepoints) — live in `Unicode.Precis.ZsPreservationFacts`. The Hangul
-- decomposition facts are proven STRUCTURALLY below
-- (`decomposeSyllable_output_no_nonAsciiZs`) via the jamo-range formula and
-- `omega`, not by enumerating 11172 syllables.

-- ═══════════════════════════════════════════════════════════════════════════════
-- POINTWISE LIFTS FROM UCD FACTS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Pointwise Hangul analog. -/
theorem decomposeSyllable_output_no_nonAsciiZs
    (cp : Nat) (arr : Array Nat)
    (h : Hangul.decomposeSyllable? cp = some arr) (j : Nat) (hj : j ∈ arr) :
    isNonAsciiZs j = false := by
  have hSyl : Hangul.isHangulSyllable cp = true := by
    unfold Hangul.decomposeSyllable? at h
    split at h
    · next hYes => exact hYes
    · simp at h
  have hRange : 0xAC00 ≤ cp ∧ cp < 0xAC00 + 11172 := by
    unfold Hangul.isHangulSyllable Hangul.SBase Hangul.SCount
           Hangul.LCount Hangul.NCount Hangul.VCount Hangul.TCount at hSyl
    exact of_decide_eq_true hSyl
  -- Structural, not an enumeration of all 11172 syllables: the decomposition
  -- FORMULA places every output in the jamo block [0x1100, 0x11C2] — the leading
  -- jamo `l = 0x1100 + sIndex/588 ≤ 0x1112`, the vowel
  -- `v = 0x1161 + (sIndex%588)/28 ≤ 0x1175`, and any trailing `0x11A7 + sIndex%28
  -- ≤ 0x11C2` — all by `omega` on the division/modulo bounds.
  have hjRange : 0x1100 ≤ j ∧ j ≤ 0x11C2 := by
    unfold Hangul.decomposeSyllable? at h
    rw [if_pos hSyl] at h
    simp only [Hangul.LBase, Hangul.VBase, Hangul.TBase, Hangul.NCount, Hangul.TCount,
               Hangul.VCount, Hangul.SBase] at h
    split at h
    · rw [Option.some.injEq] at h; subst h
      simp at hj
      rcases hj with rfl | rfl <;> omega
    · rw [Option.some.injEq] at h; subst h
      simp at hj
      rcases hj with rfl | rfl | rfl <;> omega
  -- The jamo block is disjoint from every non-ASCII Zs codepoint (all < 0x1100
  -- or > 0x11C2), so no output is a non-ASCII Zs.
  obtain ⟨hj1, hj2⟩ := hjRange
  unfold isNonAsciiZs
  cases hc : nonAsciiZsCodepoints.contains j with
  | false => rfl
  | true =>
    have hmem := Array.mem_of_contains_eq_true hc
    unfold nonAsciiZsCodepoints at hmem
    simp at hmem
    omega

/-- Pointwise: for a non-non-ASCII-Zs `cp`, every element of
    `Lookup.canonicalDecomposition cp` is also non-non-ASCII-Zs. -/
theorem canonicalDecomposition_output_no_nonAsciiZs
    (cp : Nat) (hCp : isNonAsciiZs cp = false)
    (j : Nat) (hj : j ∈ Lookup.canonicalDecomposition cp) :
    isNonAsciiZs j = false := by
  unfold Lookup.canonicalDecomposition at hj
  split at hj
  · next row hRow =>
    -- `Lookup.lookupRow` is the generated index lookup; recover `row.codepoint`
    -- and a table-mirror `src` with the same decomposition via its soundness.
    unfold Lookup.lookupRow at hRow
    have hRowCp : row.codepoint = cp := UnicodeDataIndex.lookupRow?_codepoint hRow
    obtain ⟨src, hSrcMem, hSrcCp, _hSrcCcc, hSrcDecomp⟩ :=
      UnicodeDataIndex.lookupRow?_supported_rowsList hRow
    have hSrcRows : src ∈ UnicodeData.rows := by
      simpa [UnicodeData.rows] using hSrcMem
    have hTable := nonNonAsciiZs_decomp_no_nonAsciiZs
    rw [Array.all_eq_true] at hTable
    rcases Array.getElem_of_mem hSrcRows with ⟨i, hi, hElem⟩
    have hEntry := hTable i hi
    rw [hElem] at hEntry
    simp only [Bool.or_eq_true] at hEntry
    rcases hEntry with hSrcZs | hTgtAllNonZs
    · rw [hSrcCp, hRowCp, hCp] at hSrcZs
      exact Bool.noConfusion hSrcZs
    · rw [Array.all_eq_true] at hTgtAllNonZs
      rw [← hSrcDecomp] at hj
      rcases Array.getElem_of_mem hj with ⟨k, hk, hElemJ⟩
      have hBool := hTgtAllNonZs k hk
      rw [hElemJ] at hBool
      simpa using hBool
  · simp at hj

-- ═══════════════════════════════════════════════════════════════════════════════
-- STRUCTURAL LIFTS: toNFD PRESERVES NO-NON-ASCII-Zs
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Membership through a `foldl`-with-append over an array. -/
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

/-- Forward membership through `foldl`-with-append. -/
theorem mem_foldl_append_of (f : Nat → Array Nat) (cps : Array Nat)
    (c : Nat) (hc : c ∈ cps) (d : Nat) (hd : d ∈ f c) :
    d ∈ cps.foldl (fun acc x => acc ++ f x) #[] := by
  rw [← Array.foldl_toList]
  have key : ∀ (l : List Nat) (init : Array Nat),
      (d ∈ init ∨ ∃ c' ∈ l, d ∈ f c') →
      d ∈ l.foldl (fun acc x => acc ++ f x) init := by
    intro l
    induction l with
    | nil =>
      intro init hCase
      rcases hCase with hInit | ⟨c', hc', hdf⟩
      · simpa using hInit
      · cases hc'
    | cons hd' tl ih =>
      intro init hCase
      simp only [List.foldl_cons]
      apply ih (init ++ f hd')
      rcases hCase with hInit | ⟨c', hc', hcf⟩
      · left; exact Array.mem_append.mpr (Or.inl hInit)
      · rcases List.mem_cons.mp hc' with rfl | hRest
        · left; exact Array.mem_append.mpr (Or.inr hcf)
        · right; exact ⟨c', hRest, hcf⟩
  apply key cps.toList #[]
  right
  exact ⟨c, by simpa using hc, hd⟩

/-- Fuel-bounded preservation of no-non-ASCII-Zs through
    `fullCanonicalDecomposeFuel`. -/
theorem fullCanonicalDecomposeFuel_preserves_no_nonAsciiZs (fuel : Nat) :
    ∀ cp, isNonAsciiZs cp = false →
    ∀ j ∈ Decompose.fullCanonicalDecomposeFuel fuel cp, isNonAsciiZs j = false := by
  induction fuel with
  | zero =>
    intro cp hCp j hj
    unfold Decompose.fullCanonicalDecomposeFuel at hj
    simp_all
  | succ fuel ih =>
    intro cp hCp j hj
    unfold Decompose.fullCanonicalDecomposeFuel at hj
    split at hj
    · next arr hSome =>
      exact decomposeSyllable_output_no_nonAsciiZs cp arr hSome j hj
    · next hNone =>
      generalize hStep : Lookup.canonicalDecomposition cp = step at hj
      change j ∈ (if step.isEmpty = true then #[cp]
                  else step.foldl (fun acc cp' =>
                        acc ++ Decompose.fullCanonicalDecomposeFuel fuel cp') #[]) at hj
      split at hj
      · next hEmpty =>
        simp_all
      · next hNotEmpty =>
        obtain ⟨x, hxIn, hxF⟩ :=
          mem_foldl_append (Decompose.fullCanonicalDecomposeFuel fuel) step j hj
        rw [← hStep] at hxIn
        have hxNonZs : isNonAsciiZs x = false :=
          canonicalDecomposition_output_no_nonAsciiZs cp hCp x hxIn
        exact ih x hxNonZs j hxF

/-- `decomposeSequence` preserves no-non-ASCII-Zs. -/
theorem decomposeSequence_preserves_no_nonAsciiZs
    (cps : Array Nat) (h : ∀ cp ∈ cps, isNonAsciiZs cp = false) :
    ∀ j ∈ Decompose.decomposeSequence cps, isNonAsciiZs j = false := by
  intro j hj
  unfold Decompose.decomposeSequence at hj
  obtain ⟨x, hxIn, hxF⟩ := mem_foldl_append Decompose.fullCanonicalDecompose cps j hj
  unfold Decompose.fullCanonicalDecompose at hxF
  exact fullCanonicalDecomposeFuel_preserves_no_nonAsciiZs Decompose.maxDepth x
    (h x hxIn) j hxF

/-- `toNFD` preserves no-non-ASCII-Zs. -/
theorem toNFD_preserves_no_nonAsciiZs
    (cps : Array Nat) (h : ∀ cp ∈ cps, isNonAsciiZs cp = false) :
    ∀ j ∈ NFC.toNFD cps, isNonAsciiZs j = false := by
  unfold NFC.toNFD
  intro j hj
  have hDecAll : ∀ cp ∈ Decompose.decomposeSequence cps,
                   (fun x => !isNonAsciiZs x) cp = true := by
    intro cp hcp
    have := decomposeSequence_preserves_no_nonAsciiZs cps h cp hcp
    simpa using this
  have hR := Reorder.reorder_preserves_all (fun x => !isNonAsciiZs x)
               (Decompose.decomposeSequence cps) hDecAll j hj
  simpa using hR

-- ═══════════════════════════════════════════════════════════════════════════════
-- toNFC PRESERVES NO-NON-ASCII-Zs
-- ═══════════════════════════════════════════════════════════════════════════════

/-- **`toNFC` preserves no-non-ASCII-Zs.**

    Strategy: if `toNFC x` contained a non-ASCII Zs `c`, then
    `fullCanonicalDecompose c` contains some non-ASCII Zs `d` (UCD
    fact `nonAsciiZs_fullDecompose_contains_nonAsciiZs`). Then `d ∈
    decomposeSequence (toNFC x)` ⊆ `toNFD (toNFC x)` = `toNFD x` (via
    `decompose_compose_inversion`-derived `toNFD_toNFC_eq_toNFD`).
    But `toNFD x` has no non-ASCII Zs by hypothesis, contradiction. -/
theorem toNFC_preserves_no_nonAsciiZs
    (cps : Array Nat) (h : ∀ cp ∈ cps, isNonAsciiZs cp = false) :
    ∀ cp ∈ toNFC cps, isNonAsciiZs cp = false := by
  intro c hc
  cases hZsC : isNonAsciiZs c with
  | false => rfl
  | true =>
    exfalso
    have hCinZs : c ∈ nonAsciiZsCodepoints := by
      unfold isNonAsciiZs at hZsC
      exact Array.mem_of_contains_eq_true hZsC
    have hTable := nonAsciiZs_fullDecompose_contains_nonAsciiZs
    rw [Array.all_eq_true] at hTable
    rcases Array.getElem_of_mem hCinZs with ⟨i, hi, hElem⟩
    have hAtI := hTable i hi
    rw [hElem] at hAtI
    rw [Array.any_eq_true] at hAtI
    obtain ⟨idx, hIdx, hIsZs⟩ := hAtI
    let d : Nat := (Decompose.fullCanonicalDecompose c)[idx]
    have hdInDecomp : d ∈ Decompose.fullCanonicalDecompose c :=
      Array.getElem_mem hIdx
    have hdIsZs : isNonAsciiZs d = true := hIsZs
    have hdInDecSeq : d ∈ Decompose.decomposeSequence (toNFC cps) := by
      unfold Decompose.decomposeSequence
      exact mem_foldl_append_of Decompose.fullCanonicalDecompose (toNFC cps)
        c hc d hdInDecomp
    have hdInNfd : d ∈ NFC.toNFD (toNFC cps) := by
      unfold NFC.toNFD
      exact Unicode.CaseFoldRoundtrip.reorder_mem_of_mem
        (Decompose.decomposeSequence (toNFC cps)) d hdInDecSeq
    rw [ComposeInversion.toNFD_toNFC_eq_toNFD] at hdInNfd
    have hdNotZs : isNonAsciiZs d = false :=
      toNFD_preserves_no_nonAsciiZs cps h d hdInNfd
    rw [hdNotZs] at hdIsZs
    exact Bool.noConfusion hdIsZs

end Unicode.Precis.ZsPreservation
