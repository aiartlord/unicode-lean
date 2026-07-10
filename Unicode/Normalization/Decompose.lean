/-
  Unicode.Normalization.Decompose

  Recursive canonical decomposition per UAX #15 §3.7. For each
  codepoint, either:

    * apply the Hangul algorithmic decomposition when the codepoint
      is a precomposed syllable in `0xAC00 .. 0xD7A3`; the result is
      always a primary L/V(/T) sequence needing no further recursion.
    * look up `canonicalDecomposition` in the UnicodeData table and
      recursively decompose each target codepoint until a fixed point
      is reached.

  Recursion is fuel-bounded for trivial termination. UAX #15 guarantees
  Unicode canonical decomposition has no cycles and bounded chain
  depth (in practice ≤ 4 rounds); the fuel constant here is well above
  any known real chain.
-/

import Unicode.Normalization.Lookup
import Unicode.Normalization.Hangul
import Unicode.Generated.NormalizationLookups
import Unicode.Precis.WidthMapping

namespace Unicode.Normalization.Decompose

open Unicode.Normalization
open Unicode.Generated

set_option maxRecDepth 100000

/-- Maximum recursion depth for canonical decomposition. UAX #15
    bounds the longest real canonical decomposition chain at a small
    integer (≤ 4 for every Unicode release to date); 32 leaves a
    large safety margin. -/
def maxDepth : Nat := 32

/-- Fully canonically decompose a single codepoint, recursively until
    a fixed point. Returns the `#[cp]` singleton when the codepoint
    has no decomposition (primary character). Returns the expanded
    sequence otherwise.

    `fuel` bounds recursion depth. If exhausted, the function returns an
    empty guard result rather than emitting a possibly non-decomposed
    codepoint; this case is unreachable under the `maxDepth` default on
    any real UCD release. -/
def fullCanonicalDecomposeFuel : Nat → Nat → Array Nat
  | 0,        _cp => #[]
  | fuel + 1, cp =>
    match Hangul.decomposeSyllable? cp with
    | some jamo => jamo
    | none =>
      let step := Lookup.canonicalDecomposition cp
      if step.isEmpty then
        #[cp]
      else
        step.foldl
          (fun acc cp' => acc ++ fullCanonicalDecomposeFuel fuel cp')
          #[]

/-- Fully canonical decomposition of a single codepoint. Thin wrapper
    that fixes `fuel = maxDepth`. -/
def fullCanonicalDecompose (cp : Nat) : Array Nat :=
  fullCanonicalDecomposeFuel maxDepth cp

/-- Fully canonical decomposition of a codepoint sequence. Applies
    `fullCanonicalDecompose` to each input codepoint and concatenates
    the results in order. -/
def decomposeSequence (cps : Array Nat) : Array Nat :=
  cps.foldl (fun acc cp => acc ++ fullCanonicalDecompose cp) #[]

-- ═══════════════════════════════════════════════════════════════════════════════
-- TEST VECTORS
--
-- Evaluating `fullCanonicalDecompose` on a concrete codepoint must not
-- reduce the row scan (see the fact-transport section of
-- `Unicode.Normalization.Lookup`) and must not unfold the fuel recursion
-- eagerly — one `rw [fullCanonicalDecomposeFuel.eq_def]` exposes exactly one
-- fuel level, and the recursive occurrences inside the discarded branches
-- stay folded. Each involved codepoint's table facts are witnessed by
-- linear `List.all` / `List.any` passes, then fuel-parametric evaluation
-- lemmas compose bottom-up into the vectors.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- LATIN CAPITAL LETTER A has `CCC = 0` and no canonical decomposition,
    so the pinned NFC-relevant subset omits its row. -/
theorem rows_omit_latin_A :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint ≠ 0x0041)) = true := by
  decide +kernel

/-- LATIN SMALL LETTER H is likewise outside the pinned subset. -/
theorem rows_omit_latin_h :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint ≠ 0x0068)) = true := by
  decide +kernel

/-- LATIN SMALL LETTER E is likewise outside the pinned subset. -/
theorem rows_omit_latin_e :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint ≠ 0x0065)) = true := by
  decide +kernel

/-- LATIN SMALL LETTER L is likewise outside the pinned subset. -/
theorem rows_omit_latin_l :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint ≠ 0x006C)) = true := by
  decide +kernel

/-- LATIN SMALL LETTER O is likewise outside the pinned subset. -/
theorem rows_omit_latin_o :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint ≠ 0x006F)) = true := by
  decide +kernel

/-- U+0041 has no canonical decomposition. -/
theorem canonicalDecomposition_latin_A :
    Lookup.canonicalDecomposition 0x0041 = #[] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0x0041
    (Lookup.lookupRow_none_of_all_ne 0x0041 rows_omit_latin_A)

/-- U+0068 has no canonical decomposition. -/
theorem canonicalDecomposition_latin_h :
    Lookup.canonicalDecomposition 0x0068 = #[] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0x0068
    (Lookup.lookupRow_none_of_all_ne 0x0068 rows_omit_latin_h)

/-- U+0065 has no canonical decomposition. -/
theorem canonicalDecomposition_latin_e :
    Lookup.canonicalDecomposition 0x0065 = #[] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0x0065
    (Lookup.lookupRow_none_of_all_ne 0x0065 rows_omit_latin_e)

/-- U+006C has no canonical decomposition. -/
theorem canonicalDecomposition_latin_l :
    Lookup.canonicalDecomposition 0x006C = #[] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0x006C
    (Lookup.lookupRow_none_of_all_ne 0x006C rows_omit_latin_l)

/-- U+006F has no canonical decomposition. -/
theorem canonicalDecomposition_latin_o :
    Lookup.canonicalDecomposition 0x006F = #[] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0x006F
    (Lookup.lookupRow_none_of_all_ne 0x006F rows_omit_latin_o)

/-- The pinned table carries a row for LATIN CAPITAL LETTER A WITH GRAVE. -/
theorem rows_hit_A_grave :
    UnicodeData.rowsList.any (fun r => decide (r.codepoint = 0x00C0)) = true := by
  decide +kernel

/-- Every row carrying U+00C0 decomposes it to `A` + combining grave. -/
theorem rows_decomp_A_grave :
    UnicodeData.rowsList.all (fun r =>
      decide (r.codepoint = 0x00C0 →
        r.canonicalDecomposition = #[0x0041, 0x0300])) = true := by
  decide +kernel

/-- U+00C0 canonically decomposes to `A` + combining grave. -/
theorem canonicalDecomposition_A_grave :
    Lookup.canonicalDecomposition 0x00C0 = #[0x0041, 0x0300] :=
  Lookup.canonicalDecomposition_of_hit 0x00C0 #[0x0041, 0x0300]
    rows_hit_A_grave rows_decomp_A_grave

/-- The pinned table carries a row for LATIN CAPITAL LETTER A WITH RING
    ABOVE. -/
theorem rows_hit_A_ring :
    UnicodeData.rowsList.any (fun r => decide (r.codepoint = 0x00C5)) = true := by
  decide +kernel

/-- Every row carrying U+00C5 decomposes it to `A` + combining ring above. -/
theorem rows_decomp_A_ring :
    UnicodeData.rowsList.all (fun r =>
      decide (r.codepoint = 0x00C5 →
        r.canonicalDecomposition = #[0x0041, 0x030A])) = true := by
  decide +kernel

/-- U+00C5 canonically decomposes to `A` + combining ring above. -/
theorem canonicalDecomposition_A_ring :
    Lookup.canonicalDecomposition 0x00C5 = #[0x0041, 0x030A] :=
  Lookup.canonicalDecomposition_of_hit 0x00C5 #[0x0041, 0x030A]
    rows_hit_A_ring rows_decomp_A_ring

/-- The pinned table carries a row for ANGSTROM SIGN. -/
theorem rows_hit_angstrom :
    UnicodeData.rowsList.any (fun r => decide (r.codepoint = 0x212B)) = true := by
  decide +kernel

/-- Every row carrying U+212B decomposes it to the U+00C5 singleton. -/
theorem rows_decomp_angstrom :
    UnicodeData.rowsList.all (fun r =>
      decide (r.codepoint = 0x212B →
        r.canonicalDecomposition = #[0x00C5])) = true := by
  decide +kernel

/-- U+212B canonically decomposes to the U+00C5 singleton. -/
theorem canonicalDecomposition_angstrom :
    Lookup.canonicalDecomposition 0x212B = #[0x00C5] :=
  Lookup.canonicalDecomposition_of_hit 0x212B #[0x00C5]
    rows_hit_angstrom rows_decomp_angstrom

/-- The pinned table carries a row for COMBINING GRAVE ACCENT (for its
    non-zero CCC). -/
theorem rows_hit_grave :
    UnicodeData.rowsList.any (fun r => decide (r.codepoint = 0x0300)) = true := by
  decide +kernel

/-- Every row carrying U+0300 records an empty canonical decomposition. -/
theorem rows_decomp_grave :
    UnicodeData.rowsList.all (fun r =>
      decide (r.codepoint = 0x0300 →
        r.canonicalDecomposition = #[])) = true := by
  decide +kernel

/-- U+0300 has no canonical decomposition. -/
theorem canonicalDecomposition_grave :
    Lookup.canonicalDecomposition 0x0300 = #[] :=
  Lookup.canonicalDecomposition_of_hit 0x0300 #[]
    rows_hit_grave rows_decomp_grave

/-- The pinned table carries a row for COMBINING RING ABOVE (for its
    non-zero CCC). -/
theorem rows_hit_ring :
    UnicodeData.rowsList.any (fun r => decide (r.codepoint = 0x030A)) = true := by
  decide +kernel

/-- Every row carrying U+030A records an empty canonical decomposition. -/
theorem rows_decomp_ring :
    UnicodeData.rowsList.all (fun r =>
      decide (r.codepoint = 0x030A →
        r.canonicalDecomposition = #[])) = true := by
  decide +kernel

/-- U+030A has no canonical decomposition. -/
theorem canonicalDecomposition_ring :
    Lookup.canonicalDecomposition 0x030A = #[] :=
  Lookup.canonicalDecomposition_of_hit 0x030A #[]
    rows_hit_ring rows_decomp_ring

/-- One fuel step on `A`: no decomposition, so its own singleton. -/
theorem fcdf_latin_A (fuel : Nat) :
    fullCanonicalDecomposeFuel (fuel + 1) 0x0041 = #[0x0041] := by
  rw [fullCanonicalDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_latin_A]

/-- One fuel step on `h`: no decomposition, so its own singleton. -/
theorem fcdf_latin_h (fuel : Nat) :
    fullCanonicalDecomposeFuel (fuel + 1) 0x0068 = #[0x0068] := by
  rw [fullCanonicalDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_latin_h]

/-- One fuel step on `e`: no decomposition, so its own singleton. -/
theorem fcdf_latin_e (fuel : Nat) :
    fullCanonicalDecomposeFuel (fuel + 1) 0x0065 = #[0x0065] := by
  rw [fullCanonicalDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_latin_e]

/-- One fuel step on `l`: no decomposition, so its own singleton. -/
theorem fcdf_latin_l (fuel : Nat) :
    fullCanonicalDecomposeFuel (fuel + 1) 0x006C = #[0x006C] := by
  rw [fullCanonicalDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_latin_l]

/-- One fuel step on `o`: no decomposition, so its own singleton. -/
theorem fcdf_latin_o (fuel : Nat) :
    fullCanonicalDecomposeFuel (fuel + 1) 0x006F = #[0x006F] := by
  rw [fullCanonicalDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_latin_o]

/-- One fuel step on COMBINING GRAVE ACCENT: no decomposition, so its
    own singleton. -/
theorem fcdf_grave (fuel : Nat) :
    fullCanonicalDecomposeFuel (fuel + 1) 0x0300 = #[0x0300] := by
  rw [fullCanonicalDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_grave]

/-- One fuel step on COMBINING RING ABOVE: no decomposition, so its own
    singleton. -/
theorem fcdf_ring (fuel : Nat) :
    fullCanonicalDecomposeFuel (fuel + 1) 0x030A = #[0x030A] := by
  rw [fullCanonicalDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_ring]

/-- Two fuel steps on U+00C0: expand to `A` + grave, both terminal. -/
theorem fcdf_A_grave (fuel : Nat) :
    fullCanonicalDecomposeFuel (fuel + 2) 0x00C0 = #[0x0041, 0x0300] := by
  rw [fullCanonicalDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_A_grave, fcdf_latin_A, fcdf_grave]

/-- Two fuel steps on U+00C5: expand to `A` + ring above, both terminal. -/
theorem fcdf_A_ring (fuel : Nat) :
    fullCanonicalDecomposeFuel (fuel + 2) 0x00C5 = #[0x0041, 0x030A] := by
  rw [fullCanonicalDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_A_ring, fcdf_latin_A, fcdf_ring]

/-- Three fuel steps on ANGSTROM SIGN: the U+00C5 singleton, then its
    two-step expansion — the recursive flattening in action. -/
theorem fcdf_angstrom (fuel : Nat) :
    fullCanonicalDecomposeFuel (fuel + 3) 0x212B = #[0x0041, 0x030A] := by
  rw [fullCanonicalDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_angstrom, fcdf_A_ring]

/-- `A` (no decomposition) round-trips as its own singleton. -/
theorem decompose_latin_A :
    fullCanonicalDecompose 0x0041 = #[0x0041] :=
  fcdf_latin_A 31

/-- LATIN CAPITAL LETTER A WITH GRAVE decomposes to `A` + combining grave
    in one step. -/
theorem decompose_A_grave :
    fullCanonicalDecompose 0x00C0 = #[0x0041, 0x0300] :=
  fcdf_A_grave 30

/-- ANGSTROM SIGN decomposes in TWO steps: first to LATIN CAPITAL A WITH
    RING ABOVE (0x00C5), then to `A` + combining ring above (0x030A).
    This exercises the recursive flattening. -/
theorem decompose_angstrom :
    fullCanonicalDecompose 0x212B = #[0x0041, 0x030A] :=
  fcdf_angstrom 29

/-- HANGUL SYLLABLE GAG decomposes to `L + V + T` via the algorithmic
    path; no UnicodeData lookup involved. -/
theorem decompose_GAG :
    fullCanonicalDecompose 0xAC01 = #[0x1100, 0x1161, 0x11A8] := by decide

/-- Sequence decomposition concatenates per-codepoint decompositions. -/
theorem decompose_sequence_mixed :
    decomposeSequence #[0x0041, 0x00C0, 0x212B]
      = #[0x0041, 0x0041, 0x0300, 0x0041, 0x030A] := by
  simp only [decomposeSequence, fullCanonicalDecompose, maxDepth]
  simp [fcdf_latin_A 31, fcdf_A_grave 30, fcdf_angstrom 29]

/-- Decomposition of an empty sequence is empty. -/
theorem decompose_empty : decomposeSequence #[] = #[] := by decide

/-- Decomposition of a pure-ASCII sequence is the input unchanged. -/
theorem decompose_ascii :
    decomposeSequence #[0x0068, 0x0065, 0x006C, 0x006C, 0x006F] -- "hello"
      = #[0x0068, 0x0065, 0x006C, 0x006C, 0x006F] := by
  simp only [decomposeSequence, fullCanonicalDecompose, maxDepth]
  simp [fcdf_latin_h 31, fcdf_latin_e 31, fcdf_latin_l 31, fcdf_latin_o 31]

end Unicode.Normalization.Decompose

-- ═══════════════════════════════════════════════════════════════════════════════
-- WIDTH-COMPAT NON-INTERFERENCE
--
-- The cross-module preservation lemma: if a codepoint is not a width-compat
-- source (per the PRECIS `WidthMapping` table), its full canonical decomposition
-- output sequence contains no width-compat sources either.
--
-- Used by `Unicode.Precis.Preparation` to discharge
-- `NfcPreservesNonWidthCompatSource` through the toNFD → Reorder → Compose chain.
-- ═══════════════════════════════════════════════════════════════════════════════

namespace Unicode.Normalization.Decompose

open Unicode.Normalization
open Unicode.Generated
open Unicode.Precis.WidthMapping (isWidthCompatSource lookupWidthMapping?)

theorem isWidthCompatSource_false_of_generated_non_source
    (cp : Nat) (h : WidthCompatMappings.isSource cp = false) :
    isWidthCompatSource cp = false := by
  unfold isWidthCompatSource lookupWidthMapping?
  rw [WidthCompatMappings.lookup_none_of_non_source cp h]
  rfl

/-- Codepoints in the Hangul jamo band used by canonical decomposition
    are not width-compatibility sources. -/
theorem hangulJamo_range_non_widthCompatSource
    (cp : Nat) (hLo : 0x1100 ≤ cp) (hHi : cp < 0x11C3) :
    isWidthCompatSource cp = false := by
  have hGenerated : WidthCompatMappings.isSource cp = false := by
    simp [WidthCompatMappings.isSource]
    omega
  exact isWidthCompatSource_false_of_generated_non_source cp hGenerated

/-- Every Hangul jamo codepoint (0x1100..0x11C2) is a non-width-compat-source. -/
theorem hangulJamo_non_widthCompatSource :
    ((List.range 195).map (fun i => 0x1100 + i)).all
      (fun cp => !isWidthCompatSource cp) = true := by
  rw [List.all_eq_true]
  intro cp hCp
  rcases List.mem_map.mp hCp with ⟨i, hI, hEq⟩
  have hILt : i < 195 := List.mem_range.mp hI
  rw [← hEq]
  have hWidth :
      isWidthCompatSource (0x1100 + i) = false :=
    hangulJamo_range_non_widthCompatSource (0x1100 + i) (by omega) (by omega)
  simp [hWidth]

/-- Pointwise version of `hangulSyllable_decompose_output_non_widthCompatSource`:
    any successful `decomposeSyllable?` output contains only non-width-compat-sources.
    The proof extracts the Hangul-range membership from the hypothesis and applies
    the enumerated table fact. -/
theorem decomposeSyllable_output_non_widthCompatSource
    (cp : Nat) (arr : Array Nat)
    (h : Hangul.decomposeSyllable? cp = some arr) (j : Nat) (hj : j ∈ arr) :
    isWidthCompatSource j = false := by
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
    have hModNLt : (cp - 0xAC00) % 588 < 588 := Nat.mod_lt (cp - 0xAC00) hNPos
    have hVIndexLt : ((cp - 0xAC00) % 588) / 28 < 21 := by
      exact (Nat.div_lt_iff_lt_mul hTPos).2 (by omega)
    have hTIndexLt : (cp - 0xAC00) % 28 < 28 := Nat.mod_lt (cp - 0xAC00) hTPos
    simp only [Hangul.SBase, Hangul.LBase, Hangul.VBase, Hangul.TBase,
      Hangul.VCount, Hangul.TCount, Hangul.NCount] at h
    split at h
    · next hTZero =>
      simp only [Option.some.injEq] at h
      rw [← h] at hj
      simp only [Array.mem_def, List.mem_cons] at hj
      rcases hj with hJL | hRest
      · rw [hJL]
        apply hangulJamo_range_non_widthCompatSource
        · omega
        · omega
      · rcases hRest with hJV | hEmpty
        · rw [hJV]
          apply hangulJamo_range_non_widthCompatSource
          · omega
          · omega
        · cases hEmpty
    · next hTNonzero =>
      simp only [Option.some.injEq] at h
      rw [← h] at hj
      simp only [Array.mem_def, List.mem_cons] at hj
      have hTIndexPos : 0 < (cp - 0xAC00) % 28 := by omega
      rcases hj with hJL | hRest
      · rw [hJL]
        apply hangulJamo_range_non_widthCompatSource
        · omega
        · omega
      · rcases hRest with hJV | hRest
        · rw [hJV]
          apply hangulJamo_range_non_widthCompatSource
          · omega
          · omega
        · rcases hRest with hJT | hEmpty
          · rw [hJT]
            apply hangulJamo_range_non_widthCompatSource
            · omega
            · omega
          · cases hEmpty
  · cases h

/-- Pointwise version of `canonicalDecompTargets_non_widthCompatSource`:
    every element of `Lookup.canonicalDecomposition cp` is a non-width-compat-source.
    Does not require a hypothesis on `cp` — the property holds vacuously when
    `cp` has no canonical decomposition (empty output). -/
theorem canonicalDecomposition_output_non_widthCompatSource
    (cp : Nat) (j : Nat) (hj : j ∈ Lookup.canonicalDecomposition cp) :
    isWidthCompatSource j = false := by
  have hGenerated :
      WidthCompatMappings.isSource j = false :=
    NormalizationLookups.canonicalDecomposition_target_non_source cp j hj
  exact isWidthCompatSource_false_of_generated_non_source j hGenerated

/-- Generic: membership in a `foldl`-with-append over an array factors
    through one of the source elements. -/
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

/-- **Fuel-bounded preservation.** If the input codepoint is a non-width-compat-source,
    every codepoint in its fuel-bounded canonical decomposition is also a
    non-width-compat-source. Proven by induction on `fuel`:

    * `fuel = 0` — output is empty, so the property is vacuous.
    * `fuel + 1` — case on the Hangul / table-lookup / no-decomposition branches:
      - Hangul: output is a jamo sequence; all jamo are non-sources.
      - table lookup nonempty: output is concatenation of recursive calls on the
        canonical decomposition targets; those targets are themselves non-sources
        (by the generated canonical-decomposition certificate), so the
        inductive hypothesis gives the conclusion for each recursive call.
      - empty lookup: output is `#[cp]`, direct from the hypothesis. -/
theorem fullCanonicalDecomposeFuel_preserves_non_widthCompatSource (fuel : Nat) :
    ∀ cp, isWidthCompatSource cp = false →
    ∀ j ∈ fullCanonicalDecomposeFuel fuel cp, isWidthCompatSource j = false := by
  induction fuel with
  | zero =>
    intro cp hCp j hj
    unfold fullCanonicalDecomposeFuel at hj
    simp at hj
  | succ fuel ih =>
    intro cp hCp j hj
    unfold fullCanonicalDecomposeFuel at hj
    split at hj
    · next arr hSome =>
      exact decomposeSyllable_output_non_widthCompatSource cp arr hSome j hj
    · next hNone =>
      generalize hStep : Lookup.canonicalDecomposition cp = step at hj
      change j ∈ (if step.isEmpty = true then #[cp]
                  else step.foldl (fun acc cp' => acc ++ fullCanonicalDecomposeFuel fuel cp') #[])
        at hj
      split at hj
      · next hEmpty =>
        simp at hj
        rw [hj]
        exact hCp
      · next hNotEmpty =>
        obtain ⟨x, hxIn, hxF⟩ :=
          mem_foldl_append (fullCanonicalDecomposeFuel fuel) step j hj
        rw [← hStep] at hxIn
        have hxNonSource : isWidthCompatSource x = false :=
          canonicalDecomposition_output_non_widthCompatSource cp x hxIn
        exact ih x hxNonSource j hxF

/-- **Single-codepoint preservation.** Specialization of the fuel-bounded
    version at `fuel = maxDepth`. -/
theorem fullCanonicalDecompose_preserves_non_widthCompatSource
    (cp : Nat) (h : isWidthCompatSource cp = false) :
    ∀ j ∈ fullCanonicalDecompose cp, isWidthCompatSource j = false := by
  unfold fullCanonicalDecompose
  exact fullCanonicalDecomposeFuel_preserves_non_widthCompatSource maxDepth cp h

/-- **Sequence-level preservation.** If every input codepoint is a
    non-width-compat-source, then every output codepoint of
    `decomposeSequence` is also a non-width-compat-source. -/
theorem decomposeSequence_preserves_non_widthCompatSource
    (cps : Array Nat) (h : ∀ cp ∈ cps, isWidthCompatSource cp = false) :
    ∀ j ∈ decomposeSequence cps, isWidthCompatSource j = false := by
  intro j hj
  unfold decomposeSequence at hj
  obtain ⟨x, hxIn, hxF⟩ := mem_foldl_append fullCanonicalDecompose cps j hj
  exact fullCanonicalDecompose_preserves_non_widthCompatSource x (h x hxIn) j hxF

end Unicode.Normalization.Decompose
