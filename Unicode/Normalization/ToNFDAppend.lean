/-
  Unicode.Normalization.ToNFDAppend

  Lifts `ReorderAppend.reorder_append_starter_middle` to `toNFD` in two
  flavours:

  * `toNFD_append_starter_trivial` — for starters with empty canonical
    decomposition (`fullCanonicalDecompose cp = [cp]`). Proof is direct
    via `reorder_append_starter`.

  * `toNFD_append_starter_general` — for any starter not in the small
    UCD-17.0 anomaly set `{U+0F73, U+0F75, U+0F81}` (Tibetan vowel
    signs). These three rows have `CCC = 0` but canonically decompose
    to pairs beginning with U+0F71 (CCC = 129 — a non-starter),
    violating the usual UAX #15 invariant that starter decompositions
    begin with starters. The general theorem carves these out
    explicitly via `isAnomalousStarter`; for every other starter in
    Unicode, appending commutes with NFD normalization.

  Anomaly verification: intersecting the set of
  first-canonical-decomposition-elements of starter rows with the set
  of non-starter codepoints in `UnicodeData.rows` yields exactly
  `{U+0F71}`, and the rows that expose it are exactly `{U+0F73, U+0F75,
  U+0F81}`. A `decide` over the 3045-row pinned UCD table
  confirms that every other row with non-empty decomposition begins
  with a starter.

  The general form closes Case 1 (leading-starter absorb) of
  `ComposeInversion.StepPreservesNFDEquivalence` for every non-anomalous
  starter, and the trivial form handles the remaining anomalous cases
  trivially when they arrive in NFD-form input (where the anomaly's
  decomposition has already been applied).
-/

import Unicode.Normalization.ReorderAppend
import Unicode.Normalization.Distribute
import Unicode.Normalization.NFC
import Unicode.Normalization.ToNFDAppendMirror
import Unicode.Normalization.ToNFDAppendRows0
import Unicode.Normalization.ToNFDAppendRows1
import Unicode.Normalization.ToNFDAppendRows2
import Unicode.Normalization.ToNFDAppendRows3

namespace Unicode.Normalization.ToNFDAppend

open Unicode.Normalization
open Unicode.Generated

-- ═══════════════════════════════════════════════════════════════════════════════
-- REORDER ON A SINGLETON STARTER
-- ═══════════════════════════════════════════════════════════════════════════════

/-- `reorder` is the identity on a starter singleton. -/
theorem reorder_singleton_starter (cp : Nat)
    (h : Lookup.canonicalCombiningClass cp = 0) :
    Reorder.reorder [cp] = [cp] := by
  have hAppend : Reorder.reorder ([] ++ [cp]) = Reorder.reorder [] ++ [cp] :=
    ReorderAppend.reorder_append_starter [] cp h
  rw [Reorder.reorder_empty] at hAppend
  simp at hAppend
  exact hAppend

-- ═══════════════════════════════════════════════════════════════════════════════
-- TRIVIAL CASE (EMPTY CANONICAL DECOMPOSITION)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- `toNFD` on a starter with trivial canonical decomposition is the
    identity on the singleton. -/
theorem toNFD_singleton_trivial
    (cp : Nat) (hCp : Lookup.canonicalCombiningClass cp = 0)
    (hFCD : Decompose.fullCanonicalDecompose cp = [cp]) :
    NFC.toNFD [cp] = [cp] := by
  unfold NFC.toNFD
  rw [Distribute.decomposeSequence_singleton cp]
  rw [hFCD]
  exact reorder_singleton_starter cp hCp

/-- **Trivial starter-append absorbing lemma for `toNFD`.** For starters
    with empty canonical decomposition, appending commutes directly via
    `reorder_append_starter`. -/
theorem toNFD_append_starter_trivial
    (X : List Nat) (cp : Nat)
    (hCp : Lookup.canonicalCombiningClass cp = 0)
    (hFCD : Decompose.fullCanonicalDecompose cp = [cp]) :
    NFC.toNFD (X ++ [cp]) = NFC.toNFD X ++ NFC.toNFD [cp] := by
  rw [toNFD_singleton_trivial cp hCp hFCD]
  unfold NFC.toNFD
  rw [Distribute.decomposeSequence_append X [cp]]
  rw [Distribute.decomposeSequence_singleton cp]
  rw [hFCD]
  exact ReorderAppend.reorder_append_starter (Decompose.decomposeSequence X) cp hCp

-- ═══════════════════════════════════════════════════════════════════════════════
-- STARTER-HEAD PREDICATE
-- ═══════════════════════════════════════════════════════════════════════════════

/-- An array is "starter-headed" when it is non-empty and its first
    element has `ccc = 0`. -/
structure StarterHead (arr : List Nat) : Prop where
  nonEmpty : 0 < arr.length
  firstCCC : Lookup.canonicalCombiningClass (arr[0]'nonEmpty) = 0

/-- Boolean companion: returns `true` iff the array is non-empty and its
    first element is a starter. -/
def starterHeadBool (arr : List Nat) : Bool :=
  if h : 0 < arr.length then
    decide (Lookup.canonicalCombiningClass (arr[0]'h) = 0)
  else
    false

/-- The Boolean predicate reflects the `Prop` predicate. -/
theorem starterHeadBool_iff (arr : List Nat) :
    starterHeadBool arr = true ↔ StarterHead arr := by
  constructor
  · intro hB
    unfold starterHeadBool at hB
    by_cases h : 0 < arr.length
    · simp only [h, dite_true] at hB
      exact ⟨h, of_decide_eq_true hB⟩
    · simp only [h, dite_false] at hB
      exact absurd hB Bool.false_ne_true
  · intro hP
    unfold starterHeadBool
    simp only [hP.nonEmpty, dite_true]
    exact decide_eq_true hP.firstCCC

-- `anomalousStarters` / `isAnomalousStarter` are defined in `ToNFDAppendMirror`.

-- ═══════════════════════════════════════════════════════════════════════════════
-- HANGUL-RANGE INVARIANT (structural)
--
-- Every Hangul precomposed syllable decomposes L-jamo-first (an algorithmic fact,
-- `Hangul.decomposeSyllable?`), and the L-jamo range U+1100..U+1112 has combining
-- class zero (it is absent from `UnicodeData.rows`). So the head of every Hangul
-- syllable's full canonical decomposition is a starter — proven for all 11172
-- syllables without computing any decomposition.
-- ═══════════════════════════════════════════════════════════════════════════════

theorem decomposeSyllable_isSome (cp : Nat) (h : Hangul.isHangulSyllable cp = true) :
    Hangul.decomposeSyllable? cp ≠ none := by
  unfold Hangul.decomposeSyllable?
  rw [if_pos h]
  by_cases ht : (cp - Hangul.SBase) % Hangul.TCount = 0 <;> simp [ht]

theorem hangul_fcd_eq (cp : Nat) (h : Hangul.isHangulSyllable cp = true) :
    Decompose.fullCanonicalDecompose cp = (Hangul.decomposeSyllable? cp).getD [] := by
  unfold Decompose.fullCanonicalDecompose
  rw [Decompose.fullCanonicalDecomposeFuel.eq_def]
  simp only [Decompose.maxDepth]
  cases hd : Hangul.decomposeSyllable? cp with
  | some j => simp
  | none => exact absurd hd (decomposeSyllable_isSome cp h)

theorem hangul_head (cp : Nat) (h : Hangul.isHangulSyllable cp = true) :
    (Decompose.fullCanonicalDecompose cp)[0]! = Hangul.LBase + (cp - Hangul.SBase) / Hangul.NCount := by
  rw [hangul_fcd_eq cp h]
  unfold Hangul.decomposeSyllable?
  rw [if_pos h]
  by_cases ht : (cp - Hangul.SBase) % Hangul.TCount = 0 <;> simp [ht]

theorem rows_omit_lJamo :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint < 0x1100 ∨ 0x1113 ≤ r.codepoint)) = true := by
  unfold UnicodeData.rowsList; simp only [List.all_append]; decide +kernel

theorem ccc_lJamo (cp : Nat) (hlo : 0x1100 ≤ cp) (hhi : cp ≤ 0x1112) :
    Lookup.canonicalCombiningClass cp = 0 := by
  unfold Lookup.canonicalCombiningClass
  rw [Lookup.lookupRow_none_of_all_ne cp (by
    rw [List.all_eq_true]; intro r hr
    have := of_decide_eq_true (List.all_eq_true.mp rows_omit_lJamo r hr)
    exact decide_eq_true (by omega))]

theorem hangul_size_pos (cp : Nat) (h : Hangul.isHangulSyllable cp = true) :
    0 < (Decompose.fullCanonicalDecompose cp).length := by
  rw [hangul_fcd_eq cp h]
  unfold Hangul.decomposeSyllable?
  rw [if_pos h]
  by_cases ht : (cp - Hangul.SBase) % Hangul.TCount = 0 <;> simp [ht]

theorem hangul_starterHead (i : Nat) (h : i < 11172) :
    starterHeadBool (Decompose.fullCanonicalDecompose (0xAC00 + i)) = true := by
  have hSC : Hangul.SCount = 11172 := by decide
  have hNC : Hangul.NCount = 588 := by decide
  have hsyl : Hangul.isHangulSyllable (0xAC00 + i) = true := by
    unfold Hangul.isHangulSyllable
    exact decide_eq_true (by simp only [Hangul.SBase, hSC]; omega)
  have hsize := hangul_size_pos (0xAC00 + i) hsyl
  unfold starterHeadBool
  rw [dif_pos hsize, ← getElem!_pos (Decompose.fullCanonicalDecompose (0xAC00 + i)) 0 hsize,
      hangul_head (0xAC00 + i) hsyl, hNC]
  apply decide_eq_true
  apply ccc_lJamo
  · simp only [Hangul.LBase, Hangul.SBase]; omega
  · simp only [Hangul.LBase, Hangul.SBase]; omega

/-- **Hangul-range invariant.** Every Hangul precomposed syllable's fully-expanded
    canonical decomposition is starter-headed. Proven structurally: the head is the
    L-jamo `LBase + sIndex/NCount ∈ 0x1100..0x1112`, which has CCC 0. -/
theorem hangul_fullCanonicalDecompose_starterHead :
    (List.range 11172).all
      (fun i => starterHeadBool
          (Decompose.fullCanonicalDecompose (0xAC00 + i))) = true := by
  rw [List.all_eq_true]
  intro i hi
  rw [List.mem_range] at hi
  exact hangul_starterHead i hi

-- ═══════════════════════════════════════════════════════════════════════════════
-- UCD-ROW INVARIANT (structural, via a List mirror of the decomposition)
--
-- `fullCanonicalDecompose` and `fcdFuelL` both use the generated low-byte
-- UnicodeData index. Concrete row lookups reduce over one small collision bucket
-- instead of the whole table; the row invariant still reduces per chunk and the
-- per-chunk results combine to the whole table.
-- ═══════════════════════════════════════════════════════════════════════════════

-- Mirror defs (`lookupRowL`, `canonicalDecompositionL`, `fcdFuelL`,
-- `canonicalCombiningClassL`, `starterHeadBoolL`, `rowP`) are in
-- `ToNFDAppendMirror`; here we tie them back to `Lookup`/`Decompose`.
theorem lookupRow_eq_fun : Lookup.lookupRow = lookupRowL := by
  funext cp; rfl

theorem canonicalDecomposition_eq (cp : Nat) :
    Lookup.canonicalDecomposition cp = canonicalDecompositionL cp := by
  unfold Lookup.canonicalDecomposition canonicalDecompositionL
  rw [lookupRow_eq_fun]
  cases lookupRowL cp <;> rfl

theorem fcdFuelL_eq : ∀ (fuel cp : Nat),
    Decompose.fullCanonicalDecomposeFuel fuel cp = fcdFuelL fuel cp := by
  intro fuel
  induction fuel with
  | zero => intro cp; rw [Decompose.fullCanonicalDecomposeFuel, fcdFuelL]
  | succ fuel ih =>
    intro cp
    rw [Decompose.fullCanonicalDecomposeFuel, fcdFuelL]
    cases Hangul.decomposeSyllable? cp with
    | some jamo => rfl
    | none =>
      rw [← canonicalDecomposition_eq]
      by_cases he : (Lookup.canonicalDecomposition cp).isEmpty = true
      · rw [if_pos he, if_pos he]
      · rw [if_neg (by simp [he]), if_neg (by simp [he])]
        have hstep : (fun (acc : List Nat) cp' => acc ++ Decompose.fullCanonicalDecomposeFuel fuel cp')
            = (fun (acc : List Nat) cp' => acc ++ fcdFuelL fuel cp') := by
          funext acc cp'; rw [ih cp']
        rw [hstep]

theorem fullCanonicalDecompose_eq (cp : Nat) :
    Decompose.fullCanonicalDecompose cp = fcdFuelL Decompose.maxDepth cp := by
  unfold Decompose.fullCanonicalDecompose; rw [fcdFuelL_eq]

theorem canonicalCombiningClass_eq (cp : Nat) :
    Lookup.canonicalCombiningClass cp = canonicalCombiningClassL cp := by
  unfold Lookup.canonicalCombiningClass canonicalCombiningClassL
  rw [lookupRow_eq_fun]; cases lookupRowL cp <;> rfl

theorem starterHeadBool_eq (arr : List Nat) : starterHeadBool arr = starterHeadBoolL arr := by
  unfold starterHeadBool starterHeadBoolL
  by_cases h : 0 < arr.length <;> simp [h, canonicalCombiningClass_eq]

theorem origP_eq_rowP (row : UnicodeData.UnicodeDataRow) :
    (isAnomalousStarter row.codepoint
      || decide (Lookup.canonicalCombiningClass row.codepoint ≠ 0)
      || starterHeadBool (Decompose.fullCanonicalDecompose row.codepoint)) = rowP row := by
  unfold rowP
  rw [canonicalCombiningClass_eq, fullCanonicalDecompose_eq, starterHeadBool_eq]

-- The 48 per-chunk `rowP_c0..c47` facts are proven in `ToNFDAppendRows0..3`
-- (12 chunks per file) so each `decide +kernel` batch is garbage-collected
-- between compilations; `rowsList_all_rowP` below only combines them.

theorem rowsList_all_rowP : UnicodeData.rowsList.all rowP = true := by
  unfold UnicodeData.rowsList
  simp only [List.all_append, rowP_c0, rowP_c1, rowP_c2, rowP_c3, rowP_c4, rowP_c5, rowP_c6,
    rowP_c7, rowP_c8, rowP_c9, rowP_c10, rowP_c11, rowP_c12, rowP_c13, rowP_c14, rowP_c15,
    rowP_c16, rowP_c17, rowP_c18, rowP_c19, rowP_c20, rowP_c21, rowP_c22, rowP_c23, rowP_c24,
    rowP_c25, rowP_c26, rowP_c27, rowP_c28, rowP_c29, rowP_c30, rowP_c31, rowP_c32, rowP_c33,
    rowP_c34, rowP_c35, rowP_c36, rowP_c37, rowP_c38, rowP_c39, rowP_c40, rowP_c41, rowP_c42,
    rowP_c43, rowP_c44, rowP_c45, rowP_c46, rowP_c47, Bool.and_self]

/-- **UCD-row invariant.** Every starter row of `UnicodeData.rows` not in
    `anomalousStarters` has a starter-headed full canonical decomposition. Proven
    per chunk over the List mirror (`fullCanonicalDecompose_eq`), then combined. -/
theorem rows_fullCanonicalDecompose_starterHead :
    UnicodeData.rows.all (fun row =>
      isAnomalousStarter row.codepoint
        || decide (Lookup.canonicalCombiningClass row.codepoint ≠ 0)
        || starterHeadBool (Decompose.fullCanonicalDecompose row.codepoint)) = true := by
  show UnicodeData.rowsList.all (fun (row : UnicodeData.UnicodeDataRow) =>
      isAnomalousStarter row.codepoint
        || decide (Lookup.canonicalCombiningClass row.codepoint ≠ 0)
        || starterHeadBool (Decompose.fullCanonicalDecompose row.codepoint)) = true
  have hP : (fun (row : UnicodeData.UnicodeDataRow) =>
      isAnomalousStarter row.codepoint
        || decide (Lookup.canonicalCombiningClass row.codepoint ≠ 0)
        || starterHeadBool (Decompose.fullCanonicalDecompose row.codepoint)) = rowP := by
    funext row; exact origP_eq_rowP row
  rw [hP]
  exact rowsList_all_rowP

-- ═══════════════════════════════════════════════════════════════════════════════
-- POINTWISE EXTRACTION
-- ═══════════════════════════════════════════════════════════════════════════════

/-- For any starter `cp` that is not anomalous, `fullCanonicalDecompose cp`
    is starter-headed. Dispatches across three cases: cp is a Hangul
    syllable, cp appears in `UnicodeData.rows`, or cp is not in the table
    (fallback, `fullCanonicalDecompose cp = [cp]`). -/
theorem fullCanonicalDecompose_starterHead
    (cp : Nat) (hCp : Lookup.canonicalCombiningClass cp = 0)
    (hNotAnomalous : isAnomalousStarter cp = false) :
    StarterHead (Decompose.fullCanonicalDecompose cp) := by
  by_cases hHangul : Hangul.isHangulSyllable cp = true
  · -- Hangul syllable: use Hangul table
    have hRange : 0xAC00 ≤ cp ∧ cp < 0xAC00 + 11172 := by
      unfold Hangul.isHangulSyllable Hangul.SBase Hangul.SCount
             Hangul.LCount Hangul.NCount Hangul.VCount Hangul.TCount at hHangul
      exact of_decide_eq_true hHangul
    have hTable := hangul_fullCanonicalDecompose_starterHead
    rw [List.all_eq_true] at hTable
    have hI : cp - 0xAC00 ∈ List.range 11172 := List.mem_range.mpr (by omega)
    have hAtI := hTable (cp - 0xAC00) hI
    have hCpEq : 0xAC00 + (cp - 0xAC00) = cp := by omega
    rw [hCpEq] at hAtI
    exact (starterHeadBool_iff (Decompose.fullCanonicalDecompose cp)).mp hAtI
  · -- Not Hangul: consult UCD.rows
    have hNotHangulFalse : Hangul.isHangulSyllable cp = false := by
      cases hIsHangul : Hangul.isHangulSyllable cp with
      | false => rfl
      | true => exact absurd hIsHangul hHangul
    cases hLookup : Lookup.lookupRow cp with
    | none =>
      -- cp is not in the table: canonicalDecomposition = [], full decomp = [cp]
      have hDecompEmpty : Lookup.canonicalDecomposition cp = [] := by
        unfold Lookup.canonicalDecomposition
        rw [hLookup]
      have hDsyl : Hangul.decomposeSyllable? cp = none := by
        unfold Hangul.decomposeSyllable?
        rw [hNotHangulFalse]
        simp
      have hFCD : Decompose.fullCanonicalDecompose cp = [cp] := by
        show Decompose.fullCanonicalDecomposeFuel Decompose.maxDepth cp = [cp]
        unfold Decompose.maxDepth
        unfold Decompose.fullCanonicalDecomposeFuel
        rw [hDsyl]
        simp [hDecompEmpty]
      rw [hFCD]
      refine ⟨by simp, ?headCcc⟩
      have hAccess : (([cp] : List Nat)[0]'(by simp)) = cp := by simp
      rw [hAccess]
      exact hCp
    | some row =>
      -- cp is in the indexed table: use the backed rowsList source row.
      obtain ⟨src, hSrcMem, hSrcCp, _hSrcCcc, _hSrcDecomp⟩ :=
        Unicode.Generated.UnicodeDataIndex.lookupRow?_supported_rowsList hLookup
      have hRowProp := List.all_eq_true.mp rowsList_all_rowP src hSrcMem
      rw [← origP_eq_rowP src] at hRowProp
      have hCodepointEq : row.codepoint = cp :=
        Unicode.Generated.UnicodeDataIndex.lookupRow?_codepoint hLookup
      have hSrcCodepointEq : src.codepoint = cp := hSrcCp.trans hCodepointEq
      rw [hSrcCodepointEq] at hRowProp
      simp only [Bool.or_eq_true, decide_eq_true_eq, hCp, ne_eq] at hRowProp
      rcases hRowProp with hLeft | hSH
      · rcases hLeft with hAnom | hNeCcc
        · rw [hNotAnomalous] at hAnom
          exact absurd hAnom Bool.false_ne_true
        · exfalso; exact hNeCcc trivial
      · exact (starterHeadBool_iff (Decompose.fullCanonicalDecompose cp)).mp hSH

/-- Destructure a starter-headed array into a singleton head + tail. -/
theorem starterHead_destructure
    (arr : List Nat) (h : StarterHead arr) :
    ∃ (head : Nat) (tail : List Nat),
      arr = [head] ++ tail
        ∧ Lookup.canonicalCombiningClass head = 0 := by
  match arr, h with
  | [], h => exact absurd h.nonEmpty (by simp)
  | head :: rest, h =>
    exact ⟨head, rest, rfl, by simpa using h.firstCCC⟩

-- ═══════════════════════════════════════════════════════════════════════════════
-- GENERAL STARTER-APPEND ABSORBING FOR NON-ANOMALOUS STARTERS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- **Starter-append absorbing lemma for `toNFD`, general case.**
    Appending any non-anomalous starter commutes with canonical NFD
    normalization. -/
theorem toNFD_append_starter_general
    (X : List Nat) (cp : Nat)
    (hCp : Lookup.canonicalCombiningClass cp = 0)
    (hNotAnomalous : isAnomalousStarter cp = false) :
    NFC.toNFD (X ++ [cp]) = NFC.toNFD X ++ NFC.toNFD [cp] := by
  unfold NFC.toNFD
  rw [Distribute.decomposeSequence_append X [cp]]
  rw [Distribute.decomposeSequence_singleton cp]
  have hSH := fullCanonicalDecompose_starterHead cp hCp hNotAnomalous
  obtain ⟨head, tail, hEq, hHeadCCC⟩ :=
    starterHead_destructure (Decompose.fullCanonicalDecompose cp) hSH
  rw [hEq]
  rw [show Decompose.decomposeSequence X ++ ([head] ++ tail)
         = Decompose.decomposeSequence X ++ [head] ++ tail
       from by rw [List.append_assoc]]
  rw [ReorderAppend.reorder_append_starter_middle
        (Decompose.decomposeSequence X) head tail hHeadCCC]
  rw [show ([head] ++ tail : List Nat) = [] ++ [head] ++ tail
       from by simp]
  rw [ReorderAppend.reorder_append_starter_middle [] head tail hHeadCCC]
  rw [Reorder.reorder_empty]
  simp

-- ═══════════════════════════════════════════════════════════════════════════════
-- TONFD CONGRUENCE
-- ═══════════════════════════════════════════════════════════════════════════════

/-- **ToNFD congruence for trivially-decomposed starter appends.** -/
theorem toNFD_congr_append_starter_trivial
    {a b : List Nat} (cp : Nat)
    (hCp : Lookup.canonicalCombiningClass cp = 0)
    (hFCD : Decompose.fullCanonicalDecompose cp = [cp])
    (h : NFC.toNFD a = NFC.toNFD b) :
    NFC.toNFD (a ++ [cp]) = NFC.toNFD (b ++ [cp]) := by
  rw [toNFD_append_starter_trivial a cp hCp hFCD]
  rw [toNFD_append_starter_trivial b cp hCp hFCD]
  rw [h]

/-- **ToNFD congruence for non-anomalous starter appends.** -/
theorem toNFD_congr_append_starter_general
    {a b : List Nat} (cp : Nat)
    (hCp : Lookup.canonicalCombiningClass cp = 0)
    (hNotAnomalous : isAnomalousStarter cp = false)
    (h : NFC.toNFD a = NFC.toNFD b) :
    NFC.toNFD (a ++ [cp]) = NFC.toNFD (b ++ [cp]) := by
  rw [toNFD_append_starter_general a cp hCp hNotAnomalous]
  rw [toNFD_append_starter_general b cp hCp hNotAnomalous]
  rw [h]

-- ═══════════════════════════════════════════════════════════════════════════════
-- GENERAL TONFD ABSORBING-LEFT + ++-CONGRUENCE
--
-- Direct corollaries of `ReorderAppend.reorder_absorbing_left` applied
-- at the `decomposeSequence` level. These are the structural lemmas
-- that close non-starter-append cases of
-- `ComposeInversion.StepPreservesNFDEquivalence` and underpin the
-- caseFold-preserves-NFD-equivalence reduction of
-- `CaseFoldNfdCommutesSeq`.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Definitional equation for `NFC.toNFD`. Used to fold/unfold without
    pattern-match confusion. -/
theorem toNFD_eq (X : List Nat) :
    NFC.toNFD X = Reorder.reorder (Decompose.decomposeSequence X) := rfl

/-- `decomposeSequence ∘ toNFD = toNFD`. Every codepoint in `toNFD A`
    has trivial further canonical decomposition (by
    `toNFD_output_HSR_and_FullyDecomposed`), so applying
    `decomposeSequence` again is the identity (by
    `decomposeSequence_id_on_FullyDecomposed`). -/
theorem decomposeSequence_toNFD (A : List Nat) :
    Decompose.decomposeSequence (NFC.toNFD A) = NFC.toNFD A := by
  have hFD := (NFD.toNFD_output_HSR_and_FullyDecomposed A).2
  exact NFD.decomposeSequence_id_on_FullyDecomposed (NFC.toNFD A) hFD

/-- **Absorbing-left for `toNFD`.** For any arrays `A`, `B`:

        toNFD (A ++ B) = toNFD (toNFD A ++ B)

    Pre-NFD-normalizing the left operand of a concatenation produces
    the same canonical form under subsequent `toNFD`. Direct corollary
    of `ReorderAppend.reorder_absorbing_left`: unfolding `toNFD = reorder
    ∘ decomposeSequence` on both sides and distributing
    `decomposeSequence` across `++` yields a `reorder_absorbing_left`
    invocation with the `decomposeSequence` components of the inputs. -/
theorem toNFD_absorbing_left (A B : List Nat) :
    NFC.toNFD (A ++ B) = NFC.toNFD (NFC.toNFD A ++ B) := by
  rw [toNFD_eq (A ++ B), toNFD_eq (NFC.toNFD A ++ B)]
  rw [Distribute.decomposeSequence_append A B]
  rw [Distribute.decomposeSequence_append (NFC.toNFD A) B]
  rw [decomposeSequence_toNFD A]
  rw [toNFD_eq A]
  exact ReorderAppend.reorder_absorbing_left
          (Decompose.decomposeSequence A)
          (Decompose.decomposeSequence B)

/-- **ToNFD `++`-congruence.** Two arrays with equal `toNFD` form
    preserve that equality under right-concatenation with any array.
    Direct corollary of `toNFD_absorbing_left`: the lemma rewrites
    `toNFD (a ++ c)` to `toNFD (toNFD a ++ c)` and `toNFD (b ++ c)` to
    `toNFD (toNFD b ++ c)`; substituting `toNFD a = toNFD b` closes
    the goal. -/
theorem toNFD_congr_append {a b : List Nat} (c : List Nat)
    (h : NFC.toNFD a = NFC.toNFD b) :
    NFC.toNFD (a ++ c) = NFC.toNFD (b ++ c) := by
  rw [toNFD_absorbing_left a c]
  rw [toNFD_absorbing_left b c]
  rw [h]

/-- **Absorbing-right for `toNFD`.** For any arrays `A`, `B`:

        toNFD (A ++ B) = toNFD (A ++ toNFD B)

    Pre-NFD-normalizing the right operand of a concatenation produces
    the same canonical form under subsequent `toNFD`.  Direct corollary
    of `ReorderAppend.reorder_absorbing_right`: unfolding `toNFD =
    reorder ∘ decomposeSequence`, distributing `decomposeSequence`
    across `++`, and using `decomposeSequence_toNFD` on the right
    operand reduces the claim to a `reorder_absorbing_right` on the
    `decomposeSequence` components. -/
theorem toNFD_absorbing_right (A B : List Nat) :
    NFC.toNFD (A ++ B) = NFC.toNFD (A ++ NFC.toNFD B) := by
  rw [toNFD_eq (A ++ B), toNFD_eq (A ++ NFC.toNFD B)]
  rw [Distribute.decomposeSequence_append A B]
  rw [Distribute.decomposeSequence_append A (NFC.toNFD B)]
  rw [decomposeSequence_toNFD B]
  rw [toNFD_eq B]
  exact ReorderAppend.reorder_absorbing_right
          (Decompose.decomposeSequence A)
          (Decompose.decomposeSequence B)

/-- **ToNFD prepend-congruence.** Two arrays with equal `toNFD` form
    preserve that equality under left-concatenation with any array.
    Direct corollary of `toNFD_absorbing_right`: the lemma rewrites
    `toNFD (c ++ a)` to `toNFD (c ++ toNFD a)` and `toNFD (c ++ b)` to
    `toNFD (c ++ toNFD b)`; substituting `toNFD a = toNFD b` closes
    the goal.  Companion to `toNFD_congr_append`. -/
theorem toNFD_congr_prepend {a b : List Nat} (c : List Nat)
    (h : NFC.toNFD a = NFC.toNFD b) :
    NFC.toNFD (c ++ a) = NFC.toNFD (c ++ b) := by
  rw [toNFD_absorbing_right c a]
  rw [toNFD_absorbing_right c b]
  rw [h]

end Unicode.Normalization.ToNFDAppend
