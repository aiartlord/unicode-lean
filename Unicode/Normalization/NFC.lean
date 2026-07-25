/-
  Unicode.Normalization.NFC

  Top-level Normalization Form C glue. Chains the three UAX #15 stages
  on a codepoint sequence:

    toNFC = compose ∘ reorder ∘ decompose

  Also exposes two quick-check predicates keyed off
  `DerivedNormalizationProps.nfcQC`:

    * `isNFCQuickCheck` — returns `true` when every codepoint in the
      sequence has `NFC_QC = Y`; proves the sequence is already in
      NFC without running the full pipeline.
    * `isNFC`           — the definitive check: `toNFC cps = cps`.
      Used when the quick check is inconclusive (any codepoint with
      `NFC_QC = M`) or when a caller wants the full round-trip
      guarantee.

  This module operates on codepoint sequences (`Array Nat`). Byte-level
  UTF-8 wrapping lands separately once the UTF-8 encode helpers are
  confirmed against the existing `Codec.Utf8` module.
-/

import Unicode.Normalization.Decompose
import Unicode.Normalization.Reorder
import Unicode.Normalization.Compose
import Unicode.Generated.DerivedNormalizationProps
import Unicode.Precis.WidthMapping

namespace Unicode.Normalization.NFC

open Unicode.Normalization
open Unicode.Generated

set_option maxRecDepth 100000

/-- Apply the canonical decomposition and reorder stages only — NFD.
    Available here alongside `toNFC` because downstream security
    algorithms (UTS #39 Confusables skeleton) use NFD, not NFC, as
    their normalization step. -/
def toNFD (cps : List Nat) : List Nat :=
  Reorder.reorder (Decompose.decomposeSequence cps)

/-- Apply the full NFC pipeline to a codepoint sequence. -/
def toNFC (cps : List Nat) : List Nat :=
  Compose.compose (toNFD cps)

/-- Look up a codepoint's `NFC_QuickCheck` value: the first pinned range
    containing `cp` decides, and codepoints covered by no range fall
    back to the source file's `@missing` default (`Y`). A linear scan
    of the pinned ranges — they are pairwise disjoint, so scan order
    cannot change the answer. -/
def nfcQCValue (cp : Nat) : DerivedNormalizationProps.NFC_QC :=
  match DerivedNormalizationProps.nfcQC.toList.find?
      (fun t => decide (t.1 ≤ cp ∧ cp ≤ t.2.1)) with
  | some t => t.2.2
  | none => DerivedNormalizationProps.defaultNfcQC

/-- Every pinned NFC_QC range begins at or above U+0300. One linear
    kernel pass over the range table. -/
theorem nfcQC_ranges_above_0x0300 :
    DerivedNormalizationProps.nfcQC.toList.all
      (fun t => decide (0x0300 ≤ t.1)) = true := by
  decide +kernel

theorem nfcQCValue_below_first_range (cp : Nat) (h : cp < 0x0300) :
    nfcQCValue cp = DerivedNormalizationProps.defaultNfcQC := by
  unfold nfcQCValue
  have hNone : DerivedNormalizationProps.nfcQC.toList.find?
      (fun t => decide (t.1 ≤ cp ∧ cp ≤ t.2.1)) = none := by
    rw [List.find?_eq_none]
    intro t ht
    have hGe : 0x0300 ≤ t.1 :=
      of_decide_eq_true (List.all_eq_true.mp nfcQC_ranges_above_0x0300 t ht)
    intro hIn
    have hIn' := of_decide_eq_true hIn
    omega
  rw [hNone]

theorem nfcQCValue_first_range_N (cp : Nat)
    (hLo : 0x0340 ≤ cp) (hHi : cp ≤ 0x0341) :
    nfcQCValue cp = .N := by
  unfold nfcQCValue
  have hHead : DerivedNormalizationProps.nfcQC.toList.find?
      (fun t => decide (t.1 ≤ cp ∧ cp ≤ t.2.1))
      = some (0x0340, 0x0341, DerivedNormalizationProps.NFC_QC.N) := by
    have hCons : DerivedNormalizationProps.nfcQC.toList
        = (0x0340, 0x0341, DerivedNormalizationProps.NFC_QC.N)
            :: DerivedNormalizationProps.nfcQC.toList.tail := rfl
    rewrite [hCons]
    exact List.find?_cons_of_pos (decide_eq_true ⟨hLo, hHi⟩)
  rw [hHead]

/-- Every pinned row below U+0300 records `CCC = 0` — the sub-U+0300
    rows exist only for their canonical decompositions. One linear
    kernel pass over the row list. -/
theorem rows_ccc_zero_below_0x0300 :
    UnicodeData.rowsList.all (fun r =>
      decide (r.codepoint < 0x0300 →
        r.canonicalCombiningClass = 0)) = true := by
  decide +kernel

theorem ccc_below_first_nonzero_range (cp : Nat) (h : cp < 0x0300) :
    Lookup.canonicalCombiningClass cp = 0 := by
  unfold Lookup.canonicalCombiningClass
  cases hL : Lookup.lookupRow cp with
  | none => rfl
  | some row =>
    obtain ⟨src, hSrcMem, hSrcCp, hSrcCcc, _hSrcDecomp⟩ :=
      Unicode.Generated.UnicodeDataIndex.lookupRow?_supported_rowsList hL
    have hCp : row.codepoint = cp :=
      Unicode.Generated.UnicodeDataIndex.lookupRow?_codepoint hL
    have hImp : src.codepoint < 0x0300 → src.canonicalCombiningClass = 0 :=
      of_decide_eq_true
        (List.all_eq_true.mp rows_ccc_zero_below_0x0300 src hSrcMem)
    exact hSrcCcc.symm.trans (hImp (by omega))

/-- Decidable Bool analog of `Reorder.HasSortedRuns`: `true` iff every
    adjacent pair `(x, y)` with `y` a non-starter (CCC > 0) satisfies
    `CCC x ≤ CCC y`. Starters act as run boundaries; no ordering
    constraint applies when the trailing element is a starter.

    Enumerates adjacent pairs via `l.zip l.tail` — the empty-and-
    singleton cases both produce an empty zip, yielding `true`
    vacuously without a pattern-match case split. -/
def hasSortedRunsBool (l : List Nat) : Bool :=
  (l.zip l.tail).all (fun pair =>
    decide (Lookup.canonicalCombiningClass pair.2 = 0) ||
    decide (Lookup.canonicalCombiningClass pair.1
              ≤ Lookup.canonicalCombiningClass pair.2))

/-- Unfolding equation for `hasSortedRunsBool` on a non-empty cons-cons
    list, exposing the head-pair check and the recursive tail call. -/
theorem hasSortedRunsBool_cons_cons (x y : Nat) (t : List Nat) :
    hasSortedRunsBool (x :: y :: t) =
      ((decide (Lookup.canonicalCombiningClass y = 0) ||
        decide (Lookup.canonicalCombiningClass x
                  ≤ Lookup.canonicalCombiningClass y))
       && hasSortedRunsBool (y :: t)) := by
  unfold hasSortedRunsBool
  simp [List.tail_cons, List.zip_cons_cons]

/-- `hasSortedRunsBool` decides `Reorder.HasSortedRuns`: the Bool
    version returns `true` exactly when the Prop version holds. -/
theorem hasSortedRunsBool_iff_HasSortedRuns (l : List Nat) :
    hasSortedRunsBool l = true ↔ Reorder.HasSortedRuns l := by
  induction l with
  | nil =>
    exact ⟨fun x => trivial, fun x => rfl⟩
  | cons x rest ih =>
    match rest with
    | [] =>
      exact ⟨fun x => trivial, fun x => rfl⟩
    | y :: t =>
      rw [hasSortedRunsBool_cons_cons, Bool.and_eq_true,
          Reorder.HasSortedRuns_cons_cons]
      rw [Bool.or_eq_true]
      constructor
      · intro ⟨hPair, hRest⟩
        refine ⟨?fwdImpl, ih.mp hRest⟩
        intro hYccc
        rcases hPair with hZ | hLe
        · have hYZero : Lookup.canonicalCombiningClass y = 0 := of_decide_eq_true hZ
          omega
        · exact of_decide_eq_true hLe
      · intro ⟨hCond, hRest⟩
        refine ⟨?revImpl, ih.mpr hRest⟩
        by_cases hYccc : Lookup.canonicalCombiningClass y = 0
        · left; exact decide_eq_true hYccc
        · right; exact decide_eq_true (hCond (Nat.pos_of_ne_zero hYccc))

/-- Quick check per UAX #15 §A.1 full algorithm: a sequence is
    guaranteed to be in NFC when (a) every codepoint has
    `NFC_QC = Y` AND (b) the CCC values are non-decreasing within
    non-starter runs. Returns `true` on a YES-verdict, `false`
    otherwise — inconclusive (`NFC_QC = M`) or CCC-out-of-order
    cases yield `false`; callers should fall back to `isNFC` for
    the definitive answer in those situations. -/
def isNFCQuickCheck (cps : List Nat) : Bool :=
  cps.all (fun cp => decide (nfcQCValue cp = .Y)) &&
  hasSortedRunsBool cps

/-- Definitive NFC check: a sequence is in NFC iff applying the NFC
    pipeline to it is a no-op. -/
def isNFC (cps : List Nat) : Bool :=
  toNFC cps = cps

/-- Fast-path NFC normalisation: probes `isNFCQuickCheck` first and
    returns `cps` unchanged when the cheap check passes (the master
    soundness theorem `Unicode.Normalization.QuickCheckSoundnessTheorem.quickCheck_sound`
    proves this is equal to running the full pipeline). Falls back
    to the full `toNFC` only when QC fails. For input that is
    already in NFC — the dominant case in production text — this
    avoids the decompose / reorder / compose traversal entirely. -/
def toNFCQuick (cps : List Nat) : List Nat :=
  if isNFCQuickCheck cps then cps else toNFC cps

-- ═══════════════════════════════════════════════════════════════════════════════
-- TEST VECTORS
--
-- Each `toNFC` vector is evaluated stage by stage — decompose, reorder,
-- compose — through per-stage value lemmas, never by reducing the pipeline
-- whole: the decompose and compose stages consult the row and pairs tables
-- per codepoint, and those scans must only ever be witnessed by the
-- linear-pass transports (`Unicode.Normalization.Lookup`,
-- `Compose.primaryComposite?_none_of_all_ne` / `_some_of_pair`), never
-- reduced. Codepoint facts already witnessed by `Reorder` / `Decompose`
-- are reused; only the codepoints and pairs new to these vectors get
-- fresh witnesses here.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- LATIN CAPITAL LETTER H has no UnicodeData row (`CCC = 0`, no
    decomposition), so it decomposes to its own singleton. -/
theorem canonicalDecomposition_latin_H :
    Lookup.canonicalDecomposition 0x0048 = #[] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0x0048
    (Lookup.lookupRow_none_of_all_ne 0x0048 Reorder.rows_omit_latin_H)

/-- LATIN SMALL LETTER I likewise decomposes to its own singleton. -/
theorem canonicalDecomposition_latin_i :
    Lookup.canonicalDecomposition 0x0069 = #[] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0x0069
    (Lookup.lookupRow_none_of_all_ne 0x0069 Reorder.rows_omit_latin_i)

/-- Every row carrying U+0327 records an empty canonical decomposition. -/
theorem rows_decomp_cedilla :
    UnicodeData.rowsList.all (fun r =>
      decide (r.codepoint = 0x0327 →
        r.canonicalDecomposition = #[])) = true := by
  decide +kernel

/-- COMBINING CEDILLA has no canonical decomposition. -/
theorem canonicalDecomposition_cedilla :
    Lookup.canonicalDecomposition 0x0327 = #[] :=
  Lookup.canonicalDecomposition_of_hit 0x0327 #[]
    Reorder.rows_hit_cedilla rows_decomp_cedilla

/-- Every row carrying U+030A records `CCC = 230`. -/
theorem rows_ccc_ring :
    UnicodeData.rowsList.all (fun r =>
      decide (r.codepoint = 0x030A →
        r.canonicalCombiningClass = 230)) = true := by
  decide +kernel

/-- `CCC(U+030A) = 230` — COMBINING RING ABOVE. -/
theorem ccc_combining_ring : Lookup.canonicalCombiningClass 0x030A = 230 :=
  Lookup.canonicalCombiningClass_of_hit 0x030A 230
    Decompose.rows_hit_ring rows_ccc_ring

/-- HANGUL CHOSEONG KIYEOK has no UnicodeData row: jamo are starters
    with algorithmic composition only. -/
theorem rows_omit_choseong_kiyeok :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint ≠ 0x1100)) = true := by
  decide +kernel

/-- HANGUL JUNGSEONG A likewise has no UnicodeData row. -/
theorem rows_omit_jungseong_a :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint ≠ 0x1161)) = true := by
  decide +kernel

/-- `CCC(U+1100) = 0` — HANGUL CHOSEONG KIYEOK is a starter. -/
theorem ccc_choseong_kiyeok : Lookup.canonicalCombiningClass 0x1100 = 0 :=
  Lookup.canonicalCombiningClass_of_lookupRow_none 0x1100
    (Lookup.lookupRow_none_of_all_ne 0x1100 rows_omit_choseong_kiyeok)

/-- `CCC(U+1161) = 0` — HANGUL JUNGSEONG A is a starter. -/
theorem ccc_jungseong_a : Lookup.canonicalCombiningClass 0x1161 = 0 :=
  Lookup.canonicalCombiningClass_of_lookupRow_none 0x1161
    (Lookup.lookupRow_none_of_all_ne 0x1161 rows_omit_jungseong_a)

/-- U+1100 has no canonical decomposition. -/
theorem canonicalDecomposition_choseong_kiyeok :
    Lookup.canonicalDecomposition 0x1100 = #[] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0x1100
    (Lookup.lookupRow_none_of_all_ne 0x1100 rows_omit_choseong_kiyeok)

/-- U+1161 has no canonical decomposition. -/
theorem canonicalDecomposition_jungseong_a :
    Lookup.canonicalDecomposition 0x1161 = #[] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0x1161
    (Lookup.lookupRow_none_of_all_ne 0x1161 rows_omit_jungseong_a)

/-- One fuel step on `H`: no decomposition, so its own singleton. -/
theorem fcdf_latin_H (fuel : Nat) :
    Decompose.fullCanonicalDecomposeFuel (fuel + 1) 0x0048 = #[0x0048] := by
  rw [Decompose.fullCanonicalDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_latin_H]

/-- One fuel step on `i`: no decomposition, so its own singleton. -/
theorem fcdf_latin_i (fuel : Nat) :
    Decompose.fullCanonicalDecomposeFuel (fuel + 1) 0x0069 = #[0x0069] := by
  rw [Decompose.fullCanonicalDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_latin_i]

/-- One fuel step on COMBINING CEDILLA: no decomposition, so its own
    singleton. -/
theorem fcdf_cedilla (fuel : Nat) :
    Decompose.fullCanonicalDecomposeFuel (fuel + 1) 0x0327 = #[0x0327] := by
  rw [Decompose.fullCanonicalDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_cedilla]

/-- One fuel step on HANGUL CHOSEONG KIYEOK: its own singleton. -/
theorem fcdf_choseong_kiyeok (fuel : Nat) :
    Decompose.fullCanonicalDecomposeFuel (fuel + 1) 0x1100 = #[0x1100] := by
  rw [Decompose.fullCanonicalDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_choseong_kiyeok]

/-- One fuel step on HANGUL JUNGSEONG A: its own singleton. -/
theorem fcdf_jungseong_a (fuel : Nat) :
    Decompose.fullCanonicalDecomposeFuel (fuel + 1) 0x1161 = #[0x1161] := by
  rw [Decompose.fullCanonicalDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_jungseong_a]

/-- One fuel step on HANGUL SYLLABLE GA: the algorithmic LV expansion,
    no table involved. -/
theorem fcdf_hangul_GA (fuel : Nat) :
    Decompose.fullCanonicalDecomposeFuel (fuel + 1) 0xAC00
      = #[0x1100, 0x1161] := by
  rw [Decompose.fullCanonicalDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        Hangul.LBase, Hangul.VBase, Hangul.LCount, Hangul.VCount]

/-- No pairs-table entry composes `(H, i)`. -/
theorem pairs_no_H_i :
    CanonicalComposition.compositionPairs.all
      (fun t => decide (¬ (t.1 = 0x0048 ∧ t.2.1 = 0x0069))) = true := by
  decide +kernel

/-- `(H, i)` does not primary-compose. -/
theorem primaryComposite_H_i :
    Compose.primaryComposite? 0x0048 0x0069 = none :=
  Compose.primaryComposite?_none_of_all_ne 0x0048 0x0069 (by decide) pairs_no_H_i

/-- No pairs-table entry composes `(A, cedilla)`. -/
theorem pairs_no_A_cedilla :
    CanonicalComposition.compositionPairs.all
      (fun t => decide (¬ (t.1 = 0x0041 ∧ t.2.1 = 0x0327))) = true := by
  decide +kernel

/-- `(A, cedilla)` does not primary-compose. -/
theorem primaryComposite_A_cedilla :
    Compose.primaryComposite? 0x0041 0x0327 = none :=
  Compose.primaryComposite?_none_of_all_ne 0x0041 0x0327 (by decide)
    pairs_no_A_cedilla

/-- The pairs table carries the `(A, grave)` composition. -/
theorem pairs_hit_A_grave :
    CanonicalComposition.compositionPairs.any
      (fun t => decide (t.1 = 0x0041) && decide (t.2.1 = 0x0300)) = true := by
  decide +kernel

/-- Every pairs-table entry keyed `(A, grave)` composes to U+00C0. -/
theorem pairs_pin_A_grave :
    CanonicalComposition.compositionPairs.all
      (fun t => decide ((t.1 = 0x0041 ∧ t.2.1 = 0x0300) →
        t.2.2 = 0x00C0)) = true := by
  decide +kernel

/-- `(A, grave)` primary-composes to LATIN CAPITAL LETTER A WITH GRAVE. -/
theorem primaryComposite_A_grave :
    Compose.primaryComposite? 0x0041 0x0300 = some 0x00C0 :=
  Compose.primaryComposite?_some_of_pair 0x0041 0x0300 0x00C0 (by decide)
    pairs_hit_A_grave pairs_pin_A_grave

/-- The pairs table carries the `(A, ring above)` composition. -/
theorem pairs_hit_A_ring :
    CanonicalComposition.compositionPairs.any
      (fun t => decide (t.1 = 0x0041) && decide (t.2.1 = 0x030A)) = true := by
  decide +kernel

/-- Every pairs-table entry keyed `(A, ring above)` composes to U+00C5. -/
theorem pairs_pin_A_ring :
    CanonicalComposition.compositionPairs.all
      (fun t => decide ((t.1 = 0x0041 ∧ t.2.1 = 0x030A) →
        t.2.2 = 0x00C5)) = true := by
  decide +kernel

/-- `(A, ring above)` primary-composes to LATIN CAPITAL LETTER A WITH
    RING ABOVE. -/
theorem primaryComposite_A_ring :
    Compose.primaryComposite? 0x0041 0x030A = some 0x00C5 :=
  Compose.primaryComposite?_some_of_pair 0x0041 0x030A 0x00C5 (by decide)
    pairs_hit_A_ring pairs_pin_A_ring

/-- Decompose stage on "Hi": both terminal. -/
theorem decomposeSequence_ascii :
    Decompose.decomposeSequence [0x0048, 0x0069] = [0x0048, 0x0069] := by
  simp only [Decompose.decomposeSequence, Decompose.fullCanonicalDecompose,
             Decompose.maxDepth]
  simp [fcdf_latin_H 31, fcdf_latin_i 31]

/-- Decompose stage on `A + grave`: both terminal. -/
theorem decomposeSequence_A_grave_pair :
    Decompose.decomposeSequence [0x0041, 0x0300] = [0x0041, 0x0300] := by
  simp only [Decompose.decomposeSequence, Decompose.fullCanonicalDecompose,
             Decompose.maxDepth]
  simp [Decompose.fcdf_latin_A 31, Decompose.fcdf_grave 31]

/-- Decompose stage on `À`: one expansion step. -/
theorem decomposeSequence_A_grave_precomposed :
    Decompose.decomposeSequence [0x00C0] = [0x0041, 0x0300] := by
  simp only [Decompose.decomposeSequence, Decompose.fullCanonicalDecompose,
             Decompose.maxDepth]
  simp [Decompose.fcdf_A_grave 30]

/-- Decompose stage on ANGSTROM SIGN: the recursive two-step expansion. -/
theorem decomposeSequence_angstrom :
    Decompose.decomposeSequence [0x212B] = [0x0041, 0x030A] := by
  simp only [Decompose.decomposeSequence, Decompose.fullCanonicalDecompose,
             Decompose.maxDepth]
  simp [Decompose.fcdf_angstrom 29]

/-- Decompose stage on `A + grave + cedilla`: all terminal. -/
theorem decomposeSequence_A_grave_cedilla :
    Decompose.decomposeSequence [0x0041, 0x0300, 0x0327]
      = [0x0041, 0x0300, 0x0327] := by
  simp only [Decompose.decomposeSequence, Decompose.fullCanonicalDecompose,
             Decompose.maxDepth]
  simp [Decompose.fcdf_latin_A 31, Decompose.fcdf_grave 31, fcdf_cedilla 31]

/-- Decompose stage on the L+V jamo pair: both terminal. -/
theorem decomposeSequence_jamo_LV :
    Decompose.decomposeSequence [0x1100, 0x1161] = [0x1100, 0x1161] := by
  simp only [Decompose.decomposeSequence, Decompose.fullCanonicalDecompose,
             Decompose.maxDepth]
  simp [fcdf_choseong_kiyeok 31, fcdf_jungseong_a 31]

/-- Decompose stage on HANGUL SYLLABLE GA: the algorithmic expansion. -/
theorem decomposeSequence_hangul_GA :
    Decompose.decomposeSequence [0xAC00] = [0x1100, 0x1161] := by
  simp only [Decompose.decomposeSequence, Decompose.fullCanonicalDecompose,
             Decompose.maxDepth]
  simp [fcdf_hangul_GA 31]

/-- Reorder stage on `A + grave`: already in canonical order. -/
theorem reorder_A_grave :
    Reorder.reorder [0x0041, 0x0300] = [0x0041, 0x0300] := by
  simp [Reorder.reorder, Reorder.stepReorder, Reorder.flushRun,
        Reorder.sortNonStarterRun, Reorder.insertByCCC,
        Reorder.ccc_latin_A, Reorder.ccc_combining_grave]

/-- Reorder stage on `A + ring above`: already in canonical order. -/
theorem reorder_A_ring :
    Reorder.reorder [0x0041, 0x030A] = [0x0041, 0x030A] := by
  simp [Reorder.reorder, Reorder.stepReorder, Reorder.flushRun,
        Reorder.sortNonStarterRun, Reorder.insertByCCC,
        Reorder.ccc_latin_A, ccc_combining_ring]

/-- Reorder stage on the L+V jamo pair: starters pass through. -/
theorem reorder_jamo_LV :
    Reorder.reorder [0x1100, 0x1161] = [0x1100, 0x1161] := by
  simp [Reorder.reorder, Reorder.stepReorder, Reorder.flushRun,
        Reorder.sortNonStarterRun, ccc_choseong_kiyeok, ccc_jungseong_a]

/-- One compose step: `H` registers as the active starter. -/
theorem stepCompose_init_H :
    Compose.stepCompose Compose.initialState 0x0048
      = { emitted := #[], starter := some 0x0048, buffer := [], maxCCC := 0 } := by
  rw [Compose.stepCompose.eq_def]
  simp [Compose.initialState, Reorder.ccc_latin_H]

/-- One compose step: `i` after `H` — no composition, `H` emits and `i`
    takes over as starter. -/
theorem stepCompose_H_i :
    Compose.stepCompose
      { emitted := #[], starter := some 0x0048, buffer := [], maxCCC := 0 } 0x0069
      = { emitted := #[0x0048], starter := some 0x0069, buffer := [],
          maxCCC := 0 } := by
  rw [Compose.stepCompose.eq_def]
  simp [Reorder.ccc_latin_i, primaryComposite_H_i]

/-- One compose step: `A` registers as the active starter. -/
theorem stepCompose_init_A :
    Compose.stepCompose Compose.initialState 0x0041
      = { emitted := #[], starter := some 0x0041, buffer := [], maxCCC := 0 } := by
  rw [Compose.stepCompose.eq_def]
  simp [Compose.initialState, Reorder.ccc_latin_A]

/-- One compose step: grave after `A` primary-composes to `À`. -/
theorem stepCompose_A_grave :
    Compose.stepCompose
      { emitted := #[], starter := some 0x0041, buffer := [], maxCCC := 0 } 0x0300
      = { emitted := #[], starter := some 0x00C0, buffer := [], maxCCC := 0 } := by
  rw [Compose.stepCompose.eq_def]
  simp [Reorder.ccc_combining_grave, primaryComposite_A_grave]

/-- One compose step: ring above after `A` primary-composes to `Å`. -/
theorem stepCompose_A_ring :
    Compose.stepCompose
      { emitted := #[], starter := some 0x0041, buffer := [], maxCCC := 0 } 0x030A
      = { emitted := #[], starter := some 0x00C5, buffer := [], maxCCC := 0 } := by
  rw [Compose.stepCompose.eq_def]
  simp [ccc_combining_ring, primaryComposite_A_ring]

/-- One compose step: cedilla after `A` — no `A+cedilla` form, so it
    buffers. -/
theorem stepCompose_A_cedilla :
    Compose.stepCompose
      { emitted := #[], starter := some 0x0041, buffer := [], maxCCC := 0 } 0x0327
      = { emitted := #[], starter := some 0x0041, buffer := [0x0327],
          maxCCC := 202 } := by
  rw [Compose.stepCompose.eq_def]
  simp [Reorder.ccc_combining_cedilla, primaryComposite_A_cedilla]

/-- One compose step: grave past the buffered cedilla (CCC 230 > 202)
    still reaches the starter and composes to `À`. -/
theorem stepCompose_A_cedilla_grave :
    Compose.stepCompose
      { emitted := #[], starter := some 0x0041, buffer := [0x0327],
        maxCCC := 202 } 0x0300
      = { emitted := #[], starter := some 0x00C0, buffer := [0x0327],
          maxCCC := 202 } := by
  rw [Compose.stepCompose.eq_def]
  simp [Reorder.ccc_combining_grave, primaryComposite_A_grave]

/-- One compose step: HANGUL CHOSEONG KIYEOK registers as starter. -/
theorem stepCompose_init_choseong :
    Compose.stepCompose Compose.initialState 0x1100
      = { emitted := #[], starter := some 0x1100, buffer := [], maxCCC := 0 } := by
  rw [Compose.stepCompose.eq_def]
  simp [Compose.initialState, ccc_choseong_kiyeok]

/-- One compose step: JUNGSEONG A after CHOSEONG KIYEOK composes
    algorithmically to HANGUL SYLLABLE GA. -/
theorem stepCompose_LV :
    Compose.stepCompose
      { emitted := #[], starter := some 0x1100, buffer := [], maxCCC := 0 } 0x1161
      = { emitted := #[], starter := some 0xAC00, buffer := [], maxCCC := 0 } := by
  rw [Compose.stepCompose.eq_def]
  simp [ccc_jungseong_a, Compose.primary_hangul_LV]

/-- Compose stage on "Hi": nothing composes. -/
theorem compose_ascii :
    Compose.compose [0x0048, 0x0069] = [0x0048, 0x0069] := by
  rewrite [Compose.compose.eq_def]
  rewrite [List.foldl_cons, List.foldl_cons, List.foldl_nil]
  rewrite [stepCompose_init_H, stepCompose_H_i]
  rfl

/-- Compose stage on `A + grave`: the pair composes to `À`. -/
theorem compose_A_grave :
    Compose.compose [0x0041, 0x0300] = [0x00C0] := by
  rewrite [Compose.compose.eq_def]
  rewrite [List.foldl_cons, List.foldl_cons, List.foldl_nil]
  rewrite [stepCompose_init_A, stepCompose_A_grave]
  rfl

/-- Compose stage on `A + ring above`: the pair composes to `Å`. -/
theorem compose_A_ring :
    Compose.compose [0x0041, 0x030A] = [0x00C5] := by
  rewrite [Compose.compose.eq_def]
  rewrite [List.foldl_cons, List.foldl_cons, List.foldl_nil]
  rewrite [stepCompose_init_A, stepCompose_A_ring]
  rfl

/-- Compose stage on `A + cedilla + grave`: cedilla buffers (no
    `A+cedilla` form), grave still reaches the starter and composes. -/
theorem compose_A_cedilla_grave :
    Compose.compose [0x0041, 0x0327, 0x0300] = [0x00C0, 0x0327] := by
  rewrite [Compose.compose.eq_def]
  rewrite [List.foldl_cons, List.foldl_cons, List.foldl_cons, List.foldl_nil]
  rewrite [stepCompose_init_A, stepCompose_A_cedilla,
           stepCompose_A_cedilla_grave]
  rfl

/-- Compose stage on the L+V jamo pair: algorithmic composition to GA. -/
theorem compose_jamo_LV :
    Compose.compose [0x1100, 0x1161] = [0xAC00] := by
  rewrite [Compose.compose.eq_def]
  rewrite [List.foldl_cons, List.foldl_cons, List.foldl_nil]
  rewrite [stepCompose_init_choseong, stepCompose_LV]
  rfl

/-- Empty sequence. -/
theorem toNFC_empty : toNFC [] = [] := by decide
theorem isNFC_empty : isNFC [] = true := by decide

/-- Pure ASCII is always in NFC. -/
theorem toNFC_ascii :
    toNFC [0x0048, 0x0069] = [0x0048, 0x0069] := by  -- "Hi"
  rewrite [toNFC.eq_def, toNFD.eq_def]
  rw [decomposeSequence_ascii, Reorder.reorder_ascii, compose_ascii]
theorem isNFC_ascii : isNFC [0x0048, 0x0069] = true := by
  rewrite [isNFC.eq_def]
  rewrite [toNFC_ascii]
  decide

/-- Decomposed form reduces to precomposed under NFC. -/
theorem toNFC_composes_A_grave :
    toNFC [0x0041, 0x0300] = [0x00C0] := by
  rewrite [toNFC.eq_def, toNFD.eq_def]
  rw [decomposeSequence_A_grave_pair, reorder_A_grave, compose_A_grave]

/-- Precomposed form is already in NFC (decomposes then recomposes). -/
theorem toNFC_idempotent_on_A_grave :
    toNFC [0x00C0] = [0x00C0] := by
  rewrite [toNFC.eq_def, toNFD.eq_def]
  rw [decomposeSequence_A_grave_precomposed, reorder_A_grave, compose_A_grave]
theorem isNFC_A_grave : isNFC [0x00C0] = true := by
  rewrite [isNFC.eq_def]
  rewrite [toNFC_idempotent_on_A_grave]
  decide

-- ── `é` (e + combining acute) family ────────────────────────────────────────────
-- The single canonical-composition vector the K2 hash-input detector needs,
-- proved structurally through the decompose / reorder / compose stages so the
-- `toNFC` pipeline is never reduced in the kernel.

/-- `CCC(U+0065) = 0` — LATIN SMALL LETTER E is a starter. -/
theorem ccc_latin_e : Lookup.canonicalCombiningClass 0x0065 = 0 :=
  Lookup.canonicalCombiningClass_of_lookupRow_none 0x0065
    (Lookup.lookupRow_none_of_all_ne 0x0065 Decompose.rows_omit_latin_e)

/-- The pairs table carries the `(e, acute)` composition. -/
theorem pairs_hit_e_acute :
    CanonicalComposition.compositionPairs.any
      (fun t => decide (t.1 = 0x0065) && decide (t.2.1 = 0x0301)) = true := by
  decide +kernel

/-- Every pairs-table entry keyed `(e, acute)` composes to U+00E9. -/
theorem pairs_pin_e_acute :
    CanonicalComposition.compositionPairs.all
      (fun t => decide ((t.1 = 0x0065 ∧ t.2.1 = 0x0301) →
        t.2.2 = 0x00E9)) = true := by
  decide +kernel

/-- `(e, acute)` primary-composes to LATIN SMALL LETTER E WITH ACUTE. -/
theorem primaryComposite_e_acute :
    Compose.primaryComposite? 0x0065 0x0301 = some 0x00E9 :=
  Compose.primaryComposite?_some_of_pair 0x0065 0x0301 0x00E9 (by decide)
    pairs_hit_e_acute pairs_pin_e_acute

/-- One compose step: `e` registers as the active starter. -/
theorem stepCompose_init_e :
    Compose.stepCompose Compose.initialState 0x0065
      = { emitted := #[], starter := some 0x0065, buffer := [], maxCCC := 0 } := by
  rw [Compose.stepCompose.eq_def]
  simp [Compose.initialState, ccc_latin_e]

/-- One compose step: acute after `e` primary-composes to `é`. -/
theorem stepCompose_e_acute :
    Compose.stepCompose
      { emitted := #[], starter := some 0x0065, buffer := [], maxCCC := 0 } 0x0301
      = { emitted := #[], starter := some 0x00E9, buffer := [], maxCCC := 0 } := by
  rw [Compose.stepCompose.eq_def]
  simp [Reorder.ccc_combining_acute, primaryComposite_e_acute]

/-- Decompose stage on `e + acute`: both terminal. -/
theorem decomposeSequence_e_acute_pair :
    Decompose.decomposeSequence [0x0065, 0x0301] = [0x0065, 0x0301] := by
  simp only [Decompose.decomposeSequence, Decompose.fullCanonicalDecompose,
             Decompose.maxDepth]
  simp [Decompose.fcdf_latin_e 31, Decompose.fcdf_acute 31]

/-- Decompose stage on `é`: one expansion step. -/
theorem decomposeSequence_e_acute_precomposed :
    Decompose.decomposeSequence [0x00E9] = [0x0065, 0x0301] := by
  simp only [Decompose.decomposeSequence, Decompose.fullCanonicalDecompose,
             Decompose.maxDepth]
  simp [Decompose.fcdf_e_acute 30]

/-- Reorder stage on `e + acute`: already in canonical order. -/
theorem reorder_e_acute :
    Reorder.reorder [0x0065, 0x0301] = [0x0065, 0x0301] := by
  simp [Reorder.reorder, Reorder.stepReorder, Reorder.flushRun,
        Reorder.sortNonStarterRun, Reorder.insertByCCC,
        ccc_latin_e, Reorder.ccc_combining_acute]

/-- Compose stage on `e + acute`: the pair composes to `é`. -/
theorem compose_e_acute :
    Compose.compose [0x0065, 0x0301] = [0x00E9] := by
  rewrite [Compose.compose.eq_def]
  rewrite [List.foldl_cons, List.foldl_cons, List.foldl_nil]
  rewrite [stepCompose_init_e, stepCompose_e_acute]
  rfl

/-- Decomposed `é` reduces to precomposed U+00E9 under NFC. -/
theorem toNFC_e_acute :
    toNFC [0x0065, 0x0301] = [0x00E9] := by
  rewrite [toNFC.eq_def, toNFD.eq_def]
  rw [decomposeSequence_e_acute_pair, reorder_e_acute, compose_e_acute]

/-- Precomposed `é` (U+00E9) is already in NFC: it decomposes to
    `e` + acute and recomposes to itself. -/
theorem toNFC_e_acute_precomposed :
    toNFC [0x00E9] = [0x00E9] := by
  rewrite [toNFC.eq_def, toNFD.eq_def]
  rw [decomposeSequence_e_acute_precomposed, reorder_e_acute, compose_e_acute]

/-- ANGSTROM SIGN is NOT in NFC — its canonical decomposition recomposes
    to `LATIN CAPITAL A WITH RING ABOVE` (0x00C5), not back to ANGSTROM
    (0x212B is a Full_Composition_Exclusion). -/
theorem toNFC_angstrom_to_A_ring :
    toNFC [0x212B] = [0x00C5] := by
  rewrite [toNFC.eq_def, toNFD.eq_def]
  rw [decomposeSequence_angstrom, reorder_A_ring, compose_A_ring]

/-- Out-of-order combining marks get reordered during the NFC pipeline. -/
theorem toNFC_reorders_then_composes :
    -- A + grave (230) + cedilla (202) →
    --   decompose: A + grave + cedilla (no change, no decompositions)
    --   reorder:   A + cedilla + grave (cedilla CCC=202 < grave CCC=230)
    --   compose:   A + cedilla first — no A+cedilla precomposed form
    --              keep A as starter, buffer cedilla
    --              then grave (CCC=230 > 202 buffered) — can it compose?
    --              primaryComposite?(A, grave) = À; starter := À
    --   output: À + cedilla
    toNFC [0x0041, 0x0300, 0x0327] = [0x00C0, 0x0327] := by
  rewrite [toNFC.eq_def, toNFD.eq_def]
  rw [decomposeSequence_A_grave_cedilla, Reorder.reorder_swap,
      compose_A_cedilla_grave]

/-- Hangul: decomposed jamo LV compose to the precomposed syllable. -/
theorem toNFC_hangul_compose :
    toNFC [0x1100, 0x1161] = [0xAC00] := by
  rewrite [toNFC.eq_def, toNFD.eq_def]
  rw [decomposeSequence_jamo_LV, reorder_jamo_LV, compose_jamo_LV]

/-- Hangul: precomposed syllable is already in NFC. Decomposes to jamo,
    reorders (no-op for starters), recomposes back. -/
theorem toNFC_hangul_idempotent :
    toNFC [0xAC00] = [0xAC00] := by
  rewrite [toNFC.eq_def, toNFD.eq_def]
  rw [decomposeSequence_hangul_GA, reorder_jamo_LV, compose_jamo_LV]
theorem isNFC_hangul : isNFC [0xAC00] = true := by
  rewrite [isNFC.eq_def]
  rewrite [toNFC_hangul_idempotent]
  decide

/-- `isNFCQuickCheck` is conservative: pure ASCII and standalone
    precomposed `À` both have `NFC_QC = Y` and the quick check
    returns `true`. -/
theorem quickCheck_ascii : isNFCQuickCheck [0x0048, 0x0069] = true := by
  have hH : nfcQCValue 0x0048 = .Y :=
    nfcQCValue_below_first_range 0x0048 (by decide)
  have hI : nfcQCValue 0x0069 = .Y :=
    nfcQCValue_below_first_range 0x0069 (by decide)
  have hHccc : Lookup.canonicalCombiningClass 0x0048 = 0 :=
    ccc_below_first_nonzero_range 0x0048 (by decide)
  have hIccc : Lookup.canonicalCombiningClass 0x0069 = 0 :=
    ccc_below_first_nonzero_range 0x0069 (by decide)
  have hSorted : hasSortedRunsBool [0x0048, 0x0069] = true := by
    unfold hasSortedRunsBool
    simp [hHccc, hIccc]
  unfold isNFCQuickCheck
  simp [hH, hI, hSorted]

/-- `isNFCQuickCheck` returns `false` for `NFC_QC = N` input — a
    codepoint that definitely needs normalization. COMBINING GRAVE
    TONE MARK (U+0340) has `NFC_QC = N` per the pinned tables. -/
theorem quickCheck_nfc_N : isNFCQuickCheck [0x0340] = false := by
  have hN : nfcQCValue 0x0340 = .N :=
    nfcQCValue_first_range_N 0x0340 (by decide) (by decide)
  simp [isNFCQuickCheck, hN]

/-- `nfcQCValue` default: `A` has `NFC_QC = Y` (not listed in the
    pinned table; falls back to the `defaultNfcQC`). -/
theorem nfcQC_default_ascii : nfcQCValue 0x0041 = .Y := by decide

/-- `nfcQCValue` explicit: U+0340 is listed with `NFC_QC = N`. -/
theorem nfcQC_explicit_N : nfcQCValue 0x0340 = .N := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- WIDTH-COMPAT NON-INTERFERENCE
--
-- Canonical Normalization Form C preserves the PRECIS non-width-compat-source
-- property. Composed from stage-wise preservation lemmas in Decompose, Reorder,
-- and Compose, each of which lifts its stage's table-level non-width-compat-source
-- fact (Hangul jamo / UnicodeData canonical decomposition targets / Hangul
-- syllable range) through its respective foldl.
--
-- Used by `Unicode.Precis.Preparation` to discharge
-- `NfcPreservesNonWidthCompatSource` unconditionally.
-- ═══════════════════════════════════════════════════════════════════════════════

section WidthCompatPreservation

open Unicode.Precis.WidthMapping (isWidthCompatSource)

/-- **NFD preserves non-width-compat-source.** The decompose+reorder stages
    together never introduce width-compat-source codepoints into the output. -/
theorem toNFD_preserves_non_widthCompatSource
    (cps : List Nat) (h : ∀ cp ∈ cps, isWidthCompatSource cp = false) :
    ∀ j ∈ toNFD cps, isWidthCompatSource j = false := by
  unfold toNFD
  intro j hj
  have hDecAll : ∀ cp ∈ Decompose.decomposeSequence cps,
                   (fun x => !isWidthCompatSource x) cp = true := by
    intro cp hcp
    have := Decompose.decomposeSequence_preserves_non_widthCompatSource cps h cp hcp
    simpa using this
  have hR := Reorder.reorder_preserves_all (fun x => !isWidthCompatSource x)
               (Decompose.decomposeSequence cps) hDecAll j hj
  simpa using hR

/-- **NFC preserves non-width-compat-source.** Pipelines decompose → reorder →
    compose — each stage has its own preservation lemma, this theorem composes
    them. -/
theorem toNFC_preserves_non_widthCompatSource
    (cps : List Nat) (h : ∀ cp ∈ cps, isWidthCompatSource cp = false) :
    ∀ j ∈ toNFC cps, isWidthCompatSource j = false := by
  unfold toNFC
  exact Compose.compose_preserves_non_widthCompatSource (toNFD cps)
    (toNFD_preserves_non_widthCompatSource cps h)

end WidthCompatPreservation

end Unicode.Normalization.NFC
