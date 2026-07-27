/-
  Unicode.Normalization.DetectorFormVectors

  Concrete NFC / NFKC output vectors for the code points that the security
  detectors probe outside the ASCII identity range — the LATIN SMALL LIGATURE
  FI (U+FB01) and the decomposed Hangul jamo sequence that composes to 한.

  Each vector is established stage by stage against the witness infrastructure
  (`fcd_ligature_fi` for the compatibility expansion, `primaryComposite_fi_none`
  for the composition miss, `toNFC_id_of_starters` for the single non-composing
  starter), so no output ever forces the `UnicodeData` row scan or the
  composition-pair scan to reduce. They stand in for the per-input pipeline
  reductions that would otherwise exhaust those tables inside a `decide`.
-/

import Unicode.Normalization.NFC
import Unicode.Normalization.NFKC
import Unicode.Normalization.NFKD
import Unicode.Normalization.CompatDecompose
import Unicode.Normalization.LowCodepointNfc

namespace Unicode.Normalization.DetectorFormVectors

open Unicode.Normalization Unicode.Generated

set_option maxRecDepth 100000

-- ═══════════════════════════════════════════════════════════════════════════════
-- LATIN SMALL LIGATURE FI (U+FB01) — compatibility expansion to f + i
-- ═══════════════════════════════════════════════════════════════════════════════

/-- U+FB01 carries no `UnicodeData` row in the pinned subset. -/
theorem rows_omit_ligature_fi :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint ≠ 0xFB01)) = true := by
  decide +kernel

/-- U+FB01 has no canonical decomposition (only a compatibility one). -/
theorem canonicalDecomposition_ligature_fi :
    Lookup.canonicalDecomposition 0xFB01 = [] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0xFB01
    (Lookup.lookupRow_none_of_all_ne 0xFB01 rows_omit_ligature_fi)

/-- Two fuel steps on LATIN SMALL LIGATURE FI: the compatibility branch expands
    to `f` then `i`, both terminal. -/
theorem fcd_ligature_fi (fuel : Nat) :
    CompatDecompose.fullCompatDecomposeFuel (fuel + 2) 0xFB01 = [0x0066, 0x0069] := by
  rw [CompatDecompose.fullCompatDecomposeFuel.eq_def]
  simp [show Hangul.decomposeSyllable? 0xFB01 = none from by decide,
        canonicalDecomposition_ligature_fi,
        show CompatDecompose.compatDecomposition 0xFB01 = [0x0066, 0x0069] from by decide,
        CompatDecompose.fcd_latin_f, CompatDecompose.fcd_latin_i]

/-- U+FB01 fully compat-decomposes to lowercase f + i. -/
theorem compat_decompose_ligature_fi :
    CompatDecompose.fullCompatDecompose 0xFB01 = [0x0066, 0x0069] :=
  fcd_ligature_fi 30

-- ═══════════════════════════════════════════════════════════════════════════════
-- Reorder / compose on the f + i pair
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Reorder is the identity on the f + i starter pair. -/
theorem reorder_fi : Reorder.reorder [0x0066, 0x0069] = [0x0066, 0x0069] := by
  simp [Reorder.reorder, Reorder.stepReorder, Reorder.flushRun,
        Reorder.sortNonStarterRun, NFKD.ccc_latin_f, Reorder.ccc_latin_i]

/-- `f` and `i` do not primary-compose (there is no `fi` ligature under
    canonical composition). -/
theorem primaryComposite_fi_none :
    Compose.primaryComposite? 0x0066 0x0069 = none :=
  Compose.primaryComposite?_none_of_all_ne 0x0066 0x0069 (by decide) (by decide +kernel)

/-- Compose leaves the f + i starter pair unchanged. -/
theorem compose_fi : Compose.compose [0x0066, 0x0069] = [0x0066, 0x0069] := by
  rewrite [Compose.compose.eq_def,
           List.foldl_cons, List.foldl_cons, List.foldl_nil]
  rewrite [show Compose.stepCompose Compose.initialState 0x0066
             = { emitted := [], starter := some 0x0066, buffer := [], maxCCC := 0 } by
           rw [Compose.stepCompose.eq_def]; simp [Compose.initialState, NFKD.ccc_latin_f]]
  rewrite [show Compose.stepCompose
             { emitted := [], starter := some 0x0066, buffer := [], maxCCC := 0 } 0x0069
             = { emitted := [0x0066], starter := some 0x0069, buffer := [],
                 maxCCC := 0 } by
           rw [Compose.stepCompose.eq_def]
           simp [Reorder.ccc_latin_i, primaryComposite_fi_none]]
  rfl

-- ═══════════════════════════════════════════════════════════════════════════════
-- FI ligature — full NFC and NFKC vectors
-- ═══════════════════════════════════════════════════════════════════════════════

/-- NFC is the identity on the FI ligature: it has no canonical decomposition
    and is a lone starter, so all three stages act trivially. -/
theorem toNFC_ligature_fi : NFC.toNFC [0xFB01] = [0xFB01] :=
  LowCodepointNfc.toNFC_id_of_starters [0xFB01]
    (fun cp hMem => by
      have : cp = 0xFB01 := by simpa using hMem
      subst this
      exact ⟨canonicalDecomposition_ligature_fi, by decide⟩)
    (fun cp hMem => by
      have : cp = 0xFB01 := by simpa using hMem
      subst this
      exact Lookup.canonicalCombiningClass_of_lookupRow_none 0xFB01
        (Lookup.lookupRow_none_of_all_ne 0xFB01 rows_omit_ligature_fi))
    (by simp [Compose.noAdjCompose])

/-- NFKC folds the FI ligature to its compatibility expansion f + i. -/
theorem toNFKC_ligature_fi : NFKC.toNFKC [0xFB01] = [0x0066, 0x0069] := by
  unfold NFKC.toNFKC
  rw [show NFKD.toNFKD [0xFB01] = [0x0066, 0x0069] from by
        unfold NFKD.toNFKD
        rw [show CompatDecompose.compatDecomposeSequence [0xFB01] = [0x0066, 0x0069] from by
              simp [CompatDecompose.compatDecomposeSequence, compat_decompose_ligature_fi]]
        exact reorder_fi]
  exact compose_fi

-- ═══════════════════════════════════════════════════════════════════════════════
-- Decomposed Hangul jamo sequence 한 = ᄒ + ᅡ + ᆫ  (U+1112 U+1161 U+11AB)
-- composes to the precomposed syllable U+D55C under NFKC.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- HANGUL CHOSEONG HIEUH (U+1112) carries no `UnicodeData` row. -/
theorem rows_omit_choseong_hieuh :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint ≠ 0x1112)) = true := by
  decide +kernel

/-- HANGUL JONGSEONG NIEUN (U+11AB) carries no `UnicodeData` row. -/
theorem rows_omit_jongseong_nieun :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint ≠ 0x11AB)) = true := by
  decide +kernel

/-- U+1112 has no canonical decomposition. -/
theorem canonicalDecomposition_choseong_hieuh :
    Lookup.canonicalDecomposition 0x1112 = [] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0x1112
    (Lookup.lookupRow_none_of_all_ne 0x1112 rows_omit_choseong_hieuh)

/-- U+11AB has no canonical decomposition. -/
theorem canonicalDecomposition_jongseong_nieun :
    Lookup.canonicalDecomposition 0x11AB = [] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0x11AB
    (Lookup.lookupRow_none_of_all_ne 0x11AB rows_omit_jongseong_nieun)

/-- U+1112 fully compat-decomposes to itself (a leading jamo is a starter with
    no decomposition). -/
theorem compat_decompose_choseong_hieuh :
    CompatDecompose.fullCompatDecompose 0x1112 = [0x1112] := by
  unfold CompatDecompose.fullCompatDecompose CompatDecompose.maxDepth
  rw [CompatDecompose.fullCompatDecomposeFuel.eq_def]
  simp [show Hangul.decomposeSyllable? 0x1112 = none from by decide,
        canonicalDecomposition_choseong_hieuh,
        show CompatDecompose.compatDecomposition 0x1112 = [] from by decide]

/-- U+11AB fully compat-decomposes to itself. -/
theorem compat_decompose_jongseong_nieun :
    CompatDecompose.fullCompatDecompose 0x11AB = [0x11AB] := by
  unfold CompatDecompose.fullCompatDecompose CompatDecompose.maxDepth
  rw [CompatDecompose.fullCompatDecomposeFuel.eq_def]
  simp [show Hangul.decomposeSyllable? 0x11AB = none from by decide,
        canonicalDecomposition_jongseong_nieun,
        show CompatDecompose.compatDecomposition 0x11AB = [] from by decide]

/-- CCC of the three jamos is zero (each is a starter). -/
theorem ccc_choseong_hieuh : Lookup.canonicalCombiningClass 0x1112 = 0 :=
  Lookup.canonicalCombiningClass_of_lookupRow_none 0x1112
    (Lookup.lookupRow_none_of_all_ne 0x1112 rows_omit_choseong_hieuh)

theorem ccc_jongseong_nieun : Lookup.canonicalCombiningClass 0x11AB = 0 :=
  Lookup.canonicalCombiningClass_of_lookupRow_none 0x11AB
    (Lookup.lookupRow_none_of_all_ne 0x11AB rows_omit_jongseong_nieun)

/-- Reorder is the identity on the three-jamo run (all starters, so every
    adjacent pair satisfies the sorted-runs condition vacuously). -/
theorem reorder_jamo_han :
    Reorder.reorder [0x1112, 0x1161, 0x11AB] = [0x1112, 0x1161, 0x11AB] := by
  apply Reorder.reorder_id_on_HasSortedRuns
  refine ⟨?hieuhToJungseongA, ?jungseongAToNieun, ?singleRun⟩
  · intro hJungseongAPos
    rw [NFC.ccc_jungseong_a] at hJungseongAPos
    exact absurd hJungseongAPos (Nat.lt_irrefl 0)
  · intro hNieunPos
    rw [ccc_jongseong_nieun] at hNieunPos
    exact absurd hNieunPos (Nat.lt_irrefl 0)
  · rw [Reorder.HasSortedRuns_singleton]
    exact True.intro

/-- The three jamos compat-decompose to themselves; NFKD is the identity. -/
theorem toNFKD_jamo_han :
    NFKD.toNFKD [0x1112, 0x1161, 0x11AB] = [0x1112, 0x1161, 0x11AB] := by
  unfold NFKD.toNFKD
  rw [show CompatDecompose.compatDecomposeSequence [0x1112, 0x1161, 0x11AB]
        = [0x1112, 0x1161, 0x11AB] from by
        simp [CompatDecompose.compatDecomposeSequence,
              compat_decompose_choseong_hieuh,
              CompatDecompose.compat_decompose_jungseong_a,
              compat_decompose_jongseong_nieun]]
  exact reorder_jamo_han

/-- HIEUH + A primary-compose to the LV syllable 하 (U+D558). The Hangul
    branch of `primaryComposite?` fires on the L+V pair, so this `decide`
    is closed-form jamo arithmetic — the row scan is never consulted. -/
theorem primaryComposite_hieuh_a :
    Compose.primaryComposite? 0x1112 0x1161 = some 0xD558 := by decide

/-- 하 (U+D558) + NIEUN primary-compose to the LVT syllable 한 (U+D55C),
    again by the LV+T arm of the algorithmic Hangul composition. -/
theorem primaryComposite_ha_nieun :
    Compose.primaryComposite? 0xD558 0x11AB = some 0xD55C := by decide

/-- The three jamos primary-compose L + V → LV, then LV + T → the precomposed
    syllable U+D55C, via the algorithmic Hangul composition. -/
theorem compose_jamo_han :
    Compose.compose [0x1112, 0x1161, 0x11AB] = [0xD55C] := by
  rewrite [Compose.compose.eq_def,
           List.foldl_cons, List.foldl_cons, List.foldl_cons, List.foldl_nil]
  rewrite [show Compose.stepCompose Compose.initialState 0x1112
             = { emitted := [], starter := some 0x1112, buffer := [], maxCCC := 0 } by
           rw [Compose.stepCompose.eq_def]
           simp [Compose.initialState, ccc_choseong_hieuh]]
  rewrite [show Compose.stepCompose
             { emitted := [], starter := some 0x1112, buffer := [], maxCCC := 0 } 0x1161
             = { emitted := [], starter := some 0xD558, buffer := [], maxCCC := 0 } by
           rw [Compose.stepCompose.eq_def]
           simp [NFC.ccc_jungseong_a, primaryComposite_hieuh_a]]
  rewrite [show Compose.stepCompose
             { emitted := [], starter := some 0xD558, buffer := [], maxCCC := 0 } 0x11AB
             = { emitted := [], starter := some 0xD55C, buffer := [], maxCCC := 0 } by
           rw [Compose.stepCompose.eq_def]
           simp [ccc_jongseong_nieun, primaryComposite_ha_nieun]]
  rfl

/-- NFKC composes the decomposed jamo sequence to the precomposed syllable 한. -/
theorem toNFKC_jamo_han :
    NFKC.toNFKC [0x1112, 0x1161, 0x11AB] = [0xD55C] := by
  unfold NFKC.toNFKC
  rw [toNFKD_jamo_han]
  exact compose_jamo_han

end Unicode.Normalization.DetectorFormVectors
