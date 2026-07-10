/-
  Unicode.Normalization.NFKC

  Normalization Form KC (compatibility decomposition + canonical
  reordering + canonical composition) per UAX #15 §1.3:

    toNFKC = compose ∘ toNFKD = compose ∘ reorder ∘ compatDecomposeSequence

  Parallel to `Unicode.Normalization.NFC` with the compatibility
  decomposition pipeline as the first stage. Composition is canonical
  in both NFC and NFKC: only canonical decompositions recompose under
  primary composition. Compatibility decomposition targets that have
  no canonical recomposition stay in their decomposed form.

  Quick-check is keyed off `DerivedNormalizationProps.nfkcQC`:

    * `isNFKCQuickCheck` — returns `true` when every codepoint has
      `NFKC_QC = Y` AND combining marks are in non-decreasing CCC
      order within each non-starter run; proves the sequence is
      already in NFKC without running the full pipeline.
    * `isNFKC`           — the definitive check: `toNFKC cps = cps`.
      Used when the quick check is inconclusive (any codepoint with
      `NFKC_QC = M`) or when a caller wants the full round-trip
      guarantee.
-/

import Unicode.Normalization.NFKD
import Unicode.Normalization.NFC
import Unicode.Normalization.Compose
import Unicode.Generated.DerivedNormalizationProps

namespace Unicode.Normalization.NFKC

open Unicode.Normalization
open Unicode.Generated

/-- Apply the full NFKC pipeline to a codepoint sequence. -/
def toNFKC (cps : Array Nat) : Array Nat :=
  Compose.compose (NFKD.toNFKD cps)

/-- Look up a codepoint's `NFKC_QuickCheck` value. Falls back to the
    source file's `@missing` default (`Y`) when the codepoint is not
    covered by any explicit range. -/
def nfkcQCValue (cp : Nat) : DerivedNormalizationProps.NFC_QC :=
  match DerivedNormalizationProps.nfkcQC.toList.findSome?
          (fun ⟨min, max, v⟩ => if min ≤ cp ∧ cp ≤ max then some v else none) with
  | some v => v
  | none   => DerivedNormalizationProps.defaultNfkcQC

/-- Quick check per UAX #15 Annex 8: a sequence is guaranteed to be in
    NFKC when (a) every codepoint has `NFKC_QC = Y` AND (b) CCC values
    are non-decreasing within non-starter runs. Returns `true` on a
    YES-verdict, `false` otherwise (inconclusive `M` or out-of-order
    cases). The HSR check reuses `NFC.hasSortedRunsBool` because the
    canonical reorder stage is identical to NFC's. -/
def isNFKCQuickCheck (cps : Array Nat) : Bool :=
  cps.all (fun cp => decide (nfkcQCValue cp = .Y)) &&
  NFC.hasSortedRunsBool cps.toList

/-- Definitive NFKC check: a sequence is in NFKC iff applying the NFKC
    pipeline to it is a no-op. -/
def isNFKC (cps : Array Nat) : Bool :=
  toNFKC cps = cps

set_option maxRecDepth 100000

-- ═══════════════════════════════════════════════════════════════════════════════
-- TEST VECTORS
--
-- Each `toNFKC` vector is `compose ∘ NFKD.toNFKD`: reuse the staged NFKD
-- value, then the compose stage — so the UnicodeData row scan is never
-- reduced (see the fact-transport section of
-- `Unicode.Normalization.Lookup`). The `nfkcQCValue` vectors reduce a
-- `findSome?` over the small materialized NFKC_QC range table, which
-- `decide +kernel` walks linearly.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Canonical composition is the identity on a lone starter. -/
theorem compose_single_starter (cp : Nat)
    (h : Lookup.canonicalCombiningClass cp = 0) :
    Compose.compose #[cp] = #[cp] := by
  rewrite [Compose.compose.eq_def, ← Array.foldl_toList, List.toList_toArray,
           List.foldl_cons, List.foldl_nil]
  rewrite [show Compose.stepCompose Compose.initialState cp
             = { emitted := #[], starter := some cp, buffer := [], maxCCC := 0 } by
           rw [Compose.stepCompose.eq_def]; simp [Compose.initialState, h]]
  rfl

/-- `(f, f)` does not primary-compose — there is no LATIN SMALL LIGATURE
    FF recomposition. -/
theorem primaryComposite_ff_none :
    Compose.primaryComposite? 0x0066 0x0066 = none :=
  Compose.primaryComposite?_none_of_all_ne 0x0066 0x0066 (by decide) (by decide +kernel)

/-- Compose leaves two `f` starters unchanged (no ligature recomposition). -/
theorem compose_ff : Compose.compose #[0x0066, 0x0066] = #[0x0066, 0x0066] := by
  rewrite [Compose.compose.eq_def, ← Array.foldl_toList, List.toList_toArray,
           List.foldl_cons, List.foldl_cons, List.foldl_nil]
  rewrite [show Compose.stepCompose Compose.initialState 0x0066
             = { emitted := #[], starter := some 0x0066, buffer := [], maxCCC := 0 } by
           rw [Compose.stepCompose.eq_def]; simp [Compose.initialState, NFKD.ccc_latin_f]]
  rewrite [show Compose.stepCompose
             { emitted := #[], starter := some 0x0066, buffer := [], maxCCC := 0 } 0x0066
             = { emitted := #[0x0066], starter := some 0x0066, buffer := [],
                 maxCCC := 0 } by
           rw [Compose.stepCompose.eq_def]
           simp [NFKD.ccc_latin_f, primaryComposite_ff_none]]
  rfl

/-- Empty sequence. -/
theorem toNFKC_empty : toNFKC #[] = #[] := by decide

/-- Pure ASCII is in NFKC unchanged. -/
theorem toNFKC_ascii :
    toNFKC #[0x0048, 0x0069] = #[0x0048, 0x0069] := by  -- "Hi"
  unfold toNFKC
  rw [NFKD.toNFKD_ascii]
  exact NFC.compose_ascii

/-- Decomposed → precomposed under canonical composition (same as NFC). -/
theorem toNFKC_composes_A_grave :
    toNFKC #[0x0041, 0x0300] = #[0x00C0] := by
  unfold toNFKC
  rw [show NFKD.toNFKD #[0x0041, 0x0300] = #[0x0041, 0x0300] from by
        unfold NFKD.toNFKD
        rw [show CompatDecompose.compatDecomposeSequence #[0x0041, 0x0300]
              = #[0x0041, 0x0300] from by
              simp [CompatDecompose.compatDecomposeSequence,
                    CompatDecompose.compat_decompose_latin_A,
                    CompatDecompose.compat_decompose_grave]]
        exact NFC.reorder_A_grave]
  exact NFC.compose_A_grave

/-- SUPERSCRIPT TWO U+00B2 → U+0032 under NFKC. The compat decomposition
    target (DIGIT TWO) has no canonical composition back to U+00B2, so
    the output stays decomposed. -/
theorem toNFKC_super_2 :
    toNFKC #[0x00B2] = #[0x0032] := by
  unfold toNFKC
  rw [NFKD.toNFKD_decomposes_super_2]
  exact compose_single_starter 0x0032 NFKD.ccc_digit_2

/-- NO-BREAK SPACE U+00A0 → SPACE U+0020 under NFKC. -/
theorem toNFKC_nbsp :
    toNFKC #[0x00A0] = #[0x0020] := by
  unfold toNFKC
  rw [NFKD.toNFKD_nbsp]
  exact compose_single_starter 0x0020 NFKD.ccc_space

/-- LATIN SMALL LIGATURE FF (U+FB00) → "ff" (lowercase) under NFKC. -/
theorem toNFKC_ligature_ff :
    toNFKC #[0xFB00] = #[0x0066, 0x0066] := by
  unfold toNFKC
  rw [NFKD.toNFKD_ligature_ff]
  exact compose_ff

/-- HANGUL: decomposed jamo LV recompose to the precomposed syllable. -/
theorem toNFKC_hangul :
    toNFKC #[0x1100, 0x1161] = #[0xAC00] := by
  unfold toNFKC
  rw [show NFKD.toNFKD #[0x1100, 0x1161] = #[0x1100, 0x1161] from by
        unfold NFKD.toNFKD
        rw [show CompatDecompose.compatDecomposeSequence #[0x1100, 0x1161]
              = #[0x1100, 0x1161] from by
              simp [CompatDecompose.compatDecomposeSequence,
                    CompatDecompose.compat_decompose_choseong_kiyeok,
                    CompatDecompose.compat_decompose_jungseong_a]]
        exact NFC.reorder_jamo_LV]
  exact NFC.compose_jamo_LV

/-- `isNFKCQuickCheck` is conservative: pure ASCII has `NFKC_QC = Y`
    and the quick check returns `true`. The `NFKC_QC` values reduce over
    the materialized `List`; the CCC / HSR check uses the row-transport
    CCC lemmas (never the Array scan). -/
theorem isNFKCQuickCheck_ascii :
    isNFKCQuickCheck #[0x0048, 0x0069] = true := by
  have hH : nfkcQCValue 0x0048 = .Y := by decide +kernel
  have hI : nfkcQCValue 0x0069 = .Y := by decide +kernel
  have hSorted : NFC.hasSortedRunsBool [0x0048, 0x0069] = true := by
    unfold NFC.hasSortedRunsBool
    simp [Reorder.ccc_latin_H, Reorder.ccc_latin_i]
  unfold isNFKCQuickCheck
  simp [hH, hI, hSorted]

/-- `isNFKCQuickCheck` returns `false` for an `NFKC_QC = N` codepoint.
    NO-BREAK SPACE U+00A0 has `NFKC_QC = N` per the pinned table. -/
theorem isNFKCQuickCheck_nbsp :
    isNFKCQuickCheck #[0x00A0] = false := by
  have hN : nfkcQCValue 0x00A0 = .N := by decide +kernel
  unfold isNFKCQuickCheck
  simp [hN]

/-- `nfkcQCValue` default: `A` has `NFKC_QC = Y` (not in the explicit
    table; falls back to `defaultNfkcQC`). -/
theorem nfkcQC_default_ascii : nfkcQCValue 0x0041 = .Y := by decide +kernel

/-- `nfkcQCValue` explicit: U+00A0 is listed with `NFKC_QC = N`. -/
theorem nfkcQC_explicit_N : nfkcQCValue 0x00A0 = .N := by decide +kernel

end Unicode.Normalization.NFKC
