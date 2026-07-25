/-
  Unicode.Normalization.NFKD

  Normalization Form KD (compatibility decomposition + canonical
  reordering) per UAX #15 §1.3:

    toNFKD = reorder ∘ compatDecomposeSequence

  Differs from NFD only in the decomposition stage: NFD applies just
  canonical decomposition; NFKD applies both canonical and
  compatibility decompositions. The reorder stage is identical (both
  forms canonically order combining marks within each non-starter run).
-/

import Unicode.Normalization.CompatDecompose
import Unicode.Normalization.NFC
import Unicode.Normalization.Reorder
import Unicode.Generated.DerivedNormalizationProps

namespace Unicode.Normalization.NFKD

open Unicode.Normalization
open Unicode.Generated

set_option maxRecDepth 100000

/-- Apply the compatibility decomposition + canonical reorder pipeline. -/
def toNFKD (cps : List Nat) : List Nat :=
  Reorder.reorder (CompatDecompose.compatDecomposeSequence cps)

/-- Look up a codepoint's `NFKD_QuickCheck` value. Falls back to the
    source file's `@missing` default (`Y`). -/
def nfkdQCValue (cp : Nat) : DerivedNormalizationProps.NFC_QC :=
  match DerivedNormalizationProps.nfkdQC.findSome?
          (fun ⟨min, max, v⟩ => if min ≤ cp ∧ cp ≤ max then some v else none) with
  | some v => v
  | none   => DerivedNormalizationProps.defaultNfkdQC

/-- Quick check per UAX #15 §A.1 NFKD: a sequence is guaranteed to be in
    NFKD when every codepoint has `NFKD_QC = Y` AND combining marks are
    in canonical CCC order. The HSR check reuses
    `NFC.hasSortedRunsBool` because the canonical reorder stage is
    identical between NFKD and the canonical forms. -/
def isNFKDQuickCheck (cps : List Nat) : Bool :=
  cps.all (fun cp => decide (nfkdQCValue cp = .Y)) &&
  NFC.hasSortedRunsBool cps

/-- Definitive NFKD check: a sequence is in NFKD iff applying the NFKD
    pipeline to it is a no-op. -/
def isNFKD (cps : List Nat) : Bool :=
  toNFKD cps = cps

-- ═══════════════════════════════════════════════════════════════════════════════
-- TEST VECTORS
--
-- Each `toNFKD` vector is evaluated stage by stage — compatibility
-- decompose, then canonical reorder — reusing the CompatDecompose value
-- lemmas and Reorder CCC facts, so the UnicodeData row scan is never
-- reduced (see the fact-transport section of
-- `Unicode.Normalization.Lookup`). The compatibility lookup itself reduces
-- (binary search over the materialized `CompatDecomp` table).
-- ═══════════════════════════════════════════════════════════════════════════════

/-- `CCC(U+0032) = 0` — DIGIT TWO is a starter. -/
theorem ccc_digit_2 : Lookup.canonicalCombiningClass 0x0032 = 0 :=
  Lookup.canonicalCombiningClass_of_lookupRow_none 0x0032
    (Lookup.lookupRow_none_of_all_ne 0x0032 CompatDecompose.rows_omit_digit_2)

/-- `CCC(U+0020) = 0` — SPACE is a starter. -/
theorem ccc_space : Lookup.canonicalCombiningClass 0x0020 = 0 :=
  Lookup.canonicalCombiningClass_of_lookupRow_none 0x0020
    (Lookup.lookupRow_none_of_all_ne 0x0020 CompatDecompose.rows_omit_space)

/-- `CCC(U+0066) = 0` — LATIN SMALL LETTER F is a starter. -/
theorem ccc_latin_f : Lookup.canonicalCombiningClass 0x0066 = 0 :=
  Lookup.canonicalCombiningClass_of_lookupRow_none 0x0066
    (Lookup.lookupRow_none_of_all_ne 0x0066 CompatDecompose.rows_omit_latin_f)

/-- Every row carrying U+0308 records `CCC = 230`. -/
theorem rows_ccc_combining_diaeresis :
    UnicodeData.rowsList.all (fun r =>
      decide (r.codepoint = 0x0308 →
        r.canonicalCombiningClass = 230)) = true := by decide +kernel

/-- `CCC(U+0308) = 230` — COMBINING DIAERESIS. -/
theorem ccc_combining_diaeresis : Lookup.canonicalCombiningClass 0x0308 = 230 :=
  Lookup.canonicalCombiningClass_of_hit 0x0308 230
    CompatDecompose.rows_hit_combining_diaeresis rows_ccc_combining_diaeresis

/-- Reorder is the identity on a lone DIGIT TWO. -/
theorem reorder_digit_2 : Reorder.reorder [0x0032] = [0x0032] := by
  simp [Reorder.reorder, Reorder.stepReorder, Reorder.flushRun,
        Reorder.sortNonStarterRun, ccc_digit_2]

/-- Reorder is the identity on a lone SPACE. -/
theorem reorder_space : Reorder.reorder [0x0020] = [0x0020] := by
  simp [Reorder.reorder, Reorder.stepReorder, Reorder.flushRun,
        Reorder.sortNonStarterRun, ccc_space]

/-- Reorder is the identity on SPACE + COMBINING DIAERESIS (single mark,
    already canonical). -/
theorem reorder_space_diaeresis :
    Reorder.reorder [0x0020, 0x0308] = [0x0020, 0x0308] := by
  simp [Reorder.reorder, Reorder.stepReorder, Reorder.flushRun,
        Reorder.sortNonStarterRun, Reorder.insertByCCC,
        ccc_space, ccc_combining_diaeresis]

/-- Reorder is the identity on two `f` starters. -/
theorem reorder_ff : Reorder.reorder [0x0066, 0x0066] = [0x0066, 0x0066] := by
  simp [Reorder.reorder, Reorder.stepReorder, Reorder.flushRun,
        Reorder.sortNonStarterRun, ccc_latin_f]

/-- Empty sequence. -/
theorem toNFKD_empty : toNFKD [] = [] := by decide

/-- Pure ASCII is in NFKD unchanged. -/
theorem toNFKD_ascii :
    toNFKD [0x0048, 0x0069] = [0x0048, 0x0069] := by  -- "Hi"
  unfold toNFKD
  rw [show CompatDecompose.compatDecomposeSequence [0x0048, 0x0069]
        = [0x0048, 0x0069] from by
        simp [CompatDecompose.compatDecomposeSequence,
              CompatDecompose.compat_decompose_latin_H,
              CompatDecompose.compat_decompose_latin_i]]
  exact Reorder.reorder_ascii

/-- A precomposed letter with a canonical decomposition: NFKD reaches
    it through the canonical branch (same output as NFD). -/
theorem toNFKD_decomposes_A_grave :
    toNFKD [0x00C0] = [0x0041, 0x0300] := by
  unfold toNFKD
  rw [show CompatDecompose.compatDecomposeSequence [0x00C0]
        = [0x0041, 0x0300] from by
        simp [CompatDecompose.compatDecomposeSequence,
              CompatDecompose.compat_decompose_A_grave]]
  exact NFC.reorder_A_grave

/-- SUPERSCRIPT TWO U+00B2 has only a compatibility decomposition;
    NFKD applies it where NFD would not. -/
theorem toNFKD_decomposes_super_2 :
    toNFKD [0x00B2] = [0x0032] := by
  unfold toNFKD
  rw [show CompatDecompose.compatDecomposeSequence [0x00B2]
        = [0x0032] from by
        simp [CompatDecompose.compatDecomposeSequence,
              CompatDecompose.compat_decompose_super_2]]
  exact reorder_digit_2

/-- NO-BREAK SPACE U+00A0 → U+0020 under NFKD. -/
theorem toNFKD_nbsp :
    toNFKD [0x00A0] = [0x0020] := by
  unfold toNFKD
  rw [show CompatDecompose.compatDecomposeSequence [0x00A0]
        = [0x0020] from by
        simp [CompatDecompose.compatDecomposeSequence,
              CompatDecompose.compat_decompose_nbsp]]
  exact reorder_space

/-- DIAERESIS U+00A8 → SPACE + COMBINING DIAERESIS under NFKD. The
    output's combining-mark order is already canonical (single mark). -/
theorem toNFKD_diaeresis :
    toNFKD [0x00A8] = [0x0020, 0x0308] := by
  unfold toNFKD
  rw [show CompatDecompose.compatDecomposeSequence [0x00A8]
        = [0x0020, 0x0308] from by
        simp [CompatDecompose.compatDecomposeSequence,
              CompatDecompose.compat_decompose_diaeresis]]
  exact reorder_space_diaeresis

/-- LATIN SMALL LIGATURE FF (U+FB00) decomposes via compatibility to two
    lowercase f's (U+0066 U+0066). -/
theorem toNFKD_ligature_ff :
    toNFKD [0xFB00] = [0x0066, 0x0066] := by
  unfold toNFKD
  rw [show CompatDecompose.compatDecomposeSequence [0xFB00]
        = [0x0066, 0x0066] from by
        simp [CompatDecompose.compatDecomposeSequence,
              CompatDecompose.compat_decompose_ligature_ff]]
  exact reorder_ff

/-- HANGUL precomposed syllable decomposes algorithmically (canonical
    path; compat path is unused). -/
theorem toNFKD_hangul :
    toNFKD [0xAC00] = [0x1100, 0x1161] := by
  unfold toNFKD
  rw [show CompatDecompose.compatDecomposeSequence [0xAC00]
        = [0x1100, 0x1161] from by
        simp [CompatDecompose.compatDecomposeSequence,
              CompatDecompose.compat_decompose_hangul_GA]]
  exact NFC.reorder_jamo_LV

/-- `isNFKD` returns `true` for ASCII. -/
theorem isNFKD_ascii : isNFKD [0x0048, 0x0069] = true := by
  unfold isNFKD
  rw [toNFKD_ascii]
  decide

/-- `isNFKD` returns `false` for SUPERSCRIPT TWO (decomposes). -/
theorem isNFKD_super_2 : isNFKD [0x00B2] = false := by
  unfold isNFKD
  rw [toNFKD_decomposes_super_2]
  decide

end Unicode.Normalization.NFKD
