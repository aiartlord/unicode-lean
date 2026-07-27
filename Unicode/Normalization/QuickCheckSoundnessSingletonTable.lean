/-
  Unicode.Normalization.QuickCheckSoundnessSingletonTable

  Isolates the table-scale `decide` that closes singleton-NFC
  identity for QC=Y non-Hangul starters with non-empty canonical
  decomposition. Split into a sibling module so iterations on the
  master soundness theorem do not retrigger the heavy compile (each
  rerun executes the full `toNFC` pipeline against ~700 UCD rows).
-/

import Unicode.Normalization.NFC
import Unicode.Normalization.Lookup
import Unicode.Normalization.Hangul
import Unicode.Normalization.QuickCheckSoundnessSingletonRank
import Unicode.Generated.UnicodeData

namespace Unicode.Normalization.QuickCheckSoundnessSingletonTable

open Unicode.Normalization
open Unicode.Normalization.NFC (toNFC nfcQCValue)
open Unicode.Generated

set_option maxRecDepth 100000

/-- **Singleton-NFC table for non-trivial-decomp QC=Y starters.** Every
    QC=Y non-Hangul starter `cp` with non-empty canonical decomposition
    is in NFC unchanged. The theorem keeps the exported table-shaped contract,
    while the proof routes the relevant rows through the generated rank
    certificate instead of reducing `toNFC [row.codepoint]` across the table. -/
theorem qcY_starter_nontrivial_singleton_nfc_id_table :
    UnicodeData.rows.all (fun row =>
      decide (Lookup.canonicalCombiningClass row.codepoint ≠ 0) ||
      decide (Hangul.isHangulSyllable row.codepoint = true) ||
      decide (nfcQCValue row.codepoint ≠ .Y) ||
      decide (row.canonicalDecomposition.size = 0) ||
      decide (toNFC [row.codepoint] = [row.codepoint])) = true := by
  unfold UnicodeData.rows
  rw [List.all_toArray, List.all_eq_true]
  intro row hMem
  have hCovered :=
    List.all_eq_true.mp
      QuickCheckSingletonRankData.relevant_lookup_rows_covered row hMem
  by_cases hAny : QuickCheckSingletonRankData.rows.any
      (fun entry => decide (entry.codepoint = row.codepoint)) = true
  · have hSingleton :=
      QuickCheckSoundnessSingletonRank.singletonNFC_of_rank_rows_any
        row.codepoint hAny
    have hLast :
        decide (toNFC [row.codepoint] = [row.codepoint]) = true :=
      decide_eq_true hSingleton
    rw [Bool.or_eq_true]
    exact Or.inr hLast
  · have hFirst4 :
        (((decide (Lookup.canonicalCombiningClass row.codepoint ≠ 0) ||
          decide (Hangul.isHangulSyllable row.codepoint = true)) ||
          decide (nfcQCValue row.codepoint ≠ .Y)) ||
          decide (row.canonicalDecomposition.size = 0)) = true := by
      simpa [hAny] using hCovered
    rw [Bool.or_eq_true]
    exact Or.inl hFirst4

end Unicode.Normalization.QuickCheckSoundnessSingletonTable
