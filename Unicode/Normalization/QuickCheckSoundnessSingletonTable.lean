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
import Unicode.Normalization.QuickCheckSingletonRankData
import Unicode.Generated.UnicodeData

namespace Unicode.Normalization.QuickCheckSoundnessSingletonTable

open Unicode.Normalization
open Unicode.Normalization.NFC (toNFC nfcQCValue)
open Unicode.Generated

set_option maxRecDepth 100000

/-- **Singleton-NFC table for non-trivial-decomp QC=Y starters.** Every
    QC=Y non-Hangul starter `cp` with non-empty canonical decomposition
    is in NFC unchanged. Closed by `decide` over
    `UnicodeData.rows`; the early-exit disjuncts skip rows that are
    non-starters, Hangul precomposed syllables, non-QC=Y, or
    empty-decomp, so the toNFC pipeline runs only on the (smaller)
    relevant subset. -/
theorem qcY_starter_nontrivial_singleton_nfc_id_table :
    UnicodeData.rows.all (fun row =>
      decide (Lookup.canonicalCombiningClass row.codepoint ≠ 0) ||
      decide (Hangul.isHangulSyllable row.codepoint = true) ||
      decide (nfcQCValue row.codepoint ≠ .Y) ||
      decide (row.canonicalDecomposition.size = 0) ||
      decide (toNFC #[row.codepoint] = #[row.codepoint])) = true := by
  decide

end Unicode.Normalization.QuickCheckSoundnessSingletonTable
