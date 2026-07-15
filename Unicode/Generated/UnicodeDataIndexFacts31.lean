/-
  Unicode.Generated.UnicodeDataIndexFacts31

  Membership facts for low-byte buckets 7C..7F.
-/

import Unicode.Generated.UnicodeDataIndex

namespace Unicode.Generated.UnicodeDataIndexFacts31

open Unicode.Generated
open Unicode.Generated.UnicodeData
open Unicode.Generated.UnicodeDataIndex

set_option maxRecDepth 100000
set_option linter.unusedVariables false

theorem rowsLowByte7C_all_supported_rowsList :
    rowsLowByte7C.all (fun row =>
      UnicodeData.rowsList.any (fun src =>
        decide (src.codepoint = row.codepoint ∧
          src.canonicalCombiningClass = row.canonicalCombiningClass ∧
          src.canonicalDecomposition = row.canonicalDecomposition))) = true := by
  decide +kernel

theorem rowsList_all_codepoint_mem_rowsLowByte7C :
    UnicodeData.rowsList.all (fun row =>
      decide (row.codepoint % 256 = 0x7C →
        rowsLowByte7C.any (fun indexed =>
          decide (indexed.codepoint = row.codepoint)) = true)) = true := by
  decide +kernel

theorem rowsLowByte7D_all_supported_rowsList :
    rowsLowByte7D.all (fun row =>
      UnicodeData.rowsList.any (fun src =>
        decide (src.codepoint = row.codepoint ∧
          src.canonicalCombiningClass = row.canonicalCombiningClass ∧
          src.canonicalDecomposition = row.canonicalDecomposition))) = true := by
  decide +kernel

theorem rowsList_all_codepoint_mem_rowsLowByte7D :
    UnicodeData.rowsList.all (fun row =>
      decide (row.codepoint % 256 = 0x7D →
        rowsLowByte7D.any (fun indexed =>
          decide (indexed.codepoint = row.codepoint)) = true)) = true := by
  decide +kernel

theorem rowsLowByte7E_all_supported_rowsList :
    rowsLowByte7E.all (fun row =>
      UnicodeData.rowsList.any (fun src =>
        decide (src.codepoint = row.codepoint ∧
          src.canonicalCombiningClass = row.canonicalCombiningClass ∧
          src.canonicalDecomposition = row.canonicalDecomposition))) = true := by
  decide +kernel

theorem rowsList_all_codepoint_mem_rowsLowByte7E :
    UnicodeData.rowsList.all (fun row =>
      decide (row.codepoint % 256 = 0x7E →
        rowsLowByte7E.any (fun indexed =>
          decide (indexed.codepoint = row.codepoint)) = true)) = true := by
  decide +kernel

theorem rowsLowByte7F_all_supported_rowsList :
    rowsLowByte7F.all (fun row =>
      UnicodeData.rowsList.any (fun src =>
        decide (src.codepoint = row.codepoint ∧
          src.canonicalCombiningClass = row.canonicalCombiningClass ∧
          src.canonicalDecomposition = row.canonicalDecomposition))) = true := by
  decide +kernel

theorem rowsList_all_codepoint_mem_rowsLowByte7F :
    UnicodeData.rowsList.all (fun row =>
      decide (row.codepoint % 256 = 0x7F →
        rowsLowByte7F.any (fun indexed =>
          decide (indexed.codepoint = row.codepoint)) = true)) = true := by
  decide +kernel

end Unicode.Generated.UnicodeDataIndexFacts31
