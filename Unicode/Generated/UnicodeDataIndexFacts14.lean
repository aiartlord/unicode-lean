/-
  Unicode.Generated.UnicodeDataIndexFacts14

  Membership facts for low-byte buckets 38..3B.
-/

import Unicode.Generated.UnicodeDataIndex

namespace Unicode.Generated.UnicodeDataIndexFacts14

open Unicode.Generated
open Unicode.Generated.UnicodeData
open Unicode.Generated.UnicodeDataIndex

set_option maxRecDepth 100000
set_option linter.unusedVariables false

theorem rowsLowByte38_all_supported_rowsList :
    rowsLowByte38.all (fun row =>
      UnicodeData.rowsList.any (fun src =>
        decide (src.codepoint = row.codepoint ∧
          src.canonicalCombiningClass = row.canonicalCombiningClass ∧
          src.canonicalDecomposition = row.canonicalDecomposition))) = true := by
  decide +kernel

theorem rowsList_all_codepoint_mem_rowsLowByte38 :
    UnicodeData.rowsList.all (fun row =>
      decide (row.codepoint % 256 = 0x38 →
        rowsLowByte38.any (fun indexed =>
          decide (indexed.codepoint = row.codepoint)) = true)) = true := by
  decide +kernel

theorem rowsLowByte39_all_supported_rowsList :
    rowsLowByte39.all (fun row =>
      UnicodeData.rowsList.any (fun src =>
        decide (src.codepoint = row.codepoint ∧
          src.canonicalCombiningClass = row.canonicalCombiningClass ∧
          src.canonicalDecomposition = row.canonicalDecomposition))) = true := by
  decide +kernel

theorem rowsList_all_codepoint_mem_rowsLowByte39 :
    UnicodeData.rowsList.all (fun row =>
      decide (row.codepoint % 256 = 0x39 →
        rowsLowByte39.any (fun indexed =>
          decide (indexed.codepoint = row.codepoint)) = true)) = true := by
  decide +kernel

theorem rowsLowByte3A_all_supported_rowsList :
    rowsLowByte3A.all (fun row =>
      UnicodeData.rowsList.any (fun src =>
        decide (src.codepoint = row.codepoint ∧
          src.canonicalCombiningClass = row.canonicalCombiningClass ∧
          src.canonicalDecomposition = row.canonicalDecomposition))) = true := by
  decide +kernel

theorem rowsList_all_codepoint_mem_rowsLowByte3A :
    UnicodeData.rowsList.all (fun row =>
      decide (row.codepoint % 256 = 0x3A →
        rowsLowByte3A.any (fun indexed =>
          decide (indexed.codepoint = row.codepoint)) = true)) = true := by
  decide +kernel

theorem rowsLowByte3B_all_supported_rowsList :
    rowsLowByte3B.all (fun row =>
      UnicodeData.rowsList.any (fun src =>
        decide (src.codepoint = row.codepoint ∧
          src.canonicalCombiningClass = row.canonicalCombiningClass ∧
          src.canonicalDecomposition = row.canonicalDecomposition))) = true := by
  decide +kernel

theorem rowsList_all_codepoint_mem_rowsLowByte3B :
    UnicodeData.rowsList.all (fun row =>
      decide (row.codepoint % 256 = 0x3B →
        rowsLowByte3B.any (fun indexed =>
          decide (indexed.codepoint = row.codepoint)) = true)) = true := by
  decide +kernel

end Unicode.Generated.UnicodeDataIndexFacts14
