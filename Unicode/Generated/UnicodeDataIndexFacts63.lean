/-
  Unicode.Generated.UnicodeDataIndexFacts63

  Membership facts for low-byte buckets FC..FF.
-/

import Unicode.Generated.UnicodeDataIndex

namespace Unicode.Generated.UnicodeDataIndexFacts63

open Unicode.Generated
open Unicode.Generated.UnicodeData
open Unicode.Generated.UnicodeDataIndex

set_option maxRecDepth 100000
set_option linter.unusedVariables false

theorem rowsLowByteFC_all_supported_rowsList :
    rowsLowByteFC.all (fun row =>
      UnicodeData.rowsList.any (fun src =>
        decide (src.codepoint = row.codepoint ∧
          src.canonicalCombiningClass = row.canonicalCombiningClass ∧
          src.canonicalDecomposition = row.canonicalDecomposition))) = true := by
  decide +kernel

theorem rowsList_all_codepoint_mem_rowsLowByteFC :
    UnicodeData.rowsList.all (fun row =>
      decide (row.codepoint % 256 = 0xFC →
        rowsLowByteFC.any (fun indexed =>
          decide (indexed.codepoint = row.codepoint)) = true)) = true := by
  decide +kernel

theorem rowsLowByteFD_all_supported_rowsList :
    rowsLowByteFD.all (fun row =>
      UnicodeData.rowsList.any (fun src =>
        decide (src.codepoint = row.codepoint ∧
          src.canonicalCombiningClass = row.canonicalCombiningClass ∧
          src.canonicalDecomposition = row.canonicalDecomposition))) = true := by
  decide +kernel

theorem rowsList_all_codepoint_mem_rowsLowByteFD :
    UnicodeData.rowsList.all (fun row =>
      decide (row.codepoint % 256 = 0xFD →
        rowsLowByteFD.any (fun indexed =>
          decide (indexed.codepoint = row.codepoint)) = true)) = true := by
  decide +kernel

theorem rowsLowByteFE_all_supported_rowsList :
    rowsLowByteFE.all (fun row =>
      UnicodeData.rowsList.any (fun src =>
        decide (src.codepoint = row.codepoint ∧
          src.canonicalCombiningClass = row.canonicalCombiningClass ∧
          src.canonicalDecomposition = row.canonicalDecomposition))) = true := by
  decide +kernel

theorem rowsList_all_codepoint_mem_rowsLowByteFE :
    UnicodeData.rowsList.all (fun row =>
      decide (row.codepoint % 256 = 0xFE →
        rowsLowByteFE.any (fun indexed =>
          decide (indexed.codepoint = row.codepoint)) = true)) = true := by
  decide +kernel

theorem rowsLowByteFF_all_supported_rowsList :
    rowsLowByteFF.all (fun row =>
      UnicodeData.rowsList.any (fun src =>
        decide (src.codepoint = row.codepoint ∧
          src.canonicalCombiningClass = row.canonicalCombiningClass ∧
          src.canonicalDecomposition = row.canonicalDecomposition))) = true := by
  decide +kernel

theorem rowsList_all_codepoint_mem_rowsLowByteFF :
    UnicodeData.rowsList.all (fun row =>
      decide (row.codepoint % 256 = 0xFF →
        rowsLowByteFF.any (fun indexed =>
          decide (indexed.codepoint = row.codepoint)) = true)) = true := by
  decide +kernel

end Unicode.Generated.UnicodeDataIndexFacts63
