/-
  Unicode.Generated.UnicodeDataIndexFacts62

  Membership facts for low-byte buckets F8..FB.
-/

import Unicode.Generated.UnicodeDataIndex

namespace Unicode.Generated.UnicodeDataIndexFacts62

open Unicode.Generated
open Unicode.Generated.UnicodeData
open Unicode.Generated.UnicodeDataIndex

set_option maxRecDepth 100000
set_option linter.unusedVariables false

theorem rowsLowByteF8_all_supported_rowsList :
    rowsLowByteF8.all (fun row =>
      UnicodeData.rowsList.any (fun src =>
        decide (src.codepoint = row.codepoint ∧
          src.canonicalCombiningClass = row.canonicalCombiningClass ∧
          src.canonicalDecomposition = row.canonicalDecomposition))) = true := by
  decide +kernel

theorem rowsList_all_codepoint_mem_rowsLowByteF8 :
    UnicodeData.rowsList.all (fun row =>
      decide (row.codepoint % 256 = 0xF8 →
        rowsLowByteF8.any (fun indexed =>
          decide (indexed.codepoint = row.codepoint)) = true)) = true := by
  decide +kernel

theorem rowsLowByteF9_all_supported_rowsList :
    rowsLowByteF9.all (fun row =>
      UnicodeData.rowsList.any (fun src =>
        decide (src.codepoint = row.codepoint ∧
          src.canonicalCombiningClass = row.canonicalCombiningClass ∧
          src.canonicalDecomposition = row.canonicalDecomposition))) = true := by
  decide +kernel

theorem rowsList_all_codepoint_mem_rowsLowByteF9 :
    UnicodeData.rowsList.all (fun row =>
      decide (row.codepoint % 256 = 0xF9 →
        rowsLowByteF9.any (fun indexed =>
          decide (indexed.codepoint = row.codepoint)) = true)) = true := by
  decide +kernel

theorem rowsLowByteFA_all_supported_rowsList :
    rowsLowByteFA.all (fun row =>
      UnicodeData.rowsList.any (fun src =>
        decide (src.codepoint = row.codepoint ∧
          src.canonicalCombiningClass = row.canonicalCombiningClass ∧
          src.canonicalDecomposition = row.canonicalDecomposition))) = true := by
  decide +kernel

theorem rowsList_all_codepoint_mem_rowsLowByteFA :
    UnicodeData.rowsList.all (fun row =>
      decide (row.codepoint % 256 = 0xFA →
        rowsLowByteFA.any (fun indexed =>
          decide (indexed.codepoint = row.codepoint)) = true)) = true := by
  decide +kernel

theorem rowsLowByteFB_all_supported_rowsList :
    rowsLowByteFB.all (fun row =>
      UnicodeData.rowsList.any (fun src =>
        decide (src.codepoint = row.codepoint ∧
          src.canonicalCombiningClass = row.canonicalCombiningClass ∧
          src.canonicalDecomposition = row.canonicalDecomposition))) = true := by
  decide +kernel

theorem rowsList_all_codepoint_mem_rowsLowByteFB :
    UnicodeData.rowsList.all (fun row =>
      decide (row.codepoint % 256 = 0xFB →
        rowsLowByteFB.any (fun indexed =>
          decide (indexed.codepoint = row.codepoint)) = true)) = true := by
  decide +kernel

end Unicode.Generated.UnicodeDataIndexFacts62
