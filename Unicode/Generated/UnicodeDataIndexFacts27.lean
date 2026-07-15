/-
  Unicode.Generated.UnicodeDataIndexFacts27

  Membership facts for low-byte buckets 6C..6F.
-/

import Unicode.Generated.UnicodeDataIndex

namespace Unicode.Generated.UnicodeDataIndexFacts27

open Unicode.Generated
open Unicode.Generated.UnicodeData
open Unicode.Generated.UnicodeDataIndex

set_option maxRecDepth 100000
set_option linter.unusedVariables false

theorem rowsLowByte6C_all_supported_rowsList :
    rowsLowByte6C.all (fun row =>
      UnicodeData.rowsList.any (fun src =>
        decide (src.codepoint = row.codepoint ∧
          src.canonicalCombiningClass = row.canonicalCombiningClass ∧
          src.canonicalDecomposition = row.canonicalDecomposition))) = true := by
  decide +kernel

theorem rowsList_all_codepoint_mem_rowsLowByte6C :
    UnicodeData.rowsList.all (fun row =>
      decide (row.codepoint % 256 = 0x6C →
        rowsLowByte6C.any (fun indexed =>
          decide (indexed.codepoint = row.codepoint)) = true)) = true := by
  decide +kernel

theorem rowsLowByte6D_all_supported_rowsList :
    rowsLowByte6D.all (fun row =>
      UnicodeData.rowsList.any (fun src =>
        decide (src.codepoint = row.codepoint ∧
          src.canonicalCombiningClass = row.canonicalCombiningClass ∧
          src.canonicalDecomposition = row.canonicalDecomposition))) = true := by
  decide +kernel

theorem rowsList_all_codepoint_mem_rowsLowByte6D :
    UnicodeData.rowsList.all (fun row =>
      decide (row.codepoint % 256 = 0x6D →
        rowsLowByte6D.any (fun indexed =>
          decide (indexed.codepoint = row.codepoint)) = true)) = true := by
  decide +kernel

theorem rowsLowByte6E_all_supported_rowsList :
    rowsLowByte6E.all (fun row =>
      UnicodeData.rowsList.any (fun src =>
        decide (src.codepoint = row.codepoint ∧
          src.canonicalCombiningClass = row.canonicalCombiningClass ∧
          src.canonicalDecomposition = row.canonicalDecomposition))) = true := by
  decide +kernel

theorem rowsList_all_codepoint_mem_rowsLowByte6E :
    UnicodeData.rowsList.all (fun row =>
      decide (row.codepoint % 256 = 0x6E →
        rowsLowByte6E.any (fun indexed =>
          decide (indexed.codepoint = row.codepoint)) = true)) = true := by
  decide +kernel

theorem rowsLowByte6F_all_supported_rowsList :
    rowsLowByte6F.all (fun row =>
      UnicodeData.rowsList.any (fun src =>
        decide (src.codepoint = row.codepoint ∧
          src.canonicalCombiningClass = row.canonicalCombiningClass ∧
          src.canonicalDecomposition = row.canonicalDecomposition))) = true := by
  decide +kernel

theorem rowsList_all_codepoint_mem_rowsLowByte6F :
    UnicodeData.rowsList.all (fun row =>
      decide (row.codepoint % 256 = 0x6F →
        rowsLowByte6F.any (fun indexed =>
          decide (indexed.codepoint = row.codepoint)) = true)) = true := by
  decide +kernel

end Unicode.Generated.UnicodeDataIndexFacts27
