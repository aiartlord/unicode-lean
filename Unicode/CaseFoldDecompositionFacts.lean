import Unicode.CaseFoldDecompositionFacts0
import Unicode.CaseFoldDecompositionFacts1
import Unicode.CaseFoldDecompositionFacts2
import Unicode.CaseFoldDecompositionFacts3

namespace Unicode.CaseFoldCommutation

open Unicode.Generated
open Unicode.Precis.CaseMapping

theorem nonSourceDecomp_rowsList :
    UnicodeData.rowsList.all nonSourceDecompP = true := by
  unfold UnicodeData.rowsList
  simp [nonSourceDecomp_c0, nonSourceDecomp_c1, nonSourceDecomp_c2,
    nonSourceDecomp_c3, nonSourceDecomp_c4, nonSourceDecomp_c5,
    nonSourceDecomp_c6, nonSourceDecomp_c7, nonSourceDecomp_c8,
    nonSourceDecomp_c9, nonSourceDecomp_c10, nonSourceDecomp_c11,
    nonSourceDecomp_c12, nonSourceDecomp_c13, nonSourceDecomp_c14,
    nonSourceDecomp_c15, nonSourceDecomp_c16, nonSourceDecomp_c17,
    nonSourceDecomp_c18, nonSourceDecomp_c19, nonSourceDecomp_c20,
    nonSourceDecomp_c21, nonSourceDecomp_c22, nonSourceDecomp_c23,
    nonSourceDecomp_c24, nonSourceDecomp_c25, nonSourceDecomp_c26,
    nonSourceDecomp_c27, nonSourceDecomp_c28, nonSourceDecomp_c29,
    nonSourceDecomp_c30, nonSourceDecomp_c31, nonSourceDecomp_c32,
    nonSourceDecomp_c33, nonSourceDecomp_c34, nonSourceDecomp_c35,
    nonSourceDecomp_c36, nonSourceDecomp_c37, nonSourceDecomp_c38,
    nonSourceDecomp_c39, nonSourceDecomp_c40, nonSourceDecomp_c41,
    nonSourceDecomp_c42, nonSourceDecomp_c43, nonSourceDecomp_c44,
    nonSourceDecomp_c45, nonSourceDecomp_c46, nonSourceDecomp_c47]

theorem nonCaseFoldSource_decomp_all_nonSource :
    UnicodeData.rows.all (fun row =>
      isCaseFoldSource row.codepoint ||
      row.canonicalDecomposition.all (fun d => !isCaseFoldSource d)) = true := by
  unfold UnicodeData.rows
  simpa [nonSourceDecompP] using nonSourceDecomp_rowsList

end Unicode.CaseFoldCommutation
