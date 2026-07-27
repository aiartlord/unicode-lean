import Unicode.Normalization.ToNFDAppend

namespace Unicode.Normalization.ComposeInversion

open Unicode.Generated
open Unicode.Normalization

def combP (row : UnicodeData.UnicodeDataRow) : Bool :=
  (if row.canonicalDecomposition.length = 2 then
    decide (ToNFDAppend.fcdFuelL Decompose.maxDepth row.codepoint
            = ToNFDAppend.fcdFuelL Decompose.maxDepth (row.canonicalDecomposition.getD 0 0)
              ++ ToNFDAppend.fcdFuelL Decompose.maxDepth (row.canonicalDecomposition.getD 1 0))
   else true)
  && (decide (row.canonicalCombiningClass = 0)
      || (ToNFDAppend.fcdFuelL Decompose.maxDepth row.codepoint).all
          (fun cp' => decide (ToNFDAppend.canonicalCombiningClassL cp' = row.canonicalCombiningClass)))

end Unicode.Normalization.ComposeInversion
