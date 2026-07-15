import Unicode.Generated.UnicodeData
import Unicode.Precis.CaseMapping

namespace Unicode.CaseFoldCommutation

open Unicode.Generated
open Unicode.Precis.CaseMapping

def nonSourceDecompP (row : UnicodeData.UnicodeDataRow) : Bool :=
  isCaseFoldSource row.codepoint ||
  row.canonicalDecomposition.all (fun d => !isCaseFoldSource d)

end Unicode.CaseFoldCommutation
