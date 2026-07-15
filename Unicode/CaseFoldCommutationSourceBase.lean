/-
  Unicode.CaseFoldCommutationSourceBase

  Shared predicates for bounded case-fold source commutation certificates.
-/

import Unicode.Normalization.NFC
import Unicode.Precis.CaseMapping

namespace Unicode.CaseFoldCommutation

open Unicode.Normalization
open Unicode.Generated
open Unicode.Precis.CaseMapping

def sourceCommP (entry : Nat × Array Nat) : Bool :=
  decide (NFC.toNFD (caseFold #[entry.1]) =
          NFC.toNFD (caseFold (NFC.toNFD #[entry.1])))

def sourcePointwiseP (entry : Nat × Array Nat) : Bool :=
  decide (NFC.toNFD entry.2 =
          NFC.toNFD (caseFold (NFC.toNFD #[entry.1])))

end Unicode.CaseFoldCommutation
