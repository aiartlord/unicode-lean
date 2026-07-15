/-
  Unicode.CaseFoldCommutationSource

  Aggregate source-column certificates for case-fold / NFD commutation.
  The expensive checks live in `CaseFoldCommutationSource0..4`; this
  module only combines them.
-/

import Unicode.CaseFoldCommutationSource0
import Unicode.CaseFoldCommutationSource1
import Unicode.CaseFoldCommutationSource2
import Unicode.CaseFoldCommutationSource3
import Unicode.CaseFoldCommutationSource4

namespace Unicode.CaseFoldCommutation

open Unicode.Generated

theorem sourcePointwise_foldingsList :
    CaseFolding.foldingsList.all sourcePointwiseP = true := by
  unfold CaseFolding.foldingsList
  simp [sourcePointwise_c0, sourcePointwise_c1, sourcePointwise_c2,
    sourcePointwise_c3, sourcePointwise_c4, sourcePointwise_c5,
    sourcePointwise_c6, sourcePointwise_c7, sourcePointwise_c8,
    sourcePointwise_c9, sourcePointwise_c10, sourcePointwise_c11,
    sourcePointwise_c12, sourcePointwise_c13, sourcePointwise_c14,
    sourcePointwise_c15, sourcePointwise_c16, sourcePointwise_c17,
    sourcePointwise_c18, sourcePointwise_c19, sourcePointwise_c20,
    sourcePointwise_c21, sourcePointwise_c22, sourcePointwise_c23,
    sourcePointwise_c24]

theorem sourceComm_foldingsList :
    CaseFolding.foldingsList.all sourceCommP = true := by
  unfold CaseFolding.foldingsList
  simp [sourceComm_c0, sourceComm_c1, sourceComm_c2, sourceComm_c3,
    sourceComm_c4, sourceComm_c5, sourceComm_c6, sourceComm_c7,
    sourceComm_c8, sourceComm_c9, sourceComm_c10, sourceComm_c11,
    sourceComm_c12, sourceComm_c13, sourceComm_c14, sourceComm_c15,
    sourceComm_c16, sourceComm_c17, sourceComm_c18, sourceComm_c19,
    sourceComm_c20, sourceComm_c21, sourceComm_c22, sourceComm_c23,
    sourceComm_c24]

end Unicode.CaseFoldCommutation
