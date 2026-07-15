import Unicode.CaseFoldCommutationSourceBase

namespace Unicode.CaseFoldCommutation

open Unicode.Generated

set_option maxRecDepth 100000
set_option maxHeartbeats 0

theorem sourcePointwise_c20 : CaseFolding.foldingsChunk20.all sourcePointwiseP = true := by decide +kernel
theorem sourcePointwise_c21 : CaseFolding.foldingsChunk21.all sourcePointwiseP = true := by decide +kernel
theorem sourcePointwise_c22 : CaseFolding.foldingsChunk22.all sourcePointwiseP = true := by decide +kernel
theorem sourcePointwise_c23 : CaseFolding.foldingsChunk23.all sourcePointwiseP = true := by decide +kernel
theorem sourcePointwise_c24 : CaseFolding.foldingsChunk24.all sourcePointwiseP = true := by decide +kernel

theorem sourceComm_c20 : CaseFolding.foldingsChunk20.all sourceCommP = true := by decide +kernel
theorem sourceComm_c21 : CaseFolding.foldingsChunk21.all sourceCommP = true := by decide +kernel
theorem sourceComm_c22 : CaseFolding.foldingsChunk22.all sourceCommP = true := by decide +kernel
theorem sourceComm_c23 : CaseFolding.foldingsChunk23.all sourceCommP = true := by decide +kernel
theorem sourceComm_c24 : CaseFolding.foldingsChunk24.all sourceCommP = true := by decide +kernel

end Unicode.CaseFoldCommutation
