import Unicode.CaseFoldCommutationSourceBase

namespace Unicode.CaseFoldCommutation

open Unicode.Generated

set_option maxRecDepth 100000
set_option maxHeartbeats 0

theorem sourcePointwise_c10 : CaseFolding.foldingsChunk10.all sourcePointwiseP = true := by decide +kernel
theorem sourcePointwise_c11 : CaseFolding.foldingsChunk11.all sourcePointwiseP = true := by decide +kernel
theorem sourcePointwise_c12 : CaseFolding.foldingsChunk12.all sourcePointwiseP = true := by decide +kernel
theorem sourcePointwise_c13 : CaseFolding.foldingsChunk13.all sourcePointwiseP = true := by decide +kernel
theorem sourcePointwise_c14 : CaseFolding.foldingsChunk14.all sourcePointwiseP = true := by decide +kernel

theorem sourceComm_c10 : CaseFolding.foldingsChunk10.all sourceCommP = true := by decide +kernel
theorem sourceComm_c11 : CaseFolding.foldingsChunk11.all sourceCommP = true := by decide +kernel
theorem sourceComm_c12 : CaseFolding.foldingsChunk12.all sourceCommP = true := by decide +kernel
theorem sourceComm_c13 : CaseFolding.foldingsChunk13.all sourceCommP = true := by decide +kernel
theorem sourceComm_c14 : CaseFolding.foldingsChunk14.all sourceCommP = true := by decide +kernel

end Unicode.CaseFoldCommutation
