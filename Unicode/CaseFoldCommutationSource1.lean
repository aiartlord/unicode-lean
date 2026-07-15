import Unicode.CaseFoldCommutationSourceBase

namespace Unicode.CaseFoldCommutation

open Unicode.Generated

set_option maxRecDepth 100000
set_option maxHeartbeats 0

theorem sourcePointwise_c5 : CaseFolding.foldingsChunk5.all sourcePointwiseP = true := by decide +kernel
theorem sourcePointwise_c6 : CaseFolding.foldingsChunk6.all sourcePointwiseP = true := by decide +kernel
theorem sourcePointwise_c7 : CaseFolding.foldingsChunk7.all sourcePointwiseP = true := by decide +kernel
theorem sourcePointwise_c8 : CaseFolding.foldingsChunk8.all sourcePointwiseP = true := by decide +kernel
theorem sourcePointwise_c9 : CaseFolding.foldingsChunk9.all sourcePointwiseP = true := by decide +kernel

theorem sourceComm_c5 : CaseFolding.foldingsChunk5.all sourceCommP = true := by decide +kernel
theorem sourceComm_c6 : CaseFolding.foldingsChunk6.all sourceCommP = true := by decide +kernel
theorem sourceComm_c7 : CaseFolding.foldingsChunk7.all sourceCommP = true := by decide +kernel
theorem sourceComm_c8 : CaseFolding.foldingsChunk8.all sourceCommP = true := by decide +kernel
theorem sourceComm_c9 : CaseFolding.foldingsChunk9.all sourceCommP = true := by decide +kernel

end Unicode.CaseFoldCommutation
