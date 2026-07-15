import Unicode.CaseFoldCommutationSourceBase

namespace Unicode.CaseFoldCommutation

open Unicode.Generated

set_option maxRecDepth 100000
set_option maxHeartbeats 0

theorem sourcePointwise_c15 : CaseFolding.foldingsChunk15.all sourcePointwiseP = true := by decide +kernel
theorem sourcePointwise_c16 : CaseFolding.foldingsChunk16.all sourcePointwiseP = true := by decide +kernel
theorem sourcePointwise_c17 : CaseFolding.foldingsChunk17.all sourcePointwiseP = true := by decide +kernel
theorem sourcePointwise_c18 : CaseFolding.foldingsChunk18.all sourcePointwiseP = true := by decide +kernel
theorem sourcePointwise_c19 : CaseFolding.foldingsChunk19.all sourcePointwiseP = true := by decide +kernel

theorem sourceComm_c15 : CaseFolding.foldingsChunk15.all sourceCommP = true := by decide +kernel
theorem sourceComm_c16 : CaseFolding.foldingsChunk16.all sourceCommP = true := by decide +kernel
theorem sourceComm_c17 : CaseFolding.foldingsChunk17.all sourceCommP = true := by decide +kernel
theorem sourceComm_c18 : CaseFolding.foldingsChunk18.all sourceCommP = true := by decide +kernel
theorem sourceComm_c19 : CaseFolding.foldingsChunk19.all sourceCommP = true := by decide +kernel

end Unicode.CaseFoldCommutation
