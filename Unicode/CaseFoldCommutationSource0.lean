import Unicode.CaseFoldCommutationSourceBase

namespace Unicode.CaseFoldCommutation

open Unicode.Generated

set_option maxRecDepth 100000
set_option maxHeartbeats 0

theorem sourcePointwise_c0 : CaseFolding.foldingsChunk0.all sourcePointwiseP = true := by decide +kernel
theorem sourcePointwise_c1 : CaseFolding.foldingsChunk1.all sourcePointwiseP = true := by decide +kernel
theorem sourcePointwise_c2 : CaseFolding.foldingsChunk2.all sourcePointwiseP = true := by decide +kernel
theorem sourcePointwise_c3 : CaseFolding.foldingsChunk3.all sourcePointwiseP = true := by decide +kernel
theorem sourcePointwise_c4 : CaseFolding.foldingsChunk4.all sourcePointwiseP = true := by decide +kernel

theorem sourceComm_c0 : CaseFolding.foldingsChunk0.all sourceCommP = true := by decide +kernel
theorem sourceComm_c1 : CaseFolding.foldingsChunk1.all sourceCommP = true := by decide +kernel
theorem sourceComm_c2 : CaseFolding.foldingsChunk2.all sourceCommP = true := by decide +kernel
theorem sourceComm_c3 : CaseFolding.foldingsChunk3.all sourceCommP = true := by decide +kernel
theorem sourceComm_c4 : CaseFolding.foldingsChunk4.all sourceCommP = true := by decide +kernel

end Unicode.CaseFoldCommutation
