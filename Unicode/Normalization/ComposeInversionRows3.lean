import Unicode.Normalization.ComposeInversionCombP

namespace Unicode.Normalization.ComposeInversion

open Unicode.Generated

set_option maxRecDepth 1000000

theorem combP_c36 : UnicodeData.rowsChunk36.all combP = true := by decide +kernel
theorem combP_c37 : UnicodeData.rowsChunk37.all combP = true := by decide +kernel
theorem combP_c38 : UnicodeData.rowsChunk38.all combP = true := by decide +kernel
theorem combP_c39 : UnicodeData.rowsChunk39.all combP = true := by decide +kernel
theorem combP_c40 : UnicodeData.rowsChunk40.all combP = true := by decide +kernel
theorem combP_c41 : UnicodeData.rowsChunk41.all combP = true := by decide +kernel
theorem combP_c42 : UnicodeData.rowsChunk42.all combP = true := by decide +kernel
theorem combP_c43 : UnicodeData.rowsChunk43.all combP = true := by decide +kernel
theorem combP_c44 : UnicodeData.rowsChunk44.all combP = true := by decide +kernel
theorem combP_c45 : UnicodeData.rowsChunk45.all combP = true := by decide +kernel
theorem combP_c46 : UnicodeData.rowsChunk46.all combP = true := by decide +kernel
theorem combP_c47 : UnicodeData.rowsChunk47.all combP = true := by decide +kernel

end Unicode.Normalization.ComposeInversion
