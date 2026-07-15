import Unicode.Normalization.ComposeInversionCombP

namespace Unicode.Normalization.ComposeInversion

open Unicode.Generated

set_option maxRecDepth 1000000

theorem combP_c24 : UnicodeData.rowsChunk24.all combP = true := by decide +kernel
theorem combP_c25 : UnicodeData.rowsChunk25.all combP = true := by decide +kernel
theorem combP_c26 : UnicodeData.rowsChunk26.all combP = true := by decide +kernel
theorem combP_c27 : UnicodeData.rowsChunk27.all combP = true := by decide +kernel
theorem combP_c28 : UnicodeData.rowsChunk28.all combP = true := by decide +kernel
theorem combP_c29 : UnicodeData.rowsChunk29.all combP = true := by decide +kernel
theorem combP_c30 : UnicodeData.rowsChunk30.all combP = true := by decide +kernel
theorem combP_c31 : UnicodeData.rowsChunk31.all combP = true := by decide +kernel
theorem combP_c32 : UnicodeData.rowsChunk32.all combP = true := by decide +kernel
theorem combP_c33 : UnicodeData.rowsChunk33.all combP = true := by decide +kernel
theorem combP_c34 : UnicodeData.rowsChunk34.all combP = true := by decide +kernel
theorem combP_c35 : UnicodeData.rowsChunk35.all combP = true := by decide +kernel

end Unicode.Normalization.ComposeInversion
