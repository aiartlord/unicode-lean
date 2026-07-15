import Unicode.Normalization.ComposeInversionCombP

namespace Unicode.Normalization.ComposeInversion

open Unicode.Generated

set_option maxRecDepth 1000000

theorem combP_c12 : UnicodeData.rowsChunk12.all combP = true := by decide +kernel
theorem combP_c13 : UnicodeData.rowsChunk13.all combP = true := by decide +kernel
theorem combP_c14 : UnicodeData.rowsChunk14.all combP = true := by decide +kernel
theorem combP_c15 : UnicodeData.rowsChunk15.all combP = true := by decide +kernel
theorem combP_c16 : UnicodeData.rowsChunk16.all combP = true := by decide +kernel
theorem combP_c17 : UnicodeData.rowsChunk17.all combP = true := by decide +kernel
theorem combP_c18 : UnicodeData.rowsChunk18.all combP = true := by decide +kernel
theorem combP_c19 : UnicodeData.rowsChunk19.all combP = true := by decide +kernel
theorem combP_c20 : UnicodeData.rowsChunk20.all combP = true := by decide +kernel
theorem combP_c21 : UnicodeData.rowsChunk21.all combP = true := by decide +kernel
theorem combP_c22 : UnicodeData.rowsChunk22.all combP = true := by decide +kernel
theorem combP_c23 : UnicodeData.rowsChunk23.all combP = true := by decide +kernel

end Unicode.Normalization.ComposeInversion
