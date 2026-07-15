import Unicode.Normalization.ComposeInversionCombP

namespace Unicode.Normalization.ComposeInversion

open Unicode.Generated

set_option maxRecDepth 1000000

theorem combP_c0 : UnicodeData.rowsChunk0.all combP = true := by decide +kernel
theorem combP_c1 : UnicodeData.rowsChunk1.all combP = true := by decide +kernel
theorem combP_c2 : UnicodeData.rowsChunk2.all combP = true := by decide +kernel
theorem combP_c3 : UnicodeData.rowsChunk3.all combP = true := by decide +kernel
theorem combP_c4 : UnicodeData.rowsChunk4.all combP = true := by decide +kernel
theorem combP_c5 : UnicodeData.rowsChunk5.all combP = true := by decide +kernel
theorem combP_c6 : UnicodeData.rowsChunk6.all combP = true := by decide +kernel
theorem combP_c7 : UnicodeData.rowsChunk7.all combP = true := by decide +kernel
theorem combP_c8 : UnicodeData.rowsChunk8.all combP = true := by decide +kernel
theorem combP_c9 : UnicodeData.rowsChunk9.all combP = true := by decide +kernel
theorem combP_c10 : UnicodeData.rowsChunk10.all combP = true := by decide +kernel
theorem combP_c11 : UnicodeData.rowsChunk11.all combP = true := by decide +kernel

end Unicode.Normalization.ComposeInversion
