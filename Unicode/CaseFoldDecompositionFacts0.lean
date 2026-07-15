import Unicode.CaseFoldDecompositionFactsBase

namespace Unicode.CaseFoldCommutation

open Unicode.Generated

set_option maxRecDepth 100000
set_option maxHeartbeats 0

theorem nonSourceDecomp_c0 : UnicodeData.rowsChunk0.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c1 : UnicodeData.rowsChunk1.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c2 : UnicodeData.rowsChunk2.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c3 : UnicodeData.rowsChunk3.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c4 : UnicodeData.rowsChunk4.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c5 : UnicodeData.rowsChunk5.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c6 : UnicodeData.rowsChunk6.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c7 : UnicodeData.rowsChunk7.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c8 : UnicodeData.rowsChunk8.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c9 : UnicodeData.rowsChunk9.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c10 : UnicodeData.rowsChunk10.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c11 : UnicodeData.rowsChunk11.all nonSourceDecompP = true := by decide +kernel

end Unicode.CaseFoldCommutation
