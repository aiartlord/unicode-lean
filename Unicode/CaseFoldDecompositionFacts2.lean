import Unicode.CaseFoldDecompositionFactsBase

namespace Unicode.CaseFoldCommutation

open Unicode.Generated

set_option maxRecDepth 100000
set_option maxHeartbeats 0

theorem nonSourceDecomp_c24 : UnicodeData.rowsChunk24.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c25 : UnicodeData.rowsChunk25.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c26 : UnicodeData.rowsChunk26.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c27 : UnicodeData.rowsChunk27.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c28 : UnicodeData.rowsChunk28.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c29 : UnicodeData.rowsChunk29.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c30 : UnicodeData.rowsChunk30.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c31 : UnicodeData.rowsChunk31.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c32 : UnicodeData.rowsChunk32.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c33 : UnicodeData.rowsChunk33.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c34 : UnicodeData.rowsChunk34.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c35 : UnicodeData.rowsChunk35.all nonSourceDecompP = true := by decide +kernel

end Unicode.CaseFoldCommutation
