import Unicode.CaseFoldDecompositionFactsBase

namespace Unicode.CaseFoldCommutation

open Unicode.Generated

set_option maxRecDepth 100000
set_option maxHeartbeats 0

theorem nonSourceDecomp_c12 : UnicodeData.rowsChunk12.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c13 : UnicodeData.rowsChunk13.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c14 : UnicodeData.rowsChunk14.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c15 : UnicodeData.rowsChunk15.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c16 : UnicodeData.rowsChunk16.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c17 : UnicodeData.rowsChunk17.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c18 : UnicodeData.rowsChunk18.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c19 : UnicodeData.rowsChunk19.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c20 : UnicodeData.rowsChunk20.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c21 : UnicodeData.rowsChunk21.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c22 : UnicodeData.rowsChunk22.all nonSourceDecompP = true := by decide +kernel
theorem nonSourceDecomp_c23 : UnicodeData.rowsChunk23.all nonSourceDecompP = true := by decide +kernel

end Unicode.CaseFoldCommutation
