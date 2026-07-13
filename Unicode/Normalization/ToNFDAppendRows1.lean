/-
  Unicode.Normalization.ToNFDAppendRows1

  Per-chunk starter-head facts for `UnicodeData` chunks 12–23.  See
  `ToNFDAppendRows0` for the file-split rationale.
-/

import Unicode.Normalization.ToNFDAppendMirror

namespace Unicode.Normalization.ToNFDAppend

open Unicode.Generated

theorem rowP_c12 : UnicodeData.rowsChunk12.all rowP = true := by decide +kernel
theorem rowP_c13 : UnicodeData.rowsChunk13.all rowP = true := by decide +kernel
theorem rowP_c14 : UnicodeData.rowsChunk14.all rowP = true := by decide +kernel
theorem rowP_c15 : UnicodeData.rowsChunk15.all rowP = true := by decide +kernel
theorem rowP_c16 : UnicodeData.rowsChunk16.all rowP = true := by decide +kernel
theorem rowP_c17 : UnicodeData.rowsChunk17.all rowP = true := by decide +kernel
theorem rowP_c18 : UnicodeData.rowsChunk18.all rowP = true := by decide +kernel
theorem rowP_c19 : UnicodeData.rowsChunk19.all rowP = true := by decide +kernel
theorem rowP_c20 : UnicodeData.rowsChunk20.all rowP = true := by decide +kernel
theorem rowP_c21 : UnicodeData.rowsChunk21.all rowP = true := by decide +kernel
theorem rowP_c22 : UnicodeData.rowsChunk22.all rowP = true := by decide +kernel
theorem rowP_c23 : UnicodeData.rowsChunk23.all rowP = true := by decide +kernel

end Unicode.Normalization.ToNFDAppend
