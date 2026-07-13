/-
  Unicode.Normalization.ToNFDAppendRows2

  Per-chunk starter-head facts for `UnicodeData` chunks 24–35.  See
  `ToNFDAppendRows0` for the file-split rationale.
-/

import Unicode.Normalization.ToNFDAppendMirror

namespace Unicode.Normalization.ToNFDAppend

open Unicode.Generated

theorem rowP_c24 : UnicodeData.rowsChunk24.all rowP = true := by decide +kernel
theorem rowP_c25 : UnicodeData.rowsChunk25.all rowP = true := by decide +kernel
theorem rowP_c26 : UnicodeData.rowsChunk26.all rowP = true := by decide +kernel
theorem rowP_c27 : UnicodeData.rowsChunk27.all rowP = true := by decide +kernel
theorem rowP_c28 : UnicodeData.rowsChunk28.all rowP = true := by decide +kernel
theorem rowP_c29 : UnicodeData.rowsChunk29.all rowP = true := by decide +kernel
theorem rowP_c30 : UnicodeData.rowsChunk30.all rowP = true := by decide +kernel
theorem rowP_c31 : UnicodeData.rowsChunk31.all rowP = true := by decide +kernel
theorem rowP_c32 : UnicodeData.rowsChunk32.all rowP = true := by decide +kernel
theorem rowP_c33 : UnicodeData.rowsChunk33.all rowP = true := by decide +kernel
theorem rowP_c34 : UnicodeData.rowsChunk34.all rowP = true := by decide +kernel
theorem rowP_c35 : UnicodeData.rowsChunk35.all rowP = true := by decide +kernel

end Unicode.Normalization.ToNFDAppend
