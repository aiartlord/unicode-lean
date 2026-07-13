/-
  Unicode.Normalization.ToNFDAppendRows3

  Per-chunk starter-head facts for `UnicodeData` chunks 36–47.  See
  `ToNFDAppendRows0` for the file-split rationale.
-/

import Unicode.Normalization.ToNFDAppendMirror

namespace Unicode.Normalization.ToNFDAppend

open Unicode.Generated

theorem rowP_c36 : UnicodeData.rowsChunk36.all rowP = true := by decide +kernel
theorem rowP_c37 : UnicodeData.rowsChunk37.all rowP = true := by decide +kernel
theorem rowP_c38 : UnicodeData.rowsChunk38.all rowP = true := by decide +kernel
theorem rowP_c39 : UnicodeData.rowsChunk39.all rowP = true := by decide +kernel
theorem rowP_c40 : UnicodeData.rowsChunk40.all rowP = true := by decide +kernel
theorem rowP_c41 : UnicodeData.rowsChunk41.all rowP = true := by decide +kernel
theorem rowP_c42 : UnicodeData.rowsChunk42.all rowP = true := by decide +kernel
theorem rowP_c43 : UnicodeData.rowsChunk43.all rowP = true := by decide +kernel
theorem rowP_c44 : UnicodeData.rowsChunk44.all rowP = true := by decide +kernel
theorem rowP_c45 : UnicodeData.rowsChunk45.all rowP = true := by decide +kernel
theorem rowP_c46 : UnicodeData.rowsChunk46.all rowP = true := by decide +kernel
theorem rowP_c47 : UnicodeData.rowsChunk47.all rowP = true := by decide +kernel

end Unicode.Normalization.ToNFDAppend
