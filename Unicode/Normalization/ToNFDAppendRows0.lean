/-
  Unicode.Normalization.ToNFDAppendRows0

  Per-chunk starter-head facts for `UnicodeData` chunks 0–11.  Split across
  `ToNFDAppendRows0..3` so each 12-chunk `decide +kernel` batch is a separate
  compilation unit; Lean reclaims the ~15 GB working set between files, keeping
  peak memory well under a whole-table build.
-/

import Unicode.Normalization.ToNFDAppendMirror

namespace Unicode.Normalization.ToNFDAppend

open Unicode.Generated

theorem rowP_c0 : UnicodeData.rowsChunk0.all rowP = true := by decide +kernel
theorem rowP_c1 : UnicodeData.rowsChunk1.all rowP = true := by decide +kernel
theorem rowP_c2 : UnicodeData.rowsChunk2.all rowP = true := by decide +kernel
theorem rowP_c3 : UnicodeData.rowsChunk3.all rowP = true := by decide +kernel
theorem rowP_c4 : UnicodeData.rowsChunk4.all rowP = true := by decide +kernel
theorem rowP_c5 : UnicodeData.rowsChunk5.all rowP = true := by decide +kernel
theorem rowP_c6 : UnicodeData.rowsChunk6.all rowP = true := by decide +kernel
theorem rowP_c7 : UnicodeData.rowsChunk7.all rowP = true := by decide +kernel
theorem rowP_c8 : UnicodeData.rowsChunk8.all rowP = true := by decide +kernel
theorem rowP_c9 : UnicodeData.rowsChunk9.all rowP = true := by decide +kernel
theorem rowP_c10 : UnicodeData.rowsChunk10.all rowP = true := by decide +kernel
theorem rowP_c11 : UnicodeData.rowsChunk11.all rowP = true := by decide +kernel

end Unicode.Normalization.ToNFDAppend
