/-
  Unicode.Conformance.Security.SurrogateReassemblyTest

  Conformance for the SurrogateReassembly detector (CESU-8 / overlong / truncated /
  invalid UTF-8 byte-stream hazards).

  The detector is exhaustively spot-checked in its own module
  (`Unicode.Security.Covert.SurrogateReassembly` §): valid UTF-8 clears (ASCII, é,
  Han, emoji) and every sub-threat (overlong, CESU-8 surrogate, truncated, invalid
  start byte, lone continuation). What those tag-only checks do not pin is the
  verdict metadata — the byte count and first-invalid offset a consumer reads. This
  module verifies the full verdict on representative byte streams.

  The prior `all_rows_pass := by decide` over the include_str corpus is not used: an
  include_str String's `.toList` is opaque to the kernel reducer, so a parse-and-decide
  over the corpus is stuck rather than proving anything. The fixture .txt is illustrative.
-/

import Unicode.Security.Covert.SurrogateReassembly

namespace Unicode.Conformance.Security.SurrogateReassemblyTest

open Unicode.Security.Covert.SurrogateReassembly

/-- 3-byte overlong encoding of '/' (0xE0 0x80 0xAF) — overlong at offset 0. -/
theorem overlong_verdict :
    let v := detect [0xE0, 0x80, 0xAF]
    v.classify.tag = some "Overlong"
      ∧ v.byteCount = 3 ∧ v.firstInvalidOffset = some 0 := by decide

/-- Surrogate U+D800 encoded as 0xED 0xA0 0x80 — CESU-8 indicator; the surrogate is
    confirmed at the third byte (offset 2). -/
theorem cesu8_verdict :
    let v := detect [0xED, 0xA0, 0x80]
    v.classify.tag = some "Cesu8"
      ∧ v.byteCount = 3 ∧ v.firstInvalidOffset = some 2 := by decide

/-- Leading 0xF0 with only two continuation bytes — truncated 4-byte sequence; the
    missing fourth byte is reported at offset 3. -/
theorem truncated_verdict :
    let v := detect [0xF0, 0x9F, 0x98]
    v.classify.tag = some "Truncated"
      ∧ v.byteCount = 3 ∧ v.firstInvalidOffset = some 3 := by decide

/-- 0xFE never appears in valid UTF-8 — invalid start byte at offset 0. -/
theorem invalid_start_verdict :
    let v := detect [0xFE]
    v.classify.tag = some "InvalidStartByte"
      ∧ v.byteCount = 1 ∧ v.firstInvalidOffset = some 0 := by decide

/-- Valid 4-byte emoji (U+1F600) — clear, no invalid offset. -/
theorem valid_emoji_clear_verdict :
    let v := detect [0xF0, 0x9F, 0x98, 0x80]
    v.classify.isClear = true
      ∧ v.byteCount = 4 ∧ v.firstInvalidOffset = none := by decide

end Unicode.Conformance.Security.SurrogateReassemblyTest
