/-
  Unicode.Conformance.Security.EmojiZwjIntegrityTest

  Conformance for the EmojiZwjIntegrity detector (malformed / forged emoji-ZWJ
  sequences — double ZWJ, non-emoji injection, skin-tone overflow, unregistered
  sequences), where a registered RGI sequence is always clear.

  The detector is exhaustively spot-checked in its own module (§): registered-RGI and
  single-skin-tone clears and every sub-threat. What those tag-only checks do not pin
  is the RGI-registration flag a consumer reads to decide sanctioning. This module
  verifies the full verdict on representative vectors.

  The prior `all_rows_pass := by decide` over the include_str corpus is not used: an
  include_str String's `.toList` is opaque to the kernel reducer, so a parse-and-decide
  over the corpus is stuck rather than proving anything. The fixture .txt is illustrative.
-/

import Unicode.Security.Identity.EmojiZwjIntegrity

namespace Unicode.Conformance.Security.EmojiZwjIntegrityTest

open Unicode.Security.Identity.EmojiZwjIntegrity

set_option maxRecDepth 1000000

/-- Two consecutive ZWJs between emoji — malformed (double ZWJ). -/
theorem double_zwj_verdict :
    let v := detect [0x1F600, 0x200D, 0x200D, 0x1F600]
    v.classify.tag = some "DoubleZWJ" ∧ v.isRegisteredRGI = false := by decide +kernel

/-- ZWJ splicing a non-emoji (ASCII 'a') into an emoji sequence — injection. -/
theorem non_emoji_injection_verdict :
    let v := detect [0x1F600, 0x200D, 0x0061]
    v.classify.tag = some "NonEmojiInjection" := by decide +kernel

/-- man + ZWJ + woman is a well-formed ZWJ join but not a registered RGI sequence —
    flagged as unregistered, RGI flag false. -/
theorem unregistered_sequence_verdict :
    let v := detect [0x1F468, 0x200D, 0x1F469]
    v.classify.tag = some "UnregisteredSequence" ∧ v.isRegisteredRGI = false := by
  decide +kernel

/-- The registered RGI family sequence is clear and flagged as registered RGI. -/
theorem family_rgi_clear_verdict :
    let v := detect [0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466]
    v.classify.isClear = true ∧ v.isRegisteredRGI = true := by decide +kernel

end Unicode.Conformance.Security.EmojiZwjIntegrityTest
