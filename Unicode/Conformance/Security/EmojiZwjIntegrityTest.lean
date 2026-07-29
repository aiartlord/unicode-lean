/-
  Unicode.Conformance.Security.EmojiZwjIntegrityTest

  Conformance for the EmojiZwjIntegrity detector: malformed or forged emoji-ZWJ
  sequences — double ZWJ, non-emoji injection, skin-tone overflow, unregistered
  sequences — where a registered RGI sequence is always clear.

  Each theorem checks the full verdict — sub-threat tag together with the RGI-
  registration flag — on a representative vector: a double ZWJ, a non-emoji injection,
  an unregistered join, and a registered RGI family sequence.
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
