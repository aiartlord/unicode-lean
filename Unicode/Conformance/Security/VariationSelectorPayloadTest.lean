/-
  Unicode.Conformance.Security.VariationSelectorPayloadTest

  Conformance for the VariationSelectorPayload detector (GlassWorm-class payloads
  hidden in variation-selector runs, U+FE00..U+FE0F / U+E0100..U+E01EF).

  The detector is exhaustively spot-checked in its own module
  (`Unicode.Security.Covert.VariationSelectorPayload` §): registered-clear (emoji
  presentation, Mongolian FVS), every sub-threat (direct payload, illegal target,
  embedded-after-registered, repeated base), and the VS→nibble decoder. What those
  tag-only checks do not pin is the *recovered payload bytes* and the registered vs
  suspicious position split a consumer reads. This module verifies the full verdict
  on representative vectors.

  The prior `all_rows_pass := by decide` over the include_str corpus is not used: an
  include_str String's `.toList` is opaque to the kernel reducer, so a parse-and-decide
  over the corpus is stuck rather than proving anything. The fixture .txt is illustrative.
-/

import Unicode.Security.Covert.VariationSelectorPayload

namespace Unicode.Conformance.Security.VariationSelectorPayloadTest

open Unicode.Security.Covert.VariationSelectorPayload

/-- GlassWorm-shape direct payload: two VS on base 'a' decode (nibbles 4,1) to the
    byte 0x41 — full recovered payload and suspicious positions verified. -/
theorem direct_payload_verdict :
    let v := detect [0x0061, 0xFE04, 0xFE01]
    v.classify.tag = some "DirectPayload"
      ∧ v.recoveredPayloadBytes = [0x41]
      ∧ v.suspiciousPositions = [1, 2] := by decide +kernel

/-- VS16 on Latin 'A' — no registered variation sequence exists, so it is an illegal
    target at position 1. -/
theorem illegal_target_verdict :
    let v := detect [0x0041, 0xFE0F]
    v.classify.tag = some "IllegalTarget"
      ∧ v.suspiciousPositions = [1] := by decide +kernel

/-- A supplementary VS (U+E0100) on Latin 'A' is likewise an illegal target. -/
theorem supplementary_vs_illegal_verdict :
    let v := detect [0x0041, 0xE0100]
    v.classify.tag = some "IllegalTarget" := by decide +kernel

/-- VS16 after an emoji-presentation base is a registered sequence — clear, and the
    VS position is recorded as registered rather than suspicious. -/
theorem emoji_presentation_clear_verdict :
    let v := detect [0x1F600, 0xFE0F]
    v.classify.isClear = true
      ∧ v.registeredPositions = [1] ∧ v.suspiciousPositions = [] := by decide +kernel

/-- Mongolian free variation selector on a Mongolian base — registered, clear. -/
theorem mongolian_variation_clear_verdict :
    let v := detect [0x1820, 0x180B]
    v.classify.isClear = true := by decide +kernel

end Unicode.Conformance.Security.VariationSelectorPayloadTest
