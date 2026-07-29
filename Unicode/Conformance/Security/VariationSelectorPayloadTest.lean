/-
  Unicode.Conformance.Security.VariationSelectorPayloadTest

  Conformance for the VariationSelectorPayload detector (GlassWorm-class payloads
  hidden in variation-selector runs, U+FE00..U+FE0F / U+E0100..U+E01EF).

  Each theorem checks the full verdict — sub-threat tag, recovered payload bytes, and
  the registered-vs-suspicious position split — on a representative vector: a direct
  payload, an illegal target, a supplementary-VS illegal target, a registered emoji-
  presentation sequence, and a Mongolian free variation selector.
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
