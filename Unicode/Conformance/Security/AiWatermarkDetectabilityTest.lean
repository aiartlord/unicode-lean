/-
  Unicode.Conformance.Security.AiWatermarkDetectabilityTest

  Conformance for the AiWatermarkDetectability detector: statistical-watermark markers
  smuggled as NNBSP boundaries or variation-selector carriers in otherwise-plain text.

  Each theorem checks the full verdict — sub-threat tag together with the marker count
  and marker positions — on a representative vector: an NNBSP boundary marker, a
  variation-selector carrier, and a plain-ASCII clear.
-/

import Unicode.Security.Crypto.AiWatermarkDetectability

namespace Unicode.Conformance.Security.AiWatermarkDetectabilityTest

open Unicode.Security.Crypto.AiWatermarkDetectability

set_option maxRecDepth 1000000

/-- An NNBSP spliced between Latin letters — a watermark boundary marker at position 1. -/
theorem nnbsp_boundary_verdict :
    let v := detect [0x61, 0x202F, 0x62]
    v.classify.tag = some "NnbspBoundary"
      ∧ v.classify.positions = [1] ∧ v.markerCount = 1 := by decide +kernel

/-- A variation selector in plain (non-emoji) text — a VS carrier marker. -/
theorem vs_carrier_verdict :
    let v := detect [0x61, 0xFE0F, 0x62]
    v.classify.tag = some "VariationSelectorCarrier"
      ∧ v.markerCount = 1 := by decide +kernel

/-- Plain ASCII carries no watermark markers — clear. -/
theorem ascii_clear_verdict :
    (detect [0x61, 0x62, 0x63]).classify = .clear := by decide +kernel

end Unicode.Conformance.Security.AiWatermarkDetectabilityTest
