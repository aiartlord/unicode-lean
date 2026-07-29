/-
  Unicode.Conformance.Security.AiWatermarkDetectabilityTest

  Conformance for the AiWatermarkDetectability detector (statistical-watermark markers
  smuggled as NNBSP boundaries or variation-selector carriers in otherwise-plain text).

  The detector is exhaustively spot-checked in its own module (§): ASCII/Han clears and
  every marker sub-threat. This module verifies the full verdict — tag, marker
  positions, and marker count — on representative vectors.

  The prior `all_rows_pass := by decide` over the include_str corpus is not used: an
  include_str String's `.toList` is opaque to the kernel reducer, so a parse-and-decide
  over the corpus is stuck rather than proving anything. The fixture .txt is illustrative.
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
