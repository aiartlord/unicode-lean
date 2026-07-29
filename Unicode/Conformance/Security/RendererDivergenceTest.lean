/-
  Unicode.Conformance.Security.RendererDivergenceTest

  Conformance for the RendererDivergence detector: input that renders differently
  across engines — combining-mark stacks (Zalgo), variation-selector variance,
  unregistered ZWJ, fullwidth variance, mixed-direction variance.

  Each theorem checks the full verdict — sub-threat tag together with the VS /
  combining / fullwidth counts — on a representative vector: a fullwidth-variance case
  and an ASCII clear.
-/

import Unicode.Security.Display.RendererDivergence

namespace Unicode.Conformance.Security.RendererDivergenceTest

open Unicode.Security.Display.RendererDivergence

set_option maxRecDepth 1000000

/-- Fullwidth Latin 'A' (U+FF21) renders as a wide glyph — fullwidth variance, one
    fullwidth codepoint counted. -/
theorem fullwidth_variance_verdict :
    let v := detect [0xFF21]
    v.classify.tag = some "FullwidthVariance" ∧ v.fullwidthCount = 1 := by decide +kernel

/-- Plain ASCII is stable across renderers — clear, no variance-inducing codepoints. -/
theorem ascii_clear_verdict :
    let v := detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]
    v.classify.isClear = true
      ∧ v.vsCount = 0 ∧ v.combiningCount = 0 ∧ v.fullwidthCount = 0 := by decide +kernel

end Unicode.Conformance.Security.RendererDivergenceTest
