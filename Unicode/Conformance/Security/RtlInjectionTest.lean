/-
  Unicode.Conformance.Security.RtlInjectionTest

  Conformance for the RtlInjection detector: strong right-to-left characters or bidi
  controls that hijack the display order of a left-to-right field — RTL-injection /
  field-takeover hazards.

  Each theorem checks the full verdict — sub-threat tag together with the strong-
  direction and bidi-control counts — on a representative vector: an RLO injected into
  an LTR field, a strong-RTL field takeover, and a plain-ASCII clear.
-/

import Unicode.Security.Display.RtlInjection

namespace Unicode.Conformance.Security.RtlInjectionTest

open Unicode.Security.Display.RtlInjection

-- Matches the detector module: the direction-run scans recurse past the default.
set_option maxRecDepth 1000000

/-- RLO injected into an LTR field (A ⟨RLO⟩ B) — reorders display; one bidi control. -/
theorem rlo_in_ltr_verdict :
    let v := detect [0x41, 0x202E, 0x42]
    v.classify.tag = some "RloInLTRField" ∧ v.bidiControlCount = 1 := by decide

/-- A leading strong-RTL letter takes over an otherwise-LTR field. -/
theorem rtl_takeover_verdict :
    let v := detect [0x05D0, 0x42, 0x43]
    v.classify.tag = some "FieldTakeover" ∧ v.strongRTLCount = 1 := by decide

/-- Plain ASCII is clear — no strong-RTL characters, no bidi controls. -/
theorem ascii_clear_verdict :
    let v := detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]
    v.classify.isClear = true
      ∧ v.strongRTLCount = 0 ∧ v.bidiControlCount = 0 := by decide

end Unicode.Conformance.Security.RtlInjectionTest
