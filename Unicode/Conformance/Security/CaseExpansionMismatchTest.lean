/-
  Unicode.Conformance.Security.CaseExpansionMismatchTest

  Conformance for the CaseExpansionMismatch detector: it reports a hazard when a
  codepoint's upper- or lower-case mapping expands to more than one codepoint — a
  case-folding length hazard used to smuggle length past validators.

  Each theorem checks the verdict on a documented case: ß and the ﬁ ligature expand
  under upper-casing (SS, FI); dotted capital İ expands under lower-casing.
-/

import Unicode.Security.Form.CaseExpansionMismatch

namespace Unicode.Conformance.Security.CaseExpansionMismatchTest

open Unicode.Security.Form.CaseExpansionMismatch

set_option maxRecDepth 1000000

/-- ß (U+00DF) upper-cases to "SS" — an upper expansion. -/
theorem sharp_s_upper :
    (detect [0x00DF]).classify.tag = some "UpperExpansion" := by decide +kernel

/-- The ﬁ ligature (U+FB01) upper-cases to "FI" — an upper expansion. -/
theorem fi_ligature_upper :
    (detect [0xFB01]).classify.tag = some "UpperExpansion" := by decide +kernel

/-- Dotted capital İ (U+0130) lower-cases to "i̇" (two codepoints) — a lower
    expansion, reached after the upper scan finds nothing. -/
theorem dotted_I_lower :
    (detect [0x0130]).classify.tag = some "LowerExpansion" := by decide +kernel

end Unicode.Conformance.Security.CaseExpansionMismatchTest
