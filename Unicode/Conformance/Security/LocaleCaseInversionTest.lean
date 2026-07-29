/-
  Unicode.Conformance.Security.LocaleCaseInversionTest

  Conformance for the LocaleCaseInversion detector: it reports a hazard when a
  codepoint's case mapping diverges under the Turkish or Lithuanian tailored casing
  rules — a locale-dependent case-inversion hazard (e.g. dotless-i attacks).

  Each theorem checks the verdict on a documented case: capital I and dotted İ diverge
  under Turkish rules; J-with-grave has no Turkish row and falls through to Lithuanian.
-/

import Unicode.Security.Form.LocaleCaseInversion

namespace Unicode.Conformance.Security.LocaleCaseInversionTest

open Unicode.Security.Form.LocaleCaseInversion

set_option maxRecDepth 1000000

/-- Capital I (U+0049) lower-cases to dotless ı under Turkish rules — a divergence. -/
theorem capital_I_turkish :
    (detect [0x0049]).classify.tag = some "TurkishCaseDivergence" := by decide +kernel

/-- Dotted capital İ (U+0130) diverges under Turkish rules. -/
theorem dotted_I_turkish :
    (detect [0x0130]).classify.tag = some "TurkishCaseDivergence" := by decide +kernel

/-- J + combining grave has no Turkish-conditional row, so the Turkish scan finds
    nothing and the detector falls through to a Lithuanian divergence. -/
theorem J_with_grave_lithuanian :
    (detect [0x004A, 0x0300]).classify.tag
      = some "LithuanianCaseDivergence" := by decide +kernel

end Unicode.Conformance.Security.LocaleCaseInversionTest
