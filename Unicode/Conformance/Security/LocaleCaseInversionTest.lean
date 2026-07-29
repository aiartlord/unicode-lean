/-
  Unicode.Conformance.Security.LocaleCaseInversionTest

  Conformance for the LocaleCaseInversion detector: it reports a hazard exactly when
  `firstLocaleDivergence` finds a codepoint whose case mapping diverges under the
  Turkish or Lithuanian tailored casing rules — a locale-dependent case-inversion
  hazard (e.g. dotless-i attacks).

  `detect_isClear_characterization` states the detector's contract over every input:
  the verdict is clear iff neither locale exhibits a divergence.
-/

import Unicode.Security.Form.LocaleCaseInversion

namespace Unicode.Conformance.Security.LocaleCaseInversionTest

open Unicode.Security.Form.LocaleCaseInversion

/-- **Decision-correctness (all inputs).** `detect` is clear exactly when there is no
    locale case divergence under either the Turkish or Lithuanian rules — soundness
    and completeness of the clear/hazard decision (Turkish checked first). -/
theorem detect_isClear_characterization (input : List Nat) :
    (detect input).classify.isClear
      = ((firstLocaleDivergence .turkish input).isNone
          && (firstLocaleDivergence .lithuanian input).isNone) := by
  simp only [detect, Classification.isClear]
  cases firstLocaleDivergence .turkish input <;>
    cases firstLocaleDivergence .lithuanian input <;> rfl

end Unicode.Conformance.Security.LocaleCaseInversionTest
