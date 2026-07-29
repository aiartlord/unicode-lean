/-
  Unicode.Conformance.Security.LocaleCaseInversionTest

  Conformance for the LocaleCaseInversion detector (a codepoint whose case mapping
  diverges under the Turkish or Lithuanian tailored casing rules — a locale-dependent
  case-inversion hazard, e.g. dotless-i attacks).

  The detector is a predicate composition: `detect` reports a hazard exactly when
  `firstLocaleDivergence` finds a divergence under the Turkish or Lithuanian locale.
  We verify its contract over EVERY input, structurally, with no corpus reduction —
  the divergence predicates stay opaque, so no casing is reduced. Representative
  vectors are proven in the detector module.

  The prior `all_rows_pass := by decide` over the include_str corpus is not used: an
  include_str String's `.toList` is opaque to the kernel reducer, so a parse-and-decide
  over the corpus is stuck rather than proving anything. The fixture .txt is illustrative.
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
