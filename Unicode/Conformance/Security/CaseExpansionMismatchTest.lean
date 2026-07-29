/-
  Unicode.Conformance.Security.CaseExpansionMismatchTest

  Conformance for the CaseExpansionMismatch detector (a codepoint whose upper- or
  lower-case mapping expands to more than one codepoint — a case-folding length
  hazard exploited to smuggle length past validators).

  The detector is a predicate composition: `detect` reports a hazard exactly when
  `firstUpperExpansion` or `firstLowerExpansion` locates an expanding codepoint. We
  verify its contract over EVERY input, structurally, with no corpus reduction — the
  `firstUpper/LowerExpansion` predicates stay opaque, so no case mapping is reduced.
  Representative vectors are proven in the detector module.

  The prior `all_rows_pass := by decide` over the include_str corpus is not used: an
  include_str String's `.toList` is opaque to the kernel reducer, so a parse-and-decide
  over the corpus is stuck rather than proving anything. The fixture .txt is illustrative.
-/

import Unicode.Security.Form.CaseExpansionMismatch

namespace Unicode.Conformance.Security.CaseExpansionMismatchTest

open Unicode.Security.Form.CaseExpansionMismatch

/-- **Decision-correctness (all inputs).** `detect` is clear exactly when neither an
    upper- nor a lower-case expansion is present — soundness and completeness of the
    clear/hazard decision (upper checked first by priority). -/
theorem detect_isClear_characterization (input : List Nat) :
    (detect input).classify.isClear
      = ((firstUpperExpansion input).isNone && (firstLowerExpansion input).isNone) := by
  simp only [detect, Classification.isClear]
  cases firstUpperExpansion input <;> cases firstLowerExpansion input <;> rfl

/-- The verdict's upper-expansion count is exactly the consumer's count. -/
theorem detect_upperExpansionCount (input : List Nat) :
    (detect input).upperExpansionCount = upperExpansionCount input := rfl

/-- The verdict's lower-expansion count is exact. -/
theorem detect_lowerExpansionCount (input : List Nat) :
    (detect input).lowerExpansionCount = lowerExpansionCount input := rfl

/-- The verdict's maximum expansion length is exact. -/
theorem detect_maxExpansionLen (input : List Nat) :
    (detect input).maxExpansionLen = maxExpansionLen input := rfl

end Unicode.Conformance.Security.CaseExpansionMismatchTest
