/-
  Unicode.Conformance.Security.CaseExpansionMismatchTest

  Conformance for the CaseExpansionMismatch detector: it reports a hazard exactly when
  `firstUpperExpansion` or `firstLowerExpansion` locates a codepoint whose case mapping
  expands to more than one codepoint — a case-folding length hazard.

  The theorems state the detector's contract over every input: the clear/hazard
  decision, and the upper/lower expansion counts and maximum expansion length the
  verdict carries, are each exactly the underlying scan value.
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
