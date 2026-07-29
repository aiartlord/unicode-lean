/-
  Unicode.Conformance.Security.IdentifierFormDriftTest

  Conformance for the IdentifierFormDrift detector: it reports a hazard exactly when
  `firstStatusShift` locates a codepoint whose UTS-39 Identifier_Status differs from
  that of its NFKD head — the per-codepoint sibling of AdmissibilityFormDrift.

  The theorems state the detector's contract over every input: the clear/hazard
  decision, the reported position, and the shift count are each exactly the
  underlying `firstStatusShift` / `statusShiftCount` value.
-/

import Unicode.Security.Boundary.IdentifierFormDrift

namespace Unicode.Conformance.Security.IdentifierFormDriftTest

open Unicode.Security.Boundary.IdentifierFormDrift

/-- **Decision-correctness (all inputs).** `detect` is clear exactly when no
    codepoint's UTS-39 identifier status shifts under NFKD — soundness and
    completeness of the detector as a decision procedure for identifier form drift. -/
theorem detect_isClear_characterization (input : List Nat) :
    (detect input).classify.isClear = (firstStatusShift input).isNone := by
  simp only [detect, Classification.isClear]
  cases firstStatusShift input <;> rfl

/-- **Position-correctness (all inputs).** When a hazard fires, the reported position
    is exactly the first status-shift position; when clear, no position is reported. -/
theorem detect_positions_characterization (input : List Nat) :
    (detect input).classify.positions
      = (firstStatusShift input).elim [] (fun pc => [pc.1]) := by
  simp only [detect, Classification.positions]
  cases firstStatusShift input <;> rfl

/-- **Count-correctness (all inputs).** The verdict's shift count is exactly the
    number of status-shifting codepoints a consumer would compute. -/
theorem detect_shiftCount_characterization (input : List Nat) :
    (detect input).shiftCount = statusShiftCount input := rfl

end Unicode.Conformance.Security.IdentifierFormDriftTest
