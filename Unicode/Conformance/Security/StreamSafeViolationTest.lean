/-
  Unicode.Conformance.Security.StreamSafeViolationTest

  Conformance for the StreamSafeViolation detector: it reports a hazard exactly when
  `firstOverrun` locates a non-starter run exceeding the UAX #15 Stream-Safe cap of 30
  — a normalization-buffer DoS hazard.

  The theorems state the detector's contract over every input: the clear/hazard
  decision, the reported overrun position, and the run-length / overrun-count /
  non-starter-total metadata are each exactly the underlying scan value.
-/

import Unicode.Security.Form.StreamSafeViolation

namespace Unicode.Conformance.Security.StreamSafeViolationTest

open Unicode.Security.Form.StreamSafeViolation

/-- **Decision-correctness (all inputs).** `detect` is clear exactly when there is no
    stream-safe overrun — soundness and completeness of the clear/hazard decision. -/
theorem detect_isClear_characterization (input : List Nat) :
    (detect input).classify.isClear = (firstOverrun input).isNone := by
  simp only [detect, Classification.isClear]
  cases firstOverrun input <;> rfl

/-- **Position-correctness (all inputs).** A hazard reports exactly the base position
    of the first overrun; a clear verdict reports none. -/
theorem detect_positions_characterization (input : List Nat) :
    (detect input).classify.positions
      = (firstOverrun input).elim [] (fun br => [br.1]) := by
  simp only [detect, Classification.positions]
  cases firstOverrun input <;> rfl

/-- The verdict's maximum non-starter run length is exact. -/
theorem detect_maxRunLen (input : List Nat) :
    (detect input).maxRunLen = maxRunLen input := rfl

/-- The verdict's overrun count is exact. -/
theorem detect_overrunCount (input : List Nat) :
    (detect input).overrunCount = overrunCount input := rfl

/-- The verdict's total non-starter count is exact. -/
theorem detect_totalNonStarters (input : List Nat) :
    (detect input).totalNonStarters = totalNonStarters input := rfl

end Unicode.Conformance.Security.StreamSafeViolationTest
