/-
  Unicode.Conformance.Security.StreamSafeViolationTest

  Conformance for the StreamSafeViolation detector (a non-starter run exceeding the
  UAX #15 Stream-Safe cap of 30 — a normalization-buffer DoS / stream-safe hazard).

  The detector is a predicate composition: `detect` reports a hazard exactly when
  `firstOverrun` locates a non-starter run past the cap. We verify its contract over
  EVERY input, structurally, with no corpus reduction — `firstOverrun` stays opaque.
  Representative vectors are proven in the detector module.

  The prior `all_rows_pass := by decide` over the include_str corpus is not used: an
  include_str String's `.toList` is opaque to the kernel reducer, so a parse-and-decide
  over the corpus is stuck rather than proving anything. The fixture .txt is illustrative.
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
