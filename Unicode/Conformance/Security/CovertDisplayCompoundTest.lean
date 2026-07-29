/-
  Unicode.Conformance.Security.CovertDisplayCompoundTest

  Conformance for the CovertDisplayCompound detector: it flags a compound covert-
  display hazard when a bidi control co-occurs with a suspicious variation selector or
  a tag-block codepoint — two hiding channels combined.

  `detect_isClear_characterization` states the detector's contract over every input:
  the verdict is clear unless a bidi control is present and it co-occurs with a
  suspicious variation selector or a tag-block codepoint.
-/

import Unicode.Security.Boundary.CovertDisplayCompound

namespace Unicode.Conformance.Security.CovertDisplayCompoundTest

open Unicode.Security.Boundary.CovertDisplayCompound

/-- **Decision-correctness (all inputs).** `detect` is clear exactly when there is no
    bidi control, or there is one but it co-occurs with neither a suspicious variation
    selector nor a tag-block codepoint — soundness and completeness of the clear/
    hazard decision. -/
theorem detect_isClear_characterization (input : List Nat) :
    (detect input).classify.isClear
      = ((firstBidiPos input).isNone
          || ((firstSuspiciousVsPos input).isNone && (firstTagBlockPos input).isNone)) := by
  simp only [detect, Classification.isClear]
  cases firstBidiPos input <;>
    cases firstSuspiciousVsPos input <;>
    cases firstTagBlockPos input <;> rfl

end Unicode.Conformance.Security.CovertDisplayCompoundTest
