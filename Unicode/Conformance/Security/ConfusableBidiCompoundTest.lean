/-
  Unicode.Conformance.Security.ConfusableBidiCompoundTest

  Conformance for the ConfusableBidiCompound detector: it flags a compound spoofing
  hazard when a confusable codepoint co-occurs with a bidi override or isolate —
  stronger than either signal alone.

  `detect_isClear_characterization` states the detector's contract over every input:
  the verdict is clear unless a confusable is present and it co-occurs with a bidi
  override or isolate.
-/

import Unicode.Security.Boundary.ConfusableBidiCompound

namespace Unicode.Conformance.Security.ConfusableBidiCompoundTest

open Unicode.Security.Boundary.ConfusableBidiCompound

/-- **Decision-correctness (all inputs).** `detect` is clear exactly when there is no
    confusable codepoint, or there is one but it co-occurs with neither a bidi
    override nor a bidi isolate — soundness and completeness of the clear/hazard
    decision. -/
theorem detect_isClear_characterization (input : List Nat) :
    (detect input).classify.isClear
      = ((firstConfusablePos input).isNone
          || ((firstOverridePos input).isNone && (firstIsolatePos input).isNone)) := by
  simp only [detect, Classification.isClear]
  cases firstConfusablePos input <;>
    cases firstOverridePos input <;>
    cases firstIsolatePos input <;> rfl

/-- The verdict's confusable count is exact. -/
theorem detect_confusableCount (input : List Nat) :
    (detect input).confusableCount = confusableCount input := rfl

end Unicode.Conformance.Security.ConfusableBidiCompoundTest
