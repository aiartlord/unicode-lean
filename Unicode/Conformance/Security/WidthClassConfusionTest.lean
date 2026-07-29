/-
  Unicode.Conformance.Security.WidthClassConfusionTest

  Conformance for the WidthClassConfusion detector: it reports a hazard exactly when
  `firstFullwidthFold` or `firstHalfwidthFold` locates a fullwidth/halfwidth
  compatibility form that NFKD-folds to a narrower or wider class — a width-confusion
  hazard.

  The theorems state the detector's contract over every input: the clear/hazard
  decision and the fullwidth/halfwidth fold counts are each exactly the underlying
  scan value.
-/

import Unicode.Security.Form.WidthClassConfusion

namespace Unicode.Conformance.Security.WidthClassConfusionTest

open Unicode.Security.Form.WidthClassConfusion

/-- **Decision-correctness (all inputs).** `detect` is clear exactly when neither a
    fullwidth nor a halfwidth fold is present — soundness and completeness of the
    clear/hazard decision (fullwidth checked first by priority). -/
theorem detect_isClear_characterization (input : List Nat) :
    (detect input).classify.isClear
      = ((firstFullwidthFold input).isNone && (firstHalfwidthFold input).isNone) := by
  simp only [detect, Classification.isClear]
  cases firstFullwidthFold input <;> cases firstHalfwidthFold input <;> rfl

/-- The verdict's fullwidth-fold count is exact. -/
theorem detect_fullwidthFoldCount (input : List Nat) :
    (detect input).fullwidthFoldCount = fullwidthFoldCount input := rfl

/-- The verdict's halfwidth-fold count is exact. -/
theorem detect_halfwidthFoldCount (input : List Nat) :
    (detect input).halfwidthFoldCount = halfwidthFoldCount input := rfl

end Unicode.Conformance.Security.WidthClassConfusionTest
