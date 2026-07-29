/-
  Unicode.Conformance.Security.WidthClassConfusionTest

  Conformance for the WidthClassConfusion detector (fullwidth / halfwidth compatibility
  forms that NFKD-fold to a narrower/wider ASCII or Kana class — a display/identifier
  width-confusion hazard).

  The detector is a predicate composition: `detect` reports a hazard exactly when
  `firstFullwidthFold` or `firstHalfwidthFold` locates a folding codepoint. We verify
  its contract over EVERY input, structurally, with no corpus reduction — the fold
  predicates stay opaque, so no NFKD is reduced. Representative vectors are in the
  detector module.

  The prior `all_rows_pass := by decide` over the include_str corpus is not used: an
  include_str String's `.toList` is opaque to the kernel reducer, so a parse-and-decide
  over the corpus is stuck rather than proving anything. The fixture .txt is illustrative.
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
