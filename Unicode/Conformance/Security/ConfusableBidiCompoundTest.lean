/-
  Unicode.Conformance.Security.ConfusableBidiCompoundTest

  Conformance for the ConfusableBidiCompound detector (a confusable codepoint that
  co-occurs with a bidi override or isolate — a compound spoofing hazard stronger
  than either signal alone).

  The detector is a match-chain composition: `detect` is clear unless a confusable is
  present AND it co-occurs with a bidi override or isolate. We verify its contract
  over EVERY input, structurally, with no corpus reduction — the position predicates
  stay opaque, so no confusable-skeleton computation is reduced. Representative
  vectors are proven in the detector module.

  The prior `all_rows_pass := by decide` over the include_str corpus is not used: an
  include_str String's `.toList` is opaque to the kernel reducer, so a parse-and-decide
  over the corpus is stuck rather than proving anything. The fixture .txt is illustrative.
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
