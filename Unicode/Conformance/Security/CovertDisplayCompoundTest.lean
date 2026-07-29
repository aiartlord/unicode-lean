/-
  Unicode.Conformance.Security.CovertDisplayCompoundTest

  Conformance for the CovertDisplayCompound detector (a bidi control co-occurring with
  an unregistered variation selector or a tag-block codepoint — a compound covert-
  display hazard combining two hiding channels).

  The detector is a match-chain composition: `detect` is clear unless a bidi control
  is present AND it co-occurs with a suspicious variation selector or a tag-block
  codepoint. We verify its contract over EVERY input, structurally, with no corpus
  reduction — the position predicates stay opaque. Representative vectors are proven
  in the detector module.

  The prior `all_rows_pass := by decide` over the include_str corpus is not used: an
  include_str String's `.toList` is opaque to the kernel reducer, so a parse-and-decide
  over the corpus is stuck rather than proving anything. The fixture .txt is illustrative.
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
