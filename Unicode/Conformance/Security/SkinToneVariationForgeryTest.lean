/-
  Unicode.Conformance.Security.SkinToneVariationForgeryTest

  Conformance for the SkinToneVariationForgery detector (stacked / mistargeted skin-
  tone modifiers or forced text-presentation on emoji — an emoji-forgery hazard).

  The detector is a match-chain composition: `detect` is clear unless it finds stacked
  skin tones, an invalid skin-tone target, or a forced text style. We verify its
  contract over EVERY input, structurally, with no corpus reduction — the scan
  predicates stay opaque. Representative vectors are proven in the detector module.

  The prior `all_rows_pass := by decide` over the include_str corpus is not used: an
  include_str String's `.toList` is opaque to the kernel reducer, so a parse-and-decide
  over the corpus is stuck rather than proving anything. The fixture .txt is illustrative.
-/

import Unicode.Security.Identity.SkinToneVariationForgery

namespace Unicode.Conformance.Security.SkinToneVariationForgeryTest

open Unicode.Security.Identity.SkinToneVariationForgery

/-- **Decision-correctness (all inputs).** `detect` is clear exactly when there are no
    stacked skin-tone modifiers, no invalid skin-tone target, and no forced text-
    presentation style — soundness and completeness of the clear/hazard decision,
    honouring the stacked → invalid-target → forced-style priority. -/
theorem detect_isClear_characterization (input : List Nat) :
    (detect input).classify.isClear
      = ((firstStackedSkinTones input).isNone
          && (firstInvalidSkinToneTarget input).isNone
          && (firstForcedTextStyle input).isNone) := by
  simp only [detect, Classification.isClear]
  cases firstStackedSkinTones input <;>
    cases firstInvalidSkinToneTarget input <;>
    cases firstForcedTextStyle input <;> rfl

end Unicode.Conformance.Security.SkinToneVariationForgeryTest
