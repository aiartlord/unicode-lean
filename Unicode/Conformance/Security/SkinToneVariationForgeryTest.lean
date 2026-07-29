/-
  Unicode.Conformance.Security.SkinToneVariationForgeryTest

  Conformance for the SkinToneVariationForgery detector: it flags an emoji-forgery
  hazard on stacked or mistargeted skin-tone modifiers, or forced text-presentation on
  emoji.

  `detect_isClear_characterization` states the detector's contract over every input:
  the verdict is clear unless there are stacked skin tones, an invalid skin-tone
  target, or a forced text style.
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
