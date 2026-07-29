/-
  Unicode.Conformance.Security.SkinToneVariationForgeryTest

  Conformance for the SkinToneVariationForgery detector: it flags an emoji-forgery
  hazard on stacked or mistargeted skin-tone modifiers, or forced text-presentation on
  emoji.

  Each theorem checks the verdict on a documented case: a single skin tone on a wave
  is clear, while two stacked tones, a tone on a non-base (ASCII), and a forced text-
  style selector each fire.
-/

import Unicode.Security.Identity.SkinToneVariationForgery

namespace Unicode.Conformance.Security.SkinToneVariationForgeryTest

open Unicode.Security.Identity.SkinToneVariationForgery

set_option maxRecDepth 1000000

/-- A single skin tone on 👋 is a well-formed modifier sequence — clear. -/
theorem wave_skin_tone_clear :
    (detect [0x1F44B, 0x1F3FB]).classify.isClear = true := by decide +kernel

/-- Two skin-tone modifiers on one base — stacked skin tones. -/
theorem stacked_skin_tones :
    (detect [0x1F44B, 0x1F3FB, 0x1F3FC]).classify.tag
      = some "StackedSkinTones" := by decide +kernel

/-- A skin-tone modifier on ASCII 'A' (not an emoji-modifier base) — invalid target. -/
theorem invalid_target_ascii :
    (detect [0x0041, 0x1F3FB]).classify.tag
      = some "InvalidSkinToneTarget" := by decide +kernel

/-- A text-presentation selector (VS15) forcing text style on an emoji base. -/
theorem forced_text_style :
    (detect [0x1F600, 0xFE0E]).classify.tag
      = some "ForcedTextStyle" := by decide +kernel

end Unicode.Conformance.Security.SkinToneVariationForgeryTest
