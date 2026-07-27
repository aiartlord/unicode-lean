/-
  Unicode.Security.Identity.SkinToneVariationForgerySound

  Universal bounds for the SkinToneVariationForgery tallies. `skinToneCount`,
  `vs15Count`, and `vs16Count` each add at most one per codepoint, so for every
  input the tally is at most the input size, via `Unicode.Machine.foldl_count_le`.
-/

import Unicode.Security.Identity.SkinToneVariationForgery
import Unicode.Machine

namespace Unicode.Security.Identity.SkinToneVariationForgery

open Unicode.Machine.AbstractMachine

/-- The skin-tone tally is at most the input size, for every input. -/
theorem skinToneCount_le_size (input : List Nat) :
    skinToneCount input ≤ input.length := by
  have h := foldl_count_le isSkinTone 0 input
  simpa [skinToneCount] using h

/-- The `U+FE0E` tally is at most the input size, for every input. -/
theorem vs15Count_le_size (input : List Nat) :
    vs15Count input ≤ input.length := by
  have h := foldl_count_le isVS15 0 input
  simpa [vs15Count] using h

/-- The `U+FE0F` tally is at most the input size, for every input. -/
theorem vs16Count_le_size (input : List Nat) :
    vs16Count input ≤ input.length := by
  have h := foldl_count_le isVS16 0 input
  simpa [vs16Count] using h

end Unicode.Security.Identity.SkinToneVariationForgery
