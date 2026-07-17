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
theorem skinToneCount_le_size (input : Array Nat) :
    skinToneCount input ≤ input.size := by
  have h := foldl_count_le isSkinTone 0 input.toList
  simpa [skinToneCount, Array.foldl_toList] using h

/-- The `U+FE0E` tally is at most the input size, for every input. -/
theorem vs15Count_le_size (input : Array Nat) :
    vs15Count input ≤ input.size := by
  have h := foldl_count_le isVS15 0 input.toList
  simpa [vs15Count, Array.foldl_toList] using h

/-- The `U+FE0F` tally is at most the input size, for every input. -/
theorem vs16Count_le_size (input : Array Nat) :
    vs16Count input ≤ input.size := by
  have h := foldl_count_le isVS16 0 input.toList
  simpa [vs16Count, Array.foldl_toList] using h

end Unicode.Security.Identity.SkinToneVariationForgery
