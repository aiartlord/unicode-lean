/-
  Unicode.Security.Form.WidthClassConfusionSound

  Universal bounds for the WidthClassConfusion tallies. `fullwidthFoldCount` and
  `halfwidthFoldCount` scan the input positions and add at most one per position,
  so for every input each tally is at most the input size, via
  `Unicode.Machine.array_range_foldl_step_le`.
-/

import Unicode.Security.Form.WidthClassConfusion
import Unicode.Machine

namespace Unicode.Security.Form.WidthClassConfusion

open Unicode.Machine.AbstractMachine

/-- The fullwidth-fold tally is at most the input size, for every input. -/
theorem fullwidthFoldCount_le_size (input : Array Nat) :
    fullwidthFoldCount input ≤ input.size := by
  unfold fullwidthFoldCount
  apply array_range_foldl_step_le
  intro m i
  dsimp only
  repeat' split
  all_goals omega

/-- The halfwidth-fold tally is at most the input size, for every input. -/
theorem halfwidthFoldCount_le_size (input : Array Nat) :
    halfwidthFoldCount input ≤ input.size := by
  unfold halfwidthFoldCount
  apply array_range_foldl_step_le
  intro m i
  dsimp only
  repeat' split
  all_goals omega

end Unicode.Security.Form.WidthClassConfusion
