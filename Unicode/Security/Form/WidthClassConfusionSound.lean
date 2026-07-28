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
theorem fullwidthFoldCount_le_size (input : List Nat) :
    fullwidthFoldCount input ≤ input.length := by
  unfold fullwidthFoldCount
  apply foldl_step_le_length
  intro m i
  repeat' split
  all_goals omega

/-- The halfwidth-fold tally is at most the input size, for every input. -/
theorem halfwidthFoldCount_le_size (input : List Nat) :
    halfwidthFoldCount input ≤ input.length := by
  unfold halfwidthFoldCount
  apply foldl_step_le_length
  intro m i
  repeat' split
  all_goals omega

end Unicode.Security.Form.WidthClassConfusion
