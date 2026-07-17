/-
  Unicode.Security.Display.RtlInjectionSound

  Universal bounds for the RtlInjection tallies. `countStrongRTL`,
  `countStrongLTR`, and `countBidiControl` each add at most one per codepoint,
  so for every input the tally is at most the input size, via the reusable
  `Unicode.Machine.foldl_count_le`. This keeps the detector's strong-direction
  and bidi-control counting within the input size for all inputs.
-/

import Unicode.Security.Display.RtlInjection
import Unicode.Machine

namespace Unicode.Security.Display.RtlInjection

open Unicode.Machine.AbstractMachine

/-- The strong-RTL tally is at most the input size, for every input. -/
theorem countStrongRTL_le_size (input : Array Nat) :
    countStrongRTL input ≤ input.size := by
  have h := foldl_count_le isStrongRTL 0 input.toList
  simpa [countStrongRTL, Array.foldl_toList] using h

/-- The strong-LTR tally is at most the input size, for every input. -/
theorem countStrongLTR_le_size (input : Array Nat) :
    countStrongLTR input ≤ input.size := by
  have h := foldl_count_le isStrongLTR 0 input.toList
  simpa [countStrongLTR, Array.foldl_toList] using h

/-- The bidi-control tally is at most the input size, for every input. -/
theorem countBidiControl_le_size (input : Array Nat) :
    countBidiControl input ≤ input.size := by
  have h := foldl_count_le isBidiControl 0 input.toList
  simpa [countBidiControl, Array.foldl_toList] using h

end Unicode.Security.Display.RtlInjection
