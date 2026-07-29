/-
  Unicode.Conformance.WordBreakTest

  UAX #29 word-boundary conformance. `wordBreaks` returns one break flag per boundary
  position of a codepoint sequence (length n+1). Each theorem checks it against the
  boundaries UAX #29's rules place in a representative sequence.
-/

import Unicode.Segmentation.WordBreak

namespace Unicode.Conformance.WordBreakTest

open Unicode.Segmentation.WordBreak

-- The boundary state machine recurses past the default reducer budget.
set_option maxRecDepth 1000000

/-- **Well-formedness, all inputs.** `wordBreaks` yields exactly one break flag per
    boundary position — `cps.length + 1` of them — so every position is decided. -/
theorem breaks_well_formed (cps : List Nat) :
    (wordBreaks cps).length = cps.length + 1 :=
  wordBreaks_length cps

/-- WB3d / WB999: "hi ok" breaks around the space — a boundary before `h`, between
    the two words either side of the space, and after `k`; no boundary inside a
    letter run. (`wordBreaks` returns one flag per boundary position, length n+1.) -/
theorem vector_hi_ok :
    wordBreaks [0x68, 0x69, 0x20, 0x6F, 0x6B]
      = [true, false, true, true, false, true] := by decide

/-- Empty input has a single (trivial) boundary. -/
theorem vector_empty : wordBreaks [] = [true] := by decide

/-- A single letter is one unbroken word — boundaries only at the ends. -/
theorem vector_single_letter : wordBreaks [0x61] = [true, true] := by decide

end Unicode.Conformance.WordBreakTest
