/-
  Unicode.Conformance.LineBreakTest

  UAX #14 line-breaking conformance. `lineBreaks` returns one break-opportunity flag
  per boundary position of a codepoint sequence. Each theorem checks it against the
  break opportunities UAX #14's rules place in a representative sequence.
-/

import Unicode.Segmentation.LineBreak

namespace Unicode.Conformance.LineBreakTest

open Unicode.Segmentation.LineBreak

set_option maxRecDepth 1000000

/-- **Well-formedness, all inputs.** `lineBreaks` yields exactly one break flag per
    boundary position — `cps.length + 1` of them — so every position is decided. -/
theorem breaks_well_formed (cps : List Nat) :
    (lineBreaks cps).length = cps.length + 1 :=
  lineBreaks_length cps

/-- LB7 / LB18: a break opportunity opens after the space in "a b" (SP is a break
    class), and there is a mandatory break at the end; no break before the space or
    inside a letter. (`lineBreaks` returns one flag per boundary position.) -/
theorem vector_a_space_b :
    lineBreaks [0x61, 0x20, 0x62] = [false, false, true, true] := by decide

/-- A single letter has a break only at the end. -/
theorem vector_single_letter : lineBreaks [0x61] = [false, true] := by decide

end Unicode.Conformance.LineBreakTest
