/-
  Unicode.Conformance.BidiTest

  UAX #9 bidirectional-algorithm conformance. The paragraph embedding level is
  resolved by rules P2/P3 — the level of the first strong directional character,
  defaulting to 0 (LTR) when none is present. Each theorem checks `paragraphLevel`
  against the level UAX #9 assigns a representative sequence.
-/

import Unicode.Bidi.Algorithm

namespace Unicode.Conformance.BidiTest

open Unicode.Bidi.Algorithm

set_option maxRecDepth 1000000

/-- **Binary paragraph level, all inputs.** P2/P3 assigns every paragraph base level 0
    (LTR) or 1 (RTL) — never higher. -/
theorem paragraph_level_binary (cps : List Nat) : paragraphLevel cps ≤ 1 :=
  paragraphLevel_le_one cps

/-- A Latin run resolves to paragraph level 0 (left-to-right). -/
theorem vector_latin_ltr : paragraphLevel [0x41, 0x42] = 0 := by decide

/-- A Hebrew run resolves to paragraph level 1 (right-to-left) by P2/P3. -/
theorem vector_hebrew_rtl : paragraphLevel [0x05D0, 0x05D1] = 1 := by decide

/-- An Arabic run resolves to paragraph level 1 (right-to-left). -/
theorem vector_arabic_rtl : paragraphLevel [0x0627, 0x0628] = 1 := by decide

/-- Digits carry no strong direction, so the paragraph defaults to level 0. -/
theorem vector_digits_default_ltr : paragraphLevel [0x30, 0x31] = 0 := by decide

end Unicode.Conformance.BidiTest
