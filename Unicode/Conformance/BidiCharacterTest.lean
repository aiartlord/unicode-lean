/-
  Unicode.Conformance.BidiCharacterTest

  UAX #9 bidirectional-algorithm conformance over concrete codepoint sequences
  (as opposed to abstract direction classes). Each theorem checks `paragraphLevel`
  resolves the P2/P3 paragraph direction of a representative mixed-script sequence to
  the level UAX #9 specifies.
-/

import Unicode.Bidi.Algorithm

namespace Unicode.Conformance.BidiCharacterTest

open Unicode.Bidi.Algorithm

set_option maxRecDepth 1000000

/-- A Hebrew word followed by ASCII resolves to RTL: the first strong character is
    Hebrew, so P2/P3 give paragraph level 1. -/
theorem vector_hebrew_then_latin :
    paragraphLevel [0x05D0, 0x05D1, 0x20, 0x41, 0x42] = 1 := by decide

/-- An ASCII word followed by Hebrew resolves to LTR: the first strong character is
    Latin, so the paragraph level is 0. -/
theorem vector_latin_then_hebrew :
    paragraphLevel [0x41, 0x42, 0x20, 0x05D0, 0x05D1] = 0 := by decide

/-- Leading digits are skipped by P2 (not strong); the first strong character, an
    Arabic letter, sets paragraph level 1. -/
theorem vector_digits_then_arabic :
    paragraphLevel [0x30, 0x31, 0x0627] = 1 := by decide

end Unicode.Conformance.BidiCharacterTest
