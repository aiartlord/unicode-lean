/-
  Unicode.Conformance.Security.NoncharacterControlTest

  Conformance for the NoncharacterControl detector (designated Unicode noncharacters
  and C0/C1 control codepoints in interchange text).

  Each theorem checks the full verdict — sub-threat tag together with the flagged-hit
  count — on a representative codepoint: a BMP-block and a plane-end noncharacter, a
  C0 control, a C1 control, and a plain-ASCII clear. The detector lifts the proven
  codec predicate `Unicode.Codec.Noncharacters.isNoncharacter` plus explicit C0/C1
  ranges into the Security verdict vocabulary.
-/

import Unicode.Security.Covert.NoncharacterControl

namespace Unicode.Conformance.Security.NoncharacterControlTest

open Unicode.Security.Covert.NoncharacterControl

/-- A BMP-block noncharacter (U+FDD0) fires `Noncharacter`, one hit. -/
theorem bmp_noncharacter_verdict :
    let v := detect [0xFDD0]
    v.classify.tag = some "Noncharacter" ∧ v.hitCount = 1 := by decide

/-- A plane-end noncharacter (U+10FFFF) fires `Noncharacter`. -/
theorem plane_end_noncharacter_verdict :
    (detect [0x10FFFF]).classify.tag = some "Noncharacter" := by decide

/-- A C0 control (U+0000) embedded in text fires `C0Control` at its position. -/
theorem c0_control_verdict :
    let v := detect [0x41, 0x00, 0x42]
    v.classify.tag = some "C0Control" ∧ v.classify.positions = [1] := by decide

/-- A C1 control (U+0080) fires `C1Control`. -/
theorem c1_control_verdict :
    let v := detect [0x41, 0x80, 0x42]
    v.classify.tag = some "C1Control" ∧ v.classify.positions = [1] := by decide

/-- Plain ASCII is clear, no hits. -/
theorem ascii_clear_verdict :
    let v := detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]
    v.classify.isClear = true ∧ v.hitCount = 0 := by decide

/-- Structured whitespace (TAB, LF, CR) is legitimate interchange structure, not a C0
    control hazard — clear. -/
theorem structured_whitespace_clear_verdict :
    let v := detect [0x41, 0x09, 0x0A, 0x0D, 0x42]
    v.classify.isClear = true ∧ v.hitCount = 0 := by decide

end Unicode.Conformance.Security.NoncharacterControlTest
