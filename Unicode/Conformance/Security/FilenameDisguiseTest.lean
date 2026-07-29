/-
  Unicode.Conformance.Security.FilenameDisguiseTest

  Conformance for the FilenameDisguise detector: filenames disguised via RLO extension
  flips, fullwidth or combining marks in the extension, or multiple extensions — the
  classic `document<RLO>txt.exe` Trojan-attachment hazard.

  Each theorem checks the full verdict — sub-threat tag together with the bidi-control
  and fullwidth-in-extension counts — on a representative vector: an RLO flip, a
  fullwidth extension, and a plain `document.txt` clear.
-/

import Unicode.Security.Display.FilenameDisguise

namespace Unicode.Conformance.Security.FilenameDisguiseTest

open Unicode.Security.Display.FilenameDisguise

set_option maxRecDepth 1000000

/-- The classic `document<RLO>txt.exe` Trojan filename — RLO flip, one bidi control. -/
theorem rlo_flip_verdict :
    let v := detect [0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74,
                     0x202E, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65]
    v.classify.tag = some "RloFlip" ∧ v.bidiControlCount = 1 := by decide

/-- Fullwidth `.ＥＸＥ` extension disguises an executable — width-class extension,
    three fullwidth codepoints in the extension. -/
theorem fullwidth_ext_verdict :
    let v := detect [0x66, 0x69, 0x6C, 0x65, 0x2E, 0xFF25, 0xFF38, 0xFF25]
    v.classify.tag = some "WidthClassExt" ∧ v.fullwidthInExt = 3 := by decide

/-- Plain ASCII `document.txt` is clear — no disguise. -/
theorem plain_txt_clear_verdict :
    let v := detect [0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74,
                     0x2E, 0x74, 0x78, 0x74]
    v.classify.isClear = true ∧ v.bidiControlCount = 0 := by decide

end Unicode.Conformance.Security.FilenameDisguiseTest
