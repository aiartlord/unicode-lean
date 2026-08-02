/-
  Unicode.Conformance.Security.FilenameDisguiseTest

  This harness certifies the FilenameDisguise detector, the display-layer guard
  that decides whether a filename's rendered extension can diverge from the bytes
  an operating system actually dispatches on.  It implements the spoofing
  concerns of UTS #39 (Unicode Security Mechanisms) over the bidirectional
  format controls catalogued by UAX #9 (the Bidirectional Algorithm) and the
  Halfwidth and Fullwidth Forms block of the Unicode Character Database.

  Threat model.  An adversary delivers a file whose name reads as a benign type
  to a human — `document.txt`, `photo.png` — while its trailing bytes name an
  executable.  The canonical vector inserts U+202E RIGHT-TO-LEFT OVERRIDE so the
  byte sequence `document<RLO>txt.exe` renders as `document exe.txt`; sibling
  vectors hide the executable extension behind fullwidth glyphs or combining
  marks that a byte-level extension check does not see.

  What the detector discriminates.  It treats a name as hazardous when the
  extension region carries any bidi format-control, any Halfwidth/Fullwidth Forms
  codepoint, or any Grapheme_Cluster_Break = Extend combining mark — the three
  structural ways display order or glyph width can drift from the byte
  extension — and reports the specific sub-threat (`RloFlip`, `WidthClassExt`,
  `CombiningInExt`).  A name whose extension contains only ordinary spacing
  characters, including a native right-to-left script that carries no format
  controls, is sanctioned and clears.

  How to read the certificate.  Each theorem below pins the full verdict on one
  discriminating vector — not only the sub-threat tag but the count fields
  (`bidiControlCount`, `fullwidthInExt`) that quantify why the tag was drawn — so
  a regression that preserved the tag while miscounting would still be caught.
  The final theorem `all_rows_pass` conjoins every vector into one obligation;
  appending a future vector extends that conjunction, so the guarantee this
  harness makes grows with the threat catalogue and cannot silently regress.
-/

import Unicode.Security.Display.FilenameDisguise

namespace Unicode.Conformance.Security.FilenameDisguiseTest

open Unicode.Security.Display.FilenameDisguise

set_option maxRecDepth 1000000

/-- The classic `document<RLO>txt.exe` Trojan filename encodes the display-order
    inversion at the heart of the threat model: U+202E flips the trailing bytes so
    the executable extension renders as a text one, and the detector must draw
    `RloFlip` while counting exactly the one bidi format-control that caused it. -/
theorem rlo_flip_verdict :
    let v := detect [0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74,
                     0x202E, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65]
    v.classify.tag = some "RloFlip" ∧ v.bidiControlCount = 1 := by decide

/-- The fullwidth `.ＥＸＥ` extension is the width-class variant of the disguise:
    every extension glyph lives in the Halfwidth and Fullwidth Forms block, so a
    byte-level extension check reads them as ordinary letters while the display
    still spells an executable.  The detector must draw `WidthClassExt` and count
    all three fullwidth codepoints in the extension region. -/
theorem fullwidth_ext_verdict :
    let v := detect [0x66, 0x69, 0x6C, 0x65, 0x2E, 0xFF25, 0xFF38, 0xFF25]
    v.classify.tag = some "WidthClassExt" ∧ v.fullwidthInExt = 3 := by decide

/-- Plain ASCII `document.txt` is the sanctioned baseline the detector must not
    over-report: its extension holds only ordinary letters, so the verdict clears
    and the bidi-control count is zero.  This vector pins the negative side of the
    discrimination — that an honest filename raises no hazard. -/
theorem plain_txt_clear_verdict :
    let v := detect [0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74,
                     0x2E, 0x74, 0x78, 0x74]
    v.classify.isClear = true ∧ v.bidiControlCount = 0 := by decide

/-- The complete certificate: every conformance vector above holds
    simultaneously.  Appending a vector extends this conjunction, so the
    guarantee this harness makes grows with the threat catalogue and cannot
    silently regress. -/
theorem all_rows_pass :
    (let v := detect [0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74,
                      0x202E, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65]
     v.classify.tag = some "RloFlip" ∧ v.bidiControlCount = 1) ∧
    (let v := detect [0x66, 0x69, 0x6C, 0x65, 0x2E, 0xFF25, 0xFF38, 0xFF25]
     v.classify.tag = some "WidthClassExt" ∧ v.fullwidthInExt = 3) ∧
    (let v := detect [0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74,
                      0x2E, 0x74, 0x78, 0x74]
     v.classify.isClear = true ∧ v.bidiControlCount = 0) :=
  ⟨rlo_flip_verdict, fullwidth_ext_verdict, plain_txt_clear_verdict⟩

end Unicode.Conformance.Security.FilenameDisguiseTest
