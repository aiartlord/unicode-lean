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
import Unicode.Conformance.Security.VectorFile

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

-- ═══════════════════════════════════════════════════════════════════════════════
-- The pinned vector file, executed
--
-- `Unicode/Ucd/Security/FilenameDisguiseTest.txt` is hash-pinned by
-- `scripts/check-security-hashes.sh`, which fixes its bytes.  Running the
-- detector over those bytes is a separate claim, and this section makes it:
-- `rowsList` is mirrored against a fresh parse of the file at build time, and
-- `all_vectors_pass` reduces the detector over every row in the kernel.  A row
-- added to, removed from, or edited in the file fails the build until the
-- harness agrees with it again.
-- ═══════════════════════════════════════════════════════════════════════════════

open Unicode.Conformance.Security.VectorFile (VectorRow parseFile)

/-- Raw text of the pinned vector file, embedded at compile time. -/
def vectorsRaw : String := include_str "../../Ucd/Security/FilenameDisguiseTest.txt"

/-- Every row of the pinned vector file, freshly parsed. -/
def parsedRows : List VectorRow := parseFile vectorsRaw

/-- The pinned rows, materialized so the kernel can reduce over them. -/
def rowsList : List VectorRow := [
  ⟨[0x0064, 0x006F, 0x0063, 0x0075, 0x006D, 0x0065, 0x006E, 0x0074, 0x002E, 0x0074, 0x0078, 0x0074], "Clear", []⟩,
  ⟨[0x0066, 0x0069, 0x006C, 0x0065, 0x002E, 0x0070, 0x0064, 0x0066], "Clear", []⟩,
  ⟨[0x0066, 0x006F, 0x006F], "Clear", []⟩,
  ⟨[0x0061, 0x002E, 0x0074, 0x0061, 0x0072, 0x002E, 0x0067, 0x007A], "Clear", []⟩,
  ⟨[0x05D0, 0x05D1, 0x05D2, 0x002E, 0x0074, 0x0078, 0x0074], "Clear", []⟩,
  ⟨[0x0641, 0x0644, 0x062F, 0x002E, 0x0070, 0x0064, 0x0066], "Clear", []⟩,
  ⟨[0x002E, 0x0062, 0x0061, 0x0073, 0x0068, 0x0072, 0x0063], "Clear", []⟩,
  ⟨[0x006D, 0x0079, 0x002D, 0x0066, 0x0069, 0x006C, 0x0065, 0x005F, 0x0076, 0x0032, 0x002E, 0x006D, 0x0064], "Clear", []⟩,
  ⟨[0x0066, 0x0069, 0x006C, 0x0065, 0xFF0E, 0xFF25, 0xFF38, 0xFF25], "Clear", []⟩,
  ⟨[0x0064, 0x006F, 0x0063, 0x0075, 0x006D, 0x0065, 0x006E, 0x0074, 0x202E, 0x0074, 0x0078, 0x0074, 0x002E, 0x0065, 0x0078, 0x0065], "Hazard:RloFlip", [8]⟩,
  ⟨[0x0064, 0x006F, 0x0063, 0x2067, 0x0074, 0x0078, 0x0074, 0x002E, 0x0065, 0x0078, 0x0065, 0x2069], "Hazard:RloFlip", [3]⟩,
  ⟨[0x0070, 0x0068, 0x006F, 0x0074, 0x006F, 0x202B, 0x0074, 0x0078, 0x0074, 0x002E, 0x0073, 0x0063, 0x0072], "Hazard:RloFlip", [5]⟩,
  ⟨[0x0066, 0x0069, 0x006C, 0x0065, 0x202D, 0x0074, 0x0078, 0x0074, 0x002E, 0x0070, 0x0073, 0x0031], "Hazard:RloFlip", [4]⟩,
  ⟨[0x0066, 0x0069, 0x006C, 0x0065, 0x2068, 0x0074, 0x0078, 0x0074, 0x002E, 0x0070, 0x0073, 0x0031, 0x2069], "Hazard:RloFlip", [4]⟩,
  ⟨[0x0070, 0x0068, 0x006F, 0x0074, 0x006F, 0x202E, 0x0067, 0x0070, 0x006A, 0x002E, 0x0065, 0x0078, 0x0065], "Hazard:RloFlip", [5]⟩,
  ⟨[0x0066, 0x0069, 0x006C, 0x0065, 0x002E, 0xFF25, 0xFF38, 0xFF25], "Hazard:WidthClassExt", [5]⟩,
  ⟨[0x0070, 0x0068, 0x006F, 0x0074, 0x006F, 0x002E, 0xFF30, 0x0064, 0x0066], "Hazard:WidthClassExt", [6]⟩,
  ⟨[0x0070, 0x002E, 0xFF50, 0xFF44, 0xFF46], "Hazard:WidthClassExt", [2]⟩,
  ⟨[0x0066, 0x002E, 0xFF71, 0x0070, 0x0067], "Hazard:WidthClassExt", [2]⟩,
  ⟨[0x0066, 0x0069, 0x006C, 0x0065, 0x002E, 0x0065, 0x0301, 0x0078, 0x0065], "Hazard:CombiningInExt", [6]⟩,
  ⟨[0x0061, 0x002E, 0x0070, 0x0308, 0x0064, 0x0066], "Hazard:CombiningInExt", [3]⟩,
  ⟨[0x0061, 0x002E, 0x0070, 0x0300, 0x0064, 0x0066], "Hazard:CombiningInExt", [3]⟩,
  ⟨[0x0066, 0x002E, 0x0065, 0x0301, 0x0303, 0x0078, 0x0065], "Hazard:CombiningInExt", [3]⟩,
  ⟨[0x0073, 0x0065, 0x0074, 0x0075, 0x0070, 0x002E, 0x0074, 0x0061, 0x0072, 0x002E, 0x0067, 0x007A, 0x002E, 0x0073, 0x0069, 0x0067], "Hazard:MultipleExtensions", [5, 9, 12]⟩,
  ⟨[0x0061, 0x002E, 0x0062, 0x002E, 0x0063, 0x002E, 0x0064, 0x002E, 0x0065], "Hazard:MultipleExtensions", [1, 3, 5, 7]⟩,
  ⟨[0x0061, 0x002E, 0x0062, 0x002E, 0x0063, 0x002E, 0x0064, 0x002E, 0x0065, 0x002E, 0x0066], "Hazard:MultipleExtensions", [1, 3, 5, 7, 9]⟩,
  ⟨[0x0066, 0x0069, 0x006C, 0x0065, 0x002E, 0x0074, 0x0061, 0x0072, 0x002E, 0x0067, 0x007A, 0x002E, 0x0062, 0x0061, 0x006B], "Hazard:MultipleExtensions", [4, 8, 11]⟩
]

-- `rowsList` mirrors a fresh parse of the vector file, checked at build time.
#eval do
  unless rowsList == parsedRows do
    throw (IO.userError "FilenameDisguiseTest drift: rowsList ≠ parsed vector file")

/-- Run the detector over one row and compare with the verdict the file states. -/
def verifyVectorRow (r : VectorRow) : Bool :=
  let v := detect r.codepoints
  if r.expectsClear then v.classify.isClear
  else v.classify.tag == r.expectedTag

/-- Every vector the pinned file states holds of the detector. -/
theorem all_vectors_pass : rowsList.all verifyVectorRow = true := by decide +kernel

end Unicode.Conformance.Security.FilenameDisguiseTest
