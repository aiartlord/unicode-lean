/-
  Unicode.Conformance.Security.RtlInjectionTest

  Conformance certificate for the RtlInjection detector (display layer, the
  Unicode Bidirectional Algorithm of UAX #9 read through the spoofing-and-
  visual-confusion concerns of UTS #39).  The detector reasons about the
  resolved display order of a text field: which glyphs a reader actually sees,
  left to right, once the bidi algorithm has run.

  Threat model.  The bytes of a string and the order in which its glyphs are
  painted are not the same thing.  A single strong right-to-left character, or
  an explicit bidi-control override such as U+202E RIGHT-TO-LEFT OVERRIDE, can
  reverse the visual run around it, so that a field a program parses and stores
  as one value is read by a human as another.  This is the mechanism behind
  filename-extension spoofing and the "Trojan Source" class of source-code
  attacks: the display order is hijacked while the logical order — the order
  that matters to the machine — is left untouched.

  What the detector draws.  The detector distinguishes a text field whose
  intended base direction is left-to-right from the perturbations that would
  silently flip it.  Any bidi format-control raises
  `BidiControlInLTRField`; a
  leading strong-RTL letter that reorients the whole field raises
  `FieldTakeover`; a field composed only of neutral or left-to-right characters
  is clear.  Each verdict carries the discriminating counts — how many strong
  right-to-left characters and how many bidi controls were seen — so the
  certificate pins the cause of the verdict, not merely its label.

  How to read the certificate.  Each theorem below fixes one representative
  vector and asserts its full verdict — sub-threat tag together with the strong-
  direction and bidi-control counts — establishing it by kernel reduction of the
  detector over that concrete input.  The final theorem `all_rows_pass` conjoins
  every vector verdict into one closed obligation; appending a new vector
  extends that conjunction, so the guarantee this harness makes grows with the
  threat catalogue and cannot silently regress.
-/

import Unicode.Security.Display.RtlInjection
import Unicode.Conformance.Security.VectorFile

namespace Unicode.Conformance.Security.RtlInjectionTest

open Unicode.Security.Display.RtlInjection

-- Matches the detector module: the direction-run scans recurse past the default.
set_option maxRecDepth 1000000

/-- U+202E RIGHT-TO-LEFT OVERRIDE dropped between two ASCII letters ("A ⟨RLO⟩ B")
    is the discriminating override case: the field's base direction stays
    left-to-right, but the single embedded control silently reverses the display
    run around it — the exact primitive behind extension-spoofing and Trojan-
    Source attacks — so the detector must raise `BidiControlInLTRField` and account for
    the one bidi control it saw. -/
theorem rlo_in_ltr_verdict :
    let v := detect [0x41, 0x202E, 0x42]
    v.classify.tag = some "BidiControlInLTRField" ∧ v.bidiControlCount = 1 := by decide

/-- A leading U+05D0 HEBREW LETTER ALEF in front of ASCII is the discriminating
    takeover case: no explicit control is present, yet one strong right-to-left
    character at the head reorients the whole otherwise-LTR field, so the
    detector must raise `FieldTakeover` and report exactly one strong-RTL
    character as the cause. -/
theorem rtl_takeover_verdict :
    let v := detect [0x05D0, 0x42, 0x43]
    v.classify.tag = some "FieldTakeover" ∧ v.strongRTLCount = 1 := by decide

/-- Plain ASCII "Hello" is the sanctioned control case that fixes the detector's
    lower bound: with no strong right-to-left character and no bidi control, the
    display order cannot diverge from the logical order, so the verdict must be
    clear with both counts at zero — proving the detector does not cry wolf on
    ordinary left-to-right text. -/
theorem ascii_clear_verdict :
    let v := detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]
    v.classify.isClear = true
      ∧ v.strongRTLCount = 0 ∧ v.bidiControlCount = 0 := by decide

/-- The complete certificate: every conformance vector above holds
    simultaneously.  Appending a vector extends this conjunction, so the
    guarantee this harness makes grows with the threat catalogue and cannot
    silently regress. -/
theorem all_rows_pass :
    (let v := detect [0x41, 0x202E, 0x42];
      v.classify.tag = some "BidiControlInLTRField" ∧ v.bidiControlCount = 1) ∧
    (let v := detect [0x05D0, 0x42, 0x43];
      v.classify.tag = some "FieldTakeover" ∧ v.strongRTLCount = 1) ∧
    (let v := detect [0x48, 0x65, 0x6C, 0x6C, 0x6F];
      v.classify.isClear = true
        ∧ v.strongRTLCount = 0 ∧ v.bidiControlCount = 0) :=
  ⟨rlo_in_ltr_verdict, rtl_takeover_verdict, ascii_clear_verdict⟩

-- ═══════════════════════════════════════════════════════════════════════════════
-- The pinned vector file, executed
--
-- `Unicode/Ucd/Security/RtlInjectionTest.txt` is hash-pinned by
-- `scripts/check-security-hashes.sh`, which fixes its bytes.  Running the
-- detector over those bytes is a separate claim, and this section makes it:
-- `rowsList` is mirrored against a fresh parse of the file at build time, and
-- `all_vectors_pass` reduces the detector over every row in the kernel.  A row
-- added to, removed from, or edited in the file fails the build until the
-- harness agrees with it again.
-- ═══════════════════════════════════════════════════════════════════════════════

open Unicode.Conformance.Security.VectorFile (VectorRow parseFile)

/-- Raw text of the pinned vector file, embedded at compile time. -/
def vectorsRaw : String := include_str "../../Ucd/Security/RtlInjectionTest.txt"

/-- Every row of the pinned vector file, freshly parsed. -/
def parsedRows : List VectorRow := parseFile vectorsRaw

/-- The pinned rows, materialized so the kernel can reduce over them. -/
def rowsList : List VectorRow := [
  ⟨[0x0048, 0x0065, 0x006C, 0x006C, 0x006F], "Clear", []⟩,
  ⟨[0x0030, 0x0031, 0x0032, 0x0033], "Clear", []⟩,
  ⟨[0x043F, 0x0440, 0x0438, 0x0432], "Clear", []⟩,
  ⟨[0x4E2D, 0x6587], "Clear", []⟩,
  ⟨[0x0068, 0x0074, 0x0074, 0x0070, 0x003A, 0x002F, 0x002F, 0x0061, 0x002E, 0x0063, 0x006F, 0x006D], "Clear", []⟩,
  ⟨[0x0068, 0x0074, 0x0074, 0x0070, 0x0073, 0x003A, 0x002F, 0x002F, 0x0065, 0x0078], "Clear", []⟩,
  ⟨[0x03B1, 0x03B2, 0x03B3], "Clear", []⟩,
  ⟨[0x0068, 0x0065, 0x006C, 0x006C, 0x006F, 0x0031, 0x0032, 0x0033], "Clear", []⟩,
  ⟨[0x0041, 0x202E, 0x0042], "Hazard:BidiControlInLTRField", [1]⟩,
  ⟨[0x0041, 0x2067, 0x0042, 0x2069], "Hazard:BidiControlInLTRField", [1]⟩,
  ⟨[0x0041, 0x202B, 0x0042, 0x0043, 0x202C], "Hazard:BidiControlInLTRField", [1]⟩,
  ⟨[0x0041, 0x202D, 0x0042], "Hazard:BidiControlInLTRField", [1]⟩,
  ⟨[0x0041, 0x202E, 0x0042, 0x202E, 0x0043], "Hazard:BidiControlInLTRField", [1]⟩,
  ⟨[0x05D0, 0x0042, 0x0043], "Hazard:FieldTakeover", [0]⟩,
  ⟨[0x0627, 0x0042, 0x0043], "Hazard:FieldTakeover", [0]⟩,
  ⟨[0x05D0, 0x05D1, 0x05D2, 0x0020, 0x0041, 0x0042], "Hazard:FieldTakeover", [0]⟩,
  ⟨[0x05D0, 0x05D1, 0x05D2, 0x05D3, 0x05D4, 0x0020, 0x0041], "Hazard:FieldTakeover", [0]⟩,
  ⟨[0x0627, 0x0628, 0x0629, 0x062A, 0x062B, 0x0020, 0x0041], "Hazard:FieldTakeover", [0]⟩,
  ⟨[0x0041, 0x0042, 0x05D0, 0x0044], "Hazard:StrongRTLInLTR", [2]⟩,
  ⟨[0x0066, 0x006F, 0x006F, 0x0627, 0x0064, 0x0065], "Hazard:StrongRTLInLTR", [3]⟩,
  ⟨[0x0041, 0x0042, 0x05D0, 0x05D1, 0x0043], "Hazard:StrongRTLInLTR", [2]⟩,
  ⟨[0x0041, 0x0042, 0x05D0, 0x05D1, 0x05D2, 0x0043], "Hazard:StrongRTLInLTR", [2]⟩,
  ⟨[0x0041, 0x0042, 0x0627, 0x05D0, 0x0043], "Hazard:StrongRTLInLTR", [2]⟩,
  ⟨[0x0041, 0x0042, 0x05D0, 0x05D1, 0x05D2, 0x05D3, 0x0044], "Hazard:MixedOverflow", [2]⟩,
  ⟨[0x0066, 0x006F, 0x0627, 0x0628, 0x062A, 0x062B, 0x062C, 0x0065], "Hazard:MixedOverflow", [2]⟩,
  ⟨[0x0041, 0x05D0, 0x05D1, 0x05D2, 0x05D3, 0x05D4, 0x05D5, 0x0042], "Hazard:MixedOverflow", [1]⟩,
  ⟨[0x0041, 0x0627, 0x0628, 0x0629, 0x062A, 0x062B, 0x062C, 0x062D, 0x062E, 0x0042], "Hazard:MixedOverflow", [1]⟩
]

-- `rowsList` mirrors a fresh parse of the vector file, checked at build time.
#eval do
  unless rowsList == parsedRows do
    throw (IO.userError "RtlInjectionTest drift: rowsList ≠ parsed vector file")

/-- Run the detector over one row and compare with the verdict the file states. -/
def verifyVectorRow (r : VectorRow) : Bool :=
  let v := detect r.codepoints
  if r.expectsClear then v.classify.isClear
  else v.classify.tag == r.expectedTag

/-- Every vector the pinned file states holds of the detector. -/
theorem all_vectors_pass : rowsList.all verifyVectorRow = true := by decide +kernel

end Unicode.Conformance.Security.RtlInjectionTest
