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

end Unicode.Conformance.Security.RtlInjectionTest
