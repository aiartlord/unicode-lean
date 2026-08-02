/-
  Unicode.Conformance.Security.CaseExpansionMismatchTest

  Conformance certificate for the CaseExpansionMismatch detector (form layer:
  case mappings that change the codepoint count of a string under the default
  locale, per UAX #21 Case Mappings and the length-changing entries of the
  Unicode SpecialCasing data).

  Threat model.  A handful of codepoints do not case-map one-for-one: their
  upper- or lower-case form is a sequence of two or more codepoints.  An
  adversary picks such a codepoint precisely so that the case-folded string is
  longer than the input the validator measured.  A username field bounded to
  sixteen codepoints accepts eight sharp-s characters, then overflows to
  sixteen when the store upper-folds them to "SS"; a comparison that trusts
  `length(input) == length(folded)` can be pushed off its expected size to slip
  past a fixed-width check or corrupt an adjacent buffer.

  What the detector draws.  It scans each position through its SpecialCasing
  context and asks whether `upperCodepoint` or `lowerCodepoint` under the
  default locale yields more than one codepoint.  An upper-side expansion is
  reported first; a lower-side expansion is reported only when no upper
  expansion fires, so the two tags are mutually exclusive per input.  A
  codepoint whose case mapping stays a single codepoint is sanctioned and draws
  a clear verdict.

  How to read the certificate.  Each `Row` pairs an `input` with the
  classification `tag` its verdict must carry, where `none` denotes a clear
  verdict (`isClear` holds exactly when the tag is `none`, so the tag captures
  both outcomes).  `verifyRow` recomputes `detect` and compares its tag against
  the row; `all_rows_pass` discharges the whole table in the kernel.  Appending
  a vector grows the proof obligation by one row, so coverage cannot silently
  regress as the threat catalogue widens.
-/

import Unicode.Security.Form.CaseExpansionMismatch

namespace Unicode.Conformance.Security.CaseExpansionMismatchTest

open Unicode.Security.Form.CaseExpansionMismatch

set_option maxRecDepth 1000000

-- ── §1  The certificate table ───────────────────────────────────────────────

/-- One conformance row: an `input` sequence and the classification `tag` its
    verdict must carry (`none` for a clear verdict). -/
structure Row where
  input : List Nat
  tag : Option String

/-- The representative length-changing case-mapping vectors this harness
    certifies. -/
def rows : List Row :=
  [ -- ß (U+00DF): upper-folds to the two codepoints "SS", the canonical
    -- length-smuggling expansion, so the upper scan fires at position 0.
    { input := [0x00DF], tag := some "UpperExpansion" },
    -- The ﬁ ligature (U+FB01): upper-folds to "FI", showing the hazard is not
    -- confined to sharp-s but reaches presentation-form ligatures too.
    { input := [0xFB01], tag := some "UpperExpansion" },
    -- Dotted capital İ (U+0130): stays a single codepoint when upper-cased but
    -- lower-folds to "i̇" (two codepoints), so the detector falls through the
    -- upper scan and reports a lower expansion — the discriminating lower case.
    { input := [0x0130], tag := some "LowerExpansion" } ]

/-- A row passes when `detect` reproduces the classification tag it prescribes. -/
def verifyRow (r : Row) : Bool :=
  (detect r.input).classify.tag == r.tag

-- ── §2  The closed certificate ──────────────────────────────────────────────

/-- Every certified vector draws exactly the case-expansion verdict UAX #21 and
    the SpecialCasing length-changing mappings demand. -/
theorem all_rows_pass : rows.all verifyRow = true := by decide +kernel

end Unicode.Conformance.Security.CaseExpansionMismatchTest
