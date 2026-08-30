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
import Unicode.Conformance.Security.VectorFile

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

-- ═══════════════════════════════════════════════════════════════════════════════
-- The pinned vector file, executed
--
-- `Unicode/Ucd/Security/CaseExpansionMismatchTest.txt` is hash-pinned by
-- `scripts/check-security-hashes.sh`, which fixes its bytes.  Running the
-- detector over those bytes is a separate claim, and this section makes it:
-- `rowsList` is mirrored against a fresh parse of the file at build time, and
-- `all_vectors_pass` reduces the detector over every row in the kernel.  A row
-- added to, removed from, or edited in the file fails the build until the
-- harness agrees with it again.
-- ═══════════════════════════════════════════════════════════════════════════════

open Unicode.Conformance.Security.VectorFile (VectorRow parseFile)

/-- Raw text of the pinned vector file, embedded at compile time. -/
def vectorsRaw : String := include_str "../../Ucd/Security/CaseExpansionMismatchTest.txt"

/-- Every row of the pinned vector file, freshly parsed. -/
def parsedRows : List VectorRow := parseFile vectorsRaw

/-- The pinned rows, materialized so the kernel can reduce over them. -/
def rowsList : List VectorRow := [
  ⟨[0x0048, 0x0065, 0x006C, 0x006C, 0x006F], "Clear", []⟩,
  ⟨[0x0041, 0x0042, 0x0043], "Clear", []⟩,
  ⟨[0x4E2D, 0x6587], "Clear", []⟩,
  ⟨[0x03B1, 0x03B2, 0x03B3], "Clear", []⟩,
  ⟨[0x041F, 0x0440, 0x0438, 0x0432, 0x0435, 0x0442], "Clear", []⟩,
  ⟨[0xD55C], "Clear", []⟩,
  ⟨[0x0061, 0x0062, 0x0063], "Clear", []⟩,
  ⟨[0x0627, 0x0628, 0x0629], "Clear", []⟩,
  ⟨[0x0048, 0x0045, 0x004C, 0x004C, 0x004F, 0x0020, 0x0077, 0x006F, 0x0072, 0x006C, 0x0064], "Clear", []⟩,
  ⟨[0x00DF], "Hazard:UpperExpansion", [0]⟩,
  ⟨[0xFB01], "Hazard:UpperExpansion", [0]⟩,
  ⟨[0xFB03], "Hazard:UpperExpansion", [0]⟩,
  ⟨[0x0053, 0x0074, 0x0072, 0x0061, 0x00DF, 0x0065], "Hazard:UpperExpansion", [4]⟩,
  ⟨[0xFB00], "Hazard:UpperExpansion", [0]⟩,
  ⟨[0xFB02], "Hazard:UpperExpansion", [0]⟩,
  ⟨[0xFB04], "Hazard:UpperExpansion", [0]⟩,
  ⟨[0x0390], "Hazard:UpperExpansion", [0]⟩,
  ⟨[0x0073, 0x0074, 0x0072, 0x0061, 0x00DF, 0x0065, 0x00DF], "Hazard:UpperExpansion", [4]⟩,
  ⟨[0x0130], "Hazard:LowerExpansion", [0]⟩,
  ⟨[0x0061, 0x0130, 0x0061], "Hazard:LowerExpansion", [1]⟩,
  ⟨[0x0130, 0x0073, 0x0074, 0x0061, 0x006E, 0x0062, 0x0075, 0x006C], "Hazard:LowerExpansion", [0]⟩,
  ⟨[0x0130, 0x0130], "Hazard:LowerExpansion", [0]⟩
]

-- `rowsList` mirrors a fresh parse of the vector file, checked at build time.
#eval do
  unless rowsList == parsedRows do
    throw (IO.userError "CaseExpansionMismatchTest drift: rowsList ≠ parsed vector file")

/-- Run the detector over one row and compare with the verdict the file states. -/
def verifyVectorRow (r : VectorRow) : Bool :=
  let v := detect r.codepoints
  if r.expectsClear then v.classify.isClear
  else v.classify.tag == r.expectedTag

/-- Every vector the pinned file states holds of the detector. -/
theorem all_vectors_pass : rowsList.all verifyVectorRow = true := by decide +kernel

end Unicode.Conformance.Security.CaseExpansionMismatchTest
