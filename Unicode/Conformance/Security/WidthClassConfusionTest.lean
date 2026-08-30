/-
  Unicode.Conformance.Security.WidthClassConfusionTest

  Conformance certificate for the WidthClassConfusion detector (UAX #11 East
  Asian Width; UAX #15 compatibility decomposition; form layer).

  Threat model.  Unicode carries fullwidth and halfwidth compatibility forms of
  characters that also exist at their canonical width — fullwidth Latin 'Ａ'
  (U+FF21) folds to ASCII 'A', halfwidth katakana 'ｱ' (U+FF71) folds to fullwidth
  'ア'.  The two forms look distinct on screen yet collapse to the same string
  after NFKD, so an adversary can register or transmit a name that renders one way
  to a human reviewer and compares equal to a different, sanctioned string after
  normalization — a width-class confusable in the UTS #39 family.

  What the detector draws.  It reports the fold direction of any codepoint whose
  NFKD image changes width class — FullwidthFold for a fullwidth form collapsing
  narrower, HalfwidthFold for a halfwidth form widening — and stays clear for
  characters with no width fold.

  The certificate.  Each `Row` pairs a representative input with the classification
  `tag` its verdict must draw (`none` for a clear verdict); `verifyRow` recomputes
  `detect` and compares, and `all_rows_pass` discharges the table in the kernel.
  A new attack vector is one appended row, so coverage grows with the threat
  catalogue and cannot silently regress.
-/

import Unicode.Security.Form.WidthClassConfusion
import Unicode.Conformance.Security.VectorFile

namespace Unicode.Conformance.Security.WidthClassConfusionTest

open Unicode.Security.Form.WidthClassConfusion

set_option maxRecDepth 100000

-- ── §1  The certificate table ───────────────────────────────────────────────

/-- One conformance row: an `input` sequence and the classification `tag` its
    verdict must carry (`none` for a clear verdict). -/
structure Row where
  input : List Nat
  tag : Option String

/-- The representative width-fold — and no-fold control — vectors this harness
    certifies. -/
def rows : List Row :=
  [ -- Precomposed Hangul 한 (U+D55C) sits at its canonical width; NFKD moves it to
    -- no narrower or wider class — clear.
    { input := [0xD55C], tag := none },
    -- Fullwidth 'Ａ' (U+FF21) folds to ASCII 'A' — the fullwidth-to-narrow confusable.
    { input := [0xFF21], tag := some "FullwidthFold" },
    -- Halfwidth katakana 'ｱ' (U+FF71) folds to fullwidth 'ア' — the halfwidth-to-wide fold.
    { input := [0xFF71], tag := some "HalfwidthFold" } ]

/-- A row passes when `detect` reproduces the classification tag the row prescribes. -/
def verifyRow (r : Row) : Bool :=
  (detect r.input).classify.tag == r.tag

-- ── §2  The closed certificate ──────────────────────────────────────────────

/-- Every certified vector draws exactly the verdict the NFKD width fold demands. -/
theorem all_rows_pass : rows.all verifyRow = true := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- The pinned vector file, executed
--
-- `Unicode/Ucd/Security/WidthClassConfusionTest.txt` is hash-pinned by
-- `scripts/check-security-hashes.sh`, which fixes its bytes.  Running the
-- detector over those bytes is a separate claim, and this section makes it:
-- `rowsList` is mirrored against a fresh parse of the file at build time, and
-- `all_vectors_pass` reduces the detector over every row in the kernel.  A row
-- added to, removed from, or edited in the file fails the build until the
-- harness agrees with it again.
-- ═══════════════════════════════════════════════════════════════════════════════

open Unicode.Conformance.Security.VectorFile (VectorRow parseFile)

/-- Raw text of the pinned vector file, embedded at compile time. -/
def vectorsRaw : String := include_str "../../Ucd/Security/WidthClassConfusionTest.txt"

/-- Every row of the pinned vector file, freshly parsed. -/
def parsedRows : List VectorRow := parseFile vectorsRaw

/-- The pinned rows, materialized so the kernel can reduce over them. -/
def rowsList : List VectorRow := [
  ⟨[0x0048, 0x0065, 0x006C, 0x006C, 0x006F], "Clear", []⟩,
  ⟨[0x0041, 0x0044, 0x004D, 0x0049, 0x004E], "Clear", []⟩,
  ⟨[0x4E2D, 0x6587], "Clear", []⟩,
  ⟨[0xD55C], "Clear", []⟩,
  ⟨[0xD55C, 0xAE00], "Clear", []⟩,
  ⟨[0x041F, 0x0440, 0x0438, 0x0432, 0x0435, 0x0442], "Clear", []⟩,
  ⟨[0x3042, 0x3044, 0x3046], "Clear", []⟩,
  ⟨[0x30A2, 0x30A4, 0x30A6], "Clear", []⟩,
  ⟨[0x03B1, 0x03B2, 0x03B3], "Clear", []⟩,
  ⟨[0xFF21], "Hazard:FullwidthFold", [0]⟩,
  ⟨[0xFF21, 0xFF24, 0xFF2D, 0xFF29, 0xFF2E], "Hazard:FullwidthFold", [0]⟩,
  ⟨[0xFF10, 0xFF11, 0xFF12, 0xFF13], "Hazard:FullwidthFold", [0]⟩,
  ⟨[0x0041, 0x0042, 0x0043, 0x0044, 0xFF25], "Hazard:FullwidthFold", [4]⟩,
  ⟨[0xFF50, 0xFF41, 0xFF53, 0xFF53, 0xFF57, 0xFF4F, 0xFF52, 0xFF44], "Hazard:FullwidthFold", [0]⟩,
  ⟨[0xFF01], "Hazard:FullwidthFold", [0]⟩,
  ⟨[0xFF0F], "Hazard:FullwidthFold", [0]⟩,
  ⟨[0xFF71], "Hazard:HalfwidthFold", [0]⟩,
  ⟨[0xFF72, 0xFF73, 0xFF74], "Hazard:HalfwidthFold", [0]⟩,
  ⟨[0x30A2, 0xFF72], "Hazard:HalfwidthFold", [1]⟩,
  ⟨[0xFF66], "Hazard:HalfwidthFold", [0]⟩,
  ⟨[0xFF9E], "Hazard:HalfwidthFold", [0]⟩,
  ⟨[0x0041, 0xFF71, 0x0042], "Hazard:HalfwidthFold", [1]⟩
]

-- `rowsList` mirrors a fresh parse of the vector file, checked at build time.
#eval do
  unless rowsList == parsedRows do
    throw (IO.userError "WidthClassConfusionTest drift: rowsList ≠ parsed vector file")

/-- Run the detector over one row and compare with the verdict the file states. -/
def verifyVectorRow (r : VectorRow) : Bool :=
  let v := detect r.codepoints
  if r.expectsClear then v.classify.isClear
  else v.classify.tag == r.expectedTag

/-- Every vector the pinned file states holds of the detector. -/
theorem all_vectors_pass : rowsList.all verifyVectorRow = true := by decide +kernel

end Unicode.Conformance.Security.WidthClassConfusionTest
