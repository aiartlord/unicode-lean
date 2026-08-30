/-
  Unicode.Conformance.Security.NormalizationBombTest

  Conformance certificate for the NormalizationBomb detector (UAX #15
  Normalization Forms; form layer).

  Threat model.  A single codepoint can expand into many under normalization: the
  Arabic ligature U+FDFA unfolds to eighteen codepoints under NFKD, and long runs
  of composing characters multiply further.  An adversary sends a short byte
  string that a downstream normalization pass balloons into megabytes — a
  decompression bomb that exhausts memory or CPU, the textual analogue of a zip
  bomb.

  What the detector draws.  It measures expansion against a fixed priority — a
  single-codepoint blow-up first, then the whole-input NFKD ratio, then the NFD
  ratio — and stays clear for inputs that expand within bound.  Precomposed Hangul
  (three jamos, within the per-codepoint bound) and a circled digit (compatibility
  length one) pass; the U+FDFA ligature fires the single-codepoint blow-up.

  The certificate.  Each `Row` pairs a representative input with the classification
  `tag` its verdict must draw (`none` for a clear verdict); `verifyRow` recomputes
  `detect` and compares, and `all_rows_pass` discharges the table in the kernel.
  A new attack vector is one appended row, so coverage grows with the threat
  catalogue and cannot silently regress.
-/

import Unicode.Security.Form.NormalizationBomb
import Unicode.Conformance.Security.VectorFile

namespace Unicode.Conformance.Security.NormalizationBombTest

open Unicode.Security.Form.NormalizationBomb

set_option maxRecDepth 100000

-- ── §1  The certificate table ───────────────────────────────────────────────

/-- One conformance row: an `input` sequence and the classification `tag` its
    verdict must carry (`none` for a clear verdict). -/
structure Row where
  input : List Nat
  tag : Option String

/-- The representative bomb — and within-bound control — vectors this harness
    certifies. -/
def rows : List Row :=
  [ -- Precomposed Hangul 한 (U+D55C) decomposes to three jamos, within the
    -- per-codepoint bound of four — a legitimate composed syllable, clear.
    { input := [0xD55C], tag := none },
    -- The Arabic ligature U+FDFA unfolds to eighteen codepoints under NFKD: the
    -- canonical single-codepoint amplification vector.
    { input := [0xFDFA], tag := some "SingleCpBlowup" },
    -- Circled digit one (U+2460) has a compatibility decomposition of length one,
    -- so it amplifies nothing — clear.
    { input := [0x2460], tag := none } ]

/-- A row passes when `detect` reproduces the classification tag the row prescribes. -/
def verifyRow (r : Row) : Bool :=
  (detect r.input).classify.tag == r.tag

-- ── §2  The closed certificate ──────────────────────────────────────────────

/-- Every certified vector draws exactly the verdict the expansion bounds demand. -/
theorem all_rows_pass : rows.all verifyRow = true := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- The pinned vector file, executed
--
-- `Unicode/Ucd/Security/NormalizationBombTest.txt` is hash-pinned by
-- `scripts/check-security-hashes.sh`, which fixes its bytes.  Running the
-- detector over those bytes is a separate claim, and this section makes it:
-- `rowsList` is mirrored against a fresh parse of the file at build time, and
-- `all_vectors_pass` reduces the detector over every row in the kernel.  A row
-- added to, removed from, or edited in the file fails the build until the
-- harness agrees with it again.
-- ═══════════════════════════════════════════════════════════════════════════════

open Unicode.Conformance.Security.VectorFile (VectorRow parseFile)

/-- Raw text of the pinned vector file, embedded at compile time. -/
def vectorsRaw : String := include_str "../../Ucd/Security/NormalizationBombTest.txt"

/-- Every row of the pinned vector file, freshly parsed. -/
def parsedRows : List VectorRow := parseFile vectorsRaw

/-- The pinned rows, materialized so the kernel can reduce over them. -/
def rowsList : List VectorRow := [
  ⟨[0x0048, 0x0065, 0x006C, 0x006C, 0x006F], "Clear", []⟩,
  ⟨[0x4E2D, 0x6587], "Clear", []⟩,
  ⟨[0xD55C], "Clear", []⟩,
  ⟨[0xD55C, 0xAE00], "Clear", []⟩,
  ⟨[0x2460], "Clear", []⟩,
  ⟨[0x0030, 0x0031, 0x0032, 0x0033], "Clear", []⟩,
  ⟨[0xD55C, 0xAE00, 0xC774], "Clear", []⟩,
  ⟨[0x215B, 0x215C, 0x215D], "Clear", []⟩,
  ⟨[0x216B], "Clear", []⟩,
  ⟨[0xF900], "Clear", []⟩,
  ⟨[0xFDFA], "Hazard:SingleCpBlowup", [0]⟩,
  ⟨[0x0048, 0x0069, 0xFDFA], "Hazard:SingleCpBlowup", [2]⟩,
  ⟨[0x0048, 0x0065, 0x006C, 0x006C, 0x006F, 0x0020, 0xFDFA], "Hazard:SingleCpBlowup", [6]⟩,
  ⟨[0xFDFB], "Hazard:NfkdHighExpansion", []⟩,
  ⟨[0xFDFB, 0xFDFB], "Hazard:NfkdHighExpansion", []⟩,
  ⟨[0xFDFB, 0xFDFB, 0xFDFB], "Hazard:NfkdHighExpansion", []⟩,
  ⟨[0x1F82], "Hazard:NfdHighExpansion", []⟩,
  ⟨[0x1F82, 0x1F83], "Hazard:NfdHighExpansion", []⟩,
  ⟨[0x1F86], "Hazard:NfdHighExpansion", []⟩,
  ⟨[0x1F87], "Hazard:NfdHighExpansion", []⟩,
  ⟨[0x1F8E], "Hazard:NfdHighExpansion", []⟩,
  ⟨[0x1F96], "Hazard:NfdHighExpansion", []⟩,
  ⟨[0x1F9E], "Hazard:NfdHighExpansion", []⟩,
  ⟨[0x1FA6], "Hazard:NfdHighExpansion", []⟩,
  ⟨[0x1FAE], "Hazard:NfdHighExpansion", []⟩,
  ⟨[0x1F86, 0x1F87, 0x1F96, 0x1FA6], "Hazard:NfdHighExpansion", []⟩
]

-- `rowsList` mirrors a fresh parse of the vector file, checked at build time.
#eval do
  unless rowsList == parsedRows do
    throw (IO.userError "NormalizationBombTest drift: rowsList ≠ parsed vector file")

/-- Run the detector over one row and compare with the verdict the file states. -/
def verifyVectorRow (r : VectorRow) : Bool :=
  let v := detect r.codepoints
  if r.expectsClear then v.classify.isClear
  else v.classify.tag == r.expectedTag

/-- Every vector the pinned file states holds of the detector. -/
theorem all_vectors_pass : rowsList.all verifyVectorRow = true := by decide +kernel

end Unicode.Conformance.Security.NormalizationBombTest
