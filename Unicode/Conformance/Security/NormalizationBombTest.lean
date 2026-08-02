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

end Unicode.Conformance.Security.NormalizationBombTest
