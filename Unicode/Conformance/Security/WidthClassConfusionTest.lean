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

end Unicode.Conformance.Security.WidthClassConfusionTest
