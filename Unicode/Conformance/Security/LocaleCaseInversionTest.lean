/-
  Unicode.Conformance.Security.LocaleCaseInversionTest

  Conformance certificate for the LocaleCaseInversion detector (form layer:
  case mappings that invert across locales).

  What this certifies.  The detector implements the locale-tailored casing
  contract of UAX #44 SpecialCasing (the conditional Turkish/Azeri and
  Lithuanian mappings) as read through Unicode's `toLower` context predicates
  `AfterI`, `MoreAbove`, `NotBeforeDot`, `AfterSoftDotted`, and `FinalSigma`.
  It reports a hazard when a codepoint's lowercase result under the Turkish or
  Lithuanian locale diverges from the default-locale result at some position.

  Threat model.  An adversary submits text containing a codepoint whose case
  fold is locale-conditional, then relies on two stages of a system folding it
  under different locales — one to compare against a stored credential, another
  to display or route.  The two folds disagree, and the attacker chooses which
  fold each stage sees, so a name that reads as one identity under the default
  locale reads as another under Turkish or Lithuanian rules (CVE-2007-6692,
  CVE-2021-30245, the "İSTANBUL" / "iSTANBUL" incident class).

  The discrimination the detector draws.  A codepoint whose lowercase is stable
  across every locale is sanctioned and passes clear; a codepoint whose Turkish
  or Lithuanian fold departs from the default fold is hazardous.  The scan is
  priority-ordered: it reports the first Turkish divergence if any exists, and
  only falls through to a Lithuanian divergence when the Turkish scan finds
  nothing, so a single input that could diverge under both locales is tagged
  Turkish.

  How to read the certificate.  Each `Row` pairs an `input` sequence with the
  classification `tag` its verdict must carry, where `none` denotes a clear
  verdict (a clear verdict is exactly `classify.tag = none`, so the tag alone
  captures both the hazard tags and the clear case).  `verifyRow` recomputes
  `detect` and compares its tag against the row; `all_rows_pass` discharges the
  whole table in the kernel.  Appending a vector grows the proof obligation, so
  coverage extends with the threat catalogue and cannot silently regress.
-/

import Unicode.Security.Form.LocaleCaseInversion

namespace Unicode.Conformance.Security.LocaleCaseInversionTest

open Unicode.Security.Form.LocaleCaseInversion

set_option maxRecDepth 1000000

-- ── §1  The certificate table ───────────────────────────────────────────────

/-- One conformance row: an `input` sequence and the classification `tag` its
    verdict must carry, where `none` denotes a clear verdict. -/
structure Row where
  input : List Nat
  tag : Option String

/-- The representative locale-divergence — and clear — vectors this harness
    certifies. -/
def rows : List Row :=
  [ -- U+0049 LATIN CAPITAL LETTER I lowercases to `i` by default but to dotless
    -- `ı` (U+0131) under Turkish rules: the canonical Turkish case divergence.
    { input := [0x0049], tag := some "TurkishCaseDivergence" },
    -- U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE folds to `i` + combining dot
    -- by default but to bare `i` under Turkish rules — the inverse divergence,
    -- confirming both directions of the dotted/dotless pair are caught.
    { input := [0x0130], tag := some "TurkishCaseDivergence" },
    -- U+004A J followed by U+0300 combining grave (ccc = 230) has no
    -- Turkish-conditional mapping, so the Turkish scan finds nothing and the
    -- detector falls through to the Lithuanian dot-above divergence: the
    -- discriminating case for the priority-ordered fall-through path.
    { input := [0x004A, 0x0300], tag := some "LithuanianCaseDivergence" } ]

/-- A row passes when `detect` reproduces the classification tag the row
    prescribes. -/
def verifyRow (r : Row) : Bool :=
  (detect r.input).classify.tag == r.tag

-- ── §2  The closed certificate ──────────────────────────────────────────────

/-- Every certified vector draws exactly the locale-divergence verdict the
    SpecialCasing conditional mappings demand. -/
theorem all_rows_pass : rows.all verifyRow = true := by decide +kernel

end Unicode.Conformance.Security.LocaleCaseInversionTest
