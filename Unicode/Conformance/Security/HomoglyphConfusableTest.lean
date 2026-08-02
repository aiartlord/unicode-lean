/-
  Unicode.Conformance.Security.HomoglyphConfusableTest

  Conformance certificate for the HomoglyphConfusable detector (identity layer:
  confusable-skeleton spoofing of identifiers, package names, and domains).

  What this harness certifies.  The detector implements the UTS #39
  (Unicode Security Mechanisms) §4 confusable-detection machinery together with
  the §5.1 mixed-script and §5.2 restriction-level analysis: it projects an
  input onto its confusable skeleton and tests that skeleton against a curated
  dictionary of attack targets and against the Mathematical Alphanumeric Symbols
  block.  This certificate pins the verdict the detector must draw on the
  representative inputs listed below.

  Threat model.  An adversary registers an identifier — a package on a public
  registry, a wallet name, a domain — whose rendered glyph stream is visually
  indistinguishable from a legitimate target's while its underlying codepoint
  stream differs at one or more positions.  The Mathematical Bold Capital A
  (U+1D400), for instance, renders as a heavy "A" yet is a wholly distinct
  codepoint from ASCII 'A' (U+0041); a victim reading the name cannot tell them
  apart, and a tokenizer that trusts the bytes accepts the impostor.

  The discrimination the detector draws.  A sanctioned identifier is one written
  in a single, coherent script whose codepoints carry no confusable structure —
  it passes as clear.  A hazardous identifier is one whose skeleton collides with
  a known target or whose codepoints are drawn from a look-alike block such as
  the Mathematical Alphanumeric Symbols; the detector tags such an input with the
  specific sub-threat (here, `MathAlpha`) so the caller learns not merely that the
  name is suspect but why.

  How to read the certificate.  Each `Row` pairs an `input` codepoint sequence
  with the classification `tag` its verdict must carry — `none` denoting a clear
  verdict, since `isClear` holds exactly when `tag` is `none`.  `verifyRow`
  recomputes `detect` and compares the projected tag; `all_rows_pass` discharges
  the whole table in the kernel.  Appending a vector grows the proof obligation,
  so the certified coverage can only ever widen and never silently regress.
-/

import Unicode.Security.Identity.HomoglyphConfusable

namespace Unicode.Conformance.Security.HomoglyphConfusableTest

open Unicode.Security.Identity.HomoglyphConfusable

set_option maxRecDepth 100000
set_option maxHeartbeats 8000000

-- ── §1  The certificate table ───────────────────────────────────────────────

/-- One conformance row: an `input` sequence and the classification `tag` its
    verdict must carry (`none` for a clear verdict — `isClear` holds precisely
    when the tag is absent). -/
structure Row where
  input : List Nat
  tag : Option String

/-- The representative hazard — and clear — vectors this harness certifies. -/
def rows : List Row :=
  [ -- Mathematical Bold Capital A (U+1D400): a lone Math-Alphanumeric look-alike
    -- of ASCII 'A'. It is the discriminating case for the `MathAlpha` sub-threat
    -- because no target-skeleton match applies, so the block predicate alone must
    -- carry the verdict.
    { input := [0x1D400], tag := some "MathAlpha" },
    -- Plain ASCII "Hello": a single-script Latin identifier with no confusable
    -- structure — the clear baseline that proves the detector does not fire on
    -- ordinary text.
    { input := [0x48, 0x65, 0x6C, 0x6C, 0x6F], tag := none } ]

/-- A row passes when `detect` reproduces the classification tag the row
    prescribes. -/
def verifyRow (r : Row) : Bool :=
  (detect r.input).classify.tag == r.tag

-- ── §2  The closed certificate ──────────────────────────────────────────────

/-- Every certified vector draws exactly the verdict the UTS #39 confusable
    machinery and the Math-Alphanumeric block predicate demand. -/
theorem all_rows_pass : rows.all verifyRow = true := by decide +kernel

end Unicode.Conformance.Security.HomoglyphConfusableTest
