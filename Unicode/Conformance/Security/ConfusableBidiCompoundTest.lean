/-
  Unicode.Conformance.Security.ConfusableBidiCompoundTest

  Conformance certificate for the ConfusableBidiCompound detector (boundary
  layer: the cross-layer compound of identity spoofing and display deception).

  What this certifies.  The detector unites two spec clauses that are dangerous
  together in a way neither is alone.  UTS #39 §4 defines a confusable as a
  codepoint whose skeleton collides with another's — the machinery behind the
  IDN homograph, where a Cyrillic 'а' (U+0430) stands in for Latin 'a'.  UAX #9
  defines the bidirectional format controls — the overrides and isolates that
  reorder how text renders.  ConfusableBidiCompound fires only when a confusable
  codepoint co-occurs with a bidi override or isolate in the same input.

  Threat model.  An adversary registers a domain, username, or package name in
  which a homoglyph substitutes for an ASCII letter, then wraps the string in an
  RLO override or an LRI isolate so the rendered glyphs still spell a legitimate
  identifier.  The human reader sees `admin`; the resolver, comparator, or
  filter downstream sees a different byte sequence.  This is the Trojan-Source
  class, CVE-2021-42574: the visual layer and the identity layer disagree, and
  the disagreement is engineered to pass review.

  The discrimination it draws.  A lone confusable with no bidi control is left
  to the plain homoglyph detector and stays clear here, and a bidi override over
  ordinary ASCII is left to the RTL-injection detector and likewise stays clear.
  Only the simultaneous occurrence is a compound hazard, split by the class of
  bidi control present: an override-class control yields the high-severity
  `ConfusableInOverride`, while an isolate-class control yields the softer
  `ConfusableInIsolate`.

  How to read the certificate.  Each `Row` pairs a representative input with the
  classification `tag` its verdict must carry, where `none` denotes a clear
  verdict (a clear classification has no tag, so the tag field captures the
  clear-versus-hazard distinction as well as the hazard sub-class).  `verifyRow`
  recomputes `detect` and compares the tag; `all_rows_pass` discharges the whole
  table at once.  Appending a vector grows the proof obligation, so the covered
  threat surface can only expand and never silently regress.
-/

import Unicode.Security.Boundary.ConfusableBidiCompound

namespace Unicode.Conformance.Security.ConfusableBidiCompoundTest

open Unicode.Security.Boundary.ConfusableBidiCompound

-- ── §1  The certificate table ───────────────────────────────────────────────

/-- One conformance row: an `input` codepoint sequence and the classification
    `tag` its verdict must carry, with `none` standing for a clear verdict. -/
structure Row where
  input : List Nat
  tag : Option String

/-- The representative hazard — and clear — vectors this harness certifies. -/
def rows : List Row :=
  [ -- A lone Cyrillic 'а' (U+0430) with no bidi control: confusable alone is
    -- the plain homoglyph detector's charter, so the compound stays clear here.
    { input := [0x0430], tag := none },
    -- RLO override (U+202E) then Cyrillic 'а': the canonical Trojan-Source plus
    -- IDN-homograph compound, and the discriminating case for the override arm.
    { input := [0x202E, 0x0430], tag := some "ConfusableInOverride" },
    -- LRI isolate (U+2066) then Greek 'ο' (U+03BF): a confusable inside an
    -- isolate rather than an override, exercising the softer isolate-class arm.
    { input := [0x2066, 0x03BF], tag := some "ConfusableInIsolate" } ]

/-- A row passes when `detect` reproduces the classification tag the row
    prescribes. -/
def verifyRow (r : Row) : Bool :=
  (detect r.input).classify.tag == r.tag

-- ── §2  The closed certificate ──────────────────────────────────────────────

/-- Every certified vector draws exactly the verdict the confusable table and
    the bidi-control classes demand. -/
theorem all_rows_pass : rows.all verifyRow = true := by decide

end Unicode.Conformance.Security.ConfusableBidiCompoundTest
