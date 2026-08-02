/-
  Unicode.Conformance.Security.IdentifierFormDriftTest

  Conformance certificate for the IdentifierFormDrift detector (boundary layer:
  the disagreement between an identifier validator and a form normaliser).

  Threat model.  UTS #39 assigns every codepoint an Identifier_Status of
  Allowed or Restricted, and UAX #15 defines the compatibility decomposition
  NFKD.  An adversary crafts an identifier out of Restricted compatibility
  characters — Mathematical Italic letters, fullwidth Latin, ligatures, Roman
  numerals — whose NFKD heads are ordinary Allowed characters.  A gateway that
  screens the raw text rejects the identifier, but a gateway that normalises
  first and then screens accepts it; the attacker steers the input to whichever
  order lets a spoofed identifier through.  The hazard is not any single form of
  the input but the transition between forms, which every single-form detector
  misses by construction.

  What the detector draws.  For each input codepoint it compares the
  Identifier_Status of the codepoint against the Identifier_Status of the first
  codepoint of its NFKD form.  A character with identity decomposition, or one
  whose status is unchanged across decomposition, is sanctioned and passes
  clear; a character whose verdict flips under normalisation is a hazard tagged
  `IdentifierStatusShift`, carrying the offending position for downstream policy.

  How to read the certificate.  Each `Row` pairs a representative input with the
  classification `tag` its verdict must carry, where `none` records a clear
  verdict (`isClear` holds exactly when the tag is absent, so the tag alone
  captures both outcomes).  `verifyRow` recomputes `detect` and compares the
  projected tag against the row; `all_rows_pass` discharges the whole table at
  once.  Appending a vector enlarges the proof obligation, so coverage grows
  with the threat catalogue and cannot silently regress.
-/

import Unicode.Security.Boundary.IdentifierFormDrift

namespace Unicode.Conformance.Security.IdentifierFormDriftTest

open Unicode.Security.Boundary.IdentifierFormDrift

set_option maxRecDepth 100000

-- ── §1  The certificate table ───────────────────────────────────────────────

/-- One conformance row: an `input` sequence and the classification `tag` its
    verdict must carry (`none` for a clear verdict, since `isClear` holds exactly
    when no tag is present). -/
structure Row where
  input : List Nat
  tag : Option String

/-- The representative hazard — and clear — vectors this harness certifies. -/
def rows : List Row :=
  [ -- Greek lowercase α: Allowed with an identity NFKD, so no status can shift —
    -- the sanctioned baseline that must not be flagged.
    { input := [0x03B1], tag := none },
    -- Mathematical Italic Small A: Restricted, but its NFKD head U+0061 'a' is
    -- Allowed — the canonical accept-after-normalise bypass the detector exists
    -- to catch.
    { input := [0x1D44E], tag := some "IdentifierStatusShift" },
    -- Fullwidth Capital A: a compatibility form that is Restricted, while its
    -- NFKD head U+0041 'A' is Allowed — a second decomposition family exhibiting
    -- the same status flip, guarding against a decomposition-specific fix.
    { input := [0xFF21], tag := some "IdentifierStatusShift" } ]

/-- A row passes when `detect` reproduces the classification tag the row
    prescribes. -/
def verifyRow (r : Row) : Bool :=
  (detect r.input).classify.tag == r.tag

-- ── §2  The closed certificate ──────────────────────────────────────────────

/-- Every certified vector draws exactly the identifier-status verdict UTS #39
    and NFKD together demand. -/
theorem all_rows_pass : rows.all verifyRow = true := by decide

end Unicode.Conformance.Security.IdentifierFormDriftTest
