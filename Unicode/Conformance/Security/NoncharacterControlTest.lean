/-
  Unicode.Conformance.Security.NoncharacterControlTest

  Conformance certificate for the NoncharacterControl detector (covert layer:
  designated Unicode noncharacters and C0/C1 control codepoints in interchange
  text).

  Threat model.  The Standard permanently reserves 66 noncharacters (the
  U+FDD0..U+FDEF block and the last two codepoints of every plane) for internal
  use; they must never cross an interchange boundary.  The C0 and C1 control
  blocks are equally illegitimate in plain text save for the three structural
  whitespace controls.  Smuggled into a header or identifier, such a codepoint
  can truncate a parser, terminate a string early, or slip past a filter that
  only inspects printable characters.

  What the detector draws.  It lifts the proven codec predicate
  `Unicode.Codec.Noncharacters.isNoncharacter`, together with the explicit
  C0/C1 ranges, into the Security verdict vocabulary: a `Noncharacter`,
  `C0Control`, or `C1Control` hazard tagged with the offending positions and a
  hit count, while TAB, LF, and CR pass as legitimate interchange structure.

  The certificate.  Each `Row` pairs a representative input with the verdict it
  must draw — classification `tag` (`none` for a clear verdict), the flagged-hit
  count, and the implicated positions.  `verifyRow` recomputes `detect` and
  compares all three projections; `all_rows_pass` discharges the whole table in
  the kernel.  A new vector is one appended row, so coverage grows with the
  threat catalogue and cannot silently regress.
-/

import Unicode.Security.Covert.NoncharacterControl

namespace Unicode.Conformance.Security.NoncharacterControlTest

open Unicode.Security.Covert.NoncharacterControl

-- ── §1  The certificate table ───────────────────────────────────────────────

/-- One conformance row: an `input` sequence, the classification `tag` its
    verdict must carry (`none` for a clear verdict), the number of flagged
    `hits`, and the `positions` those hits occupy. -/
structure Row where
  input : List Nat
  tag : Option String
  hits : Nat
  positions : List Nat

/-- The representative hazard — and clear — vectors this harness certifies. -/
def rows : List Row :=
  [ -- A BMP-block noncharacter: the first of the U+FDD0..U+FDEF reservation.
    { input := [0xFDD0], tag := some "Noncharacter", hits := 1, positions := [0] },
    -- The last codepoint of the last plane — the plane-end noncharacter form.
    { input := [0x10FFFF], tag := some "Noncharacter", hits := 1, positions := [0] },
    -- A C0 control (NUL) embedded mid-text: a classic string-truncation vector.
    { input := [0x41, 0x00, 0x42], tag := some "C0Control", hits := 1, positions := [1] },
    -- A C1 control (U+0080) mid-text: the high control block, equally illegal.
    { input := [0x41, 0x80, 0x42], tag := some "C1Control", hits := 1, positions := [1] },
    -- Plain ASCII carries no control or noncharacter — clear.
    { input := [0x48, 0x65, 0x6C, 0x6C, 0x6F], tag := none, hits := 0, positions := [] },
    -- TAB, LF, CR are sanctioned interchange structure, not a C0 hazard — clear.
    { input := [0x41, 0x09, 0x0A, 0x0D, 0x42], tag := none, hits := 0, positions := [] } ]

/-- A row passes when `detect` reproduces the tag, the hit count, and the hit
    positions the row prescribes. -/
def verifyRow (r : Row) : Bool :=
  let v := detect r.input
  (v.classify.tag == r.tag) && (v.hitCount == r.hits)
    && (v.classify.positions == r.positions)

-- ── §2  The closed certificate ──────────────────────────────────────────────

/-- Every certified vector draws exactly the verdict the codec predicate and the
    C0/C1 ranges demand. -/
theorem all_rows_pass : rows.all verifyRow = true := by decide

end Unicode.Conformance.Security.NoncharacterControlTest
