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
import Unicode.Conformance.Security.VectorFile

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

-- ═══════════════════════════════════════════════════════════════════════════════
-- The pinned vector file, executed
--
-- `Unicode/Ucd/Security/NoncharacterControlTest.txt` is hash-pinned by
-- `scripts/check-security-hashes.sh`, which fixes its bytes.  Running the
-- detector over those bytes is a separate claim, and this section makes it:
-- `rowsList` is mirrored against a fresh parse of the file at build time, and
-- `all_vectors_pass` reduces the detector over every row in the kernel.  A row
-- added to, removed from, or edited in the file fails the build until the
-- harness agrees with it again.
-- ═══════════════════════════════════════════════════════════════════════════════

open Unicode.Conformance.Security.VectorFile (VectorRow parseFile)

/-- Raw text of the pinned vector file, embedded at compile time. -/
def vectorsRaw : String := include_str "../../Ucd/Security/NoncharacterControlTest.txt"

/-- Every row of the pinned vector file, freshly parsed. -/
def parsedRows : List VectorRow := parseFile vectorsRaw

/-- The pinned rows, materialized so the kernel can reduce over them. -/
def rowsList : List VectorRow := [
  ⟨[0x0048, 0x0065, 0x006C, 0x006C, 0x006F], "Clear", []⟩,
  ⟨[0x0041, 0x0009, 0x000A, 0x000D, 0x0042], "Clear", []⟩,
  ⟨[0xFDCF], "Clear", []⟩,
  ⟨[0xFDF0], "Clear", []⟩,
  ⟨[0x00A0], "Clear", []⟩,
  ⟨[0x0020], "Clear", []⟩,
  ⟨[0xFFFD], "Clear", []⟩,
  ⟨[0x4E2D, 0x6587], "Clear", []⟩,
  ⟨[0xFDD0], "Hazard:Noncharacter", [0]⟩,
  ⟨[0xFDEF], "Hazard:Noncharacter", [0]⟩,
  ⟨[0xFDE0], "Hazard:Noncharacter", [0]⟩,
  ⟨[0xFFFE], "Hazard:Noncharacter", [0]⟩,
  ⟨[0xFFFF], "Hazard:Noncharacter", [0]⟩,
  ⟨[0x1FFFE], "Hazard:Noncharacter", [0]⟩,
  ⟨[0x1FFFF], "Hazard:Noncharacter", [0]⟩,
  ⟨[0x10FFFE], "Hazard:Noncharacter", [0]⟩,
  ⟨[0x10FFFF], "Hazard:Noncharacter", [0]⟩,
  ⟨[0x0041, 0xFDD0, 0x0042], "Hazard:Noncharacter", [1]⟩,
  ⟨[0xFFFE, 0x0041, 0xFFFF], "Hazard:Noncharacter", [0]⟩,
  ⟨[0x0041, 0x0000, 0x0042], "Hazard:C0Control", [1]⟩,
  ⟨[0x0000], "Hazard:C0Control", [0]⟩,
  ⟨[0x0041, 0x001B, 0x005B, 0x0033, 0x0031, 0x006D], "Hazard:C0Control", [1]⟩,
  ⟨[0x001F], "Hazard:C0Control", [0]⟩,
  ⟨[0x0041, 0x007F, 0x0042], "Hazard:C0Control", [1]⟩,
  ⟨[0x0009, 0x000B], "Hazard:C0Control", [1]⟩,
  ⟨[0x0000, 0x0041, 0x001B], "Hazard:C0Control", [0]⟩,
  ⟨[0x0041, 0x0080, 0x0042], "Hazard:C1Control", [1]⟩,
  ⟨[0x0080], "Hazard:C1Control", [0]⟩,
  ⟨[0x009F], "Hazard:C1Control", [0]⟩,
  ⟨[0x0041, 0x0085, 0x0042], "Hazard:C1Control", [1]⟩,
  ⟨[0x0000, 0xFDD0], "Hazard:C0Control", [0]⟩,
  ⟨[0x0080, 0xFFFE], "Hazard:C1Control", [0]⟩,
  ⟨[0xFDD0, 0x0000], "Hazard:Noncharacter", [0]⟩,
  ⟨[0x0000, 0x0080], "Hazard:C0Control", [0]⟩
]

-- `rowsList` mirrors a fresh parse of the vector file, checked at build time.
#eval do
  unless rowsList == parsedRows do
    throw (IO.userError "NoncharacterControlTest drift: rowsList ≠ parsed vector file")

/-- Run the detector over one row and compare with the verdict the file states:
    the classification the row prescribes, and the positions the row localises
    the hazard to. -/
def verifyVectorRow (r : VectorRow) : Bool :=
  let v := detect r.codepoints
  (if r.expectsClear then v.classify.isClear
   else v.classify.tag == r.expectedTag)
    && v.classify.positions == r.positions

/-- Every vector the pinned file states holds of the detector. -/
theorem all_vectors_pass : rowsList.all verifyVectorRow = true := by decide +kernel

end Unicode.Conformance.Security.NoncharacterControlTest
