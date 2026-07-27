/-
  Unicode.Conformance.Security.SurrogateReassemblyTest

  Conformance proof for the C4 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `SurrogateReassemblyTest.txt` fixture and `decide`-closes
  the predicate that every row's expected verdict matches what
  `Unicode.Security.Covert.SurrogateReassembly.detect` produces.

  Input bytes are encoded in column 1 of the fixture as single-byte
  hex values (each `0x00..0xFF`).  The fixture parser stores them
  in `r.input : List Nat`; the C4 detector converts to a byte list
  (`List UInt8`) via `Unicode.Security.Covert.SurrogateReassembly.toBytes`.
-/

import Unicode.Security.Fixture
import Unicode.Security.Covert.SurrogateReassembly

namespace Unicode.Conformance.Security.SurrogateReassemblyTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Covert.SurrogateReassembly

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Raw fixture + parsed rows
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Hand-curated fixture — 17 rows across 5 sections
    covering the valid-UTF-8 cases plus every Utf8RejectKind
    category surfaced by `Unicode.Codec.Utf8.firstInvalidUtf8Offset`. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/SurrogateReassemblyTest.txt"

/-- All parsed rows from the bundled fixture. -/
def rows : List Row := parseFixture rawFixture

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Per-family classification-name mapping
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Project a `Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project a `Classification` to the positions array. -/
def projectPositions (c : Classification) : List Nat :=
  c.positions

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Per-row verifier
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Validate the C4 verdict's metadata fields against the row's
    column-4 attribution.  The `reject_kind` key is redundant
    with the sub-threat tag (already checked) so the interesting
    metadata is `offset` — the byte offset of the first invalid
    byte the strict decoder rejected.  Compared against
    `v.firstInvalidOffset`. -/
def metadataMatches (v : Verdict)
    (attr : KeyValueAttribution) : Bool :=
  match attr.get? "offset" with
  | none      => true
  | some raw  =>
    match raw.toNat? with
    | none           => Function.const String false raw
    | some expected  =>
      match v.firstInvalidOffset with
      | none           => false
      | some actual    => decide (actual = expected)

/-- Run `detect` on the row's input and check the verdict against
    the fixture's expected classification, sub-threat name,
    hazard positions, AND the column-4 attribution metadata. -/
def verifyRow (r : Row) : Bool :=
  let v := detect r.input
  let (kind, subTag) := projectClassify v.classify
  let pos := projectPositions v.classify
  metadataMatches v r.attribution &&
  decide (kind = r.expectedKind) &&
  decide (subTag = r.expectedSubThreat) &&
  decide (pos = r.expectedPositions)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Headline conformance theorem + row-count gate
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Every fixture row's detector verdict matches its expected verdict. -/
theorem all_rows_pass : rows.all verifyRow = true := by decide

/-- Row-count gate. -/
theorem row_count : rows.length = 28 := by decide

/-- Section coverage gates. -/
theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).length ≥ 8 := by decide

theorem covers_invalid_start_byte :
    (rows.filter (·.sectionName = "InvalidStartByte")).length ≥ 7 := by
  decide

theorem covers_overlong :
    (rows.filter (·.sectionName = "Overlong")).length ≥ 4 := by decide

theorem covers_cesu8 :
    (rows.filter (·.sectionName = "Cesu8")).length ≥ 3 := by decide

theorem covers_truncated :
    (rows.filter (·.sectionName = "Truncated")).length ≥ 6 := by decide

end Unicode.Conformance.Security.SurrogateReassemblyTest
