/-
  Unicode.Conformance.Security.StreamSafeViolationTest

  Conformance proof for the F2 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `StreamSafeViolationTest.txt` fixture and `decide`-closes
  the predicate that every row's expected verdict matches what
  `Unicode.Security.Form.StreamSafeViolation.detect` produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Form.StreamSafeViolation

namespace Unicode.Conformance.Security.StreamSafeViolationTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Form.StreamSafeViolation

/-- Hand-curated fixture — 8 rows across 2 sections.

    * Clear (5): ASCII, Korean precomposed, a + 1 combining mark,
      a + 30 combining marks (the strict-`>` boundary), and the
      canonical CGJ-split remediation (a + 30 + CGJ + 30).
    * StreamSafeOverrun (3): a + 31 (minimum overrun), a + 50
      (clear Zalgo), and a + 31 followed by b + 34 (first
      overrun is reported). -/
def rawFixture : String :=
  include_str "../../Ucd/Security/StreamSafeViolationTest.txt"

def rows : List Row := parseFixture rawFixture

/-- Project an `Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project an `Classification` to the positions array. -/
def projectPositions (c : Classification) : List Nat :=
  c.positions

/-- Validate the F2 verdict's metadata fields against the row's
    column-4 attribution.  Recognised keys: `max_run` (longest
    non-starter run length), `overruns` (number of runs that
    breached the UAX #15 §9 Stream-Safe ceiling of 30),
    `total_ns` (total non-starters in input). -/
def metadataMatches (v : Verdict)
    (attr : KeyValueAttribution) : Bool :=
  attr.checkNatKey "max_run"  v.maxRunLen &&
  attr.checkNatKey "overruns" v.overrunCount &&
  attr.checkNatKey "total_ns" v.totalNonStarters

/-- Run `detect` on the row's input and check the verdict against
    the fixture's expected classification, sub-threat name, hazard
    positions, AND the column-4 attribution metadata. -/
def verifyRow (r : Row) : Bool :=
  let v := detect r.input
  let (kind, subTag) := projectClassify v.classify
  let pos := projectPositions v.classify
  metadataMatches v r.attribution &&
  decide (kind = r.expectedKind) &&
  decide (subTag = r.expectedSubThreat) &&
  decide (pos = r.expectedPositions)

/-- Every fixture row's detector verdict matches its expected verdict. -/
theorem all_rows_pass : rows.all verifyRow = true := by decide

/-- Row-count gate. -/
theorem row_count : rows.length = 15 := by decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).length ≥ 7 := by decide

theorem covers_overrun :
    (rows.filter (·.sectionName = "StreamSafeOverrun")).length ≥ 7 := by
  decide

end Unicode.Conformance.Security.StreamSafeViolationTest
