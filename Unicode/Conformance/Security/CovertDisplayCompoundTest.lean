/-
  Unicode.Conformance.Security.CovertDisplayCompoundTest

  Conformance proof for the X2 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `CovertDisplayCompoundTest.txt` fixture and `decide`-closes
  the predicate that every row's expected verdict matches what
  `Unicode.Security.Boundary.CovertDisplayCompound.detect` produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Boundary.CovertDisplayCompound

namespace Unicode.Conformance.Security.CovertDisplayCompoundTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Boundary.CovertDisplayCompound

/-- Hand-curated fixture — 11 rows across 3 sections.

    * Clear (5): ASCII Hello, bidi-only RLO (D3's job), VS-only
      A+VS1 (C2's job), bidi + registered emoji VS (sanctioned),
      balanced bidi without payload.
    * BidiPlusUnregisteredVs (3): RLO + A + VS1 (canonical),
      admin + RLO + X + VS1 (mid-string), LRI + B + VS3.
    * BidiPlusTagBlock (3): RLO + A + LANGUAGE_TAG, foo.t + RLO
      + tag, RLO + registered emoji + tag (priority fall-through:
      sanctioned VS doesn't fire BidiPlusUnregisteredVs but the
      tag block does fire BidiPlusTagBlock). -/
def rawFixture : String :=
  include_str "../../Ucd/Security/CovertDisplayCompoundTest.txt"

def rows : List Row := parseFixture rawFixture

/-- Project an `Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project an `Classification` to the positions array. -/
def projectPositions (c : Classification) : List Nat :=
  c.positions

/-- Run `detect` on the row's input and check the verdict against
    the fixture's expected classification, sub-threat name, and
    hazard positions. -/
def verifyRow (r : Row) : Bool :=
  let v := detect r.input
  let (kind, subTag) := projectClassify v.classify
  let pos := projectPositions v.classify
  decide (kind = r.expectedKind) &&
  decide (subTag = r.expectedSubThreat) &&
  decide (pos = r.expectedPositions)

/-- Every fixture row's detector verdict matches its expected verdict. -/
theorem all_rows_pass : rows.all verifyRow = true := by decide

/-- Row-count gate. -/
theorem row_count : rows.length = 21 := by decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).length ≥ 7 := by decide

theorem covers_unregistered_vs :
    (rows.filter (·.sectionName = "BidiPlusUnregisteredVs")).length ≥ 6 := by
  decide

theorem covers_tag_block :
    (rows.filter (·.sectionName = "BidiPlusTagBlock")).length ≥ 7 := by
  decide

end Unicode.Conformance.Security.CovertDisplayCompoundTest
