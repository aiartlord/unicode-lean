/-
  Unicode.Conformance.Security.CovertDisplayCompoundTest

  Conformance proof for the X2 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `CovertDisplayCompoundTest.txt` fixture and `native_decide`-closes
  the predicate that every row's expected verdict matches what
  `Unicode.Security.Boundary.CovertDisplayCompound.detect` produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Boundary.CovertDisplayCompound

namespace Unicode.Conformance.Security.CovertDisplayCompoundTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Boundary.CovertDisplayCompound

/-- Hand-curated v1 fixture for X2 — 11 rows across 3 sections.

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

def rows : Array Row := parseFixture rawFixture

/-- Project an `X2Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : X2Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project an `X2Classification` to the positions array. -/
def projectPositions (c : X2Classification) : Array Nat :=
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
theorem all_rows_pass : rows.all verifyRow = true := by native_decide

/-- Row-count gate. -/
theorem row_count : rows.size = 21 := by native_decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).size ≥ 7 := by native_decide

theorem covers_unregistered_vs :
    (rows.filter (·.sectionName = "BidiPlusUnregisteredVs")).size ≥ 6 := by
  native_decide

theorem covers_tag_block :
    (rows.filter (·.sectionName = "BidiPlusTagBlock")).size ≥ 7 := by
  native_decide

end Unicode.Conformance.Security.CovertDisplayCompoundTest
