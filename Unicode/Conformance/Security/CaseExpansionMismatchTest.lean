/-
  Unicode.Conformance.Security.CaseExpansionMismatchTest

  Conformance proof for the F4 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `CaseExpansionMismatchTest.txt` fixture and `decide`-closes
  the predicate that every row's expected verdict matches what
  `Unicode.Security.Form.CaseExpansionMismatch.detect` produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Form.CaseExpansionMismatch

namespace Unicode.Conformance.Security.CaseExpansionMismatchTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Form.CaseExpansionMismatch

/-- Hand-curated fixture — 12 rows across 3 sections.

    * Clear (6): ASCII Hello, capital ABC, Han 中文, Greek αβγ,
      Cyrillic привет, Korean 한.
    * UpperExpansion (4): bare ß, bare ﬁ ligature, bare ﬃ ligature
      (1 → 3), "Straße" (expansion at position 4).
    * LowerExpansion (2): bare İ (no upper expansion, falls
      through), aİa (expansion at position 1). -/
def rawFixture : String :=
  include_str "../../Ucd/Security/CaseExpansionMismatchTest.txt"

def rows : Array Row := parseFixture rawFixture

/-- Project an `Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project an `Classification` to the positions array. -/
def projectPositions (c : Classification) : Array Nat :=
  c.positions

/-- Validate the F4 verdict's metadata fields against the row's
    column-4 attribution.  Recognised keys: `upper_exp` /
    `lower_exp` (number of codepoints whose Special_Casing mapping
    expands under upper / lower casing), `max_exp` (the worst
    single-codepoint case-expansion length). -/
def metadataMatches (v : Verdict)
    (attr : KeyValueAttribution) : Bool :=
  attr.checkNatKey "upper_exp" v.upperExpansionCount &&
  attr.checkNatKey "lower_exp" v.lowerExpansionCount &&
  attr.checkNatKey "max_exp"   v.maxExpansionLen

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
theorem row_count : rows.size = 22 := by decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).size ≥ 9 := by decide

theorem covers_upper :
    (rows.filter (·.sectionName = "UpperExpansion")).size ≥ 9 := by
  decide

theorem covers_lower :
    (rows.filter (·.sectionName = "LowerExpansion")).size ≥ 4 := by
  decide

end Unicode.Conformance.Security.CaseExpansionMismatchTest
