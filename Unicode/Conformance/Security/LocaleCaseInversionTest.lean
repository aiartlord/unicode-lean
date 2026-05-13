/-
  Unicode.Conformance.Security.LocaleCaseInversionTest

  Conformance proof for the F3 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `LocaleCaseInversionTest.txt` fixture and `native_decide`-closes
  the predicate that every row's expected verdict matches what
  `Unicode.Security.Form.LocaleCaseInversion.detect` produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Form.LocaleCaseInversion

namespace Unicode.Conformance.Security.LocaleCaseInversionTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Form.LocaleCaseInversion

/-- Hand-curated v1 fixture for F3 — 12 rows across 3 sections.

    * Clear (6): ASCII Hello (no I), Han 中文, Cyrillic Russian,
      Greek lowercase, ASCII digits, capital ABCD (no I).
    * TurkishCaseDivergence (4): bare U+0049 'I', "ISTANBUL"
      (first I at position 0), bare U+0130 'İ', mixed `aİa`
      (first divergence at position 1).
    * LithuanianCaseDivergence (2): U+004A J + combining grave
      and J + combining acute — both ccc = 230 marks satisfying
      MoreAbove, both falling through past the Turkish check
      because J has no `tr` SpecialCasing row. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/LocaleCaseInversionTest.txt"

def rows : Array Row := parseFixture rawFixture

/-- Project an `Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project an `Classification` to the positions array. -/
def projectPositions (c : Classification) : Array Nat :=
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
    (rows.filter (·.sectionName = "Clear")).size ≥ 8 := by native_decide

theorem covers_turkish :
    (rows.filter (·.sectionName = "TurkishCaseDivergence")).size ≥ 6 := by
  native_decide

theorem covers_lithuanian :
    (rows.filter (·.sectionName = "LithuanianCaseDivergence")).size ≥ 5 := by
  native_decide

end Unicode.Conformance.Security.LocaleCaseInversionTest
