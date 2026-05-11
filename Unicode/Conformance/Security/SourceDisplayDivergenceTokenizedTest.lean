/-
  Unicode.Conformance.Security.SourceDisplayDivergenceTokenizedTest

  Companion conformance proof for the v1.5 region-aware D1
  behaviour.  Folds the universal `Unicode.Security.Fixture`
  parser over `SourceDisplayDivergenceTokenizedTest.txt` and
  `native_decide`-closes the predicate that every row's expected
  verdict matches what
  `Unicode.Security.Display.SourceDisplayDivergence.detect`
  produces when invoked with `Language.rust`.

  The v1 conformance proof in
  `SourceDisplayDivergenceTest.lean` continues to run the
  detector with the default `Language.none` and is unchanged
  by the v1.5 refactor.
-/

import Unicode.Security.Fixture
import Unicode.Security.Display.SourceDisplayDivergence

namespace Unicode.Conformance.Security.SourceDisplayDivergenceTokenizedTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Display.SourceDisplayDivergence
open Unicode.Security.Display.SourceCodeTokenize (Language)

/-- Hand-curated v1.5 fixture for D1 under Rust tokenization —
    11 rows across two sections.  Clear rows demonstrate that
    sub-detector hits inside string literals, line comments,
    block comments, and raw strings are filtered.  Hazard rows
    demonstrate that hits in code regions still fire D1. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/SourceDisplayDivergenceTokenizedTest.txt"

def rows : Array Row := parseFixture rawFixture

/-- Project a `D1Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : D1Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Run `detect r.input .rust` and check the verdict against the
    fixture's expected classification.  D1's compound aggregator
    leaves the positions array empty by design, so the row's
    expected positions must also be empty (or the parser will
    produce an empty array from a blank column 3). -/
def verifyRow (r : Row) : Bool :=
  let v := detect r.input Language.rust
  let (kind, subTag) := projectClassify v.classify
  decide (kind = r.expectedKind) &&
  decide (subTag = r.expectedSubThreat) &&
  decide (v.classify.positions = r.expectedPositions)

/-- Every fixture row's detector verdict under `Language.rust`
    matches its expected verdict. -/
theorem all_rows_pass : rows.all verifyRow = true := by native_decide

/-- Row-count gate. -/
theorem row_count : rows.size = 20 := by native_decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).size ≥ 8 := by native_decide

theorem covers_hazard :
    (rows.filter (·.sectionName = "Hazard")).size ≥ 10 := by native_decide

end Unicode.Conformance.Security.SourceDisplayDivergenceTokenizedTest
