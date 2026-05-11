/-
  Unicode.Conformance.Security.SourceDisplayDivergencePythonTest

  Companion conformance proof for D1 v1.5 under the Python
  grammar.  Folds the universal `Unicode.Security.Fixture`
  parser over `SourceDisplayDivergencePythonTest.txt` and
  `native_decide`-closes the predicate that every row's
  expected verdict matches what `detect input .python`
  produces.

  Mirrors the Rust-grammar fixture
  `SourceDisplayDivergenceTokenizedTest.txt` row-for-row in
  intent, exercising Python-specific tokenization (triple-
  quoted strings, `#` line comments, no block comments).
-/

import Unicode.Security.Fixture
import Unicode.Security.Display.SourceDisplayDivergence

namespace Unicode.Conformance.Security.SourceDisplayDivergencePythonTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Display.SourceDisplayDivergence
open Unicode.Security.Display.SourceCodeTokenize (Language)

def rawFixture : String :=
  include_str "../../Ucd/Security/SourceDisplayDivergencePythonTest.txt"

def rows : Array Row := parseFixture rawFixture

def projectClassify
    (c : D1Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

def verifyRow (r : Row) : Bool :=
  let v := detect r.input Language.python
  let (kind, subTag) := projectClassify v.classify
  decide (kind = r.expectedKind) &&
  decide (subTag = r.expectedSubThreat) &&
  decide (v.classify.positions = r.expectedPositions)

theorem all_rows_pass : rows.all verifyRow = true := by native_decide

theorem row_count : rows.size = 13 := by native_decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).size ≥ 7 := by native_decide

theorem covers_hazard :
    (rows.filter (·.sectionName = "Hazard")).size ≥ 6 := by native_decide

end Unicode.Conformance.Security.SourceDisplayDivergencePythonTest
