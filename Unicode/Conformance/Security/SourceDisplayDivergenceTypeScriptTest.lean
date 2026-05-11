/-
  Unicode.Conformance.Security.SourceDisplayDivergenceTypeScriptTest

  Companion conformance proof for D1 v1.5 under the TypeScript
  grammar.  Folds the universal `Unicode.Security.Fixture`
  parser over `SourceDisplayDivergenceTypeScriptTest.txt` and
  `native_decide`-closes the predicate that every row's
  expected verdict matches what `detect input .typescript`
  produces.

  Mirrors the Rust- and Python-grammar fixtures row-for-row in
  intent, exercising TypeScript-specific tokenization
  (non-nestable block comments, template literals as single
  string regions, no raw strings).
-/

import Unicode.Security.Fixture
import Unicode.Security.Display.SourceDisplayDivergence

namespace Unicode.Conformance.Security.SourceDisplayDivergenceTypeScriptTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Display.SourceDisplayDivergence
open Unicode.Security.Display.SourceCodeTokenize (Language)

def rawFixture : String :=
  include_str "../../Ucd/Security/SourceDisplayDivergenceTypeScriptTest.txt"

def rows : Array Row := parseFixture rawFixture

def projectClassify
    (c : D1Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

def verifyRow (r : Row) : Bool :=
  let v := detect r.input Language.typescript
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

end Unicode.Conformance.Security.SourceDisplayDivergenceTypeScriptTest
