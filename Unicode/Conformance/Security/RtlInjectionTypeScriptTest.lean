/-
  Unicode.Conformance.Security.RtlInjectionTypeScriptTest

  Companion conformance proof for D3 v1.5 under the TypeScript
  grammar.  Folds the universal `Unicode.Security.Fixture`
  parser over `RtlInjectionTypeScriptTest.txt` and
  `native_decide`-closes the predicate that every row's
  expected verdict matches what `detect input .typescript`
  produces.

  Mirrors the Rust- and Python-grammar D3 fixtures row-for-row
  in intent, exercising TypeScript-specific tokenization
  (non-nestable block comments, template literals as single
  string regions).
-/

import Unicode.Security.Fixture
import Unicode.Security.Display.RtlInjection

namespace Unicode.Conformance.Security.RtlInjectionTypeScriptTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Display.RtlInjection
open Unicode.Security.Display.SourceCodeTokenize (Language)

def rawFixture : String :=
  include_str "../../Ucd/Security/RtlInjectionTypeScriptTest.txt"

def rows : Array Row := parseFixture rawFixture

def projectClassify
    (c : D3Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

def verifyRow (r : Row) : Bool :=
  let v := detect r.input Language.typescript
  let (kind, subTag) := projectClassify v.classify
  decide (kind = r.expectedKind) &&
  decide (subTag = r.expectedSubThreat) &&
  decide (v.classify.positions = r.expectedPositions)

theorem all_rows_pass : rows.all verifyRow = true := by native_decide

theorem row_count : rows.size = 15 := by native_decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).size ≥ 8 := by native_decide

theorem covers_hazard :
    (rows.filter (·.sectionName = "Hazard")).size ≥ 7 := by native_decide

end Unicode.Conformance.Security.RtlInjectionTypeScriptTest
