/-
  Unicode.Conformance.Security.MixedScriptAdmissibilityTest

  Conformance proof for the I2 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `MixedScriptAdmissibilityTest.txt` fixture and
  `native_decide`-closes the predicate that every row's expected
  verdict matches what
  `Unicode.Security.Identity.MixedScriptAdmissibility.detect`
  produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Identity.MixedScriptAdmissibility

namespace Unicode.Conformance.Security.MixedScriptAdmissibilityTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Identity.MixedScriptAdmissibility

/-- Hand-curated v1 fixture for I2 — 15 rows across 5 sections
    covering: pure-script clear cases (ASCII, Cyrillic, Greek,
    Han, Hangul), Latin/Cyrillic IDN-homograph patterns,
    Latin/Greek mixing, Restricted-Identifier-Status codepoints
    (Hangul fillers + Greek lunate epsilon), and generic
    multi-script combos. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/MixedScriptAdmissibilityTest.txt"

def rows : Array Row := parseFixture rawFixture

/-- Project a `I2Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : I2Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project a `I2Classification` to the positions array. -/
def projectPositions (c : I2Classification) : Array Nat :=
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
theorem row_count : rows.size = 15 := by native_decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).size ≥ 5 := by native_decide

theorem covers_latin_cyrillic :
    (rows.filter (·.sectionName = "LatinCyrillic")).size ≥ 3 := by
  native_decide

theorem covers_latin_greek :
    (rows.filter (·.sectionName = "LatinGreek")).size ≥ 2 := by
  native_decide

theorem covers_restricted_status_cp :
    (rows.filter (·.sectionName = "RestrictedStatusCp")).size ≥ 3 := by
  native_decide

theorem covers_script_mix_other :
    (rows.filter (·.sectionName = "ScriptMixOther")).size ≥ 2 := by
  native_decide

end Unicode.Conformance.Security.MixedScriptAdmissibilityTest
