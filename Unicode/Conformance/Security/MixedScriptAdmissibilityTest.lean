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

/-- Project a `Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project a `Classification` to the positions array. -/
def projectPositions (c : Classification) : Array Nat :=
  c.positions

/-- Render a `RestrictionLevel` as the bare constructor name used
    in fixture column-4 attribution. -/
@[inline]
private def levelString : Unicode.Restriction.RestrictionLevel → String
  | .ASCIIOnly             => "ASCIIOnly"
  | .SingleScript          => "SingleScript"
  | .HighlyRestrictive     => "HighlyRestrictive"
  | .ModeratelyRestrictive => "ModeratelyRestrictive"
  | .MinimallyRestrictive  => "MinimallyRestrictive"
  | .Unrestricted          => "Unrestricted"

/-- Validate the I2 verdict's metadata fields against the row's
    column-4 attribution.  Key recognised: `level` (the row's
    UTS #39 §5 restriction level). -/
private def metadataMatches (v : Verdict)
    (attr : KeyValueAttribution) : Bool :=
  attr.checkStringKey "level" (levelString v.level)

/-- Run `detect` on the row's input and check the verdict against
    the fixture's expected classification, sub-threat name,
    hazard positions, AND the column-4 attribution metadata. -/
def verifyRow (r : Row) : Bool :=
  let v := detect r.input
  let (kind, subTag) := projectClassify v.classify
  let pos := projectPositions v.classify
  metadataMatches v r.attribution &&
  decide (kind = r.expectedKind) &&
  decide (subTag = r.expectedSubThreat) &&
  decide (pos = r.expectedPositions)

/-- Every fixture row's detector verdict matches its expected verdict. -/
theorem all_rows_pass : rows.all verifyRow = true := by native_decide

/-- Row-count gate. -/
theorem row_count : rows.size = 24 := by native_decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).size ≥ 8 := by native_decide

theorem covers_latin_cyrillic :
    (rows.filter (·.sectionName = "LatinCyrillic")).size ≥ 6 := by
  native_decide

theorem covers_latin_greek :
    (rows.filter (·.sectionName = "LatinGreek")).size ≥ 2 := by
  native_decide

theorem covers_restricted_status_cp :
    (rows.filter (·.sectionName = "RestrictedStatusCp")).size ≥ 3 := by
  native_decide

theorem covers_script_mix_other :
    (rows.filter (·.sectionName = "ScriptMixOther")).size ≥ 5 := by
  native_decide

end Unicode.Conformance.Security.MixedScriptAdmissibilityTest
