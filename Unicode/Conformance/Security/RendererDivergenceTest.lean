/-
  Unicode.Conformance.Security.RendererDivergenceTest

  Conformance proof for the D4 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `RendererDivergenceTest.txt` fixture and `native_decide`-closes
  the predicate that every row's expected verdict matches what
  `Unicode.Security.Display.RendererDivergence.detect` produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Display.RendererDivergence

namespace Unicode.Conformance.Security.RendererDivergenceTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Display.RendererDivergence

/-- Hand-curated v1 fixture for D4 — 16 rows across 6 sections
    covering: stable clear cases (ASCII, Han, Cyrillic, Hebrew,
    registered RGI family ZWJ), VS-presence variance (emoji,
    heart, standardized variation), unregistered ZWJ variance,
    Zalgo combining-stack overflow, fullwidth variance, and
    mixed-direction variance. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/RendererDivergenceTest.txt"

def rows : Array Row := parseFixture rawFixture

/-- Project a `D4Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : D4Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project a `D4Classification` to the positions array. -/
def projectPositions (c : D4Classification) : Array Nat :=
  c.positions

/-- Validate the D4 verdict's metadata fields against the row's
    column-4 attribution.  Recognised keys: `vs_count`,
    `comb_count`, `fw_count` (fullwidth characters), `has_zwj`
    (any ZWJ present), `ltr_count`, `rtl_count`. -/
private def metadataMatches (v : D4Verdict)
    (attr : KeyValueAttribution) : Bool :=
  attr.checkNatKey  "vs_count"   v.vsCount &&
  attr.checkNatKey  "comb_count" v.combiningCount &&
  attr.checkNatKey  "fw_count"   v.fullwidthCount &&
  attr.checkBoolKey "has_zwj"    v.hasZwj &&
  attr.checkNatKey  "ltr_count"  v.strongLTRCount &&
  attr.checkNatKey  "rtl_count"  v.strongRTLCount

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
theorem all_rows_pass : rows.all verifyRow = true := by native_decide

/-- Row-count gate. -/
theorem row_count : rows.size = 16 := by native_decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).size ≥ 5 := by native_decide

theorem covers_vs :
    (rows.filter (·.sectionName = "VariationSelectorVariance")).size ≥ 3 := by
  native_decide

theorem covers_unregistered_zwj :
    (rows.filter (·.sectionName = "UnregisteredZwjVariance")).size ≥ 2 := by
  native_decide

theorem covers_combining_overflow :
    (rows.filter (·.sectionName = "CombiningStackOverflow")).size ≥ 2 := by
  native_decide

theorem covers_fullwidth :
    (rows.filter (·.sectionName = "FullwidthVariance")).size ≥ 2 := by
  native_decide

theorem covers_mixed_direction :
    (rows.filter (·.sectionName = "MixedDirectionVariance")).size ≥ 2 := by
  native_decide

end Unicode.Conformance.Security.RendererDivergenceTest
