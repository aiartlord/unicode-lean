/-
  Unicode.Conformance.Security.WidthClassConfusionTest

  Conformance proof for the F5 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `WidthClassConfusionTest.txt` fixture and `native_decide`-closes
  the predicate that every row's expected verdict matches what
  `Unicode.Security.Form.WidthClassConfusion.detect` produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Form.WidthClassConfusion

namespace Unicode.Conformance.Security.WidthClassConfusionTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Form.WidthClassConfusion

/-- Hand-curated v1 fixture for F5 — 13 rows across 3 sections.

    * Clear (6): ASCII Hello, plain ASCII "ADMIN", Han 中文,
      Hangul 한 (W-class-stable), Hangul 한글, Cyrillic привет.
    * FullwidthFold (4): Ａ, ＡＤＭＩＮ, ０１２３ digits, ABCDＥ
      (mixed; first fold at position 4).
    * HalfwidthFold (3): ｱ, ｲｳｴ sequence, アｲ (fullwidth katakana
      followed by halfwidth; halfwidth at position 1, falls past
      the fullwidth check because input position 0 is W not F). -/
def rawFixture : String :=
  include_str "../../Ucd/Security/WidthClassConfusionTest.txt"

def rows : Array Row := parseFixture rawFixture

/-- Project an `F5Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : F5Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project an `F5Classification` to the positions array. -/
def projectPositions (c : F5Classification) : Array Nat :=
  c.positions

/-- Validate the F5 verdict's metadata fields against the row's
    column-4 attribution.  Recognised keys: `fw_fold` (fullwidth
    codepoints whose NFKC fold drops the East-Asian width class),
    `hw_fold` (halfwidth analogue). -/
private def metadataMatches (v : F5Verdict)
    (attr : KeyValueAttribution) : Bool :=
  attr.checkNatKey "fw_fold" v.fullwidthFoldCount &&
  attr.checkNatKey "hw_fold" v.halfwidthFoldCount

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
theorem row_count : rows.size = 22 := by native_decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).size ≥ 8 := by native_decide

theorem covers_fullwidth :
    (rows.filter (·.sectionName = "FullwidthFold")).size ≥ 7 := by
  native_decide

theorem covers_halfwidth :
    (rows.filter (·.sectionName = "HalfwidthFold")).size ≥ 6 := by
  native_decide

end Unicode.Conformance.Security.WidthClassConfusionTest
