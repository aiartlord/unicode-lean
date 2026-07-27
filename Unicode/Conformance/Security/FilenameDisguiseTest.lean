/-
  Unicode.Conformance.Security.FilenameDisguiseTest

  Conformance proof for the D2 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `FilenameDisguiseTest.txt` fixture and `decide`-closes
  the predicate that every row's expected verdict matches what
  `Unicode.Security.Display.FilenameDisguise.detect` produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Display.FilenameDisguise

namespace Unicode.Conformance.Security.FilenameDisguiseTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Display.FilenameDisguise

/-- Hand-curated fixture — 15 rows across 5 sections
    covering: plain-ASCII clear cases (txt, pdf, no-ext, two-seg
    tar.gz, native Hebrew, native Arabic), the classic RLO/RLI/RLE
    extension flip shapes, fullwidth-letter extensions, combining
    marks inside extensions, and 3+ dot multi-extension advisory. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/FilenameDisguiseTest.txt"

def rows : List Row := parseFixture rawFixture

/-- Project a `Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project a `Classification` to the positions array. -/
def projectPositions (c : Classification) : List Nat :=
  c.positions

/-- Validate the D2 verdict's metadata fields against the row's
    column-4 attribution.  Recognised keys: `dot_count` (number of
    `.` separators), `bidi_count` (bidi-control characters present),
    `fw_in_ext`, `comb_in_ext` (fullwidth / combining characters
    inside the extension). -/
def metadataMatches (v : Verdict)
    (attr : KeyValueAttribution) : Bool :=
  attr.checkNatKey "dot_count"   v.dotPositions.length &&
  attr.checkNatKey "bidi_count"  v.bidiControlCount &&
  attr.checkNatKey "fw_in_ext"   v.fullwidthInExt &&
  attr.checkNatKey "comb_in_ext" v.combiningInExt

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
theorem row_count : rows.length = 27 := by decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).length ≥ 9 := by decide

theorem covers_rlo_flip :
    (rows.filter (·.sectionName = "RloFlip")).length ≥ 6 := by decide

theorem covers_width_class :
    (rows.filter (·.sectionName = "WidthClassExt")).length ≥ 4 := by
  decide

theorem covers_combining_in_ext :
    (rows.filter (·.sectionName = "CombiningInExt")).length ≥ 4 := by
  decide

theorem covers_multiple_extensions :
    (rows.filter (·.sectionName = "MultipleExtensions")).length ≥ 4 := by
  decide

end Unicode.Conformance.Security.FilenameDisguiseTest
