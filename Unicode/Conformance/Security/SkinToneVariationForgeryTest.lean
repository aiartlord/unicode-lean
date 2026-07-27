/-
  Unicode.Conformance.Security.SkinToneVariationForgeryTest

  Conformance proof for the I4 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `SkinToneVariationForgeryTest.txt` fixture and
  `decide`-closes the predicate that every row's
  expected verdict matches what
  `Unicode.Security.Identity.SkinToneVariationForgery.detect`
  produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Identity.SkinToneVariationForgery

namespace Unicode.Conformance.Security.SkinToneVariationForgeryTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Identity.SkinToneVariationForgery

/-- Hand-curated fixture — 15 rows across 4 sections
    covering: legitimate single-skin-tone uses on
    modifier-base codepoints (wave-hand, man), stacked
    skin-tones, skin-tone on non-modifier-base targets (ASCII,
    grinning face, Han, digit), and VS15-induced forced-text-style
    on emoji-default codepoints. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/SkinToneVariationForgeryTest.txt"

def rows : List Row := parseFixture rawFixture

/-- Project an `Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project an `Classification` to the positions array. -/
def projectPositions (c : Classification) : List Nat :=
  c.positions

/-- Validate the I4 verdict's metadata fields against the row's
    column-4 attribution.  Recognised keys: `skin_tone_count`,
    `vs15_count` (text-presentation VS-15 occurrences),
    `vs16_count` (emoji-presentation VS-16 occurrences). -/
def metadataMatches (v : Verdict)
    (attr : KeyValueAttribution) : Bool :=
  attr.checkNatKey "skin_tone_count" v.skinToneCount &&
  attr.checkNatKey "vs15_count"      v.variationSelector15Count &&
  attr.checkNatKey "vs16_count"      v.variationSelector16Count

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
theorem row_count : rows.length = 24 := by decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).length ≥ 8 := by decide

theorem covers_stacked :
    (rows.filter (·.sectionName = "StackedSkinTones")).length ≥ 3 := by
  decide

theorem covers_invalid_target :
    (rows.filter (·.sectionName = "InvalidSkinToneTarget")).length ≥ 6 := by
  decide

theorem covers_forced_text :
    (rows.filter (·.sectionName = "ForcedTextStyle")).length ≥ 6 := by
  decide

end Unicode.Conformance.Security.SkinToneVariationForgeryTest
