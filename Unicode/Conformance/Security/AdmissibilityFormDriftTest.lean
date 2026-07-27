/-
  Unicode.Conformance.Security.AdmissibilityFormDriftTest

  Conformance proof for the X4 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `AdmissibilityFormDriftTest.txt` fixture and `decide`-closes
  the predicate that every row's expected verdict matches what
  `Unicode.Security.Boundary.AdmissibilityFormDrift.detect` produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Boundary.AdmissibilityFormDrift

namespace Unicode.Conformance.Security.AdmissibilityFormDriftTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Boundary.AdmissibilityFormDrift

/-- Hand-curated fixture — 13 rows across 2 sections.

    * Clear (7): ASCII admin, ASCII Hello, precomposed Hangul 한,
      Greek αβγ, x0, leading-digit "012" (both sides false —
      form-stable), Cyrillic привет.
    * AdmissibilityFormDrift (6): ﬁ ligature, Math Italic admin,
      Fullwidth Ａ, decomposed jamos for 한 (passes X1, fires X4
      because the whole-string verdict flips under NFKC
      composition), decomposed jamos for 한국, Roman numeral Ⅳ. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/AdmissibilityFormDriftTest.txt"

def rows : List Row := parseFixture rawFixture

/-- Project an `Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project an `Classification` to the positions array.
    X4 reports no positions because the predicate is whole-string. -/
def projectPositions (c : Classification) : List Nat :=
  c.positions

/-- Validate the X4 verdict's metadata fields against the row's
    column-4 attribution.  Recognised keys: `input_adm` /
    `nfkc_adm` (booleans recording whether the raw input and its
    NFKC form respectively are UTS #39 §5 admissible at the
    Moderately-Restrictive level). -/
def metadataMatches (v : Verdict)
    (attr : KeyValueAttribution) : Bool :=
  attr.checkBoolKey "input_adm" v.inputAdmissible &&
  attr.checkBoolKey "nfkc_adm"  v.nfkcAdmissible

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
theorem row_count : rows.length = 23 := by decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).length ≥ 9 := by decide

theorem covers_drift :
    (rows.filter (·.sectionName = "AdmissibilityFormDrift")).length ≥ 12 := by
  decide

end Unicode.Conformance.Security.AdmissibilityFormDriftTest
