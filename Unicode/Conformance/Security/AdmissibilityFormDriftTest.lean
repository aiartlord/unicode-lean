/-
  Unicode.Conformance.Security.AdmissibilityFormDriftTest

  Conformance proof for the X4 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `AdmissibilityFormDriftTest.txt` fixture and `native_decide`-closes
  the predicate that every row's expected verdict matches what
  `Unicode.Security.Boundary.AdmissibilityFormDrift.detect` produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Boundary.AdmissibilityFormDrift

namespace Unicode.Conformance.Security.AdmissibilityFormDriftTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Boundary.AdmissibilityFormDrift

/-- Hand-curated v1 fixture for X4 — 13 rows across 2 sections.

    * Clear (7): ASCII admin, ASCII Hello, precomposed Hangul 한,
      Greek αβγ, x0, leading-digit "012" (both sides false —
      form-stable), Cyrillic привет.
    * AdmissibilityFormDrift (6): ﬁ ligature, Math Italic admin,
      Fullwidth Ａ, decomposed jamos for 한 (passes X1, fires X4
      because the whole-string verdict flips under NFKC
      composition), decomposed jamos for 한국, Roman numeral Ⅳ. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/AdmissibilityFormDriftTest.txt"

def rows : Array Row := parseFixture rawFixture

/-- Project an `X4Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : X4Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project an `X4Classification` to the positions array.
    X4 reports no positions because the predicate is whole-string. -/
def projectPositions (c : X4Classification) : Array Nat :=
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
theorem row_count : rows.size = 13 := by native_decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).size ≥ 6 := by native_decide

theorem covers_drift :
    (rows.filter (·.sectionName = "AdmissibilityFormDrift")).size ≥ 5 := by
  native_decide

end Unicode.Conformance.Security.AdmissibilityFormDriftTest
