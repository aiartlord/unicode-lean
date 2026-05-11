/-
  Unicode.Conformance.Security.RtlInjectionTest

  Conformance proof for the D3 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `RtlInjectionTest.txt` fixture and `native_decide`-closes the
  predicate that every row's expected verdict matches what
  `Unicode.Security.Display.RtlInjection.detect` produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Display.RtlInjection

namespace Unicode.Conformance.Security.RtlInjectionTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Display.RtlInjection

/-- Hand-curated v1 fixture for D3 — 15 rows across 5 sections
    covering: plain-ASCII / digits / Cyrillic / Han / URL clear
    cases, bidi-format-control injections (RLO, RLI+PDI, RLE+PDF),
    leading-Hebrew / leading-Arabic field-direction takeovers,
    short mid-stream strong-RTL hits, and 4+ char RTL runs that
    trip the overflow heuristic. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/RtlInjectionTest.txt"

def rows : Array Row := parseFixture rawFixture

/-- Project a `D3Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : D3Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project a `D3Classification` to the positions array. -/
def projectPositions (c : D3Classification) : Array Nat :=
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
theorem row_count : rows.size = 16 := by native_decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).size ≥ 5 := by native_decide

theorem covers_rlo :
    (rows.filter (·.sectionName = "RloInLTRField")).size ≥ 3 := by
  native_decide

theorem covers_field_takeover :
    (rows.filter (·.sectionName = "FieldTakeover")).size ≥ 3 := by
  native_decide

theorem covers_strong_rtl_in_ltr :
    (rows.filter (·.sectionName = "StrongRTLInLTR")).size ≥ 3 := by
  native_decide

theorem covers_mixed_overflow :
    (rows.filter (·.sectionName = "MixedOverflow")).size ≥ 2 := by
  native_decide

end Unicode.Conformance.Security.RtlInjectionTest
