/-
  Unicode.Conformance.Security.ConfusableBidiCompoundTest

  Conformance proof for the X3 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `ConfusableBidiCompoundTest.txt` fixture and `native_decide`-closes
  the predicate that every row's expected verdict matches what
  `Unicode.Security.Boundary.ConfusableBidiCompound.detect` produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Boundary.ConfusableBidiCompound

namespace Unicode.Conformance.Security.ConfusableBidiCompoundTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Boundary.ConfusableBidiCompound

/-- Hand-curated v1 fixture for X3 — 15 rows across 3 sections.

    * Clear (6): ASCII Hello, ASCII admin (no bidi → clear even
      though m is a confusable), Cyrillic а alone (I1 case),
      RLO + ABC (D3 case, ABC chosen to avoid confusables),
      Greek αβγ (no bidi), Han 中文.
    * ConfusableInOverride (6): RLO + а, аdmin + RLO (confusable
      at 0), RLO + Greek ο, LRO + Cyrillic А, x + а + PDF
      (PDF-only override terminator), plain ASCII admin + RLO
      (m → rn case at position 2).
    * ConfusableInIsolate (3): LRI + а, RLI + Greek Α, FSI + а
      + PDI (full isolate wrapping).

    Positions are always reported as `[confusablePos, bidiPos]`
    in that order regardless of lexical order in the input. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/ConfusableBidiCompoundTest.txt"

def rows : Array Row := parseFixture rawFixture

/-- Project an `X3Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : X3Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project an `X3Classification` to the positions array. -/
def projectPositions (c : X3Classification) : Array Nat :=
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

theorem covers_override :
    (rows.filter (·.sectionName = "ConfusableInOverride")).size ≥ 5 := by
  native_decide

theorem covers_isolate :
    (rows.filter (·.sectionName = "ConfusableInIsolate")).size ≥ 3 := by
  native_decide

end Unicode.Conformance.Security.ConfusableBidiCompoundTest
