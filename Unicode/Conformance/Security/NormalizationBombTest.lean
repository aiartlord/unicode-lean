/-
  Unicode.Conformance.Security.NormalizationBombTest

  Conformance proof for the F1 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `NormalizationBombTest.txt` fixture and `native_decide`-closes
  the predicate that every row's expected verdict matches what
  `Unicode.Security.Form.NormalizationBomb.detect` produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Form.NormalizationBomb

namespace Unicode.Conformance.Security.NormalizationBombTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Form.NormalizationBomb

/-- Hand-curated v1 fixture for F1 — 8 rows across 2 sections.
    Clear: ASCII, Han, single Korean syllable 한, two Korean
    syllables 한글 (at the 300% NFD threshold), circled digit ①,
    ASCII digits.  SingleCpBlowup: U+FDFA (18-cp NFKD) and
    U+FDFB (8-cp NFKD), both Arabic compatibility ligatures. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/NormalizationBombTest.txt"

def rows : Array Row := parseFixture rawFixture

/-- Project an `F1Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : F1Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project an `F1Classification` to the positions array. -/
def projectPositions (c : F1Classification) : Array Nat :=
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
theorem row_count : rows.size = 8 := by native_decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).size ≥ 5 := by native_decide

theorem covers_single_cp_blowup :
    (rows.filter (·.sectionName = "SingleCpBlowup")).size ≥ 2 := by
  native_decide

end Unicode.Conformance.Security.NormalizationBombTest
