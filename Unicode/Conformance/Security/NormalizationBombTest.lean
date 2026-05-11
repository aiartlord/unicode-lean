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

/-- Hand-curated v1 fixture for F1 — 11 rows across 4 sections.
    Every sub-threat is reachable by at least one row.

    * Clear (6): ASCII, Han, 한, 한글 (at 300% NFD threshold),
      ① circled-one, ASCII digits.
    * SingleCpBlowup (1): U+FDFA — Arabic ligature SALLALLAHOU
      ALAYHE WASALLAM (1 cp → 18 cps NFKD).
    * NfkdHighExpansion (2): U+FDFB (1 cp → 8 cps NFKD ratio
      800%) and doubled FDFB.
    * NfdHighExpansion (2): Greek extended U+1F82 (NFD=4
      ratio 400%) and a Greek pair 1F82+1F83. -/
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
theorem row_count : rows.size = 11 := by native_decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).size ≥ 5 := by native_decide

theorem covers_single_cp_blowup :
    (rows.filter (·.sectionName = "SingleCpBlowup")).size ≥ 1 := by
  native_decide

theorem covers_nfkd_high :
    (rows.filter (·.sectionName = "NfkdHighExpansion")).size ≥ 2 := by
  native_decide

theorem covers_nfd_high :
    (rows.filter (·.sectionName = "NfdHighExpansion")).size ≥ 2 := by
  native_decide

end Unicode.Conformance.Security.NormalizationBombTest
