/-
  Unicode.Conformance.Security.NormalizationBombTest

  Conformance proof for the F1 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `NormalizationBombTest.txt` fixture and `decide`-closes
  the predicate that every row's expected verdict matches what
  `Unicode.Security.Form.NormalizationBomb.detect` produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Form.NormalizationBomb

namespace Unicode.Conformance.Security.NormalizationBombTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Form.NormalizationBomb

/-- Hand-curated fixture — 11 rows across 4 sections.
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

def rows : List Row := parseFixture rawFixture

/-- Project an `Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project an `Classification` to the positions array. -/
def projectPositions (c : Classification) : List Nat :=
  c.positions

/-- Validate the F1 verdict's metadata fields against the row's
    column-4 attribution.  Recognised keys: `nfd_len`, `nfkd_len`,
    `input_len`, `max_per_cp` (the worst single-codepoint NFKD
    expansion). -/
def metadataMatches (v : Verdict)
    (attr : KeyValueAttribution) : Bool :=
  attr.checkNatKey "nfd_len"    v.nfdLen &&
  attr.checkNatKey "nfkd_len"   v.nfkdLen &&
  attr.checkNatKey "input_len"  v.inputLen &&
  attr.checkNatKey "max_per_cp" v.maxPerCpExpansion

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
theorem row_count : rows.length = 26 := by decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).length ≥ 10 := by decide

theorem covers_single_cp_blowup :
    (rows.filter (·.sectionName = "SingleCpBlowup")).length ≥ 3 := by
  decide

theorem covers_nfkd_high :
    (rows.filter (·.sectionName = "NfkdHighExpansion")).length ≥ 3 := by
  decide

theorem covers_nfd_high :
    (rows.filter (·.sectionName = "NfdHighExpansion")).length ≥ 9 := by
  decide

end Unicode.Conformance.Security.NormalizationBombTest
