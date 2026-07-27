/-
  Unicode.Conformance.Security.IdentifierFormDriftTest

  Conformance proof for the X1 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `IdentifierFormDriftTest.txt` fixture and `decide`-closes
  the predicate that every row's expected verdict matches what
  `Unicode.Security.Boundary.IdentifierFormDrift.detect` produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Boundary.IdentifierFormDrift

namespace Unicode.Conformance.Security.IdentifierFormDriftTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Boundary.IdentifierFormDrift

/-- Hand-curated fixture — 13 rows across 2 sections.

    * Clear (5): ASCII Hello, plain ASCII admin, Han 中文, Greek
      αβγ, Cyrillic привет.  Each row's per-cp Identifier_Status
      equals the NFKD-head Identifier_Status via identity NFKD.
      Hangul is intentionally *not* in Clear — precomposed
      syllables are Allowed but their jamo NFKD heads are
      Restricted, so pure Hangul is itself an X1 case.
    * IdentifierStatusShift (8): Math Italic 𝑎, Math Italic
      𝑎𝑑𝑚𝑖𝑛 (shift at position 0), Fullwidth Ａ, Circled Ⓐ,
      ﬁ ligature (F5 misses, EAW = N), Roman numeral Ⅳ, ASCII
      prefix abc𝑎 (shift at position 3), precomposed Hangul 한
      (Allowed → jamo Restricted). -/
def rawFixture : String :=
  include_str "../../Ucd/Security/IdentifierFormDriftTest.txt"

def rows : List Row := parseFixture rawFixture

/-- Project an `Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project an `Classification` to the positions array. -/
def projectPositions (c : Classification) : List Nat :=
  c.positions

/-- Validate the X1 verdict's metadata fields against the row's
    column-4 attribution.  Recognised key: `shift_count` (the
    number of codepoints whose UTS #39 Identifier_Status / Type
    classification shifts between the raw input and its NFKC
    normalization). -/
def metadataMatches (v : Verdict)
    (attr : KeyValueAttribution) : Bool :=
  attr.checkNatKey "shift_count" v.shiftCount

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
theorem row_count : rows.length = 25 := by decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).length ≥ 7 := by decide

theorem covers_shift :
    (rows.filter (·.sectionName = "IdentifierStatusShift")).length ≥ 15 := by
  decide

end Unicode.Conformance.Security.IdentifierFormDriftTest
