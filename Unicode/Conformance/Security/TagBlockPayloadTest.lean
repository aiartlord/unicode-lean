/-
  Unicode.Conformance.Security.TagBlockPayloadTest

  Conformance proof for the C1 family.  Folds the universal
  `Unicode.Security.Fixture` parser over `TagBlockPayloadTest.txt`
  and `decide`-closes the predicate that every row's
  expected verdict matches what
  `Unicode.Security.Covert.TagBlockPayload.detect` produces.

  Shape mirrors `VariationSelectorPayloadTest.lean`; both use the
  shared universal fixture parser + a family-specific
  `projectClassify` adapter to project the family's verdict onto
  the universal `ClassificationKind` vocabulary.
-/

import Unicode.Security.Fixture
import Unicode.Security.Covert.TagBlockPayload

namespace Unicode.Conformance.Security.TagBlockPayloadTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Covert.TagBlockPayload

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Raw fixture + parsed rows
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Hand-curated fixture — 16 rows across 5 sections
    covering Clear / DirectAscii / LanguageTagRevival / MixedBlock /
    BareTagPresent, including Goodside's canonical Jan 2024 attack. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/TagBlockPayloadTest.txt"

/-- All parsed rows from the bundled fixture. -/
def rows : List Row := parseFixture rawFixture

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Per-family classification-name mapping
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Project a `Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project a `Classification` to the positions array. -/
def projectPositions (c : Classification) : List Nat :=
  c.positions

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Per-row verifier
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Validate the C1 verdict's metadata fields against the row's
    column-4 attribution.  Keys recognised: `tag_count` (vs
    `v.totalTagChars`) and `total_cps` (vs `v.input.length`). -/
def metadataMatches (v : Verdict)
    (attr : KeyValueAttribution) : Bool :=
  attr.checkNatKey "tag_count" v.totalTagChars &&
  attr.checkNatKey "total_cps" v.input.length

/-- Run `detect` on the row's input and check the verdict against
    the fixture's expected classification, sub-threat name,
    hazard positions, AND the column-4 attribution metadata. -/
def verifyRow (r : Row) : Bool :=
  let v := detect r.input
  let (kind, subTag) := projectClassify v.classify
  let pos := projectPositions v.classify
  decide (kind = r.expectedKind) &&
  decide (subTag = r.expectedSubThreat) &&
  decide (pos = r.expectedPositions) &&
  metadataMatches v r.attribution

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Headline conformance theorem + row-count gate
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Every fixture row's detector verdict matches its expected verdict. -/
theorem all_rows_pass : rows.all verifyRow = true := by decide

/-- Row-count gate (catches fixture corruption / accidental rewrites). -/
theorem row_count : rows.length = 24 := by decide

/-- Section coverage gates. -/
theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).length ≥ 8 := by decide

theorem covers_direct_ascii :
    (rows.filter (·.sectionName = "DirectAscii")).length ≥ 6 := by decide

theorem covers_language_tag_revival :
    (rows.filter (·.sectionName = "LanguageTagRevival")).length ≥ 2 := by
  decide

theorem covers_mixed_block :
    (rows.filter (·.sectionName = "MixedBlock")).length ≥ 5 := by decide

theorem covers_bare_tag_present :
    (rows.filter (·.sectionName = "BareTagPresent")).length ≥ 3 := by
  decide

/-- Goodside's canonical attack decodes correctly. -/
theorem goodside_recovers :
    (detect [0xE0050, 0xE0072, 0xE0069, 0xE006E, 0xE0074,
              0xE0020, 0xE0027, 0xE0070, 0xE0077, 0xE006E,
              0xE0065, 0xE0064, 0xE0027]).recoveredAscii
      = "Print 'pwned'" := by
  decide

end Unicode.Conformance.Security.TagBlockPayloadTest
