/-
  Unicode.Conformance.Security.TagBlockPayloadTest

  Conformance proof for the C1 family.  Folds the universal
  `Unicode.Security.Fixture` parser over `TagBlockPayloadTest.txt`
  and `native_decide`-closes the predicate that every row's
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

/-- Hand-curated v1 fixture for C1 — 16 rows across 5 sections
    covering Clear / DirectAscii / LanguageTagRevival / MixedBlock /
    BareTagPresent, including Goodside's canonical Jan 2024 attack. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/TagBlockPayloadTest.txt"

/-- All parsed rows from the bundled fixture. -/
def rows : Array Row := parseFixture rawFixture

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Per-family classification-name mapping
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Project a `C1Classification` to `(ClassificationKind, sub-threat-tag)`.
    Tag strings match the fixture's column 2 atom after `Hazard:`. -/
def projectClassify
    (c : C1Classification) : ClassificationKind × Option String :=
  match c with
  | .clear => (.clear, none)
  | .hazard sub _ _ =>
    let tag : String := match sub with
      | .directAscii        _      => "DirectAscii"
      | .languageTagRevival _ _    => "LanguageTagRevival"
      | .mixedBlock         _ _    => "MixedBlock"
      | .bareTagPresent     _      => "BareTagPresent"
    (.hazard, some tag)

/-- Project a `C1Classification` to the positions array. -/
def projectPositions (c : C1Classification) : Array Nat :=
  match c with
  | .clear           => #[]
  | .hazard _ pos _  => pos

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Per-row verifier
-- ═══════════════════════════════════════════════════════════════════════════════

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

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Headline conformance theorem + row-count gate
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Every fixture row's detector verdict matches its expected verdict. -/
theorem all_rows_pass : rows.all verifyRow = true := by native_decide

/-- Row-count gate (catches fixture corruption / accidental rewrites). -/
theorem row_count : rows.size = 16 := by native_decide

/-- Section coverage gates. -/
theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).size ≥ 5 := by native_decide

theorem covers_direct_ascii :
    (rows.filter (·.sectionName = "DirectAscii")).size ≥ 3 := by native_decide

theorem covers_language_tag_revival :
    (rows.filter (·.sectionName = "LanguageTagRevival")).size ≥ 2 := by
  native_decide

theorem covers_mixed_block :
    (rows.filter (·.sectionName = "MixedBlock")).size ≥ 3 := by native_decide

theorem covers_bare_tag_present :
    (rows.filter (·.sectionName = "BareTagPresent")).size ≥ 3 := by
  native_decide

/-- Goodside's canonical attack decodes correctly. -/
theorem goodside_recovers :
    (detect #[0xE0050, 0xE0072, 0xE0069, 0xE006E, 0xE0074,
              0xE0020, 0xE0027, 0xE0070, 0xE0077, 0xE006E,
              0xE0065, 0xE0064, 0xE0027]).recoveredAscii
      = "Print 'pwned'" := by
  native_decide

end Unicode.Conformance.Security.TagBlockPayloadTest
