/-
  Unicode.Conformance.Security.VariationSelectorPayloadTest

  Conformance proof for the C2 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `VariationSelectorPayloadTest.txt` fixture and `native_decide`-closes
  the predicate that every row's expected verdict matches what
  `Unicode.Security.Covert.VariationSelectorPayload.detect` produces.

  This is the template-by-example for per-family conformance harnesses.
  Every other family harness (C / I / D / F / X / K) will follow
  the same shape:

    1. Embed the fixture via `include_str`
    2. Parse rows via `Unicode.Security.Fixture.parseFixture`
    3. Define `verifyRow : Row → Bool` that runs the family `detect`
       and compares against the fixture row's expected classification
    4. Close a single headline theorem `all_rows_pass` via `native_decide`
    5. Close a row-count gate via `native_decide`
-/

import Unicode.Security.Fixture
import Unicode.Security.Covert.VariationSelectorPayload

namespace Unicode.Conformance.Security.VariationSelectorPayloadTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Covert.VariationSelectorPayload

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Raw fixture + parsed rows
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Hand-curated v1 fixture — 18 rows across 5 sections covering
    every C2 sub-threat and the registered-clear cases.

    A future revision will expand this to ~6,000 rows by walking
    every entry of `StandardizedVariants.txt` and
    `emoji-variation-sequences.txt` for the registered-clear
    section, plus per-byte-length sweeps of synthesized payloads. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/VariationSelectorPayloadTest.txt"

/-- All parsed rows from the bundled fixture. -/
def rows : Array Row := parseFixture rawFixture

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Per-family classification-name mapping
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Project a `C2Classification` to its `ClassificationKind` and
    sub-threat name.  Delegates to `C2Classification.tag` /
    `C2Classification.isClear`. -/
def projectClassify
    (c : C2Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project a `C2Classification` to its positions array. -/
def projectPositions (c : C2Classification) : Array Nat :=
  c.positions

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Per-row verifier
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Validate the C2 verdict's metadata fields against the row's
    column-4 attribution.  Keys recognised: `registered_vs` and
    `suspicious_vs` against the corresponding `positions.size`. -/
private def metadataMatches (v : C2Verdict)
    (attr : KeyValueAttribution) : Bool :=
  attr.checkNatKey "registered_vs" v.registeredPositions.size &&
  attr.checkNatKey "suspicious_vs" v.suspiciousPositions.size

/-- Run `detect` on the row's input and check the verdict against
    the fixture's expected classification, sub-threat name,
    hazard positions, AND the column-4 attribution metadata. -/
def verifyRow (r : Row) : Bool :=
  let v := detect r.input
  let (kind, subTag) := projectClassify v.classify
  let pos := projectPositions v.classify
  metadataMatches v r.attribution &&
  decide (kind = r.expectedKind) &&
  decide (subTag = r.expectedSubThreat) &&
  decide (pos = r.expectedPositions)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Headline conformance theorem + row-count gate
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Every fixture row's detector verdict matches its expected verdict. -/
theorem all_rows_pass : rows.all verifyRow = true := by native_decide

/-- Row-count gate (catches fixture corruption / accidental rewrites). -/
theorem row_count : rows.size = 17 := by native_decide

/-- Section coverage gate — every named section is represented. -/
theorem covers_registered_clear :
    (rows.filter (·.sectionName = "RegisteredClear")).size ≥ 5 := by
  native_decide

theorem covers_direct_payload :
    (rows.filter (·.sectionName = "DirectPayload")).size ≥ 2 := by
  native_decide

theorem covers_illegal_target :
    (rows.filter (·.sectionName = "IllegalTarget")).size ≥ 3 := by
  native_decide

theorem covers_repeated_base :
    (rows.filter (·.sectionName = "RepeatedBase")).size ≥ 2 := by
  native_decide

theorem covers_embedded_after_reg :
    (rows.filter (·.sectionName = "EmbeddedAfterRegistered")).size ≥ 2 := by
  native_decide

theorem covers_leading_vs :
    (rows.filter (·.sectionName = "LeadingVS")).size ≥ 1 := by
  native_decide

end Unicode.Conformance.Security.VariationSelectorPayloadTest
