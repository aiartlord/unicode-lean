/-
  Unicode.Conformance.Security.ZeroWidthPayloadTest

  Conformance proof for the C3 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `ZeroWidthPayloadTest.txt` fixture and `native_decide`-closes
  the predicate that every row's expected verdict matches what
  `Unicode.Security.Covert.ZeroWidthPayload.detect` produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Covert.ZeroWidthPayload

namespace Unicode.Conformance.Security.ZeroWidthPayloadTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Covert.ZeroWidthPayload

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Raw fixture + parsed rows
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Hand-curated v1 fixture for C3 — 18 rows across 5 sections
    covering RGI-legitimate ZWJ emoji sequences (sanctioned
    `.clear`), binary payloads, WORD JOINER injection,
    suspected NNBSP AI-watermark patterns, bare zero-widths
    (BOM, single ZWSP), and annotation-mark misuse. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/ZeroWidthPayloadTest.txt"

/-- All parsed rows from the bundled fixture. -/
def rows : Array Row := parseFixture rawFixture

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Per-family classification-name mapping
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Project a `C3Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : C3Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project a `C3Classification` to the positions array. -/
def projectPositions (c : C3Classification) : Array Nat :=
  c.positions

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Per-row verifier
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Validate the C3 verdict's metadata fields against the row's
    column-4 attribution.  Keys recognised: `zwsp_count`,
    `zwj_count`, `wj_count`, `nnbsp_count`. -/
private def metadataMatches (v : C3Verdict)
    (attr : KeyValueAttribution) : Bool :=
  attr.checkNatKey "zwsp_count"  v.zwspCount &&
  attr.checkNatKey "zwj_count"   v.zwjCount &&
  attr.checkNatKey "wj_count"    v.wordJoinerCount &&
  attr.checkNatKey "nnbsp_count" v.nnbspCount

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
theorem row_count : rows.size = 28 := by native_decide

/-- Section coverage gates. -/
theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).size ≥ 8 := by native_decide

theorem covers_binary_payload :
    (rows.filter (·.sectionName = "BinaryPayload")).size ≥ 5 := by
  native_decide

theorem covers_word_joiner :
    (rows.filter (·.sectionName = "WordJoinerInjection")).size ≥ 4 := by
  native_decide

theorem covers_ai_watermark :
    (rows.filter (·.sectionName = "AIWatermarkNNBSP")).size ≥ 2 := by
  native_decide

theorem covers_bare_zero_width :
    (rows.filter (·.sectionName = "BareZeroWidth")).size ≥ 4 := by
  native_decide

theorem covers_annotation_misuse :
    (rows.filter (·.sectionName = "AnnotationMisuse")).size ≥ 5 := by
  native_decide

end Unicode.Conformance.Security.ZeroWidthPayloadTest
