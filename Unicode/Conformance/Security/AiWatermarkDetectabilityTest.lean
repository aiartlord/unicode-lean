/-
  Unicode.Conformance.Security.AiWatermarkDetectabilityTest

  Conformance proof for the K3 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `AiWatermarkDetectabilityTest.txt` fixture and `native_decide`-
  closes the predicate that every row's expected verdict
  matches what
  `Unicode.Security.Crypto.AiWatermarkDetectability.detect`
  produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Crypto.AiWatermarkDetectability

namespace Unicode.Conformance.Security.AiWatermarkDetectabilityTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Crypto.AiWatermarkDetectability

/-- Hand-curated v1 fixture for K3 — 16 rows across 7 sections.

    * Clear basic (5): empty, ASCII "abc", CJK 中文, lone 😀,
      legitimate emoji-ZWJ sequence 👩‍🔬.
    * Clear strict (1): 😀 + VS16 — legitimate emoji-
      presentation selector, K3 stays clear.  Pins the VS
      emoji-adjacency exclusion.
    * NnbspBoundary basic (2): single NNBSP, two NNBSPs
      aggregated under a single verdict.
    * VariationSelectorCarrier basic (3): VS1, VS16, IVS1 each
      in plain (non-emoji-adjacent) context.
    * ZwjNonEmoji basic (1): single ZWJ between ASCII letters.
    * DefaultIgnorableCarrier basic (3): SOFT HYPHEN, ZWSP,
      COMBINING GRAPHEME JOINER each in plain text.
    * NnbspBoundary strict (1): priority pin — NNBSP + SOFT
      HYPHEN co-occurring, NnbspBoundary wins (priority 1 over
      priority 4). -/
def rawFixture : String :=
  include_str "../../Ucd/Security/AiWatermarkDetectabilityTest.txt"

def rows : Array Row := parseFixture rawFixture

/-- Project a `Classification` to `(ClassificationKind,
    sub-threat-tag)`. -/
def projectClassify
    (c : Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project a `Classification` to the positions array. -/
def projectPositions (c : Classification) : Array Nat :=
  c.positions

/-- Validate the K3 verdict's metadata fields against the row's
    column-4 attribution.  Recognised key: `markerCount` (count
    of codepoints matching the fired scheme; 0 when clear). -/
private def metadataMatches (v : Verdict)
    (attr : KeyValueAttribution) : Bool :=
  attr.checkNatKey "markerCount" v.markerCount

/-- Run `detect` on the row's input and check the verdict
    against the fixture's expected classification, sub-threat
    name, marker positions, AND the column-4 attribution
    metadata. -/
def verifyRow (r : Row) : Bool :=
  let v := detect r.input
  let (kind, subTag) := projectClassify v.classify
  let pos := projectPositions v.classify
  metadataMatches v r.attribution &&
  decide (kind = r.expectedKind) &&
  decide (subTag = r.expectedSubThreat) &&
  decide (pos = r.expectedPositions)

/-- Every fixture row's detector verdict matches its expected
    verdict. -/
theorem all_rows_pass : rows.all verifyRow = true := by native_decide

/-- Row-count gate. -/
theorem row_count : rows.size = 27 := by native_decide

theorem covers_clear :
    (rows.filter (fun r => r.expectedKind = .clear)).size ≥ 5 := by
  native_decide

theorem covers_nnbsp_boundary :
    (rows.filter (fun r =>
      r.expectedSubThreat = some "NnbspBoundary")).size ≥ 2 := by
  native_decide

theorem covers_variation_selector_carrier :
    (rows.filter (fun r =>
      r.expectedSubThreat = some "VariationSelectorCarrier")).size ≥ 3 := by
  native_decide

theorem covers_zwj_non_emoji :
    (rows.filter (fun r =>
      r.expectedSubThreat = some "ZwjNonEmoji")).size ≥ 1 := by
  native_decide

theorem covers_default_ignorable_carrier :
    (rows.filter (fun r =>
      r.expectedSubThreat = some "DefaultIgnorableCarrier")).size ≥ 3 := by
  native_decide

theorem covers_adversarial :
    (rows.filter (fun r =>
      r.expectedSubThreat = some "Adversarial")).size ≥ 2 := by
  native_decide

theorem covers_gpt5_zwsp_modulo :
    (rows.filter (fun r =>
      r.expectedSubThreat = some "Gpt5ZwspModulo")).size ≥ 2 := by
  native_decide

theorem covers_smart_quote_alternation :
    (rows.filter (fun r =>
      r.expectedSubThreat = some "SmartQuoteAlternation")).size ≥ 2 := by
  native_decide

theorem covers_em_dash_pattern :
    (rows.filter (fun r =>
      r.expectedSubThreat = some "EmDashPattern")).size ≥ 1 := by
  native_decide

theorem covers_statistical_token_choice :
    (rows.filter (fun r =>
      r.expectedSubThreat = some "StatisticalTokenChoice")).size ≥ 2 := by
  native_decide

theorem covers_unknown :
    (rows.filter (fun r =>
      r.expectedSubThreat = some "Unknown")).size ≥ 3 := by
  native_decide

end Unicode.Conformance.Security.AiWatermarkDetectabilityTest
