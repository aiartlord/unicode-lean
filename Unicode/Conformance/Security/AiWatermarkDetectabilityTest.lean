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

/-- Hand-curated fixture — 27 rows exercising every probe in
    `AiWatermarkDetectability.detect`.  Section structure:

    * Clear (6) — empty, ASCII, CJK, lone emoji, legitimate
      emoji-ZWJ sequence, emoji + VS16 presentation selector.
    * NnbspBoundary (2) — single NNBSP, multi-NNBSP aggregate.
    * VariationSelectorCarrier (3) — VS1 / VS16 / IVS1 in
      plain (non-emoji-adjacent) context.
    * ZwjNonEmoji (1) — single ZWJ between ASCII letters.
    * DefaultIgnorableCarrier (3) — SOFT HYPHEN, ZWSP,
      COMBINING GRAPHEME JOINER.
    * Adversarial (2) — NNBSP at arithmetic positions, with
      a strict priority-pin row.
    * Gpt5ZwspModulo (2) — ZWSP at arithmetic positions, with
      a strict priority-pin row.
    * SmartQuoteAlternation (2) — curly double-quote pair and
      curly single-quote pair.
    * EmDashPattern (1) — two em-dashes with no hyphen-minus.
    * StatisticalTokenChoice (2) — vocabulary hit "delve"
      alone and "moreover" embedded.
    * Unknown (3) — multi-category mixing (NNBSP + DI, VS +
      ZWJ, NNBSP + VS + DI). -/
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

/-- Every constructor of `SubThreat` has at least one fixture
    row.  Catches the "structurally reachable but no fixture
    exercising it" failure mode where a sub-threat name exists
    in the type system but no input drives the detector to emit
    it.  Each entry is the string returned by
    `Classification.tag` for the corresponding constructor. -/
theorem every_subthreat_has_fixture_row :
    let expectedSubThreats : Array String :=
      #[ "NnbspBoundary"
       , "VariationSelectorCarrier"
       , "ZwjNonEmoji"
       , "DefaultIgnorableCarrier"
       , "Gpt5ZwspModulo"
       , "EmDashPattern"
       , "SmartQuoteAlternation"
       , "StatisticalTokenChoice"
       , "Adversarial"
       , "Unknown" ]
    expectedSubThreats.all (fun name =>
      rows.any (fun r => r.expectedSubThreat = some name)) = true := by
  native_decide

end Unicode.Conformance.Security.AiWatermarkDetectabilityTest
