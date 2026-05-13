/-
  Unicode.Conformance.Security.HashInputStabilityTest

  Conformance proof for the K2 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `HashInputStabilityTest.txt` fixture and `native_decide`-
  closes the predicate that every row's expected verdict
  matches what
  `Unicode.Security.Crypto.HashInputStability.detect` produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Crypto.HashInputStability

namespace Unicode.Conformance.Security.HashInputStabilityTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Crypto.HashInputStability

/-- Hand-curated fixture for K2 across all six sub-threats.

    Sections (current row counts):

    * Clear basic / strict: empty, ASCII, precomposed é, CJK,
      mixed, internal space, trailing U+3000.
    * TrailingWhitespace basic / strict: trailing SPACE / TAB
      / LF / CRLF, priority pin with NFC drift.
    * NormalizationDrift basic: decomposed é, decomposed á,
      Hangul jamos, mid-string decomposition.
    * EncodingMismatch basic: ASCII labeled non-utf-8.
    * SignedMessageRule basic: PGP 4880 trailing-whitespace,
      PGP 9580 bare-LF, RFC 8785 decomposed-é, RFC 8259
      unescaped control char.
    * AuditLogReinterpretation basic: written vs read diverge.
    * WebhookSignatureDrift basic: client vs server diverge. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/HashInputStabilityTest.txt"

def rows : Array Row := parseFixture rawFixture

/-- Project a `Classification` to `(ClassificationKind,
    sub-threat-tag)`. -/
def projectClassify
    (c : Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project a `Classification` to the positions array. -/
def projectPositions (c : Classification) : Array Nat :=
  c.positions

/-- Validate the K2 verdict's metadata fields against the row's
    column-4 attribution.  Recognised key: `stableSize` (the
    codepoint count of the canonical NFC + trim form). -/
private def metadataMatches (v : Verdict)
    (attr : KeyValueAttribution) : Bool :=
  attr.checkNatKey "stableSize" v.stableSize

/-- Parse a space-separated hex codepoint list (mirrors
    `Unicode.Security.Fixture.parseCodepointList`). -/
private def parseHexList (s : String) : Array Nat :=
  ((s.splitOn " ").filterMap (fun tok =>
    let t := tok.trimAscii.toString
    if t.isEmpty then none
    else some (t.foldl (fun acc c =>
      let v :=
        if c.isDigit then c.toNat - '0'.toNat
        else if c.toNat ≥ 'a'.toNat ∧ c.toNat ≤ 'f'.toNat then
          c.toNat - 'a'.toNat + 10
        else if c.toNat ≥ 'A'.toNat ∧ c.toNat ≤ 'F'.toNat then
          c.toNat - 'A'.toNat + 10
        else 0
      acc * 16 + v) 0))).toArray

/-- Parse a `Context` from the row's attribution dictionary.
    Recognised keys (all optional):
      * `declaredEnc`  — string label, e.g. "utf-8" / "utf-16"
      * `rfcRule`      — RfcRule identifier per `RfcRule.tag`
      * `asWritten`    — space-separated hex codepoints
      * `serverBytes`  — space-separated hex codepoints

    Missing keys → corresponding field stays `none` (default
    Context behaviour identical to bare `detect`). -/
def parseContext (attr : KeyValueAttribution) : Context :=
  { declaredEncoding := attr.get? "declaredEnc"
    rfcRule          := (attr.get? "rfcRule").bind RfcRule.fromTag
    asWritten        := (attr.get? "asWritten").map parseHexList
    serverBytes      := (attr.get? "serverBytes").map parseHexList }

/-- Run `detectWithContext` on the row's input + parsed
    context and check the verdict against the fixture's
    expected classification, sub-threat name, hazard positions,
    AND the column-4 attribution metadata. -/
def verifyRow (r : Row) : Bool :=
  let ctx := parseContext r.attribution
  let v := detectWithContext ctx r.input
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
theorem row_count : rows.size = 26 := by native_decide

theorem covers_clear :
    (rows.filter (fun r => r.expectedKind = .clear)).size ≥ 7 := by
  native_decide

theorem covers_trailing_whitespace :
    (rows.filter (fun r =>
      r.expectedSubThreat = some "TrailingWhitespace")).size ≥ 5 := by
  native_decide

theorem covers_normalization_drift :
    (rows.filter (fun r =>
      r.expectedSubThreat = some "NormalizationDrift")).size ≥ 4 := by
  native_decide

theorem covers_encoding_mismatch :
    (rows.filter (fun r =>
      r.expectedSubThreat = some "EncodingMismatch")).size ≥ 3 := by
  native_decide

theorem covers_signed_message_rule :
    (rows.filter (fun r =>
      r.expectedSubThreat = some "SignedMessageRule")).size ≥ 4 := by
  native_decide

theorem covers_audit_log_reinterpretation :
    (rows.filter (fun r =>
      r.expectedSubThreat = some "AuditLogReinterpretation")).size ≥ 2 := by
  native_decide

theorem covers_webhook_signature_drift :
    (rows.filter (fun r =>
      r.expectedSubThreat = some "WebhookSignatureDrift")).size ≥ 1 := by
  native_decide

/-- Every constructor of `SubThreat` has at least one fixture
    row.  Catches the "structurally reachable but no fixture
    exercising it" failure mode where a sub-threat name exists
    in the type system but no input drives the detector to emit
    it.  Each entry is the string returned by
    `Classification.tag` for the corresponding constructor. -/
theorem every_subthreat_has_fixture_row :
    let expectedSubThreats : Array String :=
      #[ "NormalizationDrift"
       , "TrailingWhitespace"
       , "EncodingMismatch"
       , "SignedMessageRule"
       , "AuditLogReinterpretation"
       , "WebhookSignatureDrift" ]
    expectedSubThreats.all (fun name =>
      rows.any (fun r => r.expectedSubThreat = some name)) = true := by
  native_decide

end Unicode.Conformance.Security.HashInputStabilityTest
