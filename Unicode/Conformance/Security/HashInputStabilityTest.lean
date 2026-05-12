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

/-- Hand-curated v1 fixture for K2 — 15 rows across 4 sections.

    * Clear basic (5): empty, ASCII "abc", precomposed é, 中文,
      ASCII + precomposed é mixed.
    * Clear strict (2): internal-only space (only trailing is
      framing), trailing U+3000 (Unicode whitespace is content).
    * TrailingWhitespace basic (4): trailing SPACE / TAB / LF /
      CRLF.
    * NormalizationDrift basic (4): decomposed é, decomposed á,
      Hangul jamos compose to 한, mid-string decomposition in
      "Hello é world".
    * TrailingWhitespace strict (1): combined NFC drift +
      trailing space (priority pin — trailing wins). -/
def rawFixture : String :=
  include_str "../../Ucd/Security/HashInputStabilityTest.txt"

def rows : Array Row := parseFixture rawFixture

/-- Project a `K2Classification` to `(ClassificationKind,
    sub-threat-tag)`. -/
def projectClassify
    (c : K2Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project a `K2Classification` to the positions array. -/
def projectPositions (c : K2Classification) : Array Nat :=
  c.positions

/-- Validate the K2 verdict's metadata fields against the row's
    column-4 attribution.  Recognised key: `stableSize` (the
    codepoint count of the canonical NFC + trim form). -/
private def metadataMatches (v : K2Verdict)
    (attr : KeyValueAttribution) : Bool :=
  attr.checkNatKey "stableSize" v.stableSize

/-- Run `detect` on the row's input and check the verdict
    against the fixture's expected classification, sub-threat
    name, hazard positions, AND the column-4 attribution
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
theorem row_count : rows.size = 16 := by native_decide

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

end Unicode.Conformance.Security.HashInputStabilityTest
