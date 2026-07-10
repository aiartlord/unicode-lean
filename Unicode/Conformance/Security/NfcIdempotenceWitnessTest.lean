/-
  Unicode.Conformance.Security.NfcIdempotenceWitnessTest

  Conformance proof for the F6 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `NfcIdempotenceWitnessTest.txt` fixture and `decide`-closes
  the predicate that every row's expected verdict matches what
  `Unicode.Security.Form.NfcIdempotenceWitness.detect` produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Form.NfcIdempotenceWitness

namespace Unicode.Conformance.Security.NfcIdempotenceWitnessTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Form.NfcIdempotenceWitness

/-- Hand-curated fixture — 12 rows across 3 sections.

    * Clear (5): ASCII Hello, precomposed é, Han 中文, Hangul 한,
      Cyrillic привет.
    * NonNfcForm (4): decomposed é, decomposed á+è, decomposed ö,
      decomposed Hangul jamos (composed by toNFC to 한).
    * NonNfkcCompatForm (3): ﬁ ligature (EAW = N, F5 misses),
      ﬃ ligature, Roman numeral Ⅳ. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/NfcIdempotenceWitnessTest.txt"

def rows : Array Row := parseFixture rawFixture

/-- Project an `Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project an `Classification` to the positions array. -/
def projectPositions (c : Classification) : Array Nat :=
  c.positions

/-- Validate the F6 verdict's metadata fields against the row's
    column-4 attribution.  Recognised keys: `nfc_len`, `nfkc_len`
    (the NFC and NFKC normal-form lengths produced by the
    underlying normalizer). -/
def metadataMatches (v : Verdict)
    (attr : KeyValueAttribution) : Bool :=
  attr.checkNatKey "nfc_len"  v.nfcLen &&
  attr.checkNatKey "nfkc_len" v.nfkcLen

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
theorem row_count : rows.size = 26 := by decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).size ≥ 8 := by decide

theorem covers_non_nfc :
    (rows.filter (·.sectionName = "NonNfcForm")).size ≥ 9 := by
  decide

theorem covers_non_nfkc :
    (rows.filter (·.sectionName = "NonNfkcCompatForm")).size ≥ 9 := by
  decide

end Unicode.Conformance.Security.NfcIdempotenceWitnessTest
