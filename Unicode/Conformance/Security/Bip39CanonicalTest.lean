/-
  Unicode.Conformance.Security.Bip39CanonicalTest

  Conformance proof for the K1 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `Bip39CanonicalTest.txt` fixture and `native_decide`-closes
  the predicate that every row's expected verdict matches what
  `Unicode.Security.Crypto.Bip39Canonical.detect` produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Crypto.Bip39Canonical

namespace Unicode.Conformance.Security.Bip39CanonicalTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Crypto.Bip39Canonical
open Unicode.Generated.BIP39 (Language)

/-- Hand-curated v1 fixture for K1 — 20 rows across 9 sections.

    * Clear basic (6): English 12-word test vector, Spanish,
      Italian, French, Czech, Portuguese 3-word mnemonics.
    * Clear strict (1): Japanese 3-word with U+0020 separators.
    * NonNFKD basic (3): NFC Spanish "ábaco", U+FB01 ligature,
      U+00A0 NBSP between letters.
    * NonNFKD strict (1): Japanese U+3000 separator.
    * TrailingWhitespace basic (2): trailing U+0020, trailing
      U+3000.
    * WhitespaceAnomaly basic (2): double internal space,
      leading single space.
    * MixedCase basic (2): "Abandon", "ABANDON".
    * WordlistMismatch basic (2): "qzqz", "abandon qzqz".
    * LanguageAmbiguous strict (1): Spanish-"ábaco" + Italian-
      "abaco" collision. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/Bip39CanonicalTest.txt"

def rows : Array Row := parseFixture rawFixture

/-- Map a `Language` to its canonical lowercase tag, used to
    match against the row's `language=<tag>` attribution. -/
def langToString : Language → String
  | .english             => "english"
  | .japanese            => "japanese"
  | .korean              => "korean"
  | .spanish             => "spanish"
  | .chineseSimplified   => "chinese_simplified"
  | .chineseTraditional  => "chinese_traditional"
  | .french              => "french"
  | .italian             => "italian"
  | .czech               => "czech"
  | .portuguese          => "portuguese"

/-- Project a `K1Classification` to `(ClassificationKind,
    sub-threat-tag)`. -/
def projectClassify
    (c : K1Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project a `K1Classification` to the positions array. -/
def projectPositions (c : K1Classification) : Array Nat :=
  c.positions

/-- Validate the K1 verdict's metadata fields against the row's
    column-4 attribution.  Recognised keys: `wordCount` (always
    present), `language` (present only for clear verdicts; on
    hazard verdicts the attribution must not assert a language). -/
private def metadataMatches (v : K1Verdict)
    (attr : KeyValueAttribution) : Bool :=
  let languageStr :=
    match v.classify with
    | .clear lang        => langToString lang
    | .hazard _sub _ps   => ""
  attr.checkNatKey    "wordCount" v.wordCount &&
  attr.checkStringKey "language"  languageStr

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

/-- Every fixture row's detector verdict matches its expected
    verdict. -/
theorem all_rows_pass : rows.all verifyRow = true := by native_decide

/-- Row-count gate. -/
theorem row_count : rows.size = 20 := by native_decide

theorem covers_clear :
    (rows.filter (fun r => r.expectedKind = .clear)).size ≥ 7 := by
  native_decide

theorem covers_non_nfkd :
    (rows.filter (fun r =>
      r.expectedSubThreat = some "NonNFKD")).size ≥ 4 := by
  native_decide

theorem covers_trailing_whitespace :
    (rows.filter (fun r =>
      r.expectedSubThreat = some "TrailingWhitespace")).size ≥ 2 := by
  native_decide

theorem covers_whitespace_anomaly :
    (rows.filter (fun r =>
      r.expectedSubThreat = some "WhitespaceAnomaly")).size ≥ 2 := by
  native_decide

theorem covers_mixed_case :
    (rows.filter (fun r =>
      r.expectedSubThreat = some "MixedCase")).size ≥ 2 := by
  native_decide

theorem covers_wordlist_mismatch :
    (rows.filter (fun r =>
      r.expectedSubThreat = some "WordlistMismatch")).size ≥ 2 := by
  native_decide

theorem covers_language_ambiguous :
    (rows.filter (fun r =>
      r.expectedSubThreat = some "LanguageAmbiguous")).size ≥ 1 := by
  native_decide

end Unicode.Conformance.Security.Bip39CanonicalTest
