/-
  Unicode.Conformance.Security.EmojiZwjIntegrityTest

  Conformance proof for the I3 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `EmojiZwjIntegrityTest.txt` fixture and `decide`-closes
  the predicate that every row's expected verdict matches what
  `Unicode.Security.Identity.EmojiZwjIntegrity.detect` produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Identity.EmojiZwjIntegrity

namespace Unicode.Conformance.Security.EmojiZwjIntegrityTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Identity.EmojiZwjIntegrity

/-- Hand-curated fixture — 14 rows across 5 sections
    covering: pure-emoji clear cases (Hello, single 😀, single
    skin-tone, registered family ZWJ, registered couple ZWJ),
    Double-ZWJ adjacency, ZWJ adjacent to non-emoji (Latin, digit,
    Han), 17-codepoint over-length chain, and 5/6 skin-tone
    overflow patterns. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/EmojiZwjIntegrityTest.txt"

def rows : List Row := parseFixture rawFixture

/-- Project an `Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project an `Classification` to the positions array. -/
def projectPositions (c : Classification) : List Nat :=
  c.positions

/-- Validate the EmojiZwjIntegrity verdict's metadata fields
    against the row's column-4 attribution.  Recognised keys:
    `chain_len` (the ZWJ chain length), `zwj_count` (the size of
    `zwjPositions`), `skin_tone_count`, and `is_rgi` (registered
    RGI flag). -/
def metadataMatches (v : Verdict)
    (attr : KeyValueAttribution) : Bool :=
  attr.checkNatKey   "chain_len"       v.chainLength &&
  attr.checkNatKey   "zwj_count"       v.zwjPositions.length &&
  attr.checkNatKey   "skin_tone_count" v.skinToneCount &&
  attr.checkBoolKey  "is_rgi"          v.isRegisteredRGI

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
theorem row_count : rows.length = 22 := by decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).length ≥ 8 := by decide

theorem covers_double_zwj :
    (rows.filter (·.sectionName = "DoubleZWJ")).length ≥ 3 := by decide

theorem covers_non_emoji_injection :
    (rows.filter (·.sectionName = "NonEmojiInjection")).length ≥ 5 := by
  decide

theorem covers_over_length :
    (rows.filter (·.sectionName = "OverLength")).length ≥ 2 := by decide

theorem covers_skin_tone_overflow :
    (rows.filter (·.sectionName = "SkinToneOverflow")).length ≥ 3 := by
  decide

end Unicode.Conformance.Security.EmojiZwjIntegrityTest
