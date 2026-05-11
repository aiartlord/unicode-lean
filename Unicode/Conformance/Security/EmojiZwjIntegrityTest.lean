/-
  Unicode.Conformance.Security.EmojiZwjIntegrityTest

  Conformance proof for the I3 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `EmojiZwjIntegrityTest.txt` fixture and `native_decide`-closes
  the predicate that every row's expected verdict matches what
  `Unicode.Security.Identity.EmojiZwjIntegrity.detect` produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Identity.EmojiZwjIntegrity

namespace Unicode.Conformance.Security.EmojiZwjIntegrityTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Identity.EmojiZwjIntegrity

/-- Hand-curated v1 fixture for I3 — 14 rows across 5 sections
    covering: pure-emoji clear cases (Hello, single 😀, single
    skin-tone, registered family ZWJ, registered couple ZWJ),
    Double-ZWJ adjacency, ZWJ adjacent to non-emoji (Latin, digit,
    Han), 17-codepoint over-length chain, and 5/6 skin-tone
    overflow patterns. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/EmojiZwjIntegrityTest.txt"

def rows : Array Row := parseFixture rawFixture

/-- Project an `I3Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : I3Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project an `I3Classification` to the positions array. -/
def projectPositions (c : I3Classification) : Array Nat :=
  c.positions

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

/-- Every fixture row's detector verdict matches its expected verdict. -/
theorem all_rows_pass : rows.all verifyRow = true := by native_decide

/-- Row-count gate. -/
theorem row_count : rows.size = 14 := by native_decide

theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).size ≥ 5 := by native_decide

theorem covers_double_zwj :
    (rows.filter (·.sectionName = "DoubleZWJ")).size ≥ 2 := by native_decide

theorem covers_non_emoji_injection :
    (rows.filter (·.sectionName = "NonEmojiInjection")).size ≥ 3 := by
  native_decide

theorem covers_over_length :
    (rows.filter (·.sectionName = "OverLength")).size ≥ 1 := by native_decide

theorem covers_skin_tone_overflow :
    (rows.filter (·.sectionName = "SkinToneOverflow")).size ≥ 2 := by
  native_decide

end Unicode.Conformance.Security.EmojiZwjIntegrityTest
