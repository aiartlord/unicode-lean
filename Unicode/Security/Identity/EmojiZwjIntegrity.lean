/-
  Unicode.Security.Identity.EmojiZwjIntegrity

  I3 — Detection of malformed / unsanctioned emoji ZWJ-sequence
  shapes per UTS #51.

  Threat model.  Tier A₁..A₂.  Adversary crafts an emoji-shaped
  codepoint sequence containing one or more `U+200D` ZERO WIDTH
  JOINERs but violating the sanctioned ZWJ-sequence shape — by
  exceeding the RGI length cap, by joining a non-Emoji
  codepoint, by emitting adjacent ZWJ pairs, or by overflowing
  the skin-tone count.

  Sanctioning model.  UTS #51 defines RGI ZWJ sequences in
  `emoji-zwj-sequences.txt`.  Any other ZWJ-containing sequence
  is renderer-dependent: some libraries render as a fragmented
  glyph chain (showing each component plus a small "joiner"
  glyph), others as a single ad-hoc glyph, others as a default-
  rendering fallback.  This renderer-divergence is the attack
  surface I3 closes.

  Algorithm shape (one pass over `input`).

    Phase 1 — collect ZWJ positions and skin-tone count.
    Phase 2 — short-circuit `.clear` if there are no ZWJs and the
              skin-tone count is at most 1.
    Phase 3 — check sub-threats by priority:
                1. `doubleZWJ`            ZWJ-ZWJ adjacency
                2. `nonEmojiInjection`    ZWJ adjacent to a non-emoji
                                          codepoint
                3. `overLength`           sequence longer than the
                                          conservative RGI cap
                4. `skinToneOverflow`     skin-tone count > 4
                                          (family-emoji maximum)
                5. `unregisteredSequence` catch-all when the
                                          codepoint stream contains
                                          ZWJs but is not in
                                          `emoji-zwj-sequences.txt`.
-/

import Unicode.Security.Calculus
import Unicode.Emoji
import Unicode.Generated.EmojiSequences

namespace Unicode.Security.Identity.EmojiZwjIntegrity

open Unicode.Security.Calculus

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Conservative cap on the length of a sanctioned RGI ZWJ
    sequence in `emoji-zwj-sequences.txt` (UCD 16.0.0).  The
    longest current entry is the four-person-with-skin-tones
    family which can reach ~13-14 codepoints; we use 16 as a
    safe upper bound. -/
def maxRgiLength : Nat := 16

/-- The ZERO WIDTH JOINER codepoint. -/
def zwj : Nat := 0x200D

/-- Sub-threat enumeration for I3.

    Priority order (highest first):
      1. `doubleZWJ`            ZWJ-ZWJ adjacency
      2. `nonEmojiInjection`    ZWJ adjacent to non-emoji codepoint
      3. `overLength`           sequence longer than `maxRgiLength`
      4. `skinToneOverflow`     ≥ 5 skin-tone modifiers
      5. `unregisteredSequence` ZWJ present, not in RGI set,
                                no other sub-threat matched
-/
inductive I3SubThreat where
  | doubleZWJ            (positions : Array Nat)
  | nonEmojiInjection    (zwjPos : Nat) (nonEmojiCp : Nat)
  | overLength           (length : Nat) (maxLength : Nat)
  | skinToneOverflow     (count : Nat)
  | unregisteredSequence (chainLen : Nat)
  deriving DecidableEq, Repr, Inhabited

/-- Top-level classification for I3. -/
inductive I3Classification where
  | clear
  | hazard (sub : I3SubThreat) (positions : Array Nat) (decoded : ByteArray)
  deriving Inhabited

/-- I3 verdict — the structured output of `detect`. -/
structure I3Verdict where
  input             : Array Nat
  classify          : I3Classification
  zwjPositions      : Array Nat
  chainLength       : Nat
  isRegisteredRGI   : Bool
  skinToneCount     : Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Core predicates
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cp` is the ZWJ codepoint. -/
@[inline]
def isZwj (cp : Nat) : Bool := cp = zwj

/-- True iff `cp` is a sanctioned ZWJ-sequence target — i.e.
    `cp` appears at some position of a registered RGI ZWJ
    sequence in `emoji-zwj-sequences.txt`.  Membership is the
    canonical "what can flank a ZWJ?" predicate; the older
    approximation via `Emoji_Presentation` either misclassified
    keycap-eligible ASCII digits as targets (because they
    inherit the wider `Emoji` property) or required an explicit
    `U+2764` exception (because `HEAVY BLACK HEART` is itself
    not `Emoji_Presentation`).  Reusing the Standard's own
    membership data avoids both.

    Delegates to `Unicode.Generated.EmojiSequences.isInZwjAlphabet`. -/
@[inline]
def isEmojiTarget (cp : Nat) : Bool :=
  Unicode.Generated.EmojiSequences.isInZwjAlphabet cp

/-- Collect ZWJ positions in `input`. -/
def zwjPositions (input : Array Nat) : Array Nat :=
  (Array.range input.size).filterMap (fun i =>
    if h : i < input.size then
      if isZwj input[i] then some i else none
    else none)

/-- Find adjacent ZWJ positions (returns the position of the
    first ZWJ in each ZWJ-ZWJ pair). -/
def doubleZwjPositions (input : Array Nat) : Array Nat :=
  (Array.range input.size).filterMap (fun i =>
    if h : i + 1 < input.size then
      if isZwj (input[i]'(by omega)) ∧ isZwj input[i + 1] then some i
      else none
    else none)

/-- Find the first ZWJ position where either neighbor is a
    non-emoji codepoint.  Returns `some (zwjPos, offendingCp)`
    on hit. -/
def firstNonEmojiInjection (input : Array Nat) : Option (Nat × Nat) :=
  let zwjs := zwjPositions input
  zwjs.findSome? (fun p =>
    if p > 0 ∧ p + 1 < input.size then
      let prev := input[p - 1]!
      let next := input[p + 1]!
      if ¬ isEmojiTarget prev then some (p, prev)
      else if ¬ isEmojiTarget next then some (p, next)
      else none
    else
      -- ZWJ at the edge of input is also an injection-class hazard.
      some (p, 0))

/-- Count of skin-tone modifier codepoints (U+1F3FB..U+1F3FF). -/
def skinToneCount (input : Array Nat) : Nat :=
  input.foldl (fun n cp =>
    if Unicode.Emoji.isEmojiModifier cp then n + 1 else n) 0

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The I3 detection function. -/
def detect (input : Array Nat) : I3Verdict :=
  let zwjs := zwjPositions input
  let stCount := skinToneCount input
  let isRgi := Unicode.Generated.EmojiSequences.isRegisteredZwjSequence input
  let chainLen := if zwjs.isEmpty then 0 else input.size
  if zwjs.isEmpty ∧ stCount ≤ 1 then
    { input := input,
      classify := .clear,
      zwjPositions := #[],
      chainLength := 0,
      isRegisteredRGI := isRgi,
      skinToneCount := stCount }
  else
    let classification : I3Classification :=
      -- Phase 1: registered RGI sequence is always clear.
      if isRgi then .clear
      else
        -- Phase 2: ZWJ-ZWJ adjacency.
        let dzwj := doubleZwjPositions input
        if dzwj.size > 0 then
          .hazard (.doubleZWJ dzwj) dzwj ByteArray.empty
        else
          -- Phase 3: ZWJ adjacent to non-emoji.
          match firstNonEmojiInjection input with
          | some (zwjPos, offendCp) =>
            .hazard (.nonEmojiInjection zwjPos offendCp)
              #[zwjPos] ByteArray.empty
          | none =>
            -- Phase 4: length cap.
            if input.size > maxRgiLength then
              .hazard (.overLength input.size maxRgiLength)
                #[] ByteArray.empty
            -- Phase 5: skin-tone overflow.
            else if stCount ≥ 5 then
              .hazard (.skinToneOverflow stCount) #[] ByteArray.empty
            -- Phase 6: catch-all for unregistered ZWJ sequences.
            else if zwjs.size > 0 then
              .hazard (.unregisteredSequence input.size) zwjs ByteArray.empty
            else .clear
    { input := input,
      classify := classification,
      zwjPositions := zwjs,
      chainLength := chainLen,
      isRegisteredRGI := isRgi,
      skinToneCount := stCount }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Fixture-row tag string for each `I3SubThreat` constructor. -/
def I3SubThreat.tag : I3SubThreat → String
  | .doubleZWJ            positions             =>
      Function.const (Array Nat) "DoubleZWJ" positions
  | .nonEmojiInjection    zwjPos nonEmojiCp     =>
      Function.const (Nat × Nat) "NonEmojiInjection" (zwjPos, nonEmojiCp)
  | .overLength           length maxLength      =>
      Function.const (Nat × Nat) "OverLength" (length, maxLength)
  | .skinToneOverflow     count                 =>
      Function.const Nat "SkinToneOverflow" count
  | .unregisteredSequence chainLen              =>
      Function.const Nat "UnregisteredSequence" chainLen

/-- True iff the classification is `.clear`. -/
def I3Classification.isClear : I3Classification → Bool
  | .clear                     => true
  | .hazard sub positions decoded =>
      Function.const (I3SubThreat × Array Nat × ByteArray) false
        (sub, positions, decoded)

/-- Tag string of a classification. -/
def I3Classification.tag : I3Classification → Option String
  | .clear                     => none
  | .hazard sub positions decoded =>
      Function.const (Array Nat × ByteArray) (some sub.tag) (positions, decoded)

/-- Positions array of a classification. -/
def I3Classification.positions : I3Classification → Array Nat
  | .clear                     => #[]
  | .hazard sub positions decoded =>
      Function.const (I3SubThreat × ByteArray) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear. -/
theorem detect_empty_clear : (detect #[]).classify.isClear = true := by
  native_decide

/-- Pure ASCII is clear. -/
theorem detect_ascii_clear :
    (detect #[0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  native_decide

/-- Plain emoji (no ZWJ) is clear. -/
theorem detect_plain_emoji_clear :
    (detect #[0x1F600]).classify.isClear = true := by native_decide

/-- Single skin-tone modifier on a base — clear (count = 1). -/
theorem detect_one_skintone_clear :
    (detect #[0x1F44B, 0x1F3FB]).classify.isClear = true := by native_decide

/-- Family of four (man + woman + girl + boy via ZWJs) — registered RGI. -/
theorem detect_family_rgi_clear :
    (detect #[0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467,
              0x200D, 0x1F466]).classify.isClear = true := by native_decide

/-- ZWJ + ZWJ adjacency — `.doubleZWJ`. -/
theorem detect_double_zwj :
    (detect #[0x1F600, 0x200D, 0x200D, 0x1F600]).classify.tag
      = some "DoubleZWJ" := by native_decide

/-- ZWJ joining ASCII 'a' — `.nonEmojiInjection`. -/
theorem detect_non_emoji_injection :
    (detect #[0x1F600, 0x200D, 0x0061]).classify.tag
      = some "NonEmojiInjection" := by native_decide

/-- Five skin-tone modifiers — `.skinToneOverflow`. -/
theorem detect_skin_tone_overflow :
    (detect #[0x1F44B, 0x1F3FB, 0x1F3FC, 0x1F3FD, 0x1F3FE, 0x1F3FF]).classify.tag
      = some "SkinToneOverflow" := by native_decide

/-- `MAN + ZWJ + LAPTOP` is registered (`👨‍💻` = man technologist) —
    must be clear. -/
theorem detect_man_laptop_registered_clear :
    (detect #[0x1F468, 0x200D, 0x1F4BB]).classify.isClear = true := by
  native_decide

/-- `MAN + ZWJ + WOMAN` is a sequence where both sides ARE in the
    RGI ZWJ alphabet (they appear in registered family and couple
    sequences) but the joined sequence `man + ZWJ + woman` itself
    is NOT a registered RGI entry.  Surfaces as
    `.unregisteredSequence`. -/
theorem detect_unregistered :
    (detect #[0x1F468, 0x200D, 0x1F469]).classify.tag
      = some "UnregisteredSequence" := by native_decide

/-- `GRINNING FACE + ZWJ + LAPTOP` — the grinning face does NOT
    appear in any registered RGI ZWJ sequence, so it is not a
    valid ZWJ-join target.  This now correctly surfaces as
    `.nonEmojiInjection` rather than the looser
    `.unregisteredSequence` we got before adopting the
    structural `zwjAlphabet` predicate. -/
theorem detect_grinning_laptop_non_emoji_injection :
    (detect #[0x1F600, 0x200D, 0x1F4BB]).classify.tag
      = some "NonEmojiInjection" := by native_decide

end Unicode.Security.Identity.EmojiZwjIntegrity
