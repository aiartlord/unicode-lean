/-
  Unicode.Security.Identity.SkinToneVariationForgery

  I4 — Detection of skin-tone modifier and variation-selector
  abuse on emoji bases per UTS #51 (Unicode Emoji).

  Threat model.  Tier A₁.  Adversary places a skin-tone modifier
  on a codepoint that does NOT bear the `Emoji_Modifier_Base`
  property, stacks multiple skin-tones on a single base, or
  forces a text-style render on an emoji-default codepoint via
  the `U+FE0E` variation selector (sometimes used to hide a
  payload-bearing glyph in plain sight).

  Distinction from C2 (variation-selector payload).
    C2 detects pair-aligned VS *runs* that decode to bytes,
    plus illegal-VS-on-non-emoji-base.  I4 catches the orthogonal
    case of *semantic* VS / skin-tone misuse on a single base
    that doesn't fit the payload-shaped pattern.  Both can fire
    on the same input; D1 aggregates.

  Sub-threats (priority order).

    1. `stackedSkinTones`      ≥ 2 skin-tone modifiers attached
                              to a single base codepoint.
    2. `invalidSkinToneTarget`  skin-tone modifier on a base that
                              does not have `Emoji_Modifier_Base`.
    3. `forcedTextStyle`       `U+FE0E` (VS15) on a codepoint
                              that has `Emoji_Presentation`
                              (forcing it to text-style render).
-/

import Unicode.Security.Calculus
import Unicode.Emoji

namespace Unicode.Security.Identity.SkinToneVariationForgery

open Unicode.Security.Calculus

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Sub-threat enumeration for I4. -/
inductive SubThreat where
  | stackedSkinTones       (basePos : Nat) (modifiers : Array Nat)
  | invalidSkinToneTarget  (basePos : Nat) (baseCp : Nat) (modifierCp : Nat)
  | forcedTextStyle        (basePos : Nat) (baseCp : Nat)
  deriving DecidableEq, Repr, Inhabited

/-- Top-level classification for I4. -/
inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : Array Nat) (decoded : ByteArray)
  deriving Inhabited

/-- I4 verdict — the structured output of `detect`. -/
structure Verdict where
  input              : Array Nat
  classify           : Classification
  skinToneCount      : Nat
  variationSelector15Count : Nat
  variationSelector16Count : Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Core predicates (re-exports for ergonomics)
-- ═══════════════════════════════════════════════════════════════════════════════

@[inline] def isSkinTone (cp : Nat) : Bool :=
  Unicode.Emoji.isEmojiModifier cp

@[inline] def isSkinToneBase (cp : Nat) : Bool :=
  Unicode.Emoji.isEmojiModifierBase cp

@[inline] def isVS15 (cp : Nat) : Bool := cp = 0x0FE0E

@[inline] def isVS16 (cp : Nat) : Bool := cp = 0x0FE0F

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Sub-detectors
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Find the first position `p` where `input[p]` is a base
    codepoint immediately followed by ≥ 2 skin-tone modifiers.
    Returns `some (basePos, firstTwoMods)`.  We only collect the
    first two stacked modifiers; a longer stack still fires the
    same sub-threat. -/
def firstStackedSkinTones (input : Array Nat) : Option (Nat × Array Nat) :=
  (Array.range input.size).findSome? (fun p =>
    if h : p + 2 < input.size then
      if isSkinTone (input[p + 1]'(by omega)) ∧
         isSkinTone (input[p + 2]'(by omega)) then
        some (p, #[input[p + 1]'(by omega), input[p + 2]'(by omega)])
      else
        none
    else
      none)

/-- Find the first skin-tone modifier whose preceding codepoint
    is NOT in `Emoji_Modifier_Base`.  Returns
    `some (basePos, baseCp, modifierCp)` on hit. -/
def firstInvalidSkinToneTarget
    (input : Array Nat) : Option (Nat × Nat × Nat) :=
  (Array.range input.size).findSome? (fun i =>
    if h : i < input.size then
      if isSkinTone (input[i]'h) ∧ i > 0 then
        let basePos := i - 1
        if hb : basePos < input.size then
          let baseCp := input[basePos]'hb
          if ¬ isSkinToneBase baseCp then
            some (basePos, baseCp, input[i]'h)
          else none
        else none
      else none
    else none)

/-- Find the first `U+FE0E` whose preceding codepoint has
    `Emoji_Presentation`.  Returns `some (basePos, baseCp)`. -/
def firstForcedTextStyle (input : Array Nat) : Option (Nat × Nat) :=
  (Array.range input.size).findSome? (fun i =>
    if h : i < input.size then
      if isVS15 (input[i]'h) ∧ i > 0 then
        let basePos := i - 1
        if hb : basePos < input.size then
          let baseCp := input[basePos]'hb
          if Unicode.Emoji.isEmojiPresentation baseCp then
            some (basePos, baseCp)
          else none
        else none
      else none
    else none)

/-- Count of skin-tone modifier codepoints in `input`. -/
def skinToneCount (input : Array Nat) : Nat :=
  input.foldl (fun n cp => if isSkinTone cp then n + 1 else n) 0

/-- Count of `U+FE0E` codepoints in `input`. -/
def vs15Count (input : Array Nat) : Nat :=
  input.foldl (fun n cp => if isVS15 cp then n + 1 else n) 0

/-- Count of `U+FE0F` codepoints in `input`. -/
def vs16Count (input : Array Nat) : Nat :=
  input.foldl (fun n cp => if isVS16 cp then n + 1 else n) 0

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The I4 detection function. -/
def detect (input : Array Nat) : Verdict :=
  let stc := skinToneCount input
  let v15 := vs15Count input
  let v16 := vs16Count input
  let classification : Classification :=
    match firstStackedSkinTones input with
    | some (basePos, mods) =>
      let modPositions :=
        (Array.range mods.size).map (fun i => basePos + 1 + i)
      .hazard (.stackedSkinTones basePos mods)
        modPositions ByteArray.empty
    | none =>
      match firstInvalidSkinToneTarget input with
      | some (basePos, baseCp, modCp) =>
        .hazard (.invalidSkinToneTarget basePos baseCp modCp)
          #[basePos + 1] ByteArray.empty
      | none =>
        match firstForcedTextStyle input with
        | some (basePos, baseCp) =>
          .hazard (.forcedTextStyle basePos baseCp)
            #[basePos + 1] ByteArray.empty
        | none => .clear
  { input := input,
    classify := classification,
    skinToneCount := stc,
    variationSelector15Count := v15,
    variationSelector16Count := v16 }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Fixture-row tag string for each `SubThreat` constructor. -/
def SubThreat.tag : SubThreat → String
  | .stackedSkinTones      basePos modifiers     =>
      Function.const (Nat × Array Nat) "StackedSkinTones" (basePos, modifiers)
  | .invalidSkinToneTarget basePos baseCp modCp  =>
      Function.const (Nat × Nat × Nat) "InvalidSkinToneTarget"
        (basePos, baseCp, modCp)
  | .forcedTextStyle       basePos baseCp        =>
      Function.const (Nat × Nat) "ForcedTextStyle" (basePos, baseCp)

/-- True iff the classification is `.clear`. -/
def Classification.isClear : Classification → Bool
  | .clear                     => true
  | .hazard sub positions decoded =>
      Function.const (SubThreat × Array Nat × ByteArray) false
        (sub, positions, decoded)

/-- Tag string of a classification. -/
def Classification.tag : Classification → Option String
  | .clear                     => none
  | .hazard sub positions decoded =>
      Function.const (Array Nat × ByteArray) (some sub.tag) (positions, decoded)

/-- Positions array of a classification. -/
def Classification.positions : Classification → Array Nat
  | .clear                     => #[]
  | .hazard sub positions decoded =>
      Function.const (SubThreat × ByteArray) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear. -/
theorem detect_empty_clear : (detect #[]).classify.isClear = true := by
  native_decide

/-- Pure ASCII is clear. -/
theorem detect_ascii_clear :
    (detect #[0x48, 0x65]).classify.isClear = true := by native_decide

/-- Plain emoji is clear. -/
theorem detect_plain_emoji_clear :
    (detect #[0x1F600]).classify.isClear = true := by native_decide

/-- Single skin-tone modifier on a modifier-base — clear. -/
theorem detect_wave_skin_tone_clear :
    (detect #[0x1F44B, 0x1F3FB]).classify.isClear = true := by native_decide

/-- Two skin-tones in a row on a modifier-base — `.stackedSkinTones`. -/
theorem detect_stacked_skin_tones :
    (detect #[0x1F44B, 0x1F3FB, 0x1F3FC]).classify.tag
      = some "StackedSkinTones" := by native_decide

/-- Skin-tone on ASCII letter — `.invalidSkinToneTarget`. -/
theorem detect_invalid_target_ascii :
    (detect #[0x0041, 0x1F3FB]).classify.tag
      = some "InvalidSkinToneTarget" := by native_decide

/-- Skin-tone on smiley-face (not a modifier-base) — `.invalidSkinToneTarget`. -/
theorem detect_invalid_target_smiley :
    (detect #[0x1F600, 0x1F3FB]).classify.tag
      = some "InvalidSkinToneTarget" := by native_decide

/-- VS15 on Emoji_Presentation codepoint (smiley) — `.forcedTextStyle`. -/
theorem detect_forced_text_style :
    (detect #[0x1F600, 0xFE0E]).classify.tag
      = some "ForcedTextStyle" := by native_decide

end Unicode.Security.Identity.SkinToneVariationForgery
