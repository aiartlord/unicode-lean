/-
  Unicode.Security.Identity.SkinToneVariationForgery

  Detection of skin-tone modifier and variation-selector
  abuse on emoji bases per UTS #51 (Unicode Emoji).

  Threat model.  Tier A₁.  Adversary places a skin-tone modifier
  on a codepoint that does NOT bear the `Emoji_Modifier_Base`
  property, stacks multiple skin-tones on a single base, or
  forces a text-style render on an emoji-default codepoint via
  the `U+FE0E` variation selector (sometimes used to hide a
  payload-bearing glyph in plain sight).

  Distinction from VariationSelectorPayload.
    VariationSelectorPayload detects pair-aligned VS *runs* that
    decode to bytes, plus illegal-VS-on-non-emoji-base.
    SkinToneVariationForgery catches the orthogonal
    case of *semantic* VS / skin-tone misuse on a single base
    that doesn't fit the payload-shaped pattern.  Both can fire
    on the same input; SourceDisplayDivergence aggregates.

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

set_option maxRecDepth 1000000

open Unicode.Security.Calculus

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Sub-threat enumeration for SkinToneVariationForgery. -/
inductive SubThreat where
  | stackedSkinTones       (basePos : Nat) (modifiers : List Nat)
  | invalidSkinToneTarget  (basePos : Nat) (baseCp : Nat) (modifierCp : Nat)
  | forcedTextStyle        (basePos : Nat) (baseCp : Nat)
  deriving DecidableEq, Repr, Inhabited

/-- Top-level classification for SkinToneVariationForgery. -/
inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : List Nat) (decoded : ByteArray)
  deriving Inhabited

/-- Verdict — the structured output of `detect`. -/
structure Verdict where
  input              : List Nat
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

/-- Forward-triple inventory: `(basePos, baseCp, next1, next2)` for
    every position with two following codepoints, via zips against
    the drop-1 and drop-2 views. -/
def triples (input : List Nat) : List (Nat × Nat × Nat × Nat) :=
  (((input.zip (input.drop 1)).zip (input.drop 2)).zipIdx).map
    (fun entry => (entry.2, entry.1.1.1, entry.1.1.2, entry.1.2))

/-- Prev-pair inventory: `(index, prev, cp)` for every position that
    has a preceding codepoint, via a zip against the drop-1 view. -/
def prevPairs (input : List Nat) : List (Nat × Nat × Nat) :=
  ((input.zip (input.drop 1)).zipIdx).map
    (fun entry => (entry.2, entry.1.1, entry.1.2))

/-- Find the first position `p` where `input[p]` is a base
    codepoint immediately followed by ≥ 2 skin-tone modifiers.
    Returns `some (basePos, firstTwoMods)`.  We only collect the
    first two stacked modifiers; a longer stack still fires the
    same sub-threat. -/
def firstStackedSkinTones (input : List Nat) : Option (Nat × List Nat) :=
  (triples input).findSome? (fun t =>
    if isSkinTone t.2.2.1 ∧ isSkinTone t.2.2.2 then
      some (t.1, [t.2.2.1, t.2.2.2])
    else none)

/-- Find the first skin-tone modifier whose preceding codepoint
    is NOT in `Emoji_Modifier_Base`.  Returns
    `some (basePos, baseCp, modifierCp)` on hit. -/
def firstInvalidSkinToneTarget
    (input : List Nat) : Option (Nat × Nat × Nat) :=
  (prevPairs input).findSome? (fun pr =>
    if isSkinTone pr.2.2 ∧ ¬ isSkinToneBase pr.2.1 then
      some (pr.1, pr.2.1, pr.2.2)
    else none)

/-- Find the first `U+FE0E` whose preceding codepoint has
    `Emoji_Presentation`.  Returns `some (basePos, baseCp)`. -/
def firstForcedTextStyle (input : List Nat) : Option (Nat × Nat) :=
  (prevPairs input).findSome? (fun pr =>
    if isVS15 pr.2.2 ∧ Unicode.Emoji.isEmojiPresentation pr.2.1 then
      some (pr.1, pr.2.1)
    else none)

/-- Count of skin-tone modifier codepoints in `input`. -/
def skinToneCount (input : List Nat) : Nat :=
  input.foldl (fun n cp => if isSkinTone cp then n + 1 else n) 0

/-- Count of `U+FE0E` codepoints in `input`. -/
def vs15Count (input : List Nat) : Nat :=
  input.foldl (fun n cp => if isVS15 cp then n + 1 else n) 0

/-- Count of `U+FE0F` codepoints in `input`. -/
def vs16Count (input : List Nat) : Nat :=
  input.foldl (fun n cp => if isVS16 cp then n + 1 else n) 0

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The SkinToneVariationForgery detection function. -/
def detect (input : List Nat) : Verdict :=
  let stc := skinToneCount input
  let v15 := vs15Count input
  let v16 := vs16Count input
  let classification : Classification :=
    match firstStackedSkinTones input with
    | some (basePos, mods) =>
      let modPositions :=
        (List.range mods.length).map (fun i => basePos + 1 + i)
      .hazard (.stackedSkinTones basePos mods)
        modPositions ByteArray.empty
    | none =>
      match firstInvalidSkinToneTarget input with
      | some (basePos, baseCp, modCp) =>
        .hazard (.invalidSkinToneTarget basePos baseCp modCp)
          [basePos + 1] ByteArray.empty
      | none =>
        match firstForcedTextStyle input with
        | some (basePos, baseCp) =>
          .hazard (.forcedTextStyle basePos baseCp)
            [basePos + 1] ByteArray.empty
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
      Function.const (Nat × List Nat) "StackedSkinTones" (basePos, modifiers)
  | .invalidSkinToneTarget basePos baseCp modCp  =>
      Function.const (Nat × Nat × Nat) "InvalidSkinToneTarget"
        (basePos, baseCp, modCp)
  | .forcedTextStyle       basePos baseCp        =>
      Function.const (Nat × Nat) "ForcedTextStyle" (basePos, baseCp)

/-- True iff the classification is `.clear`. -/
def Classification.isClear : Classification → Bool
  | .clear                     => true
  | .hazard sub positions decoded =>
      Function.const (SubThreat × List Nat × ByteArray) false
        (sub, positions, decoded)

/-- Tag string of a classification. -/
def Classification.tag : Classification → Option String
  | .clear                     => none
  | .hazard sub positions decoded =>
      Function.const (List Nat × ByteArray) (some sub.tag) (positions, decoded)

/-- Positions array of a classification. -/
def Classification.positions : Classification → List Nat
  | .clear                     => []
  | .hazard sub positions decoded =>
      Function.const (SubThreat × ByteArray) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear. -/
theorem detect_empty_clear : (detect []).classify.isClear = true := by
  decide

/-- Pure ASCII is clear. -/
theorem detect_ascii_clear :
    (detect [0x48, 0x65]).classify.isClear = true := by decide +kernel

/-- Plain emoji is clear. -/
theorem detect_plain_emoji_clear :
    (detect [0x1F600]).classify.isClear = true := by decide +kernel

/-- Single skin-tone modifier on a modifier-base — clear. -/
theorem detect_wave_skin_tone_clear :
    (detect [0x1F44B, 0x1F3FB]).classify.isClear = true := by decide +kernel

/-- Two skin-tones in a row on a modifier-base — `.stackedSkinTones`. -/
theorem detect_stacked_skin_tones :
    (detect [0x1F44B, 0x1F3FB, 0x1F3FC]).classify.tag
      = some "StackedSkinTones" := by decide +kernel

/-- Skin-tone on ASCII letter — `.invalidSkinToneTarget`. -/
theorem detect_invalid_target_ascii :
    (detect [0x0041, 0x1F3FB]).classify.tag
      = some "InvalidSkinToneTarget" := by decide +kernel

/-- Skin-tone on smiley-face (not a modifier-base) — `.invalidSkinToneTarget`. -/
theorem detect_invalid_target_smiley :
    (detect [0x1F600, 0x1F3FB]).classify.tag
      = some "InvalidSkinToneTarget" := by decide +kernel

/-- VS15 on Emoji_Presentation codepoint (smiley) — `.forcedTextStyle`. -/
theorem detect_forced_text_style :
    (detect [0x1F600, 0xFE0E]).classify.tag
      = some "ForcedTextStyle" := by decide +kernel

end Unicode.Security.Identity.SkinToneVariationForgery
