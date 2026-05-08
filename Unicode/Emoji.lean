/-
  Unicode.Emoji

  UTS #51 emoji sequences and presentation selectors. Builds on the
  per-codepoint property predicates exported by
  `Unicode.Generated.EmojiData` and adds the multi-codepoint
  recognisers that real text needs:

    * Variation selectors  — VS15 / VS16 (text vs emoji presentation)
    * Regional indicators  — pairs forming flag sequences
    * Modifier sequences   — base + skin-tone modifier
    * Keycap sequences     — digit/'#'/'*' + VS16 + U+20E3
    * Tag sequences        — base + tag-spec + U+E007F (cancel tag)
    * ZWJ sequences        — emoji + (ZWJ + emoji)+ joined chains

  These shapes are the complete set of UTS #51 §1.3 emoji sequence
  patterns. The predicates here are sufficient for downstream
  segmentation (UAX #29 grapheme cluster boundary GB11/GB12/GB13
  rules) and for "is this an emoji?" checks in user-facing UI.
-/

import Unicode.Generated.EmojiData
import Unicode.Generated.EmojiSequences

namespace Unicode.Emoji

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 SINGLE-CODEPOINT PREDICATES (re-exported for ergonomics)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cp` has the Emoji property. -/
def isEmoji (cp : Nat) : Bool :=
  Unicode.Generated.EmojiData.isEmoji cp

/-- True iff `cp` has the Emoji_Presentation property. -/
def isEmojiPresentation (cp : Nat) : Bool :=
  Unicode.Generated.EmojiData.isEmojiPresentation cp

/-- True iff `cp` is one of the five skin-tone modifiers. -/
def isEmojiModifier (cp : Nat) : Bool :=
  Unicode.Generated.EmojiData.isEmojiModifier cp

/-- True iff `cp` accepts a skin-tone modifier following it. -/
def isEmojiModifierBase (cp : Nat) : Bool :=
  Unicode.Generated.EmojiData.isEmojiModifierBase cp

/-- True iff `cp` has the Extended_Pictographic property. -/
def isExtendedPictographic (cp : Nat) : Bool :=
  Unicode.Generated.EmojiData.isExtendedPictographic cp

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 VARIATION SELECTORS  (UTS #51 §1.4.5)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- U+FE0E VARIATION SELECTOR-15 forces text presentation on the
    immediately preceding codepoint. -/
def textPresentationSelector : Nat := 0xFE0E

/-- U+FE0F VARIATION SELECTOR-16 forces emoji presentation on the
    immediately preceding codepoint. -/
def emojiPresentationSelector : Nat := 0xFE0F

/-- True iff `cp` is U+FE0E (text variation selector). -/
def isTextPresentationSelector (cp : Nat) : Bool :=
  cp = textPresentationSelector

/-- True iff `cp` is U+FE0F (emoji variation selector). -/
def isEmojiPresentationSelector (cp : Nat) : Bool :=
  cp = emojiPresentationSelector

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 REGIONAL INDICATORS / FLAG SEQUENCES  (UTS #51 §1.4.5 RGI flag)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cp` is a regional indicator symbol letter
    (U+1F1E6..U+1F1FF). Two consecutive regional indicators form
    a flag sequence (e.g. U+1F1FA + U+1F1F8 = 🇺🇸). -/
def isRegionalIndicator (cp : Nat) : Bool :=
  Nat.ble 0x1F1E6 cp && Nat.ble cp 0x1F1FF

/-- True iff `cps` is exactly a two-codepoint RGI flag sequence
    (two regional indicators). The actual valid set is the
    [unicode-region-subtag-registry] subset; this predicate accepts
    every well-formed pair, leaving region-validity to callers. -/
def isFlagSequence (cps : Array Nat) : Bool :=
  cps.size = 2
    && (match cps[0]?, cps[1]? with
        | some a, some b => isRegionalIndicator a && isRegionalIndicator b
        | _, _ => false)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 EMOJI MODIFIER SEQUENCE  (UTS #51 §1.4.6 ED-13)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cps` is a two-codepoint emoji modifier sequence:
    an Emoji_Modifier_Base followed by an Emoji_Modifier. -/
def isEmojiModifierSequence (cps : Array Nat) : Bool :=
  cps.size = 2
    && (match cps[0]?, cps[1]? with
        | some a, some b => isEmojiModifierBase a && isEmojiModifier b
        | _, _ => false)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 KEYCAP SEQUENCE  (UTS #51 §1.4.6 ED-14a)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The ten ASCII digits, '#', and '*' that admit a keycap form. -/
def isKeycapBase (cp : Nat) : Bool :=
  cp = 0x23 || cp = 0x2A
    || (Nat.ble 0x30 cp && Nat.ble cp 0x39)

/-- U+20E3 COMBINING ENCLOSING KEYCAP. -/
def combiningEnclosingKeycap : Nat := 0x20E3

/-- True iff `cps` is exactly `[base, U+FE0F, U+20E3]` for a keycap
    base codepoint (digit / '#' / '*'). -/
def isKeycapSequence (cps : Array Nat) : Bool :=
  cps.size = 3
    && (match cps[0]?, cps[1]?, cps[2]? with
        | some a, some b, some c =>
          isKeycapBase a
            && b = emojiPresentationSelector
            && c = combiningEnclosingKeycap
        | _, _, _ => false)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 TAG SEQUENCE  (UTS #51 §1.4.6 ED-14c — subdivision flags)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- U+E0020..U+E007E are tag-spec codepoints used for subdivision-flag
    sequences (e.g. England, Scotland, Wales). -/
def isTagSpecChar (cp : Nat) : Bool :=
  Nat.ble 0xE0020 cp && Nat.ble cp 0xE007E

/-- U+E007F CANCEL TAG terminates a tag sequence. -/
def cancelTag : Nat := 0xE007F

/-- True iff `cps` is a tag sequence: a base codepoint with the
    Emoji property, followed by one or more tag-spec characters,
    terminated by U+E007F CANCEL TAG. -/
def isTagSequence (cps : Array Nat) : Bool :=
  if cps.size < 3 then false
  else
    match cps[0]?, cps[cps.size - 1]? with
    | some base, some last =>
      isEmoji base
        && last = cancelTag
        && (cps.extract 1 (cps.size - 1)).all isTagSpecChar
    | _, _ => false

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 ZWJ SEQUENCE  (UTS #51 §1.4.7)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- U+200D ZERO WIDTH JOINER. -/
def zwj : Nat := 0x200D

/-- True iff `cp` is U+200D ZERO WIDTH JOINER. -/
def isZwj (cp : Nat) : Bool := cp = zwj

/-- True iff `cps` contains at least one U+200D ZERO WIDTH JOINER
    AND every U+200D in `cps` lies strictly between two non-ZWJ
    codepoints (no leading, trailing, or doubled ZWJ). This is the
    structural shape of a UTS #51 §1.4.7 emoji ZWJ sequence; it
    does not enforce that each segment is itself a valid emoji
    cluster, which the segmentation layer checks via UAX #29 GB11. -/
def isZwjSequence (cps : Array Nat) : Bool := Id.run do
  if cps.size < 3 then return false
  let mut sawZwj : Bool := false
  for h : i in [0:cps.size] do
    let cp := cps[i]
    if cp = zwj then
      sawZwj := true
      -- Reject leading or trailing ZWJ.
      if i = 0 ∨ i + 1 = cps.size then return false
      -- Reject ZWJ adjacent to another ZWJ.
      let prev := cps[i - 1]!
      let next := cps[i + 1]!
      if prev = zwj ∨ next = zwj then return false
  return sawZwj

-- ═══════════════════════════════════════════════════════════════════════════════
-- §8 EMOJI SEQUENCE — UNION
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cps` is *any* recognised emoji sequence shape: a single
    emoji codepoint (with optional VS15/VS16), a flag sequence, a
    modifier sequence, a keycap sequence, a tag sequence, or a ZWJ
    sequence. The shapes are checked in the order listed; ambiguous
    inputs (which can't actually arise — the shapes are disjoint by
    construction) take the first match. -/
def isEmojiSequence (cps : Array Nat) : Bool :=
  -- Bare emoji codepoint.
  (cps.size = 1 && (match cps[0]? with
                     | some cp => isEmoji cp
                     | none    => false))
  -- Emoji codepoint with explicit presentation selector.
  || (cps.size = 2 && (match cps[0]?, cps[1]? with
                         | some a, some b =>
                           isEmoji a && (b = emojiPresentationSelector
                                          || b = textPresentationSelector)
                         | _, _ => false))
  || isFlagSequence cps
  || isEmojiModifierSequence cps
  || isKeycapSequence cps
  || isTagSequence cps
  || isZwjSequence cps

-- ═══════════════════════════════════════════════════════════════════════════════
-- §9 TEST VECTORS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- U+1F600 GRINNING FACE has Emoji and Emoji_Presentation. -/
theorem isEmoji_grinning : isEmoji 0x1F600 = true := by native_decide
theorem isEmojiPresentation_grinning :
    isEmojiPresentation 0x1F600 = true := by native_decide

/-- ASCII '0' has Emoji (the keycap base) but NOT Emoji_Presentation
    (which means it defaults to text — only `0 + VS16 + U+20E3`
    forms a keycap). -/
theorem isEmoji_zero : isEmoji 0x30 = true := by native_decide
theorem isEmojiPresentation_zero : isEmojiPresentation 0x30 = false := by native_decide

/-- U+1F3FB EMOJI MODIFIER FITZPATRICK TYPE-1-2 is an Emoji_Modifier. -/
theorem isEmojiModifier_fitz12 : isEmojiModifier 0x1F3FB = true := by native_decide

/-- U+1F44B WAVING HAND SIGN is an Emoji_Modifier_Base. -/
theorem isEmojiModifierBase_wave :
    isEmojiModifierBase 0x1F44B = true := by native_decide

/-- U+1F1FA REGIONAL INDICATOR SYMBOL LETTER U is a regional indicator. -/
theorem isRegionalIndicator_U : isRegionalIndicator 0x1F1FA = true := by native_decide

/-- ASCII 'A' is NOT a regional indicator. -/
theorem isRegionalIndicator_A : isRegionalIndicator 0x41 = false := by native_decide

/-- 🇺🇸 (U+1F1FA U+1F1F8) is a flag sequence. -/
theorem isFlagSequence_us :
    isFlagSequence #[0x1F1FA, 0x1F1F8] = true := by native_decide

/-- A single regional indicator alone is NOT a flag sequence. -/
theorem isFlagSequence_single :
    isFlagSequence #[0x1F1FA] = false := by native_decide

/-- 👋🏽 (waving hand + medium skin) is an emoji modifier sequence. -/
theorem isEmojiModifierSequence_wave_med :
    isEmojiModifierSequence #[0x1F44B, 0x1F3FD] = true := by native_decide

/-- A skin-tone applied to a non-base codepoint is NOT a modifier sequence. -/
theorem isEmojiModifierSequence_invalid :
    isEmojiModifierSequence #[0x1F600, 0x1F3FD] = false := by native_decide

/-- 1️⃣ (digit + VS16 + keycap) is a keycap sequence. -/
theorem isKeycapSequence_one :
    isKeycapSequence #[0x31, 0xFE0F, 0x20E3] = true := by native_decide

/-- A keycap base without VS16 is NOT a keycap sequence. -/
theorem isKeycapSequence_no_vs16 :
    isKeycapSequence #[0x31, 0x20E3] = false := by native_decide

/-- 👨‍👩‍👧 (father + ZWJ + mother + ZWJ + daughter) is a ZWJ sequence. -/
theorem isZwjSequence_family :
    isZwjSequence #[0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467] = true := by
  native_decide

/-- A leading ZWJ is rejected. -/
theorem isZwjSequence_leading :
    isZwjSequence #[0x200D, 0x1F468] = false := by native_decide

/-- A trailing ZWJ is rejected. -/
theorem isZwjSequence_trailing :
    isZwjSequence #[0x1F468, 0x200D] = false := by native_decide

/-- Doubled ZWJ is rejected. -/
theorem isZwjSequence_doubled :
    isZwjSequence #[0x1F468, 0x200D, 0x200D, 0x1F469] = false := by native_decide

/-- A bare emoji codepoint is an emoji sequence. -/
theorem isEmojiSequence_grinning :
    isEmojiSequence #[0x1F600] = true := by native_decide

/-- A flag is an emoji sequence. -/
theorem isEmojiSequence_flag :
    isEmojiSequence #[0x1F1FA, 0x1F1F8] = true := by native_decide

/-- A ZWJ family is an emoji sequence. -/
theorem isEmojiSequence_family :
    isEmojiSequence #[0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467] = true := by
  native_decide

/-- Plain ASCII text is NOT an emoji sequence. -/
theorem isEmojiSequence_ascii :
    isEmojiSequence #[0x68, 0x69] = false := by native_decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §10 RGI VALIDATION — registered sequences only
--
-- The structural predicates above accept any well-shaped sequence;
-- the predicates below additionally require the sequence to appear
-- in `emoji-sequences.txt` or `emoji-zwj-sequences.txt`. RGI =
-- Recommended for General Interchange (UTS #51 ED-27). Renderers,
-- keyboards, and pickers should match against the RGI set rather
-- than the structural set, because a structurally-valid ZWJ chain
-- like `🚀‍🦒` (rocket + ZWJ + giraffe) has no agreed-upon glyph.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cps` is exactly a registered RGI keycap sequence
    (`emoji-sequences.txt` row of type `Emoji_Keycap_Sequence`). -/
def isRgiKeycapSequence (cps : Array Nat) : Bool :=
  Unicode.Generated.EmojiSequences.isRegisteredKeycapSequence cps

/-- True iff `cps` is a registered RGI flag (region) sequence. -/
def isRgiFlagSequence (cps : Array Nat) : Bool :=
  Unicode.Generated.EmojiSequences.isRegisteredFlagSequence cps

/-- True iff `cps` is a registered RGI modifier (skin-tone) sequence. -/
def isRgiModifierSequence (cps : Array Nat) : Bool :=
  Unicode.Generated.EmojiSequences.isRegisteredModifierSequence cps

/-- True iff `cps` is a registered RGI subdivision-flag tag sequence
    (England, Scotland, Wales — the three RGI tag sequences in
    Emoji 16.0). -/
def isRgiTagSequence (cps : Array Nat) : Bool :=
  Unicode.Generated.EmojiSequences.isRegisteredTagSequence cps

/-- True iff `cps` is a registered RGI ZWJ sequence (family,
    profession, gender variant, hair component, direction). -/
def isRgiZwjSequence (cps : Array Nat) : Bool :=
  Unicode.Generated.EmojiSequences.isRegisteredZwjSequence cps

/-- True iff `cps` is in the RGI_Emoji set per UTS #51 ED-27: a
    Basic_Emoji codepoint or sequence, a registered keycap, flag,
    modifier, tag, or ZWJ sequence. -/
def isRgiEmoji (cps : Array Nat) : Bool :=
  -- Bare Basic_Emoji codepoint.
  (cps.size = 1 && (match cps[0]? with
                     | some cp => Unicode.Generated.EmojiSequences.isBasicEmojiCodepoint cp
                     | none    => false))
  || Unicode.Generated.EmojiSequences.isBasicEmojiSequence cps
  || isRgiKeycapSequence cps
  || isRgiFlagSequence cps
  || isRgiModifierSequence cps
  || isRgiTagSequence cps
  || isRgiZwjSequence cps

-- ═══════════════════════════════════════════════════════════════════════════════
-- §11 RGI TEST VECTORS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- 👋 (waving hand, U+1F44B) is a registered Basic_Emoji codepoint. -/
theorem isRgiEmoji_wave : isRgiEmoji #[0x1F44B] = true := by native_decide

/-- 🇺🇸 (U+1F1FA U+1F1F8) is a registered RGI flag sequence. -/
theorem isRgiFlagSequence_us :
    isRgiFlagSequence #[0x1F1FA, 0x1F1F8] = true := by native_decide

/-- Two arbitrary regional indicators with no registered region are
    NOT a registered RGI flag. -/
theorem isRgiFlagSequence_unregistered :
    isRgiFlagSequence #[0x1F1E6, 0x1F1E6] = false := by native_decide

/-- 1️⃣ (digit + VS16 + keycap) is a registered RGI keycap sequence. -/
theorem isRgiKeycapSequence_one :
    isRgiKeycapSequence #[0x31, 0xFE0F, 0x20E3] = true := by native_decide

/-- 👋🏽 (waving hand + medium skin) is a registered RGI modifier sequence. -/
theorem isRgiModifierSequence_wave_med :
    isRgiModifierSequence #[0x1F44B, 0x1F3FD] = true := by native_decide

/-- 👨‍👩‍👧 (family: man, woman, girl) is a registered RGI ZWJ sequence. -/
theorem isRgiZwjSequence_family :
    isRgiZwjSequence #[0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467] = true := by
  native_decide

/-- A structurally-valid ZWJ chain that is NOT registered (rocket +
    ZWJ + giraffe) is rejected by `isRgiZwjSequence` but accepted
    by the structural `isZwjSequence`. -/
theorem isRgiZwjSequence_unregistered :
    isRgiZwjSequence #[0x1F680, 0x200D, 0x1F992] = false := by native_decide

theorem isZwjSequence_unregistered_structural_passes :
    isZwjSequence #[0x1F680, 0x200D, 0x1F992] = true := by native_decide

/-- 🏴󠁧󠁢󠁥󠁮󠁧󠁿 (England subdivision flag) is a registered RGI tag sequence. -/
theorem isRgiTagSequence_england :
    isRgiTagSequence #[0x1F3F4, 0xE0067, 0xE0062, 0xE0065, 0xE006E,
                       0xE0067, 0xE007F] = true := by
  native_decide

end Unicode.Emoji
