/-
  Unicode.Security.Crypto.AiWatermarkDetectability

  K3 — Detection of inputs carrying character-level markers
  consistent with a known AI watermark scheme.  Per
  `docs/specs/security/L6-cryptographic-stability.md` §K3, this
  family answers the question: does this input contain codepoint
  patterns that are signatures of a known watermark scheme?

  v1 scope is **character-level only**.  Statistical / token-
  distribution watermarks, per-segment integrity, and the
  genuine-vs-adversarial distinction are deferred:

    * Statistical watermarks (token-choice biasing) require
      access to the token stream and a per-provider distribution
      catalog — not a character-level test.
    * Per-segment integrity introduces segment-boundary
      ambiguity (K3-OQ-3); v1 is whole-input only.
    * Genuine-vs-adversarial distinction requires statistical
      protocol-consistency checks (K3-OQ-2); v1 reports
      `suspectedWatermark` only, never claims `genuine`.

  Threat model.  Tier A₁ (provenance-attribution attacker).
  Adversary submits text that either (a) carries an AI provider's
  watermark codepoints (legitimate provenance marker) or (b)
  carries injected fake markers to discredit the content as AI-
  generated.  A character-level detector cannot distinguish (a)
  from (b) — protocol-consistency is statistical — so v1 emits
  `suspectedWatermark` for both cases and lets downstream code
  apply provider-specific verification.

  Detection (priority order, first hit wins):

    1. `nnbspBoundary` — input contains U+202F NARROW NO-BREAK
       SPACE.  Reported as the GPT-4-class boundary marker.
       NNBSP has legitimate use in Mongolian, French Canadian,
       and some Polish typography; v1 flags ANY NNBSP because
       distinguishing legitimate use from watermark use requires
       a language tagger that this layer does not have.

    2. `variationSelectorCarrier` — input contains a Variation
       Selector (U+FE00..U+FE0F or U+E0100..U+E01EF) that is
       NOT adjacent to an emoji codepoint.  VS-after-emoji is
       legitimate (text / emoji presentation selectors, per
       UTS #51); VS in plain text is a payload-carrier signal.

    3. `zwjNonEmoji` — input contains U+200D ZERO WIDTH JOINER
       that is NOT adjacent to an emoji codepoint.  ZWJ in
       emoji-ZWJ sequences is legitimate; ZWJ in plain text is
       a payload-carrier signal.

    4. `defaultIgnorableCarrier` — input contains a
       Default_Ignorable_Code_Point that is none of the above
       three categories.  Catch-all for invisible-codepoint
       carriers (SOFT HYPHEN, COMBINING GRAPHEME JOINER, etc.).

  Six additional spec sub-threats (K3-INV-1's `gpt5_zwsp_modulo`,
  `claude_em_dash_pattern`, `gemini_smart_quote_alternation`,
  the `statisticalTokenChoice` distribution probe, the
  `adversarial` injection witness, and the `unknown` anomaly
  bucket) require analytical context this character-level
  detector cannot supply: a per-provider modulo schedule,
  statistical regularity over the document, or a comparison
  against an externally-trained classifier.  They are declared
  in `K3SubThreat` for future-extension consistency but never
  emitted by the v1 detector.

  Note on overlap with C2 and C3.  A VS payload fires BOTH C2
  VariationSelectorPayload (covert-channel lens — "does this
  input smuggle data?") AND K3 here (watermark-attribution
  lens — "was this input produced by an AI with marker scheme
  S?").  A ZWJ in plain text similarly fires both C3
  ZeroWidthPayload and K3.  This is intentional: the two lenses
  ask different questions about the same byte.  An input that
  fires both gets composite rejection at higher Levels and
  isolated rejection at `cryptoAdmissible .aiAttribution`.
-/

import Unicode.Security.Calculus
import Unicode.Generated.DerivedCoreProperties
import Unicode.Generated.EmojiData
import Unicode.Identifier

namespace Unicode.Security.Crypto.AiWatermarkDetectability

open Unicode.Security.Calculus

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Sub-threats K3 can fire.  The first four are emitted by the
    v1 detector; the remaining six are declared for spec-
    consistency with `L6-cryptographic-stability.md` §K3.1 but
    require context (statistical regularity, per-provider
    modulo schedules, per-document distribution baselines) that
    the codepoint-only API does not carry. -/
inductive K3SubThreat where
  | nnbspBoundary             (markerCount : Nat)
  | variationSelectorCarrier  (markerCount : Nat)
  | zwjNonEmoji               (markerCount : Nat)
  | defaultIgnorableCarrier   (markerCount : Nat)
  -- Declared but never emitted in v1:
  | gpt5ZwspModulo            (firstPos : Nat)
  | emDashPattern             (firstPos : Nat)
  | smartQuoteAlternation     (firstPos : Nat)
  | statisticalTokenChoice    (firstPos : Nat)
  | adversarial               (impersonatedScheme : String) (firstPos : Nat)
  | unknown                   (anomalyMarker : Nat)
  deriving DecidableEq, Repr, Inhabited

/-- Top-level K3 classification.  `.clear` = no watermark
    marker detected (semantically `noWatermark`); `.hazard`
    carries the fired sub-threat plus the marker positions. -/
inductive K3Classification where
  | clear
  | hazard (sub : K3SubThreat) (positions : Array Nat)
  deriving DecidableEq, Repr, Inhabited

/-- K3 verdict — the structured output of `detect`.
    `markerCount` is the count of codepoints matching the fired
    scheme's probe (0 when clear).  Mirrors K2's `stableSize`
    in shape — a single scalar the harness can pin on every
    fixture row. -/
structure K3Verdict where
  input        : Array Nat
  classify     : K3Classification
  markerCount  : Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Universal projections (isClear / tag / positions)
-- ═══════════════════════════════════════════════════════════════════════════════

namespace K3Classification

@[inline] def isClear : K3Classification → Bool
  | .clear              => true
  | .hazard sub ps      =>
    Function.const (K3SubThreat × Array Nat) false (sub, ps)

@[inline] def tag : K3Classification → Option String
  | .clear              => none
  | .hazard sub ps      =>
    Function.const (Array Nat) (
      match sub with
      | .nnbspBoundary count            =>
        Function.const Nat (some "NnbspBoundary") count
      | .variationSelectorCarrier count =>
        Function.const Nat (some "VariationSelectorCarrier") count
      | .zwjNonEmoji count              =>
        Function.const Nat (some "ZwjNonEmoji") count
      | .defaultIgnorableCarrier count  =>
        Function.const Nat (some "DefaultIgnorableCarrier") count
      | .gpt5ZwspModulo pos             =>
        Function.const Nat (some "Gpt5ZwspModulo") pos
      | .emDashPattern pos              =>
        Function.const Nat (some "EmDashPattern") pos
      | .smartQuoteAlternation pos      =>
        Function.const Nat (some "SmartQuoteAlternation") pos
      | .statisticalTokenChoice pos     =>
        Function.const Nat (some "StatisticalTokenChoice") pos
      | .adversarial scheme pos         =>
        Function.const (String × Nat) (some "Adversarial") (scheme, pos)
      | .unknown anomaly                =>
        Function.const Nat (some "Unknown") anomaly
    ) ps

@[inline] def positions : K3Classification → Array Nat
  | .clear              => #[]
  | .hazard sub ps      => Function.const K3SubThreat ps sub

end K3Classification

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Codepoint probes
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cp` is U+202F NARROW NO-BREAK SPACE.  Per UCD this
    is `gc=Zs` (space separator), NOT default-ignorable; the
    K3 detector treats it as a watermark marker on its own
    inventory because no L1–L5 family classifies it under the
    same lens. -/
@[inline] def isNnbsp (cp : Nat) : Bool := decide (cp = 0x202F)

/-- True iff `cp` is U+200D ZERO WIDTH JOINER. -/
@[inline] def isZwj (cp : Nat) : Bool := decide (cp = 0x200D)

/-- True iff `cp` is a Variation Selector.  The basic VS block
    (U+FE00..U+FE0F) carries VS1..VS16; Plane-14 IVS
    (U+E0100..U+E01EF) carries VS17..VS256. -/
@[inline] def isVariationSelector (cp : Nat) : Bool :=
  (decide (0xFE00 ≤ cp) && decide (cp ≤ 0xFE0F))
  || (decide (0xE0100 ≤ cp) && decide (cp ≤ 0xE01EF))

/-- True iff `cp` is Default_Ignorable_Code_Point per
    DerivedCoreProperties.txt. -/
@[inline] def isDefaultIgnorable (cp : Nat) : Bool :=
  Unicode.Identifier.inRanges cp
    Unicode.Generated.DerivedCoreProperties.defaultIgnorable

/-- True iff `cp` has `Emoji = Yes` per emoji-data.txt. -/
@[inline] def isEmoji (cp : Nat) : Bool :=
  Unicode.Generated.EmojiData.isEmoji cp

/-- True iff `input[i]` is adjacent (immediate predecessor OR
    immediate successor in the codepoint stream) to an emoji
    codepoint.  Used by the VS and ZWJ probes to exclude
    legitimate emoji-context occurrences from K3's marker
    inventory.  Two-sided check, single pass. -/
def isAdjacentToEmoji (input : Array Nat) (i : Nat) : Bool :=
  let prevIsEmoji :=
    if h0 : 0 < i then
      if hLt : i - 1 < input.size then
        isEmoji input[i - 1]
      else
        Function.const (0 < i) false h0
    else false
  let nextIsEmoji :=
    if hLt : i + 1 < input.size then
      isEmoji input[i + 1]
    else false
  prevIsEmoji || nextIsEmoji

/-- All positions in `input` matching predicate `p`. -/
def allPositions (p : Nat → Bool) (input : Array Nat) : Array Nat :=
  (Array.range input.size).filterMap (fun i =>
    if h : i < input.size then
      if p input[i] then some i else none
    else none)

/-- Count of codepoints in `input` matching predicate `p`. -/
@[inline] def countWhere (p : Nat → Bool) (input : Array Nat) : Nat :=
  (input.filter p).size

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Probe spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

theorem isNnbsp_positive : isNnbsp 0x202F = true := by native_decide
theorem isNnbsp_negative_space : isNnbsp 0x20 = false := by native_decide
theorem isNnbsp_negative_ideographic : isNnbsp 0x3000 = false := by native_decide

theorem isZwj_positive : isZwj 0x200D = true := by native_decide
theorem isZwj_negative_zwsp : isZwj 0x200B = false := by native_decide
theorem isZwj_negative_zwnj : isZwj 0x200C = false := by native_decide

theorem isVS_positive_VS1 : isVariationSelector 0xFE00 = true := by native_decide
theorem isVS_positive_VS16 : isVariationSelector 0xFE0F = true := by native_decide
theorem isVS_positive_IVS1 : isVariationSelector 0xE0100 = true := by native_decide
theorem isVS_negative_ascii : isVariationSelector 0x61 = false := by native_decide
theorem isVS_negative_zwj : isVariationSelector 0x200D = false := by native_decide

theorem isDefaultIgnorable_zwsp :
    isDefaultIgnorable 0x200B = true := by native_decide
theorem isDefaultIgnorable_zwj :
    isDefaultIgnorable 0x200D = true := by native_decide
theorem isDefaultIgnorable_softHyphen :
    isDefaultIgnorable 0x00AD = true := by native_decide
theorem isDefaultIgnorable_nnbsp_false :
    isDefaultIgnorable 0x202F = false := by native_decide
theorem isDefaultIgnorable_ascii_false :
    isDefaultIgnorable 0x61 = false := by native_decide

theorem isEmoji_smiley : isEmoji 0x1F600 = true := by native_decide
theorem isEmoji_zwj_false : isEmoji 0x200D = false := by native_decide
theorem isEmoji_ascii_false : isEmoji 0x61 = false := by native_decide

/-- VS16 sitting between 'a' and 'b' (no emoji adjacent) — flagged. -/
theorem isAdjacentToEmoji_negative :
    isAdjacentToEmoji #[0x61, 0xFE0F, 0x62] 1 = false := by native_decide

/-- VS16 sitting after 😀 — adjacent to emoji, excluded. -/
theorem isAdjacentToEmoji_after_smiley :
    isAdjacentToEmoji #[0x1F600, 0xFE0F] 1 = true := by native_decide

/-- VS16 sitting before 😀 — adjacent to emoji, excluded. -/
theorem isAdjacentToEmoji_before_smiley :
    isAdjacentToEmoji #[0xFE0F, 0x1F600] 0 = true := by native_decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The K3 detection function.

    Priority order (first hit wins):
      1. `nnbspBoundary`           — any U+202F NNBSP present.
      2. `variationSelectorCarrier` — VS NOT adjacent to emoji.
      3. `zwjNonEmoji`             — ZWJ NOT adjacent to emoji.
      4. `defaultIgnorableCarrier` — residual Default_Ignorable
                                     codepoint (not already
                                     classified above).
      5. clear                     — no watermark marker.

    The `markerCount` field carries the count of codepoints
    matching the fired scheme (0 when clear).  Positions array
    holds every position matching the fired scheme.
-/
def detect (input : Array Nat) : K3Verdict :=
  let nnbspPositions := allPositions isNnbsp input
  let nnbspCount := nnbspPositions.size

  let vsAllPos := allPositions isVariationSelector input
  let vsNonEmojiPos := vsAllPos.filter
    (fun i => ¬ (isAdjacentToEmoji input i))
  let vsNonEmojiCount := vsNonEmojiPos.size

  let zwjAllPos := allPositions isZwj input
  let zwjNonEmojiPos := zwjAllPos.filter
    (fun i => ¬ (isAdjacentToEmoji input i))
  let zwjNonEmojiCount := zwjNonEmojiPos.size

  -- Residual default-ignorables: exclude codepoints already
  -- classified by the three probes above so a single ZWJ
  -- doesn't fire BOTH zwjNonEmoji AND defaultIgnorableCarrier.
  let isResidualDI : Nat → Bool := fun cp =>
    isDefaultIgnorable cp
    && (¬ isVariationSelector cp)
    && (¬ isZwj cp)
  let diPositions := allPositions isResidualDI input
  let diCount := diPositions.size

  let (classification, firedCount) : K3Classification × Nat :=
    if nnbspCount > 0 then
      (.hazard (.nnbspBoundary nnbspCount) nnbspPositions, nnbspCount)
    else if vsNonEmojiCount > 0 then
      (.hazard (.variationSelectorCarrier vsNonEmojiCount) vsNonEmojiPos,
       vsNonEmojiCount)
    else if zwjNonEmojiCount > 0 then
      (.hazard (.zwjNonEmoji zwjNonEmojiCount) zwjNonEmojiPos,
       zwjNonEmojiCount)
    else if diCount > 0 then
      (.hazard (.defaultIgnorableCarrier diCount) diPositions, diCount)
    else (.clear, 0)

  { input := input,
    classify := classification,
    markerCount := firedCount }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 Detect spot-check theorems
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear (vacuous no-watermark). -/
theorem detect_empty_clear :
    (detect #[]).classify = .clear := by native_decide

/-- Pure ASCII is clear — no markers. -/
theorem detect_ascii_clear :
    (detect #[0x61, 0x62, 0x63]).classify = .clear := by native_decide

/-- CJK Han is clear — no markers. -/
theorem detect_han_clear :
    (detect #[0x4E2D, 0x6587]).classify = .clear := by native_decide

/-- Single U+202F NNBSP fires NnbspBoundary at position 1. -/
theorem detect_nnbsp_fires :
    let v := detect #[0x61, 0x202F, 0x62]
    v.classify.tag = some "NnbspBoundary"
    ∧ v.classify.positions = #[1]
    ∧ v.markerCount = 1 := by native_decide

/-- VS16 between ASCII letters (no emoji adjacent) fires
    VariationSelectorCarrier. -/
theorem detect_vs_in_plain_text_fires :
    let v := detect #[0x61, 0xFE0F, 0x62]
    v.classify.tag = some "VariationSelectorCarrier"
    ∧ v.markerCount = 1 := by native_decide

/-- VS16 after 😀 is legitimate emoji-presentation selector —
    K3 stays clear.  Pins the emoji-adjacency exclusion. -/
theorem detect_vs_after_emoji_clear :
    (detect #[0x1F600, 0xFE0F]).classify = .clear := by native_decide

/-- ZWJ between ASCII letters fires ZwjNonEmoji. -/
theorem detect_zwj_in_plain_text_fires :
    let v := detect #[0x61, 0x200D, 0x62]
    v.classify.tag = some "ZwjNonEmoji"
    ∧ v.markerCount = 1 := by native_decide

/-- ZWJ between two emoji bases is legitimate emoji-ZWJ
    sequence — K3 stays clear.  The "woman + ZWJ + scientist"
    sequence base 👩 (U+1F469) + ZWJ + 🔬 (U+1F52C) shape. -/
theorem detect_zwj_emoji_sequence_clear :
    (detect #[0x1F469, 0x200D, 0x1F52C]).classify = .clear := by
  native_decide

/-- SOFT HYPHEN (U+00AD) fires DefaultIgnorableCarrier — it's
    default-ignorable, not NNBSP, not VS, not ZWJ. -/
theorem detect_soft_hyphen_fires :
    let v := detect #[0x61, 0x00AD, 0x62]
    v.classify.tag = some "DefaultIgnorableCarrier"
    ∧ v.markerCount = 1 := by native_decide

/-- ZWSP (U+200B) fires DefaultIgnorableCarrier — it's
    default-ignorable but not classified by the three probes
    above (ZWJ-specific, VS-specific, or NNBSP).  The C3
    BareZeroWidth family ALSO fires; K3 is the watermark lens,
    C3 is the covert-channel lens.  Composite rejection at
    higher Levels; isolated rejection under
    `cryptoAdmissible .aiAttribution`. -/
theorem detect_zwsp_fires :
    let v := detect #[0x61, 0x200B, 0x62]
    v.classify.tag = some "DefaultIgnorableCarrier"
    ∧ v.markerCount = 1 := by native_decide

/-- Priority pin: when BOTH NNBSP and a default-ignorable fire,
    NnbspBoundary wins (priority 1 over priority 4).  Pinned by
    NNBSP + SOFT HYPHEN co-occurring. -/
theorem detect_priority_nnbsp_over_di :
    let v := detect #[0x61, 0x202F, 0x00AD, 0x62]
    v.classify.tag = some "NnbspBoundary" := by native_decide

/-- Priority pin: when BOTH VS-non-emoji and ZWJ-non-emoji
    apply, VariationSelectorCarrier wins (priority 2 over
    priority 3). -/
theorem detect_priority_vs_over_zwj :
    let v := detect #[0x61, 0xFE0F, 0x200D, 0x62]
    v.classify.tag = some "VariationSelectorCarrier" := by
  native_decide

/-- Multiple NNBSPs are aggregated into a single
    NnbspBoundary verdict with markerCount = total. -/
theorem detect_multiple_nnbsp_aggregates :
    let v := detect #[0x61, 0x202F, 0x62, 0x202F, 0x63]
    v.classify.tag = some "NnbspBoundary"
    ∧ v.markerCount = 2
    ∧ v.classify.positions = #[1, 3] := by native_decide

end Unicode.Security.Crypto.AiWatermarkDetectability
