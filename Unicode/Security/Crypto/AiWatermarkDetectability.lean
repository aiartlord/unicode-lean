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
  in `SubThreat` for future-extension consistency but never
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
inductive SubThreat where
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
inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : Array Nat)
  deriving DecidableEq, Repr, Inhabited

/-- K3 verdict — the structured output of `detect`.
    `markerCount` is the count of codepoints matching the fired
    scheme's probe (0 when clear).  Mirrors K2's `stableSize`
    in shape — a single scalar the harness can pin on every
    fixture row. -/
structure Verdict where
  input        : Array Nat
  classify     : Classification
  markerCount  : Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Universal projections (isClear / tag / positions)
-- ═══════════════════════════════════════════════════════════════════════════════

namespace Classification

@[inline] def isClear : Classification → Bool
  | .clear              => true
  | .hazard sub ps      =>
    Function.const (SubThreat × Array Nat) false (sub, ps)

@[inline] def tag : Classification → Option String
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

@[inline] def positions : Classification → Array Nat
  | .clear              => #[]
  | .hazard sub ps      => Function.const SubThreat ps sub

end Classification

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

/-- True iff `cp` is U+200B ZERO WIDTH SPACE.  Used by the
    `gpt5ZwspModulo` probe to detect ZWSP carriers. -/
@[inline] def isZwsp (cp : Nat) : Bool := decide (cp = 0x200B)

/-- True iff `cp` is U+2014 EM DASH.  Used by the `emDashPattern`
    probe to detect the "AI-prefers-em-dash" stylistic
    signature. -/
@[inline] def isEmDash (cp : Nat) : Bool := decide (cp = 0x2014)

/-- True iff `cp` is U+002D HYPHEN-MINUS (ASCII).  Used as the
    natural-writing baseline for the `emDashPattern` probe. -/
@[inline] def isHyphenMinus (cp : Nat) : Bool := decide (cp = 0x002D)

/-- True iff `cp` is one of the four "curly" / typographic
    quotation marks: U+2018 / U+2019 (single open/close) and
    U+201C / U+201D (double open/close).  Used by the
    `smartQuoteAlternation` probe. -/
@[inline] def isCurlyQuote (cp : Nat) : Bool :=
  decide (cp = 0x2018) || decide (cp = 0x2019)
  || decide (cp = 0x201C) || decide (cp = 0x201D)

/-- True iff `cp` is an ASCII straight quote — U+0022 (double)
    or U+0027 (single / apostrophe).  Used as the natural-
    writing baseline for the `smartQuoteAlternation` probe. -/
@[inline] def isStraightQuote (cp : Nat) : Bool :=
  decide (cp = 0x0022) || decide (cp = 0x0027)

/-- True iff `positions` forms an arithmetic progression
    (all consecutive gaps equal).  Empty + singleton arrays
    are vacuously arithmetic.  Used by the `adversarial`
    (NNBSP-too-regular) and `gpt5ZwspModulo` (ZWSP-modulo)
    probes to detect over-regular marker placement. -/
def positionsAreArithmetic (positions : Array Nat) : Bool :=
  if positions.size < 2 then true
  else
    let p0 := positions.getD 0 0
    let p1 := positions.getD 1 0
    let firstGap := p1 - p0
    (Array.range (positions.size - 1)).all (fun i =>
      let curr := positions.getD i 0
      let next := positions.getD (i + 1) 0
      decide (next - curr = firstGap))

/-- First start-position at which `pattern` appears as a
    contiguous subarray of `input`, or `none` if absent.  Used
    by `statisticalTokenChoice` to scan for AI-favored lexical
    patterns. -/
def containsSubarray (pattern input : Array Nat) : Option Nat :=
  if pattern.size = 0 then none
  else if pattern.size > input.size then none
  else
    let maxStart := input.size - pattern.size
    (Array.range (maxStart + 1)).findSome? (fun start =>
      if (Array.range pattern.size).all (fun j =>
        let inputAtPos := input.getD (start + j) 0
        let patternAtPos := pattern.getD j 0
        decide (inputAtPos = patternAtPos))
      then some start else none)

/-- A small catalog of "AI-favored" lexical patterns — words
    over-represented in public reports of GPT-class output.
    Each pattern is the codepoint sequence for an ASCII word.
    v1 covers "delve", "tapestry", "moreover".  Extending this
    catalog is the maintenance path for the
    `statisticalTokenChoice` probe; no signature change is
    needed. -/
def aiFavoredVocabulary : Array (Array Nat) :=
  #[ #[0x64, 0x65, 0x6C, 0x76, 0x65]                      -- "delve"
   , #[0x74, 0x61, 0x70, 0x65, 0x73, 0x74, 0x72, 0x79]    -- "tapestry"
   , #[0x6D, 0x6F, 0x72, 0x65, 0x6F, 0x76, 0x65, 0x72]    -- "moreover"
   ]

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

    Priority order (first hit wins, most specific first):
       1. `adversarial`             — NNBSP count ≥ 3 AND
                                      positions form an
                                      arithmetic progression
                                      (over-regular placement
                                      suggests deliberate
                                      injection).
       2. `gpt5ZwspModulo`          — ZWSP count ≥ 3 AND
                                      positions form an
                                      arithmetic progression.
       3. `unknown`                 — invisible markers from
                                      ≥ 2 distinct categories
                                      (NNBSP / VS / ZWJ /
                                      residual-DI) co-occur in
                                      the same input.  Means
                                      "we see watermark markers
                                      but cannot attribute them
                                      to a single scheme."
       4. `nnbspBoundary`           — any U+202F NNBSP present
                                      (single-category input).
       5. `variationSelectorCarrier` — VS NOT adjacent to emoji.
       6. `zwjNonEmoji`             — ZWJ NOT adjacent to emoji.
       7. `smartQuoteAlternation`   — paired curly quotes (count
                                      ≥ 2) AND no ASCII straight
                                      quotes (the "AI prefers
                                      curly quotes" stylistic
                                      signature).
       8. `emDashPattern`           — em-dash count ≥ 2 AND no
                                      ASCII hyphen-minus (the
                                      "AI prefers em-dashes"
                                      stylistic signature).
       9. `statisticalTokenChoice`  — input contains a known
                                      AI-favored lexical pattern
                                      from `aiFavoredVocabulary`.
      10. `defaultIgnorableCarrier` — residual Default_Ignorable
                                      codepoint (single-category
                                      DI input).
      11. clear                     — no watermark marker.

    The `markerCount` field carries the count of codepoints
    matching the fired scheme (0 when clear).  Positions array
    holds every position matching the fired scheme.

    Why "specific first": adversarial is a refinement of
    nnbspBoundary; gpt5ZwspModulo refines defaultIgnorableCarrier
    (ZWSP is default-ignorable); smartQuoteAlternation /
    emDashPattern / statisticalTokenChoice are visible-character
    signatures.  Ordering them most-specific-first ensures the
    verdict names the most-informative attribution available.
-/
def detect (input : Array Nat) : Verdict :=
  let nnbspPositions := allPositions isNnbsp input
  let nnbspCount := nnbspPositions.size

  -- Probe 1: adversarial — NNBSP too-regular.
  let adversarialFires :=
    decide (nnbspCount ≥ 3) ∧ positionsAreArithmetic nnbspPositions

  -- Probe 2: gpt5ZwspModulo — ZWSP arithmetic progression.
  let zwspPositions := allPositions isZwsp input
  let zwspCount := zwspPositions.size
  let zwspModuloFires :=
    decide (zwspCount ≥ 3) ∧ positionsAreArithmetic zwspPositions

  let vsAllPos := allPositions isVariationSelector input
  let vsNonEmojiPos := vsAllPos.filter
    (fun i => ¬ (isAdjacentToEmoji input i))
  let vsNonEmojiCount := vsNonEmojiPos.size

  let zwjAllPos := allPositions isZwj input
  let zwjNonEmojiPos := zwjAllPos.filter
    (fun i => ¬ (isAdjacentToEmoji input i))
  let zwjNonEmojiCount := zwjNonEmojiPos.size

  -- Probe 6: smartQuoteAlternation — curly quotes only.
  let curlyPositions := allPositions isCurlyQuote input
  let curlyCount := curlyPositions.size
  let hasStraightQuote := input.any isStraightQuote
  let smartQuoteFires := decide (curlyCount ≥ 2) ∧ ¬ hasStraightQuote

  -- Probe 7: emDashPattern — em-dashes without hyphen-minus.
  let emDashPositions := allPositions isEmDash input
  let emDashCount := emDashPositions.size
  let hasHyphenMinus := input.any isHyphenMinus
  let emDashFires := decide (emDashCount ≥ 2) ∧ ¬ hasHyphenMinus

  -- Probe 8: statisticalTokenChoice — scan vocabulary.
  let vocabHit := aiFavoredVocabulary.findSome?
    (fun pattern => containsSubarray pattern input)

  -- Residual default-ignorables (excluding ZWSP — handled by
  -- gpt5ZwspModulo first when the modulo pattern matches; bare
  -- ZWSPs without the modulo pattern STILL fall through to
  -- defaultIgnorableCarrier).
  let isResidualDI : Nat → Bool := fun cp =>
    isDefaultIgnorable cp
    && (¬ isVariationSelector cp)
    && (¬ isZwj cp)
  let diPositions := allPositions isResidualDI input
  let diCount := diPositions.size

  -- Probe 3: unknown — invisible markers from multiple
  -- categories.  Means the input mixes scheme-relevant
  -- codepoints in a way that prevents single-scheme
  -- attribution.  Counts how many of the four invisible
  -- categories (NNBSP / VS-non-emoji / ZWJ-non-emoji /
  -- residual-DI) have any markers; if ≥ 2, fire.
  let categoryCount : Nat :=
    (if nnbspCount > 0 then 1 else 0)
    + (if vsNonEmojiCount > 0 then 1 else 0)
    + (if zwjNonEmojiCount > 0 then 1 else 0)
    + (if diCount > 0 then 1 else 0)
  let unknownFires := decide (categoryCount ≥ 2)
  let totalInvisibleCount :=
    nnbspCount + vsNonEmojiCount + zwjNonEmojiCount + diCount

  let (classification, firedCount) : Classification × Nat :=
    if adversarialFires then
      let firstPos := nnbspPositions.getD 0 0
      (.hazard (.adversarial "nnbspBoundary" firstPos) nnbspPositions,
       nnbspCount)
    else if zwspModuloFires then
      let firstPos := zwspPositions.getD 0 0
      (.hazard (.gpt5ZwspModulo firstPos) zwspPositions, zwspCount)
    else if unknownFires then
      let allInvisiblePos :=
        (Array.range input.size).filterMap (fun i =>
          let cp := input.getD i 0
          if isNnbsp cp || isVariationSelector cp
             || isZwj cp || isDefaultIgnorable cp
          then some i else none)
      (.hazard (.unknown totalInvisibleCount) allInvisiblePos,
       totalInvisibleCount)
    else if nnbspCount > 0 then
      (.hazard (.nnbspBoundary nnbspCount) nnbspPositions, nnbspCount)
    else if vsNonEmojiCount > 0 then
      (.hazard (.variationSelectorCarrier vsNonEmojiCount) vsNonEmojiPos,
       vsNonEmojiCount)
    else if zwjNonEmojiCount > 0 then
      (.hazard (.zwjNonEmoji zwjNonEmojiCount) zwjNonEmojiPos,
       zwjNonEmojiCount)
    else if smartQuoteFires then
      let firstPos := curlyPositions.getD 0 0
      (.hazard (.smartQuoteAlternation firstPos) curlyPositions, curlyCount)
    else if emDashFires then
      let firstPos := emDashPositions.getD 0 0
      (.hazard (.emDashPattern firstPos) emDashPositions, emDashCount)
    else match vocabHit with
    | some pos =>
      (.hazard (.statisticalTokenChoice pos) #[pos], 1)
    | none =>
      if diCount > 0 then
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

/-- Priority pin: when NNBSP AND a default-ignorable co-occur,
    `Unknown` fires (priority 3) — the input mixes two
    invisible-marker categories and cannot be attributed to a
    single scheme.  Pinned by NNBSP + SOFT HYPHEN. -/
theorem detect_priority_unknown_over_nnbsp_with_di :
    let v := detect #[0x61, 0x202F, 0x00AD, 0x62]
    v.classify.tag = some "Unknown" := by native_decide

/-- Priority pin: when BOTH VS-non-emoji and ZWJ-non-emoji
    apply, `Unknown` fires (priority 3) — same multi-category
    semantic as above. -/
theorem detect_priority_unknown_over_vs_with_zwj :
    let v := detect #[0x61, 0xFE0F, 0x200D, 0x62]
    v.classify.tag = some "Unknown" := by
  native_decide

/-- Multiple NNBSPs are aggregated into a single
    NnbspBoundary verdict with markerCount = total. -/
theorem detect_multiple_nnbsp_aggregates :
    let v := detect #[0x61, 0x202F, 0x62, 0x202F, 0x63]
    v.classify.tag = some "NnbspBoundary"
    ∧ v.markerCount = 2
    ∧ v.classify.positions = #[1, 3] := by native_decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 Refinement-probe spot checks (the six previously-deferred variants)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- `adversarial` fires when input has ≥ 3 NNBSPs at arithmetic-
    progression positions (every-second-character placement).
    Pinning that the over-regular pattern outranks the generic
    `nnbspBoundary` verdict. -/
theorem detect_adversarial_arithmetic_nnbsp :
    -- "a NNBSP b NNBSP c NNBSP d" — NNBSPs at 1,3,5 (gap 2).
    let v := detect #[0x61, 0x202F, 0x62, 0x202F, 0x63, 0x202F, 0x64]
    v.classify.tag = some "Adversarial"
    ∧ v.markerCount = 3 := by native_decide

/-- 2-NNBSP input STAYS in `nnbspBoundary` — adversarial
    threshold is ≥ 3. -/
theorem detect_nnbsp_two_below_adversarial_threshold :
    (detect #[0x61, 0x202F, 0x62, 0x202F, 0x63]).classify.tag
      = some "NnbspBoundary" := by native_decide

/-- `gpt5ZwspModulo` fires when input has ≥ 3 ZWSPs at
    arithmetic-progression positions.  ZWSPs are default-
    ignorable, so the modulo pattern outranks the generic
    `defaultIgnorableCarrier` verdict. -/
theorem detect_gpt5_zwsp_modulo :
    -- "a ZWSP b ZWSP c ZWSP d" — ZWSPs at 1,3,5 (gap 2).
    let v := detect #[0x61, 0x200B, 0x62, 0x200B, 0x63, 0x200B, 0x64]
    v.classify.tag = some "Gpt5ZwspModulo"
    ∧ v.markerCount = 3 := by native_decide

/-- Two ZWSPs (below the modulo threshold of 3) fall through
    to `defaultIgnorableCarrier`. -/
theorem detect_zwsp_two_below_modulo_threshold :
    (detect #[0x61, 0x200B, 0x62, 0x200B, 0x63]).classify.tag
      = some "DefaultIgnorableCarrier" := by native_decide

/-- `smartQuoteAlternation` fires when input has ≥ 2 curly
    quotes and no ASCII straight quotes.  Position is the
    first curly-quote position. -/
theorem detect_smart_quote_alternation :
    -- "“abc”" — U+201C abc U+201D (LEFT DOUBLE / RIGHT DOUBLE).
    let v := detect #[0x201C, 0x61, 0x62, 0x63, 0x201D]
    v.classify.tag = some "SmartQuoteAlternation"
    ∧ v.markerCount = 2 := by native_decide

/-- Curly quotes mixed with ASCII straight quotes — the
    "natural-writing" baseline is broken; smartQuoteAlternation
    stays silent.  Falls through to `clear`. -/
theorem detect_smart_quote_with_straight_clear :
    -- U+201C abc U+201D + ASCII '"'
    (detect #[0x201C, 0x61, 0x22, 0x201D]).classify = .clear := by
  native_decide

/-- `emDashPattern` fires when input has ≥ 2 em-dashes and no
    ASCII hyphen-minus. -/
theorem detect_em_dash_pattern :
    -- "ab — cd — ef"
    let v := detect
      #[0x61, 0x62, 0x20, 0x2014, 0x20, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66]
    v.classify.tag = some "EmDashPattern"
    ∧ v.markerCount = 2 := by native_decide

/-- Em-dashes mixed with ASCII hyphen-minus — natural-writing
    baseline present; emDashPattern stays silent. -/
theorem detect_em_dash_with_hyphen_clear :
    -- "ab-cd — ef"
    (detect #[0x61, 0x62, 0x2D, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66]).classify
    = .clear := by native_decide

/-- `statisticalTokenChoice` fires on the AI-favored word
    "delve" as a contiguous codepoint sub-array of input. -/
theorem detect_statistical_token_delve :
    -- "I delve into ..."  — bytes for "delve" at position 0.
    let v := detect #[0x64, 0x65, 0x6C, 0x76, 0x65]
    v.classify.tag = some "StatisticalTokenChoice"
    ∧ v.markerCount = 1 := by native_decide

/-- `statisticalTokenChoice` finds "moreover" embedded in a
    longer ASCII string. -/
theorem detect_statistical_token_moreover_embedded :
    -- "; moreover, "
    let v := detect
      #[0x3B, 0x20, 0x6D, 0x6F, 0x72, 0x65, 0x6F, 0x76, 0x65, 0x72, 0x2C, 0x20]
    v.classify.tag = some "StatisticalTokenChoice"
    ∧ v.classify.positions = #[2] := by native_decide

/-- `unknown` fires on multi-category invisible-marker mixing:
    NNBSP + DI co-occur — two distinct categories, cannot be
    attributed to a single scheme. -/
theorem detect_unknown_nnbsp_plus_di :
    let v := detect #[0x61, 0x202F, 0x00AD, 0x62]
    v.classify.tag = some "Unknown"
    ∧ v.markerCount = 2 := by native_decide

/-- `unknown` fires on VS + ZWJ co-occurring (both in plain
    non-emoji context). -/
theorem detect_unknown_vs_plus_zwj :
    let v := detect #[0x61, 0xFE0F, 0x200D, 0x62]
    v.classify.tag = some "Unknown"
    ∧ v.markerCount = 2 := by native_decide

/-- `unknown` fires on NNBSP + ZWJ co-occurring. -/
theorem detect_unknown_nnbsp_plus_zwj :
    let v := detect #[0x61, 0x202F, 0x200D, 0x62]
    v.classify.tag = some "Unknown"
    ∧ v.markerCount = 2 := by native_decide

/-- Single-category invisible-marker inputs DO NOT fire
    `unknown` — they fall through to the specific probe.
    Pin: single NNBSP fires nnbspBoundary (not unknown). -/
theorem detect_single_category_skips_unknown :
    (detect #[0x61, 0x202F, 0x62]).classify.tag
      = some "NnbspBoundary" := by native_decide

/-- Priority pin: `adversarial` fires before `nnbspBoundary`
    when both apply. -/
theorem detect_priority_adversarial_over_nnbsp :
    let v := detect #[0x61, 0x202F, 0x62, 0x202F, 0x63, 0x202F, 0x64]
    v.classify.tag = some "Adversarial" := by native_decide

/-- Priority pin: `gpt5ZwspModulo` fires before
    `defaultIgnorableCarrier` when both apply. -/
theorem detect_priority_zwsp_modulo_over_di :
    let v := detect #[0x61, 0x200B, 0x62, 0x200B, 0x63, 0x200B, 0x64]
    v.classify.tag = some "Gpt5ZwspModulo" := by native_decide

end Unicode.Security.Crypto.AiWatermarkDetectability
