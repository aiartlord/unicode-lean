/-
  Unicode.Security.Covert.ZeroWidthPayload

  C3 — Detection of payloads encoded in zero-width and
  near-zero-width Unicode codepoints.

  Threat model.  Tier A₁ (local injector).  Adversary embeds
  zero-width / no-glyph codepoints inside otherwise-normal text
  to carry a covert binary payload, to splice WORD JOINER /
  byte-order-mark sequences into identifiers, or to emit a
  suspected AI-watermark NNBSP pattern.

  Zero-width codepoint inventory.

    U+200B  ZERO WIDTH SPACE                (ZWSP)
    U+200C  ZERO WIDTH NON-JOINER            (ZWNJ)
    U+200D  ZERO WIDTH JOINER                (ZWJ)
    U+200E  LEFT-TO-RIGHT MARK               (LRM)
    U+200F  RIGHT-TO-LEFT MARK               (RLM)
    U+2060  WORD JOINER                      (WJ)
    U+2061..U+2064  invisible math operators
    U+202F  NARROW NO-BREAK SPACE            (NNBSP)
    U+FEFF  ZERO WIDTH NO-BREAK SPACE / BOM
    U+FFF9..U+FFFB  INTERLINEAR ANNOTATION marks

  Sanctioning model.

    * ZWJ between two emoji codepoints is a sanctioned RGI
      emoji-ZWJ-sequence position (per UTS #51) and is treated
      as `.clear`.
    * Every other zero-width occurrence is reportable.

  Algorithm shape (one pass over `input`).

    Phase 1 — collect zero-width positions.
    Phase 2 — remove positions that are RGI-context legitimate
              (ZWJ flanked by emoji codepoints).
    Phase 3 — short-circuit `.clear` if no suspicious positions.
    Phase 4 — classify sub-threat by priority:
                1. annotationMisuse     — U+FFF9..U+FFFB present
                                          and structurally invalid
                2. wordJoinerInjection  — U+2060 present
                3. aiWatermarkNNBSP     — U+202F count ≥ 2 (heuristic)
                4. binaryPayload        — ≥ 2 ZWSP/ZWJ pairings
                5. bareZeroWidth        — fallback
-/

import Unicode.Security.Calculus
import Unicode.Emoji
import Unicode.Generated.EmojiSequences
import Unicode.Generated.DerivedCoreProperties

namespace Unicode.Security.Covert.ZeroWidthPayload

open Unicode.Security.Calculus

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Sub-threat enumeration for C3.

    Priority order (highest first):
      1. `annotationMisuse`     structural-invariant violation
      2. `wordJoinerInjection`  WORD JOINER injection
      3. `aiWatermarkNNBSP`     suspected AI-watermark NNBSP burst
      4. `binaryPayload`        ZWSP/ZWJ binary alphabet present
      5. `bareZeroWidth`        single isolated zero-width fallback
-/
inductive SubThreat where
  | annotationMisuse    (anchors separators terminators : Nat)
  | wordJoinerInjection (count : Nat)
  | aiWatermarkNNBSP    (count : Nat)
  | binaryPayload       (zwspCount zwjCount : Nat)
  | bareZeroWidth       (cp : Nat)
  deriving DecidableEq, Repr, Inhabited

/-- Top-level classification for C3. -/
inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : Array Nat) (decoded : ByteArray)
  deriving Inhabited

/-- C3 verdict — the structured output of `detect`. -/
structure Verdict where
  input              : Array Nat
  classify           : Classification
  zwPositions        : Array Nat                  -- every zero-width position
  suspiciousPositions: Array Nat                  -- minus RGI-context ZWJ
  totalZeroWidth     : Nat
  zwspCount          : Nat
  zwjCount           : Nat
  wordJoinerCount    : Nat
  nnbspCount         : Nat
  annotationCount    : Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Core predicates
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cp` is a Unicode codepoint that renders as nothing
    OR is in the explicit "tracked zero-width" set (ZWSP, ZWNJ,
    ZWJ, LRM, RLM, WJ, NNBSP, BOM, annotations).

    Built on top of UCD `Default_Ignorable_Code_Point` plus the
    explicit list — `Default_Ignorable` catches every invisible
    codepoint per UAX #44 (soft hyphen, CGJ, ALM, Hangul fillers,
    Mongolian VS / vowel separator, INHIBIT/ACTIVATE controls,
    shorthand format, music format, etc.) while the explicit list
    preserves the existing sub-threat dispatch (NNBSP / WordJoiner /
    Annotation / BareZeroWidth).

    Sibling-detector codepoints are NOT re-handled here:
      - U+FE00..U+FE0F (VS1..VS16)        — VariationSelectorPayload
      - U+E0100..U+E01EF (VS17..VS256)    — VariationSelectorPayload
      - U+E0000..U+E007F (Tag block)      — TagBlockPayload
      - U+202A..U+202E (LRE/RLE/PDF/LRO/RLO) — BidiControlBalance
      - U+2066..U+2069 (LRI/RLI/FSI/PDI)   — BidiControlBalance
    These ARE Default_Ignorable per UCD but are dispatched to
    their own family detector for richer payload-decoding /
    bidi-stack tracking, so we EXCLUDE them from the ZW set to
    avoid double-counting.  LRM / RLM (U+200E / U+200F) are NOT
    excluded — they're direction markers, not push/pop bidi
    controls, and BidiControlBalance doesn't track them. -/
@[inline]
def isVariationSelectorRange (cp : Nat) : Bool :=
  (0xFE00 ≤ cp ∧ cp ≤ 0xFE0F) ∨
  (0xE0100 ≤ cp ∧ cp ≤ 0xE01EF)

@[inline]
def isTagBlockRange (cp : Nat) : Bool :=
  0xE0000 ≤ cp ∧ cp ≤ 0xE007F

@[inline]
def isBidiFormattingRange (cp : Nat) : Bool :=
  (0x202A ≤ cp ∧ cp ≤ 0x202E) ∨
  (0x2066 ≤ cp ∧ cp ≤ 0x2069)

@[inline]
def isZeroWidthChar (cp : Nat) : Bool :=
  -- The explicit historical set — preserved so the existing
  -- sub-threat dispatch (NNBSP / WordJoiner / Annotation /
  -- BareZeroWidth) reads exactly as before for these codepoints.
  --   U+200B..U+200F  ZWSP / ZWNJ / ZWJ / LRM / RLM
  --   U+2060..U+2064  WORD JOINER + invisible math operators
  --   U+202F          NARROW NO-BREAK SPACE  (AI watermark)
  --   U+FEFF          ZERO WIDTH NO-BREAK SPACE / BOM
  --   U+FFF9..U+FFFB  INTERLINEAR ANNOTATION marks
  (0x200B ≤ cp ∧ cp ≤ 0x200F) ∨
  (0x2060 ≤ cp ∧ cp ≤ 0x2064) ∨
  cp = 0x202F ∨
  cp = 0xFEFF ∨
  (0xFFF9 ≤ cp ∧ cp ≤ 0xFFFB) ∨
  -- UAX #44 Default_Ignorable_Code_Point — catches every other
  -- invisible codepoint (soft hyphen, CGJ, ALM, Hangul fillers,
  -- Mongolian VS / vowel separator, INHIBIT/ACTIVATE controls,
  -- shorthand-format, music-format, …).  Excluded: ranges
  -- handled by VariationSelectorPayload and TagBlockPayload.
  (Generated.DerivedCoreProperties.defaultIgnorable.any
    (fun lh => decide (lh.fst ≤ cp ∧ cp ≤ lh.snd))
    ∧ ¬ isVariationSelectorRange cp
    ∧ ¬ isTagBlockRange cp
    ∧ ¬ isBidiFormattingRange cp)

@[inline] def isZwsp (cp : Nat) : Bool := cp = 0x200B
@[inline] def isZwj  (cp : Nat) : Bool := cp = 0x200D
@[inline] def isWordJoiner (cp : Nat) : Bool := cp = 0x2060
@[inline] def isNNBSP (cp : Nat) : Bool := cp = 0x202F
@[inline] def isAnnotationAnchor     (cp : Nat) : Bool := cp = 0xFFF9
@[inline] def isAnnotationSeparator  (cp : Nat) : Bool := cp = 0xFFFA
@[inline] def isAnnotationTerminator (cp : Nat) : Bool := cp = 0xFFFB
@[inline] def isAnnotationMark       (cp : Nat) : Bool :=
  0xFFF9 ≤ cp ∧ cp ≤ 0xFFFB

/-- True iff a ZWJ at position `p` in `input` is flanked by two
    codepoints that *actually* participate in some registered RGI
    ZWJ sequence — `Unicode.Generated.EmojiSequences.isInZwjAlphabet`
    is the membership predicate derived from
    `emoji-zwj-sequences.txt` itself.

    The structural membership predicate is strictly narrower
    than `Unicode.Emoji.isEmoji`: keycap-eligible ASCII digits
    and other Emoji-property codepoints that never appear in
    any registered ZWJ sequence are excluded, so a ZWJ between
    two such codepoints is correctly classified as suspicious
    rather than legitimate. -/
def isLegitimateZwjContext (input : Array Nat) (p : Nat) : Bool :=
  if p > 0 ∧ p + 1 < input.size then
    Unicode.Generated.EmojiSequences.isInZwjAlphabet input[p - 1]! ∧
    Unicode.Generated.EmojiSequences.isInZwjAlphabet input[p + 1]!
  else
    false

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Aggregate counters
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Tally tracked zero-width codepoint counts in a single pass. -/
structure ZWCounts where
  zwspCount       : Nat
  zwjCount        : Nat
  wordJoinerCount : Nat
  nnbspCount      : Nat
  anchorCount     : Nat
  separatorCount  : Nat
  terminatorCount : Nat
  deriving Inhabited

def ZWCounts.zero : ZWCounts := default

def tally (input : Array Nat) : ZWCounts := Id.run do
  let mut c : ZWCounts := .zero
  for cp in input do
    if isZwsp cp then c := { c with zwspCount := c.zwspCount + 1 }
    if isZwj cp  then c := { c with zwjCount := c.zwjCount + 1 }
    if isWordJoiner cp then
      c := { c with wordJoinerCount := c.wordJoinerCount + 1 }
    if isNNBSP cp then c := { c with nnbspCount := c.nnbspCount + 1 }
    if isAnnotationAnchor cp then
      c := { c with anchorCount := c.anchorCount + 1 }
    if isAnnotationSeparator cp then
      c := { c with separatorCount := c.separatorCount + 1 }
    if isAnnotationTerminator cp then
      c := { c with terminatorCount := c.terminatorCount + 1 }
  pure c

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Sub-threat selection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff the annotation-mark counts violate the
    ANCHOR ... SEPARATOR ... TERMINATOR structural invariant.
    Strictly: every well-formed annotation has exactly equal
    counts of all three marks.  Anything else is a violation. -/
def annotationIllFormed (c : ZWCounts) : Bool :=
  let totalAnnotation := c.anchorCount + c.separatorCount + c.terminatorCount
  if totalAnnotation = 0 then false
  else
    decide (c.anchorCount ≠ c.separatorCount) ∨
    decide (c.separatorCount ≠ c.terminatorCount)

/-- Pick the sub-threat from the tallies.  Returns `none` when
    no zero-width suspicion remains after legitimacy filtering. -/
def pickSubThreat
    (suspicious : Array Nat) (input : Array Nat) (c : ZWCounts) :
    Option SubThreat :=
  if suspicious.isEmpty then
    none
  else if annotationIllFormed c then
    some (.annotationMisuse c.anchorCount c.separatorCount c.terminatorCount)
  else if c.wordJoinerCount > 0 then
    some (.wordJoinerInjection c.wordJoinerCount)
  else if c.nnbspCount ≥ 2 then
    some (.aiWatermarkNNBSP c.nnbspCount)
  else if c.zwspCount + c.zwjCount ≥ 2 then
    some (.binaryPayload c.zwspCount c.zwjCount)
  else
    let p := suspicious[0]!
    if h : p < input.size then
      some (.bareZeroWidth input[p])
    else
      some (.bareZeroWidth 0)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The C3 detection function.  Returns a structured verdict
    over the codepoint sequence `input`. -/
def detect (input : Array Nat) : Verdict :=
  -- Phase 1: collect every zero-width position.
  let zwPositions : Array Nat :=
    (Array.range input.size).filterMap (fun i =>
      if h : i < input.size then
        if isZeroWidthChar input[i] then some i else none
      else none)
  -- Phase 2: drop positions whose codepoint is ZWJ flanked by
  -- two emoji codepoints (sanctioned RGI emoji-ZWJ-sequence).
  let suspicious : Array Nat :=
    zwPositions.filter (fun p =>
      if h : p < input.size then
        let cp := input[p]
        ¬ (isZwj cp ∧ isLegitimateZwjContext input p)
      else true)
  let counts := tally input
  if zwPositions.isEmpty then
    { input := input,
      classify := .clear,
      zwPositions := #[],
      suspiciousPositions := #[],
      totalZeroWidth := 0,
      zwspCount := 0, zwjCount := 0,
      wordJoinerCount := 0, nnbspCount := 0, annotationCount := 0 }
  else
    let annotationCount :=
      counts.anchorCount + counts.separatorCount + counts.terminatorCount
    match pickSubThreat suspicious input counts with
    | none =>
      -- All zero-widths are legitimate (e.g., emoji ZWJ only).
      { input := input,
        classify := .clear,
        zwPositions := zwPositions,
        suspiciousPositions := #[],
        totalZeroWidth := zwPositions.size,
        zwspCount := counts.zwspCount, zwjCount := counts.zwjCount,
        wordJoinerCount := counts.wordJoinerCount,
        nnbspCount := counts.nnbspCount,
        annotationCount := annotationCount }
    | some sub =>
      { input := input,
        classify := .hazard sub suspicious ByteArray.empty,
        zwPositions := zwPositions,
        suspiciousPositions := suspicious,
        totalZeroWidth := zwPositions.size,
        zwspCount := counts.zwspCount, zwjCount := counts.zwjCount,
        wordJoinerCount := counts.wordJoinerCount,
        nnbspCount := counts.nnbspCount,
        annotationCount := annotationCount }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Fixture-row tag string for each `SubThreat` constructor. -/
def SubThreat.tag : SubThreat → String
  | .annotationMisuse    anchors separators terminators =>
      Function.const (Nat × Nat × Nat) "AnnotationMisuse"
        (anchors, separators, terminators)
  | .wordJoinerInjection count                          =>
      Function.const Nat "WordJoinerInjection" count
  | .aiWatermarkNNBSP    count                          =>
      Function.const Nat "AIWatermarkNNBSP" count
  | .binaryPayload       zwspCount zwjCount             =>
      Function.const (Nat × Nat) "BinaryPayload" (zwspCount, zwjCount)
  | .bareZeroWidth       cp                             =>
      Function.const Nat "BareZeroWidth" cp

/-- True iff the classification is `.clear`. -/
def Classification.isClear : Classification → Bool
  | .clear                     => true
  | .hazard sub positions decoded =>
      Function.const (SubThreat × Array Nat × ByteArray) false
        (sub, positions, decoded)

/-- Tag string of a classification (`none` for `.clear`). -/
def Classification.tag : Classification → Option String
  | .clear                     => none
  | .hazard sub positions decoded =>
      Function.const (Array Nat × ByteArray) (some sub.tag) (positions, decoded)

/-- Positions array of a classification (empty for `.clear`). -/
def Classification.positions : Classification → Array Nat
  | .clear                     => #[]
  | .hazard sub positions decoded =>
      Function.const (SubThreat × ByteArray) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear. -/
theorem detect_empty_clear : (detect #[]).classify.isClear = true := by
  decide

/-- Pure ASCII is clear. -/
theorem detect_ascii_clear :
    (detect #[0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  decide

/-- Emoji ZWJ sequence "👨‍💻" is clear (RGI-context). -/
theorem detect_emoji_zwj_clear :
    (detect #[0x1F468, 0x200D, 0x1F4BB]).classify.isClear = true := by
  decide

/-- ZWJ between two emojis remains clear even with a third emoji
    after another ZWJ. -/
theorem detect_emoji_zwj_chain_clear :
    (detect #[0x1F468, 0x200D, 0x1F469, 0x200D,
              0x1F466]).classify.isClear = true := by decide

/-- Two ZWSPs in plain text — `.binaryPayload`. -/
theorem detect_two_zwsp_binary :
    (detect #[0x48, 0x200B, 0x69, 0x200B, 0x69]).classify.tag
      = some "BinaryPayload" := by decide

/-- ZWSP + ZWJ mixed — `.binaryPayload` (ZWJ alone, no emoji context). -/
theorem detect_zwsp_zwj_mix_binary :
    (detect #[0x48, 0x200B, 0x200D, 0x69]).classify.tag
      = some "BinaryPayload" := by decide

/-- WORD JOINER injected into Latin text — `.wordJoinerInjection`. -/
theorem detect_word_joiner :
    (detect #[0x48, 0x2060, 0x69]).classify.tag
      = some "WordJoinerInjection" := by decide

/-- Two NNBSPs in a row — suspected AI watermark. -/
theorem detect_nnbsp_watermark :
    (detect #[0x48, 0x202F, 0x69, 0x202F, 0x6F]).classify.tag
      = some "AIWatermarkNNBSP" := by decide

/-- Bare BOM (`U+FEFF`) in the middle of text — `.bareZeroWidth`. -/
theorem detect_bare_bom :
    (detect #[0x48, 0xFEFF, 0x69]).classify.tag
      = some "BareZeroWidth" := by decide

/-- A single bare ZWSP — `.bareZeroWidth`. -/
theorem detect_bare_zwsp :
    (detect #[0x48, 0x200B, 0x69]).classify.tag
      = some "BareZeroWidth" := by decide

/-- Annotation anchor without separator + terminator — misuse. -/
theorem detect_annotation_misuse :
    (detect #[0x48, 0xFFF9, 0x69]).classify.tag
      = some "AnnotationMisuse" := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 Predicate sanity checks
-- ═══════════════════════════════════════════════════════════════════════════════

theorem is_zw_zwsp : isZeroWidthChar 0x200B = true := by decide
theorem is_zw_zwj : isZeroWidthChar 0x200D = true := by decide
theorem is_zw_wj : isZeroWidthChar 0x2060 = true := by decide
theorem is_zw_nnbsp : isZeroWidthChar 0x202F = true := by decide
theorem is_zw_bom : isZeroWidthChar 0xFEFF = true := by decide
theorem is_zw_anchor : isZeroWidthChar 0xFFF9 = true := by decide
theorem is_zw_terminator : isZeroWidthChar 0xFFFB = true := by decide
theorem is_zw_ascii : isZeroWidthChar 0x41 = false := by decide
theorem is_zw_emoji : isZeroWidthChar 0x1F600 = false := by decide

end Unicode.Security.Covert.ZeroWidthPayload
