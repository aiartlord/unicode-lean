/-
  Unicode.Security.Display.RtlInjection

  D3 — Detection of right-to-left content injected into nominally
  left-to-right contexts (form fields, URLs, log lines,
  identifier-bearing UI text declared LTR).

  Threat model.  Tier A₁..A₂.  Adversary inserts strong-RTL
  codepoints or RTL bidi format-controls into a field whose
  declared display direction is LTR, causing the surrounding
  display to reorder.  Distinct from C5 (Trojan Source) — D3
  flags strong-RTL content regardless of bidi-balance, while C5
  is specifically about unbalanced embedding / isolate / orphan
  pop in source-code context.

  v1 scope: the input is treated as a declared-LTR string.  Pure
  Hebrew / Arabic / Persian text fires strong-RTL detection in
  this mode.  Callers handling Hebrew / Arabic / Persian UI
  strings must declare the field as RTL and dispatch to a
  separate detector; this module does not auto-detect declared
  direction from the input.

  v1.5 region-aware tokenization (this revision).  The
  `detect` function takes an optional `Language` parameter that
  dispatches to the shared `Unicode.Security.Display.SourceCode
  Tokenize` state machine.  Under `Language.cStyleGeneric` or
  `Language.rust`, sub-detector hits whose position sits inside
  a string literal, line comment, or block comment are filtered
  out — the bidi codepoint is data or documentation, not
  display deception in the surrounding code.  Under
  `Language.none` the whole input is treated as one code
  region, preserving v1 behaviour exactly.

  Mirrors the v1.5 plumbing in
  `Unicode.Security.Display.SourceDisplayDivergence` and uses
  the same `positionInCode` predicate.

  Sub-threats (priority order):

    1. `rloInLTRField`    any bidi format-control codepoint
                          (LRE/RLE/LRO/RLO/PDF/LRI/RLI/FSI/PDI).
    2. `fieldTakeover`    the first non-trivial strong character
                          is RTL (causes the whole field to
                          render right-to-left).
    3. `strongRTLInLTR`   ≥ 1 strong-RTL codepoint inside an
                          otherwise-LTR stream (anywhere except
                          leading).
    4. `mixedOverflow`    a run of ≥ 4 consecutive strong-RTL
                          characters in the middle of the input
                          (heuristic for visible reordering).
-/

import Unicode.Security.Calculus
import Unicode.Security.Display.SourceCodeTokenize
import Unicode.TrojanSource
import Unicode.Bidi.Algorithm

namespace Unicode.Security.Display.RtlInjection

open Unicode.Security.Calculus
open Unicode.Security.Display.SourceCodeTokenize (Language positionInCode)
open Unicode.Generated.DerivedBidiClass (BidiClass)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

inductive D3SubThreat where
  | rloInLTRField   (controlPos : Nat) (controlCp : Nat)
  | fieldTakeover   (firstRtlPos : Nat) (firstRtlCp : Nat)
  | strongRTLInLTR  (rtlCount : Nat) (firstPos : Nat)
  | mixedOverflow   (runLength : Nat) (runStart : Nat)
  deriving DecidableEq, Repr, Inhabited

inductive D3Classification where
  | clear
  | hazard (sub : D3SubThreat) (positions : Array Nat) (decoded : ByteArray)
  deriving Inhabited

structure D3Verdict where
  input              : Array Nat
  classify           : D3Classification
  strongRTLCount     : Nat
  strongLTRCount     : Nat
  bidiControlCount   : Nat
  longestRtlRunLen   : Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Core predicates
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff the codepoint's `Bidi_Class` is strong RTL (R or AL). -/
@[inline]
def isStrongRTL (cp : Nat) : Bool :=
  match Unicode.Bidi.Algorithm.lookupBidiClass cp with
  | .R       => true
  | .AL      => true
  | otherBc  => Function.const BidiClass false otherBc

/-- True iff the codepoint's `Bidi_Class` is strong LTR (L). -/
@[inline]
def isStrongLTR (cp : Nat) : Bool :=
  match Unicode.Bidi.Algorithm.lookupBidiClass cp with
  | .L       => true
  | otherBc  => Function.const BidiClass false otherBc

/-- True iff `cp` is one of the 9 bidi format-controls. -/
@[inline]
def isBidiControl (cp : Nat) : Bool :=
  Unicode.TrojanSource.isBidiFormatControl cp

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Counters and scanners
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Count of strong-RTL codepoints in `input`. -/
def countStrongRTL (input : Array Nat) : Nat :=
  input.foldl (fun n cp => if isStrongRTL cp then n + 1 else n) 0

/-- Count of strong-LTR codepoints in `input`. -/
def countStrongLTR (input : Array Nat) : Nat :=
  input.foldl (fun n cp => if isStrongLTR cp then n + 1 else n) 0

/-- Count of bidi format-control codepoints in `input`. -/
def countBidiControl (input : Array Nat) : Nat :=
  input.foldl (fun n cp => if isBidiControl cp then n + 1 else n) 0

/-- Position of the first bidi format-control in `input`. -/
def firstBidiControlPos (input : Array Nat) : Option (Nat × Nat) :=
  (Array.range input.size).findSome? (fun i =>
    if h : i < input.size then
      if isBidiControl input[i] then some (i, input[i]) else none
    else none)

/-- Position of the first strong codepoint (L, R, or AL) in `input`. -/
def firstStrongCharPos (input : Array Nat) : Option (Nat × Nat × Bool) :=
  -- Returns (position, codepoint, isRtl)
  (Array.range input.size).findSome? (fun i =>
    if h : i < input.size then
      let cp := input[i]
      if isStrongRTL cp then some (i, cp, true)
      else if isStrongLTR cp then some (i, cp, false)
      else none
    else none)

/-- Position of the first strong-RTL codepoint in `input`. -/
def firstStrongRTLPos (input : Array Nat) : Option (Nat × Nat) :=
  (Array.range input.size).findSome? (fun i =>
    if h : i < input.size then
      if isStrongRTL input[i] then some (i, input[i]) else none
    else none)

/-- Length of the longest consecutive run of strong-RTL codepoints
    in `input`, together with the starting position of that run.
    Returns `(0, 0)` if no RTL chars. -/
def longestRtlRun (input : Array Nat) : Nat × Nat := Id.run do
  let mut longest : Nat := 0
  let mut longestStart : Nat := 0
  let mut current : Nat := 0
  let mut currentStart : Nat := 0
  let mut i : Nat := 0
  for cp in input do
    if isStrongRTL cp then
      if current = 0 then currentStart := i
      current := current + 1
      if current > longest then
        longest := current
        longestStart := currentStart
    else
      current := 0
    i := i + 1
  pure (longest, longestStart)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The D3 detection function.  Assumes LTR-declared context.

    `lang` defaults to `Language.none`, which treats the whole
    input as one code region — equivalent to the v1
    language-agnostic behaviour.  Callers passing
    `Language.cStyleGeneric` or `Language.rust` get region-aware
    filtering: a sub-detector that would fire on a bidi
    codepoint sitting inside a string literal, line comment, or
    block comment is suppressed, because the codepoint is data
    or documentation, not display deception in the surrounding
    code.

    The aggregate counters (`strongRTLCount`, `strongLTRCount`,
    `bidiControlCount`, `longestRtlRunLen`) on the returned
    Verdict are computed against the whole input — they
    describe what the input contains, not what the detector
    decided to fire on.  Only `classify` is region-aware. -/
def detect (input : Array Nat) (lang : Language := .none) : D3Verdict :=
  let strongRTL := countStrongRTL input
  let strongLTR := countStrongLTR input
  let bidiCtl := countBidiControl input
  let (runLen, runStart) := longestRtlRun input
  let inCode (p : Nat) : Bool := positionInCode lang input p
  let classification : D3Classification :=
    -- Phase 1: bidi format-control trumps all, but only if the
    -- offending codepoint sits in code.  We walk the input to
    -- find the first in-code bidi control; if every bidi
    -- control is in string / comment context, we fall through
    -- to Phase 2 as if there were no bidi controls.
    let firstInCodeBidi : Option (Nat × Nat) :=
      (Array.range input.size).findSome? (fun i =>
        if h : i < input.size then
          if isBidiControl input[i] ∧ inCode i then
            some (i, input[i])
          else none
        else none)
    match firstInCodeBidi with
    | some (pos, ctlCp) =>
      .hazard (.rloInLTRField pos ctlCp) #[pos] ByteArray.empty
    | none =>
      -- Phase 2: leading-RTL field-direction takeover.  Same
      -- region-aware shift: we want the first STRONG character
      -- that's in code, since a leading RTL letter inside a
      -- string literal is a data point, not a field takeover.
      let firstInCodeStrong : Option (Nat × Nat × Bool) :=
        (Array.range input.size).findSome? (fun i =>
          if h : i < input.size then
            if ¬ inCode i then none
            else
              let cp := input[i]
              if isStrongRTL cp then some (i, cp, true)
              else if isStrongLTR cp then some (i, cp, false)
              else none
          else none)
      match firstInCodeStrong with
      | some (pos, cp, true) =>
        .hazard (.fieldTakeover pos cp) #[pos] ByteArray.empty
      | _ =>
        -- Phase 3: mid-stream strong-RTL.  Filter the run /
        -- count machinery through `inCode` to avoid firing on
        -- bidi text safely tucked inside a string literal.
        let inCodeRtlPositions : Array Nat :=
          (Array.range input.size).filterMap (fun i =>
            if h : i < input.size then
              if isStrongRTL input[i] ∧ inCode i then some i else none
            else none)
        let inCodeRtlCount : Nat := inCodeRtlPositions.size
        let inCodeRunLen : Nat := Id.run do
          let mut longest : Nat := 0
          let mut current : Nat := 0
          for i in Array.range input.size do
            if h : i < input.size then
              if isStrongRTL input[i] ∧ inCode i then
                current := current + 1
                if current > longest then longest := current
              else
                current := 0
          pure longest
        if inCodeRtlCount > 0 then
          if inCodeRunLen ≥ 4 then
            -- Find start of the longest in-code run.
            let firstInRun : Nat :=
              if h : inCodeRtlPositions.size > 0 then
                inCodeRtlPositions[0]'h
              else 0
            .hazard (.mixedOverflow inCodeRunLen firstInRun)
              #[firstInRun] ByteArray.empty
          else
            let firstRtlPos : Nat :=
              if h : inCodeRtlPositions.size > 0 then
                inCodeRtlPositions[0]'h
              else 0
            .hazard (.strongRTLInLTR inCodeRtlCount firstRtlPos)
              #[firstRtlPos] ByteArray.empty
        else
          .clear
  { input := input,
    classify := classification,
    strongRTLCount := strongRTL,
    strongLTRCount := strongLTR,
    bidiControlCount := bidiCtl,
    longestRtlRunLen := runLen }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Fixture-row tag string for each `D3SubThreat` constructor. -/
def D3SubThreat.tag : D3SubThreat → String
  | .rloInLTRField  controlPos controlCp =>
      Function.const (Nat × Nat) "RloInLTRField" (controlPos, controlCp)
  | .fieldTakeover  firstRtlPos firstRtlCp =>
      Function.const (Nat × Nat) "FieldTakeover" (firstRtlPos, firstRtlCp)
  | .strongRTLInLTR rtlCount firstPos =>
      Function.const (Nat × Nat) "StrongRTLInLTR" (rtlCount, firstPos)
  | .mixedOverflow  runLength runStart =>
      Function.const (Nat × Nat) "MixedOverflow" (runLength, runStart)

/-- True iff the classification is `.clear`. -/
def D3Classification.isClear : D3Classification → Bool
  | .clear                     => true
  | .hazard sub positions decoded =>
      Function.const (D3SubThreat × Array Nat × ByteArray) false
        (sub, positions, decoded)

/-- Tag string of a classification. -/
def D3Classification.tag : D3Classification → Option String
  | .clear                     => none
  | .hazard sub positions decoded =>
      Function.const (Array Nat × ByteArray) (some sub.tag) (positions, decoded)

/-- Positions array of a classification. -/
def D3Classification.positions : D3Classification → Array Nat
  | .clear                     => #[]
  | .hazard sub positions decoded =>
      Function.const (D3SubThreat × ByteArray) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear. -/
theorem detect_empty_clear : (detect #[]).classify.isClear = true := by
  native_decide

/-- Plain ASCII is clear in an LTR-declared field. -/
theorem detect_ascii_clear :
    (detect #[0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  native_decide

/-- Pure digits are clear (numeric / European-number bidi class). -/
theorem detect_digits_clear :
    (detect #[0x30, 0x31, 0x32, 0x33]).classify.isClear = true := by
  native_decide

/-- Single Cyrillic letter is clear — Cyrillic is `L` (strong LTR). -/
theorem detect_cyrillic_clear :
    (detect #[0x043F]).classify.isClear = true := by native_decide

/-- Han ideograph is clear — Han is `L`. -/
theorem detect_han_clear :
    (detect #[0x4E2D]).classify.isClear = true := by native_decide

/-- RLO (U+202E) in input fires `.rloInLTRField`. -/
theorem detect_rlo_in_field :
    (detect #[0x41, 0x202E, 0x42]).classify.tag = some "RloInLTRField" := by
  native_decide

/-- A leading Hebrew letter (strong RTL) fires `.fieldTakeover`. -/
theorem detect_field_takeover_hebrew :
    (detect #[0x05D0, 0x42, 0x43]).classify.tag = some "FieldTakeover" := by
  native_decide

/-- A leading Arabic letter (strong RTL via AL) fires `.fieldTakeover`. -/
theorem detect_field_takeover_arabic :
    (detect #[0x0627, 0x42, 0x43]).classify.tag = some "FieldTakeover" := by
  native_decide

/-- An LTR-starting field with one Hebrew letter mid-stream fires
    `.strongRTLInLTR` (RTL count = 1, run < 4). -/
theorem detect_mid_stream_hebrew :
    (detect #[0x41, 0x42, 0x05D0, 0x44]).classify.tag
      = some "StrongRTLInLTR" := by native_decide

/-- An LTR-starting field with a 4-char Hebrew run fires
    `.mixedOverflow`. -/
theorem detect_overflow_hebrew :
    (detect #[0x41, 0x42, 0x05D0, 0x05D1, 0x05D2, 0x05D3, 0x44]).classify.tag
      = some "MixedOverflow" := by native_decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 v1.5 region-aware spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Under `Language.none`, the behaviour matches v1 — the whole
    input is one code region.  An RLO mid-input fires
    `RloInLTRField`. -/
theorem detect_none_rlo_fires :
    (detect #[0x41, 0x202E, 0x42] .none).classify.tag
      = some "RloInLTRField" := by native_decide

/-- Under `Language.rust`, an RLO inside a string literal is
    filtered out — the C-style tokenizer routes the position
    into the in-string region.  The whole-input scan returns
    Clear. -/
theorem detect_rust_rlo_in_string_clear :
    (detect #[0x22, 0x41, 0x202E, 0x42, 0x22] .rust).classify.isClear
      = true := by native_decide

/-- Under `Language.rust`, an RLO inside a Rust line comment is
    filtered out. -/
theorem detect_rust_rlo_in_line_comment_clear :
    (detect #[0x2F, 0x2F, 0x202E] .rust).classify.isClear
      = true := by native_decide

/-- Under `Language.rust`, an RLO inside a Rust block comment is
    filtered out. -/
theorem detect_rust_rlo_in_block_comment_clear :
    (detect #[0x2F, 0x2A, 0x202E, 0x2A, 0x2F] .rust).classify.isClear
      = true := by native_decide

/-- Under `Language.rust`, an RLO in code BEFORE a string
    literal still fires — the code-region prefix carries the
    hit. -/
theorem detect_rust_rlo_in_code_fires :
    (detect #[0x202E, 0x22, 0x41, 0x22] .rust).classify.tag
      = some "RloInLTRField" := by native_decide

/-- Under `Language.rust`, Hebrew text inside a string literal is
    filtered out — no field takeover claim against a string
    literal that happens to contain Hebrew. -/
theorem detect_rust_hebrew_in_string_clear :
    (detect #[0x22, 0x05D0, 0x05D1, 0x05D2, 0x22] .rust).classify.isClear
      = true := by native_decide

/-- Under `Language.rust`, a 5-char Hebrew run inside a string
    literal stays clear (would have been MixedOverflow under
    .none). -/
theorem detect_rust_hebrew_run_in_string_clear :
    (detect #[0x22, 0x05D0, 0x05D1, 0x05D2, 0x05D3, 0x05D4, 0x22]
        .rust).classify.isClear = true := by native_decide

/-- Under `Language.rust`, a mid-stream Hebrew letter outside
    any string / comment still fires `StrongRTLInLTR`. -/
theorem detect_rust_hebrew_in_code_fires :
    (detect #[0x41, 0x42, 0x05D0, 0x44] .rust).classify.tag
      = some "StrongRTLInLTR" := by native_decide

end Unicode.Security.Display.RtlInjection
