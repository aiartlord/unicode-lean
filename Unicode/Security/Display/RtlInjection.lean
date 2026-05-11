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
  Hebrew / Arabic / Persian text would naturally trip strong-RTL
  detection in this mode, which is the right behavior in an
  LTR-declared form field but the wrong behavior for a Hebrew-
  language UI string — callers must distinguish those contexts
  themselves.

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
import Unicode.TrojanSource
import Unicode.Bidi.Algorithm

namespace Unicode.Security.Display.RtlInjection

open Unicode.Security.Calculus
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

/-- The D3 detection function.  Assumes LTR-declared context. -/
def detect (input : Array Nat) : D3Verdict :=
  let strongRTL := countStrongRTL input
  let strongLTR := countStrongLTR input
  let bidiCtl := countBidiControl input
  let (runLen, runStart) := longestRtlRun input
  let classification : D3Classification :=
    -- Phase 1: bidi format-control trumps all.
    match firstBidiControlPos input with
    | some (pos, ctlCp) =>
      .hazard (.rloInLTRField pos ctlCp) #[pos] ByteArray.empty
    | none =>
      -- Phase 2: leading-RTL field-direction takeover.
      match firstStrongCharPos input with
      | some (pos, cp, true) =>
        -- First strong char is RTL — field takeover.
        .hazard (.fieldTakeover pos cp) #[pos] ByteArray.empty
      | _ =>
        -- Phase 3: mid-stream strong-RTL.
        if strongRTL > 0 then
          -- Decide between mixedOverflow (long run) and the
          -- generic strongRTLInLTR.
          if runLen ≥ 4 then
            .hazard (.mixedOverflow runLen runStart)
              #[runStart] ByteArray.empty
          else
            match firstStrongRTLPos input with
            | some (firstRtlPos, _firstRtlCp) =>
              .hazard (.strongRTLInLTR strongRTL firstRtlPos)
                #[firstRtlPos] ByteArray.empty
            | none =>
              -- Unreachable when strongRTL > 0.
              .clear
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

end Unicode.Security.Display.RtlInjection
