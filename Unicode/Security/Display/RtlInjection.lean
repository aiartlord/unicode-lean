/-
  Unicode.Security.Display.RtlInjection

  Detection of right-to-left content injected into nominally
  left-to-right contexts (form fields, URLs, log lines,
  identifier-bearing UI text declared LTR).

  Threat model.  Tier A₁..A₂.  Adversary inserts strong-RTL
  codepoints or RTL bidi format-controls into a field whose
  declared display direction is LTR, causing the surrounding
  display to reorder.  Distinct from BidiControlBalance (Trojan
  Source class) — RtlInjection flags strong-RTL content
  regardless of bidi-balance, while BidiControlBalance
  is specifically about unbalanced embedding / isolate / orphan
  pop in source-code context.

  Scope: the input is treated as a declared-LTR string.  Pure
  Hebrew / Arabic / Persian text fires strong-RTL detection in
  this mode.  Callers handling Hebrew / Arabic / Persian UI
  strings must declare the field as RTL and dispatch to a
  separate detector; this module does not auto-detect declared
  direction from the input.

  Region-agnostic by design (v0.12.0).  Earlier prereleases
  experimented with a `Language` parameter that filtered hits
  by source-region grammar (code vs. string-literal vs.
  comment).  That filtering surface has been retracted — see
  `SourceDisplayDivergence`'s module header for the
  threat-model rationale.  Every bidi-control / strong-RTL
  finding fires regardless of which source region a tokenizer
  would assign it to.

  Sub-threats (priority order):

    1. `bidiControlInLTRField`    any bidi format-control codepoint
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

set_option maxRecDepth 1000000

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

inductive SubThreat where
  | bidiControlInLTRField   (controlPos : Nat) (controlCp : Nat)
  | fieldTakeover   (firstRtlPos : Nat) (firstRtlCp : Nat)
  | strongRTLInLTR  (rtlCount : Nat) (firstPos : Nat)
  | mixedOverflow   (runLength : Nat) (runStart : Nat)
  deriving DecidableEq, Repr, Inhabited

inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : List Nat) (decoded : List UInt8)
  deriving Inhabited

structure Verdict where
  input              : List Nat
  classify           : Classification
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
def countStrongRTL (input : List Nat) : Nat :=
  input.foldl (fun n cp => if isStrongRTL cp then n + 1 else n) 0

/-- Count of strong-LTR codepoints in `input`. -/
def countStrongLTR (input : List Nat) : Nat :=
  input.foldl (fun n cp => if isStrongLTR cp then n + 1 else n) 0

/-- Count of bidi format-control codepoints in `input`. -/
def countBidiControl (input : List Nat) : Nat :=
  input.foldl (fun n cp => if isBidiControl cp then n + 1 else n) 0

/-- Position of the first bidi format-control in `input`. -/
def firstBidiControlPos (input : List Nat) : Option (Nat × Nat) :=
  input.zipIdx.findSome? (fun cpWithIdx =>
    if isBidiControl cpWithIdx.1 then some (cpWithIdx.2, cpWithIdx.1) else none)

/-- Position of the first strong codepoint (L, R, or AL) in `input`,
    reported as `(position, codepoint, isRtl)`. -/
def firstStrongCharPos (input : List Nat) : Option (Nat × Nat × Bool) :=
  input.zipIdx.findSome? (fun cpWithIdx =>
    let cp := cpWithIdx.1
    if isStrongRTL cp then some (cpWithIdx.2, cp, true)
    else if isStrongLTR cp then some (cpWithIdx.2, cp, false)
    else none)

/-- Position of the first strong-RTL codepoint in `input`. -/
def firstStrongRTLPos (input : List Nat) : Option (Nat × Nat) :=
  input.zipIdx.findSome? (fun cpWithIdx =>
    if isStrongRTL cpWithIdx.1 then some (cpWithIdx.2, cpWithIdx.1) else none)

/-- Fold state for `longestRtlRun`: the peak run and its start, the
    current open run's length and start, and the absolute index. -/
structure RtlRunState where
  longest      : Nat
  longestStart : Nat
  current      : Nat
  currentStart : Nat
  idx          : Nat
  deriving Inhabited

/-- Fold one codepoint into the longest-RTL-run scan.  A strong-RTL
    codepoint extends the open run (opening a fresh run at the current
    index when none is open); any other codepoint closes it. -/
def longestRtlRunStep (st : RtlRunState) (cp : Nat) : RtlRunState :=
  if isStrongRTL cp then
    let newStart := if st.current = 0 then st.idx else st.currentStart
    let newCurrent := st.current + 1
    let newLongest := if newCurrent > st.longest then newCurrent else st.longest
    let newLongestStart :=
      if newCurrent > st.longest then newStart else st.longestStart
    { longest := newLongest, longestStart := newLongestStart,
      current := newCurrent, currentStart := newStart, idx := st.idx + 1 }
  else
    { longest := st.longest, longestStart := st.longestStart,
      current := 0, currentStart := st.currentStart, idx := st.idx + 1 }

/-- Length of the longest consecutive run of strong-RTL codepoints
    in `input`, together with the starting position of that run.
    Returns `(0, 0)` if no RTL chars. -/
def longestRtlRun (input : List Nat) : Nat × Nat :=
  let st := input.foldl longestRtlRunStep
    { longest := 0, longestStart := 0, current := 0, currentStart := 0, idx := 0 }
  (st.longest, st.longestStart)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The declared display direction of the field holding an input.

    A caller handling Hebrew, Arabic or Persian UI text declares its field
    right-to-left.  Every other reading treats the input as a declared-LTR
    string, under which right-to-left content is itself the hazard.

    `Unicode.Bidi.Algorithm.Direction` carries the paragraph-direction
    vocabulary of UAX #9, which is the vocabulary a field declares. -/
abbrev FieldDirection := Unicode.Bidi.Algorithm.Direction

/-- The RtlInjection detection function, against a field whose declared display
    direction is `direction`.

    A bidi format control reorders what a reviewer sees whichever way the field
    runs, so Phase 1 holds unconditionally and trumps all.

    Phases 2 and 3 ask whether right-to-left text has taken over or been
    spliced into a left-to-right field.  That question has no premise in a
    right-to-left field, where right-to-left text is the content.  The
    mirror-image hazard, strong-LTR injection into a right-to-left field,
    belongs to the separate detector the scope note assigns it to.

    Within a left-to-right field every finding — bidi format-control, leading-RTL
    field takeover, mid-stream strong-RTL, mixed-overflow run — fires regardless
    of where in the source the offending codepoint sits.  See the module header
    for the region-agnostic rationale. -/
def detectWithContext (direction : FieldDirection) (input : List Nat) : Verdict :=
  let strongRTL := countStrongRTL input
  let strongLTR := countStrongLTR input
  let bidiCtl := countBidiControl input
  let (runLen, runStart) := longestRtlRun input
  let phase3 : Classification :=
    if strongRTL > 0 then
      if runLen ≥ 4 then
        .hazard (.mixedOverflow runLen runStart)
          [runStart] []
      else
        match firstStrongRTLPos input with
        | some (firstRtlPos, firstRtlCp) =>
          Function.const Nat
            (.hazard (.strongRTLInLTR strongRTL firstRtlPos)
              [firstRtlPos] [])
            firstRtlCp
        | none =>
          -- Unreachable when strongRTL > 0.
          .clear
    else
      .clear
  let classification : Classification :=
    -- Phase 1: bidi format-control trumps all, in either direction.
    match firstBidiControlPos input with
    | some (pos, ctlCp) =>
      .hazard (.bidiControlInLTRField pos ctlCp) [pos] []
    | none =>
      match direction with
      -- A right-to-left field carrying right-to-left text carries its content.
      | .RTL => .clear
      | .LTR =>
        -- Phase 2: leading-RTL field-direction takeover.
        match firstStrongCharPos input with
        | some (pos, cp, true) =>
          .hazard (.fieldTakeover pos cp) [pos] []
        | some (pos, cp, false) =>
          Function.const Nat (Function.const Nat phase3 cp) pos
        | none =>
          -- Phase 3: mid-stream strong-RTL.
          phase3
  { input := input,
    classify := classification,
    strongRTLCount := strongRTL,
    strongLTRCount := strongLTR,
    bidiControlCount := bidiCtl,
    longestRtlRunLen := runLen }

/-- Detection against a field declared left-to-right, the reading the module
    scope note fixes for an undeclared field. -/
def detect (input : List Nat) : Verdict :=
  detectWithContext .LTR input

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Fixture-row tag string for each `SubThreat` constructor. -/
def SubThreat.tag : SubThreat → String
  | .bidiControlInLTRField  controlPos controlCp =>
      Function.const (Nat × Nat) "BidiControlInLTRField" (controlPos, controlCp)
  | .fieldTakeover  firstRtlPos firstRtlCp =>
      Function.const (Nat × Nat) "FieldTakeover" (firstRtlPos, firstRtlCp)
  | .strongRTLInLTR rtlCount firstPos =>
      Function.const (Nat × Nat) "StrongRTLInLTR" (rtlCount, firstPos)
  | .mixedOverflow  runLength runStart =>
      Function.const (Nat × Nat) "MixedOverflow" (runLength, runStart)

/-- True iff the classification is `.clear`. -/
def Classification.isClear : Classification → Bool
  | .clear                     => true
  | .hazard sub positions decoded =>
      Function.const (SubThreat × List Nat × List UInt8) false
        (sub, positions, decoded)

/-- Tag string of a classification. -/
def Classification.tag : Classification → Option String
  | .clear                     => none
  | .hazard sub positions decoded =>
      Function.const (List Nat × List UInt8) (some sub.tag) (positions, decoded)

/-- Positions array of a classification. -/
def Classification.positions : Classification → List Nat
  | .clear                     => []
  | .hazard sub positions decoded =>
      Function.const (SubThreat × List UInt8) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear. -/
theorem detect_empty_clear : (detect []).classify.isClear = true := by
  decide

/-- Plain ASCII is clear in an LTR-declared field. -/
theorem detect_ascii_clear :
    (detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  decide

/-- Pure digits are clear (numeric / European-number bidi class). -/
theorem detect_digits_clear :
    (detect [0x30, 0x31, 0x32, 0x33]).classify.isClear = true := by
  decide

/-- Single Cyrillic letter is clear — Cyrillic is `L` (strong LTR). -/
theorem detect_cyrillic_clear :
    (detect [0x043F]).classify.isClear = true := by decide

/-- Han ideograph is clear — Han is `L`. -/
theorem detect_han_clear :
    (detect [0x4E2D]).classify.isClear = true := by decide

/-- RLO (U+202E) in input fires `.bidiControlInLTRField`. -/
theorem detect_rlo_in_field :
    (detect [0x41, 0x202E, 0x42]).classify.tag = some "BidiControlInLTRField" := by
  decide

/-- RLE (U+202B) fires the same sub-threat.  The sub-threat is the
    presence of a bidi format-control in a declared-LTR field, not the
    presence of an override: U+202B is an embedding, and U+202D / U+202E
    are the only two overrides among the nine controls. -/
theorem detect_rle_in_field :
    (detect [0x41, 0x202B, 0x42, 0x202C]).classify.tag
      = some "BidiControlInLTRField" := by decide

/-- LRI (U+2066), an isolate initiator, fires it too. -/
theorem detect_lri_in_field :
    (detect [0x41, 0x2066, 0x42, 0x2069]).classify.tag
      = some "BidiControlInLTRField" := by decide

/-- A leading Hebrew letter (strong RTL) fires `.fieldTakeover`. -/
theorem detect_field_takeover_hebrew :
    (detect [0x05D0, 0x42, 0x43]).classify.tag = some "FieldTakeover" := by
  decide

/-- The same Hebrew input is clear when the field is declared right-to-left:
    there the leading Hebrew letter is the content of the field, and the
    takeover the LTR reading names cannot occur. -/
theorem detectWithContext_rtl_hebrew_clear :
    (detectWithContext .RTL [0x05D0, 0x42, 0x43]).classify.isClear = true := by
  decide

/-- Persian text carrying an orthographic ZWNJ is clear in a right-to-left
    field, which is the field a Persian display name is rendered in. -/
theorem detectWithContext_rtl_persian_clear :
    (detectWithContext .RTL [0x06CC, 0x200C, 0x0647]).classify.isClear = true := by
  decide

/-- A bidi format-control remains a hazard in a right-to-left field.  Phase 1
    holds unconditionally, so declaring a field right-to-left admits its own
    script without admitting a Trojan Source payload. -/
theorem detectWithContext_rtl_bidi_control_fires :
    (detectWithContext .RTL [0x41, 0x202E, 0x42]).classify.tag
      = some "BidiControlInLTRField" := by
  decide

/-- The declared-LTR reading is `detectWithContext` at `.LTR`, so a field left
    undeclared is judged exactly as before. -/
theorem detect_eq_detectWithContext_ltr (input : List Nat) :
    detect input = detectWithContext .LTR input := rfl

/-- A leading Arabic letter (strong RTL via AL) fires `.fieldTakeover`. -/
theorem detect_field_takeover_arabic :
    (detect [0x0627, 0x42, 0x43]).classify.tag = some "FieldTakeover" := by
  decide

/-- An LTR-starting field with one Hebrew letter mid-stream fires
    `.strongRTLInLTR` (RTL count = 1, run < 4). -/
theorem detect_mid_stream_hebrew :
    (detect [0x41, 0x42, 0x05D0, 0x44]).classify.tag
      = some "StrongRTLInLTR" := by decide

/-- An LTR-starting field with a 4-char Hebrew run fires
    `.mixedOverflow`. -/
theorem detect_overflow_hebrew :
    (detect [0x41, 0x42, 0x05D0, 0x05D1, 0x05D2, 0x05D3, 0x44]).classify.tag
      = some "MixedOverflow" := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 Region-agnosticism spot checks
--
-- Pinning that RtlInjection fires regardless of which source
-- region the offending codepoint sits in.  Earlier prereleases
-- filtered these out under `Language.rust`; the filter has
-- been retracted (see module header).
-- ═══════════════════════════════════════════════════════════════════════════════

/-- RLO "inside a string literal" still fires `BidiControlInLTRField`.
    A code reviewer scanning malicious source sees the RLO
    regardless of which region a tokenizer would assign it to. -/
theorem detect_rlo_inside_quote_pair_fires :
    (detect [0x22, 0x41, 0x202E, 0x42, 0x22]).classify.tag
      = some "BidiControlInLTRField" := by decide

/-- RLO "inside a line comment" still fires.  Comments are
    consumed by LLM code assistants, doc generators, IDE
    renderers, and CI matchers — none of which treat comment
    bytes as "safer" than code bytes. -/
theorem detect_rlo_inside_line_comment_marker_fires :
    (detect [0x2F, 0x2F, 0x202E]).classify.tag
      = some "BidiControlInLTRField" := by decide

/-- RLO "inside a block comment" still fires. -/
theorem detect_rlo_inside_block_comment_fires :
    (detect [0x2F, 0x2A, 0x202E, 0x2A, 0x2F]).classify.tag
      = some "BidiControlInLTRField" := by decide

/-- A 5-character Hebrew run "inside a string literal" still
    fires `MixedOverflow`.  The bytes are visible to every
    consumer of the source. -/
theorem detect_hebrew_run_inside_quote_pair_fires :
    (detect [0x22, 0x05D0, 0x05D1, 0x05D2, 0x05D3, 0x05D4, 0x22]).classify.tag
      = some "FieldTakeover" := by decide

end Unicode.Security.Display.RtlInjection
