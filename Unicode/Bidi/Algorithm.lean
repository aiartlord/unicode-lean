/-
  Unicode.Bidi.Algorithm

  Unicode Bidirectional Algorithm per UAX #9 (Unicode 17.0.0).

  Pipeline (operating on a single paragraph):

    P1–P3   paragraph splitting and base direction discovery
    X1–X10  explicit-formatting processing (embedding, override,
            isolate, PDF, PDI) with a directional status stack
    W1–W7   weak-type resolution
    N0–N2   bracket pairing (N0) and neutral resolution (N1, N2)
    I1–I2   implicit embedding-level adjustment
    L1–L4   line-level reset, run reversal, and mirroring helpers

  This module operates on a paragraph as `List Nat` codepoints. Line
  breaking is the caller's responsibility; the L1 / L2 reorder stage is
  applied to one line at a time via `reorderLine`. L3 (combining-mark
  stickiness) is the renderer's concern. L4 is exposed through
  `mirrorChar` so the renderer can apply it after reordering.

  Bidi class lookups go through the pinned `DerivedBidiClass` table.
  Bracket pairing goes through `BidiBrackets`. Mirroring goes through
  `BidiMirroring`.

  Implementation note: every per-character walk is expressed via
  `List.foldl` / `List.mapIdx` so termination is automatic. Stack-
  shaped logic (X-rules, bracket matching) carries its own state
  through `foldl`.
-/

import Unicode.Generated.DerivedBidiClass
import Unicode.Generated.BidiBrackets
import Unicode.Generated.BidiMirroring

namespace Unicode.Bidi.Algorithm

open Unicode.Generated.DerivedBidiClass (BidiClass)
open Unicode.Generated

set_option maxRecDepth 100000

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 TYPES
-- ═══════════════════════════════════════════════════════════════════════════════

/-- An embedding level. UAX #9 §3.3.2 caps depth at 125. -/
abbrev Level := Nat

/-- Maximum embedding depth permitted by UAX #9 §3.3.2. -/
def maxDepth : Nat := 125

/-- Strong directionality outcome of paragraph-level discovery. -/
inductive Direction where
  | LTR
  | RTL
  deriving DecidableEq, Repr, Inhabited

/-- Directional override outcome of a stack frame. `none` means no
    override; `some .LTR` forces L; `some .RTL` forces R. -/
abbrev OverrideState := Option Direction

/-- One frame of the directional status stack used by X1–X8. -/
structure StackEntry where
  level    : Level
  override : OverrideState
  isolate  : Bool
  deriving Repr, Inhabited

/-- Per-character record carried through the algorithm. `origClass`
    captures the Bidi_Class read from `DerivedBidiClass`; `level` is
    the assigned embedding level; `resolvedClass` is the class after
    W-rules and N-rules. -/
structure CharRecord where
  codepoint     : Nat
  origClass     : BidiClass
  level         : Level
  resolvedClass : BidiClass
  deriving Repr, Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 BIDI_CLASS LOOKUP
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Look up a codepoint's `Bidi_Class` from the pinned `DerivedBidiClass`
    table. `explicitRanges` first, then `defaultRanges` (which cover
    every codepoint per the UAX #44 default-range convention). -/
def lookupBidiClass (cp : Nat) : BidiClass :=
  Unicode.Generated.DerivedBidiClass.lookup cp

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 PARAGRAPH LEVEL — P2 / P3
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Whether a Bidi class is "strong" for paragraph direction discovery. -/
def isStrong (bc : BidiClass) : Bool :=
  match bc with
  | .L | .R | .AL => true
  | .EN | .ES | .ET | .AN | .CS | .NSM | .BN | .B | .S | .WS
  | .ON | .LRE | .LRO | .RLE | .RLO | .PDF | .LRI | .RLI | .FSI | .PDI => false

/-- P2: scan for the first strong character outside any isolate. The
    fold tracks `(found?, isolateDepth)`; isolate initiators bump the
    depth, PDI decrements it (clamped at zero), and a strong class at
    depth 0 finalises `found?`. -/
def firstStrongIgnoringIsolates (cps : List Nat) : Option BidiClass :=
  Prod.fst <| cps.foldl
    (fun (acc : Option BidiClass × Nat) cp =>
      match acc with
      | (some foundClass, foundDepth) => (some foundClass, foundDepth)
      | (none, depth) =>
        let bc := lookupBidiClass cp
        match bc with
        | .LRI | .RLI | .FSI => (none, depth + 1)
        | .PDI               => (none, if depth = 0 then 0 else depth - 1)
        | .L | .R | .AL | .EN | .ES | .ET | .AN | .CS | .NSM | .BN
        | .B | .S | .WS | .ON | .LRE | .LRO | .RLE | .RLO | .PDF =>
          if depth = 0 ∧ isStrong bc then (some bc, depth) else (none, depth))
    (none, 0)

/-- P2 + P3: paragraph base level. R or AL strong → 1 (RTL). Else 0 (LTR). -/
def paragraphLevel (cps : List Nat) : Level :=
  match firstStrongIgnoringIsolates cps with
  | some .R | some .AL => 1
  | none
  | some .L | some .EN | some .ES | some .ET | some .AN | some .CS
  | some .NSM | some .BN | some .B | some .S | some .WS | some .ON
  | some .LRE | some .LRO | some .RLE | some .RLO | some .PDF
  | some .LRI | some .RLI | some .FSI | some .PDI => 0

/-- P2 + P3: paragraph base direction. -/
def paragraphDirection (cps : List Nat) : Direction :=
  if paragraphLevel cps = 0 then .LTR else .RTL

/-- Embedding direction: even level → LTR; odd → RTL. -/
def embeddingDirection (level : Level) : Direction :=
  if level % 2 = 0 then .LTR else .RTL

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 EXPLICIT FORMATTING — X1 / X2 / X3 / X4 / X5 / X5a / X5b / X5c / X6 / X6a / X7 / X8 / X9 / X10
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Round `level` up to the next odd value (used by RLE / RLO / RLI). -/
def nextOdd (level : Level) : Level :=
  if level % 2 = 0 then level + 1 else level + 2

/-- Round `level` up to the next even value (used by LRE / LRO / LRI). -/
def nextEven (level : Level) : Level :=
  if level % 2 = 0 then level + 2 else level + 1

/-- True when `lvl` is within the depth bound for new pushes. -/
def levelInBounds (lvl : Level) : Bool :=
  decide (lvl ≤ maxDepth)

/-- Apply the override (if any) on a stack frame. -/
def applyOverride (origClass : BidiClass) (entry : StackEntry) : BidiClass :=
  match entry.override with
  | some .LTR => BidiClass.L
  | some .RTL => BidiClass.R
  | none      => origClass

/-- Top-of-stack accessor with a sentinel when the stack is empty. -/
def topEntry (st : List StackEntry) : StackEntry :=
  match st.getLast? with
  | some e => e
  | none   => { level := 0, override := none, isolate := false }

/-- Internal X-rules state. -/
structure XState where
  stack            : List StackEntry
  overflowEmbed    : Nat
  overflowIsolate  : Nat
  validIsolates    : Nat
  records          : List CharRecord
  deriving Inhabited

/-- X5c look-ahead: scan from `start + 1` forward and return the
    `Bidi_Class` of the first strong character (L, R, or AL) that
    falls inside the FSI scope at `start`. Characters between any
    inner isolate initiator (LRI / RLI / FSI) and its matching PDI
    are ignored. The scan terminates at the matching PDI of the
    outer FSI, or at the end of the codepoint array if no matching
    PDI exists. -/
def firstStrongInScope (cps : List Nat) (start : Nat) : Option BidiClass :=
  let tail := cps.drop (start + 1)
  Prod.fst <| tail.foldl
    (fun (acc : Option BidiClass × Nat × Bool) cp =>
      let (result, depth, stopped) := acc
      if stopped ∨ result.isSome then acc
      else
        let bc := lookupBidiClass cp
        match bc with
        | .LRI | .RLI | .FSI => (none, depth + 1, false)
        | .PDI =>
          if depth = 0 then (none, 0, true)
          else (none, depth - 1, false)
        | .L | .R | .AL =>
          if depth = 0 then (some bc, depth, false)
          else (none, depth, false)
        | .EN | .ES | .ET | .AN | .CS | .NSM | .BN | .B | .S | .WS
        | .ON | .LRE | .LRO | .RLE | .RLO | .PDF =>
          (none, depth, false))
    (none, 0, false)

/-- Per-position rewrite for X5c. Returns the LRI / RLI codepoint
    that the FSI at `i` resolves to per UAX #9 §3.3.2 X5c, or the
    original codepoint at position `i` when it is not FSI. -/
def resolveFSIAt (cps : List Nat) (i : Nat) (cp : Nat) : Nat :=
  if lookupBidiClass cp = .FSI then
    match firstStrongInScope cps i with
    | some .R | some .AL => 0x2067
    | some .L | some .EN | some .ES | some .ET | some .AN | some .CS
    | some .NSM | some .BN | some .B | some .S | some .WS | some .ON
    | some .LRE | some .LRO | some .RLE | some .RLO | some .PDF
    | some .LRI | some .RLI | some .FSI | some .PDI
    | none => 0x2066
  else cp

/-- X5c: replace every FSI codepoint with the RLI codepoint (U+2067)
    when its scope's first strong character is R or AL, otherwise
    with the LRI codepoint (U+2066). After this pass, the X-rules
    driver receives no FSI characters; the FSI behavior is fully
    determined upstream and matches UAX #9 §3.3.2 X5c. -/
def resolveFSI (cps : List Nat) : List Nat :=
  cps.mapIdx (resolveFSIAt cps)

/-- Per-position invariant for X5c: every codepoint emitted by
    `resolveFSIAt` has Bidi class ≠ FSI. Proves three branches —
    the RLI replacement (0x2067 → .RLI), the LRI replacement
    (0x2066 → .LRI), and the passthrough where the input class
    was already non-FSI by the if-condition. -/
theorem resolveFSIAt_no_FSI (cps : List Nat) (i cp : Nat) :
    lookupBidiClass (resolveFSIAt cps i cp) ≠ .FSI := by
  unfold resolveFSIAt
  split
  · split <;> decide
  · next hcp => exact hcp

/-- One iteration of the X-rules per UAX #9 §3.3.2, processing one cp.
    Callers run `resolveFSI` first so this driver never sees an FSI
    codepoint; the `.FSI` arm below is retained for total-function
    coverage and mirrors the LRI path it would have resolved to. -/
def xStep (paragraphLevel : Level) (cp : Nat) (s : XState) : XState :=
  let bc       := lookupBidiClass cp
  let top      := topEntry s.stack
  let curLevel := top.level
  match bc with
  -- UAX #9 X2 / X3 / X4 / X5: an explicit-formatting control that
  -- can't be pushed becomes an overflow-embedding event ONLY when
  -- there is no outstanding overflow-isolate. If `overflowIsolate > 0`
  -- the embedding control is silently consumed (no stack effect, no
  -- counter change) per the BIDI reference behaviour. Without this
  -- guard, deep-nesting paragraphs miscount overflowEmbed and the
  -- trailing PDF fails to pop the real-frame stack back down.
  | .RLE =>
    let newLvl := nextOdd curLevel
    if levelInBounds newLvl ∧ s.overflowEmbed = 0 ∧ s.overflowIsolate = 0 then
      { s with stack := s.stack ++ [{ level := newLvl, override := none, isolate := false }] }
    else if s.overflowIsolate = 0 then
      { s with overflowEmbed := s.overflowEmbed + 1 }
    else s
  | .LRE =>
    let newLvl := nextEven curLevel
    if levelInBounds newLvl ∧ s.overflowEmbed = 0 ∧ s.overflowIsolate = 0 then
      { s with stack := s.stack ++ [{ level := newLvl, override := none, isolate := false }] }
    else if s.overflowIsolate = 0 then
      { s with overflowEmbed := s.overflowEmbed + 1 }
    else s
  | .RLO =>
    let newLvl := nextOdd curLevel
    if levelInBounds newLvl ∧ s.overflowEmbed = 0 ∧ s.overflowIsolate = 0 then
      { s with stack := s.stack ++ [{ level := newLvl, override := some .RTL, isolate := false }] }
    else if s.overflowIsolate = 0 then
      { s with overflowEmbed := s.overflowEmbed + 1 }
    else s
  | .LRO =>
    let newLvl := nextEven curLevel
    if levelInBounds newLvl ∧ s.overflowEmbed = 0 ∧ s.overflowIsolate = 0 then
      { s with stack := s.stack ++ [{ level := newLvl, override := some .LTR, isolate := false }] }
    else if s.overflowIsolate = 0 then
      { s with overflowEmbed := s.overflowEmbed + 1 }
    else s
  | .RLI =>
    let newLvl := nextOdd curLevel
    -- UAX #9 X5b: when the parent stack frame carries a directional
    -- override, the isolate-initiator character itself is treated as
    -- having the override class for the bidi properties.
    let resolved := applyOverride bc top
    let rec0 : CharRecord :=
      { codepoint := cp, origClass := bc, level := curLevel, resolvedClass := resolved }
    if levelInBounds newLvl ∧ s.overflowEmbed = 0 ∧ s.overflowIsolate = 0 then
      { s with
        stack := s.stack ++ [{ level := newLvl, override := none, isolate := true }],
        validIsolates := s.validIsolates + 1,
        records := s.records ++ [rec0] }
    else
      { s with overflowIsolate := s.overflowIsolate + 1, records := s.records ++ [rec0] }
  | .LRI =>
    let newLvl := nextEven curLevel
    let resolved := applyOverride bc top
    let rec0 : CharRecord :=
      { codepoint := cp, origClass := bc, level := curLevel, resolvedClass := resolved }
    if levelInBounds newLvl ∧ s.overflowEmbed = 0 ∧ s.overflowIsolate = 0 then
      { s with
        stack := s.stack ++ [{ level := newLvl, override := none, isolate := true }],
        validIsolates := s.validIsolates + 1,
        records := s.records ++ [rec0] }
    else
      { s with overflowIsolate := s.overflowIsolate + 1, records := s.records ++ [rec0] }
  -- FSI: provably unreachable when input flows from `resolveFSI`,
  -- per `resolveFSIAt_no_FSI` above. Lean's exhaustiveness check
  -- requires every Bidi class to have a match arm; this one mirrors
  -- the LRI behaviour so a direct call to `xStep` on a hand-constructed
  -- FSI codepoint still falls back to X5c's LRI default rather than
  -- panicking.
  | .FSI =>
    let newLvl := nextEven curLevel
    let resolved := applyOverride bc top
    let rec0 : CharRecord :=
      { codepoint := cp, origClass := bc, level := curLevel, resolvedClass := resolved }
    if levelInBounds newLvl ∧ s.overflowEmbed = 0 ∧ s.overflowIsolate = 0 then
      { s with
        stack := s.stack ++ [{ level := newLvl, override := none, isolate := true }],
        validIsolates := s.validIsolates + 1,
        records := s.records ++ [rec0] }
    else
      { s with overflowIsolate := s.overflowIsolate + 1, records := s.records ++ [rec0] }
  | .PDI =>
    if s.overflowIsolate > 0 then
      let rec0 : CharRecord :=
        { codepoint := cp, origClass := bc, level := curLevel, resolvedClass := bc }
      { s with overflowIsolate := s.overflowIsolate - 1, records := s.records ++ [rec0] }
    else if s.validIsolates = 0 then
      let rec0 : CharRecord :=
        { codepoint := cp, origClass := bc, level := curLevel, resolvedClass := bc }
      { s with records := s.records ++ [rec0] }
    else
      let popped  := (s.stack.reverse.dropWhile (fun e => ! e.isolate)).reverse
      let popped' := popped.dropLast
      let newTop  := topEntry popped'
      -- UAX #9 X6a: PDI is treated as having the directional override
      -- direction of the stack frame restored after popping the
      -- matched isolate scope.
      let resolved := applyOverride bc newTop
      { s with
        stack := popped',
        overflowEmbed := 0,
        validIsolates := s.validIsolates - 1,
        records := s.records ++
          [{ codepoint := cp, origClass := bc, level := newTop.level,
            resolvedClass := resolved }] }
  | .PDF =>
    if s.overflowIsolate > 0 then s
    else if s.overflowEmbed > 0 then { s with overflowEmbed := s.overflowEmbed - 1 }
    else if s.stack.length ≥ 2 ∧ ! top.isolate then { s with stack := s.stack.dropLast }
    else s
  -- X9: BN is removed alongside the embedding / override controls
  -- handled above. The X-rules state machine treats it as a no-op
  -- so it never appears in the output records array.
  | .BN => s
  -- UAX #9 X8: the paragraph separator (B) gets the paragraph
  -- embedding level, NOT the current stack level. Override does
  -- not apply.
  | .B =>
    let rec0 : CharRecord :=
      { codepoint := cp, origClass := bc, level := paragraphLevel,
        resolvedClass := bc }
    { s with records := s.records ++ [rec0] }
  | .L | .R | .AL | .EN | .ES | .ET | .AN | .CS | .NSM
  | .S | .WS | .ON =>
    let resolved := applyOverride bc top
    let rec0 : CharRecord :=
      { codepoint := cp, origClass := bc, level := curLevel, resolvedClass := resolved }
    { s with records := s.records ++ [rec0] }

/-- X-rules driver with an explicit paragraph base level. Resolves
    FSI per X5c first, then applies the explicit-formatting state
    machine over the resolved codepoint array. -/
def assignLevelsAt (cps : List Nat) (pLevel : Level) : List CharRecord :=
  let resolved := resolveFSI cps
  let seed     : XState :=
    { stack            := [{ level := pLevel, override := none, isolate := false }],
      overflowEmbed    := 0,
      overflowIsolate  := 0,
      validIsolates    := 0,
      records          := [] }
  (resolved.foldl (fun acc cp => xStep pLevel cp acc) seed).records

/-- X-rules driver with the paragraph level discovered from P2/P3.
    The paragraph base level is computed on the original array
    because P2 ignores all isolate interiors and is therefore
    invariant under FSI-to-RLI/LRI rewriting. -/
def assignLevels (cps : List Nat) : List CharRecord :=
  assignLevelsAt cps (paragraphLevel cps)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 LEVEL RUNS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Split a record array into level runs `[start, endExclusive)`. -/
def levelRuns (records : List CharRecord) : List (Nat × Nat) :=
  if records.isEmpty then []
  else
    let n := records.length
    let initLvl := (records[0]!).level
    let result := records.foldl
      (fun (acc : List (Nat × Nat) × Nat × Nat × Level) r =>
        let (runs, idx, curStart, curLvl) := acc
        if idx = 0 then (runs, 1, 0, r.level)
        else if r.level = curLvl then (runs, idx + 1, curStart, curLvl)
        else (runs ++ [(curStart, idx)], idx + 1, idx, r.level))
      ([], 0, 0, initLvl)
    let runs := result.1
    let curStart := result.2.2.1
    runs ++ [(curStart, n)]

/-- Find matching pairs of isolate initiators (LRI / RLI / FSI) and
    their PDIs in the records array. Returns `(initiator_idx, pdi_idx)`
    pairs in initiator-order. Unmatched initiators or unmatched PDIs
    are excluded. -/
def findIsolatePairs (records : List CharRecord) : List (Nat × Nat) :=
  let final : List Nat × List (Nat × Nat) × Nat :=
    records.foldl
      (fun (acc : List Nat × List (Nat × Nat) × Nat) r =>
        let (stack, pairs, idx) := acc
        match r.resolvedClass with
        | .LRI | .RLI | .FSI => (stack ++ [idx], pairs, idx + 1)
        | .PDI =>
          if stack.length > 0 then
            let openIdx := stack[stack.length - 1]!
            (stack.dropLast, pairs ++ [(openIdx, idx)], idx + 1)
          else (stack, pairs, idx + 1)
        | .L | .R | .AL | .EN | .ES | .ET | .AN | .CS | .NSM | .BN
        | .B | .S | .WS | .ON | .LRE | .LRO | .RLE | .RLO | .PDF =>
          (stack, pairs, idx + 1))
      ([], [], 0)
  final.2.1

/-- Compute isolating run sequences (IRSes) from the X-rules output.
    Each IRS is the list of record indices belonging to that IRS, in
    increasing order. Per UAX #9 §3.3.2 an IRS chains level runs
    whose last character is an isolate initiator with a matching
    PDI starting a later level run. -/
def computeIRSes (records : List CharRecord) : List (List Nat) :=
  if records.isEmpty then []
  else
    let runs := levelRuns records
    let pairs := findIsolatePairs records
    -- For each level-run index, the index of the level run it chains
    -- into (via an isolate match), or `none` for a terminus.
    let nextRun : List (Option Nat) :=
      runs.map (fun range =>
        let lastIdx := range.2 - 1
        if h : lastIdx < records.length then
          match (records[lastIdx]'h).resolvedClass with
          | .LRI | .RLI | .FSI =>
            match pairs.findSome? (fun p =>
              if p.1 = lastIdx then some p.2 else none) with
            | some pdiIdx =>
              runs.findIdx? (fun r => r.1 ≤ pdiIdx ∧ pdiIdx < r.2)
            | none => none
          | .L | .R | .AL | .EN | .ES | .ET | .AN | .CS | .NSM | .BN
          | .B | .S | .WS | .ON | .LRE | .LRO | .RLE | .RLO | .PDF
          | .PDI => none
        else none)
    -- A level-run index is the SOS of an IRS iff it has no
    -- predecessor in the chain. Compute the set of indices that
    -- ARE chained into; the heads are the complement.
    let chainedInto : List Bool := Id.run do
      let mut acc : List Bool := List.replicate runs.length false
      for opt in nextRun do
        match opt with
        | some j =>
          if j < acc.length then
            acc := acc.set j true
        | none => pure ()
      return acc
    -- For each head run, follow the chain forward through `nextRun`
    -- to collect every record index in the resulting IRS.
    let buildChain (head : Nat) : List Nat := Id.run do
      let mut acc : List Nat := []
      let mut cur : Option Nat := some head
      let mut steps := 0
      while cur.isSome ∧ steps < runs.length do
        match cur with
        | none => pure ()
        | some runIdx =>
          if let some range := runs[runIdx]? then
            if let some nxt := nextRun[runIdx]? then
              for k in [range.1 : range.2] do
                acc := acc ++ [k]
              cur := nxt
            else
              cur := none
          else
            cur := none
        steps := steps + 1
      return acc
    (List.range runs.length).foldl
      (fun (out : List (List Nat)) i =>
        if chainedInto[i]! then out
        else out ++ [buildChain i])
      []

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 W-RULES — W1 / W2 / W3 / W4 / W5 / W6 / W7
-- ═══════════════════════════════════════════════════════════════════════════════

/-- W1: NSM picks up its predecessor's class. NSMs after isolate
    initiators or PDI take ON. -/
def applyW1 (sosClass : BidiClass) (records : List CharRecord) : List CharRecord :=
  Prod.fst <| records.foldl
    (fun (acc : List CharRecord × BidiClass) r =>
      let (out, prev) := acc
      let newClass :=
        match r.resolvedClass with
        | .NSM =>
          match prev with
          | .LRI | .RLI | .FSI | .PDI => .ON
          | .L | .R | .AL | .EN | .ES | .ET | .AN | .CS | .NSM | .BN
          | .B | .S | .WS | .ON | .LRE | .LRO | .RLE | .RLO | .PDF => prev
        | .L | .R | .AL | .EN | .ES | .ET | .AN | .CS | .BN
        | .B | .S | .WS | .ON | .LRE | .LRO | .RLE | .RLO | .PDF
        | .LRI | .RLI | .FSI | .PDI => r.resolvedClass
      (out ++ [{ r with resolvedClass := newClass }],newClass))
    ([], sosClass)

/-- W2: EN preceded by AL (with intervening EN/ET/ES/CS/NSM) → AN. -/
def applyW2 (sosClass : BidiClass) (records : List CharRecord) : List CharRecord :=
  Prod.fst <| records.foldl
    (fun (acc : List CharRecord × BidiClass) r =>
      let (out, lastStrong) := acc
      let cls := r.resolvedClass
      let newClass :=
        match cls with
        | .EN => if lastStrong = .AL then .AN else .EN
        | .L | .R | .AL | .ES | .ET | .AN | .CS | .NSM | .BN
        | .B | .S | .WS | .ON | .LRE | .LRO | .RLE | .RLO | .PDF
        | .LRI | .RLI | .FSI | .PDI => cls
      let newStrong :=
        match cls with
        | .L | .R | .AL => cls
        | .EN | .ES | .ET | .AN | .CS | .NSM | .BN
        | .B | .S | .WS | .ON | .LRE | .LRO | .RLE | .RLO | .PDF
        | .LRI | .RLI | .FSI | .PDI => lastStrong
      (out ++ [{ r with resolvedClass := newClass }],newStrong))
    ([], sosClass)

/-- W3: every AL → R. -/
def applyW3 (records : List CharRecord) : List CharRecord :=
  records.map (fun r =>
    if r.resolvedClass = .AL then { r with resolvedClass := .R } else r)

/-- W4: a single ES between two ENs becomes EN. A single CS between two
    ENs becomes EN. A single CS between two ANs becomes AN. -/
def applyW4 (records : List CharRecord) : List CharRecord :=
  let n := records.length
  records.mapIdx (fun i r =>
    if 0 < i ∧ i + 1 < n then
      let prev := records[i - 1]!
      let next := records[i + 1]!
      match r.resolvedClass with
      | .ES =>
        if prev.resolvedClass = .EN ∧ next.resolvedClass = .EN then
          { r with resolvedClass := .EN }
        else r
      | .CS =>
        if prev.resolvedClass = .EN ∧ next.resolvedClass = .EN then
          { r with resolvedClass := .EN }
        else if prev.resolvedClass = .AN ∧ next.resolvedClass = .AN then
          { r with resolvedClass := .AN }
        else r
      | .L | .R | .AL | .EN | .ET | .AN | .NSM | .BN
      | .B | .S | .WS | .ON | .LRE | .LRO | .RLE | .RLO | .PDF
      | .LRI | .RLI | .FSI | .PDI => r
    else r)

/-- W5 forward pass: precompute, for each index, whether the preceding
    contiguous ET-run is preceded by an EN. -/
def w5LeftAdjEN (records : List CharRecord) : List Bool :=
  Prod.fst <| records.foldl
    (fun (acc : List Bool × Bool) r =>
      let (out, lastNonEtWasEN) := acc
      match r.resolvedClass with
      | .ET => (out ++ [lastNonEtWasEN], lastNonEtWasEN)
      | .EN => (out ++ [true], true)
      | .L | .R | .AL | .ES | .AN | .CS | .NSM | .BN
      | .B | .S | .WS | .ON | .LRE | .LRO | .RLE | .RLO | .PDF
      | .LRI | .RLI | .FSI | .PDI => (out ++ [false], false))
    ([], false)

/-- W5 backward pass: precompute, for each index, whether the following
    contiguous ET-run is followed by an EN. -/
def w5RightAdjEN (records : List CharRecord) : List Bool :=
  let reversed := records.reverse
  let revFlags := Prod.fst <| reversed.foldl
    (fun (acc : List Bool × Bool) r =>
      let (out, lastNonEtWasEN) := acc
      match r.resolvedClass with
      | .ET => (out ++ [lastNonEtWasEN], lastNonEtWasEN)
      | .EN => (out ++ [true], true)
      | .L | .R | .AL | .ES | .AN | .CS | .NSM | .BN
      | .B | .S | .WS | .ON | .LRE | .LRO | .RLE | .RLO | .PDF
      | .LRI | .RLI | .FSI | .PDI => (out ++ [false], false))
    ([], false)
  revFlags.reverse

/-- W5: ETs adjacent to an EN take EN. -/
def applyW5 (records : List CharRecord) : List CharRecord :=
  let leftAdj  := w5LeftAdjEN records
  let rightAdj := w5RightAdjEN records
  records.mapIdx (fun i r =>
    if r.resolvedClass = .ET ∧ ((leftAdj[i]?.getD false) ∨ (rightAdj[i]?.getD false)) then
      { r with resolvedClass := .EN }
    else r)

/-- W6: any remaining ES, CS, ET → ON. -/
def applyW6 (records : List CharRecord) : List CharRecord :=
  records.map (fun r =>
    match r.resolvedClass with
    | .ES | .CS | .ET => { r with resolvedClass := .ON }
    | .L | .R | .AL | .EN | .AN | .NSM | .BN
    | .B | .S | .WS | .ON | .LRE | .LRO | .RLE | .RLO | .PDF
    | .LRI | .RLI | .FSI | .PDI => r)

/-- W7: every EN whose nearest preceding strong is L becomes L. -/
def applyW7 (sosClass : BidiClass) (records : List CharRecord) : List CharRecord :=
  Prod.fst <| records.foldl
    (fun (acc : List CharRecord × BidiClass) r =>
      let (out, lastStrong) := acc
      let cls := r.resolvedClass
      let newClass :=
        match cls with
        | .EN => if lastStrong = .L then .L else .EN
        | .L | .R | .AL | .ES | .ET | .AN | .CS | .NSM | .BN
        | .B | .S | .WS | .ON | .LRE | .LRO | .RLE | .RLO | .PDF
        | .LRI | .RLI | .FSI | .PDI => cls
      let newStrong :=
        match cls with
        | .L | .R => cls
        | .AL | .EN | .ES | .ET | .AN | .CS | .NSM | .BN
        | .B | .S | .WS | .ON | .LRE | .LRO | .RLE | .RLO | .PDF
        | .LRI | .RLI | .FSI | .PDI => lastStrong
      (out ++ [{ r with resolvedClass := newClass }],newStrong))
    ([], sosClass)

/-- Apply W1 .. W7 in sequence. -/
def applyWeakRules (sosClass : BidiClass) (records : List CharRecord) : List CharRecord :=
  applyW7 sosClass
    (applyW6 (applyW5 (applyW4 (applyW3 (applyW2 sosClass (applyW1 sosClass records))))))

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 BRACKETS — N0
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Look up a codepoint's bracket entry, if any. -/
def lookupBracket (cp : Nat) : Option BidiBrackets.BidiBracketRow :=
  BidiBrackets.lookup? cp

/-- Internal state for bracket pair scanning. -/
structure BracketPairState where
  index : Nat
  stack : List (Nat × Nat)        -- (open-index, expected-close codepoint)
  pairs : List (Nat × Nat)        -- (open-index, close-index)
  deriving Inhabited

/-- BD16 caps the bracket-pair stack at 63 entries. -/
def bracketStackBound : Nat := 63

/-- Canonical-equivalence collapse for bracket pairing per UAX #9
    §3.1.3: brackets are matched after applying NFD. The only
    canonical decompositions among bracket-class characters are
    U+2329 → U+3008 and U+232A → U+3009; map them here so the
    pairing stack handles canonically-equivalent inputs as the
    same bracket. -/
def canonicalBracketEquiv (cp : Nat) : Nat :=
  match cp with
  | 0x2329 => 0x3008
  | 0x232A => 0x3009
  | otherCp => otherCp

/-- One state snapshot of the bracket-pair scan with overflow flag.
    Once the bracket-pair stack overflows past `bracketStackBound`,
    UAX #9 BD16 abandons pairing for the rest of the IRS — the
    `aborted` flag captures that and short-circuits subsequent
    bracket events. -/
structure BracketPairScanState where
  index   : Nat
  stack   : List (Nat × Nat)
  pairs   : List (Nat × Nat)
  aborted : Bool
  deriving Inhabited

def findBracketPairs (records : List CharRecord) : List (Nat × Nat) :=
  let final : BracketPairScanState := records.foldl
    (fun (s : BracketPairScanState) r =>
      let i := s.index
      if s.aborted then { s with index := i + 1 }
      else
      match lookupBracket r.codepoint with
      | some br =>
        let cpCanon   := canonicalBracketEquiv r.codepoint
        let pairCanon := canonicalBracketEquiv br.pair
        match br.bracketType with
        | .Open =>
          if s.stack.length < bracketStackBound then
            { s with index := i + 1, stack := s.stack ++ [(i, pairCanon)] }
          else
            -- BD16 stack-overflow: abandon all bracket pairing for
            -- the remainder of this IRS.
            { s with index := i + 1, aborted := true }
        | .Close =>
          -- UAX #9 BD16: pair the closing bracket with the NEAREST
          -- (top-most) matching opener on the stack, then discard
          -- every entry above it in the stack as unmatched.
          let kRev :=
            s.stack.reverse.findIdx? (fun pair => pair.2 = cpCanon)
          match kRev with
          | some kFromTop =>
            let k := s.stack.length - 1 - kFromTop
            let openIdx := (s.stack[k]!).1
            let stack' := s.stack.take k
            { s with index := i + 1, stack := stack', pairs := s.pairs ++ [(openIdx, i)] }
          | none =>
            { s with index := i + 1 }
      | none =>
        { s with index := i + 1 })
    ({ index := 0, stack := [], pairs := [], aborted := false }
        : BracketPairScanState)
  final.pairs

-- ═══════════════════════════════════════════════════════════════════════════════
-- §8 N-RULES — N0 / N1 / N2
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Direction projection used by N-rules. L → LTR; R/AN/EN → RTL. -/
def asNDir (bc : BidiClass) : Option Direction :=
  match bc with
  | .L              => some .LTR
  | .R | .AN | .EN  => some .RTL
  | .AL | .ES | .ET | .CS | .NSM | .BN | .B | .S | .WS | .ON
  | .LRE | .LRO | .RLE | .RLO | .PDF | .LRI | .RLI | .FSI | .PDI => none

/-- True for the neutral / isolate-formatting classes that N1/N2 act on. -/
def isNeutralOrIsolate (bc : BidiClass) : Bool :=
  match bc with
  | .B | .S | .WS | .ON | .FSI | .LRI | .RLI | .PDI => true
  | .L | .R | .AL | .EN | .ES | .ET | .AN | .CS | .NSM | .BN
  | .LRE | .LRO | .RLE | .RLO | .PDF => false

/-- Resolve a single bracket pair per N0. -/
def resolveBracketPair (records : List CharRecord)
    (level : Level) (openIdx closeIdx : Nat) : List CharRecord :=
  -- A bracket whose resolved class differs from its original class
  -- has had its direction fixed by an LRE / LRO / RLE / RLO override
  -- earlier in X-rules. Per the BIDI reference behaviour exercised
  -- by `BidiCharacterTest.txt`, N0 leaves such overridden brackets
  -- alone — the override wins. Skip the entire pair when either
  -- bracket carries an override.
  let openOverridden :=
    if openIdx < records.length then
      let r := records[openIdx]!
      r.origClass != r.resolvedClass
    else false
  let closeOverridden :=
    if closeIdx < records.length then
      let r := records[closeIdx]!
      r.origClass != r.resolvedClass
    else false
  if openOverridden ∨ closeOverridden then records
  else
  let embed := embeddingDirection level
  -- N0(a): inside the bracket scope, EN and AN are treated as R for
  -- the purpose of determining bracket direction.
  let asN0Dir : BidiClass → Option Direction := fun bc =>
    match bc with
    | .L              => some .LTR
    | .R | .AL        => some .RTL
    | .EN | .AN       => some .RTL
    | .ES | .ET | .CS | .NSM | .BN | .B | .S | .WS | .ON
    | .LRE | .LRO | .RLE | .RLO | .PDF
    | .LRI | .RLI | .FSI | .PDI => none
  let inside := (records.take closeIdx).drop (openIdx + 1)
  let res := inside.foldl
    (fun (acc : Bool × Bool) r =>
      let (sawEmbed, sawOpp) := acc
      match asN0Dir r.resolvedClass with
      | some d =>
        if d = embed then (true, sawOpp)
        else (sawEmbed, true)
      | none => acc)
    (false, false)
  let (sawEmbed, sawOpp) := res
  let toClass (d : Direction) : BidiClass :=
    match d with | .LTR => .L | .RTL => .R
  -- UAX #9 N0 post-processing: when the bracket direction differs
  -- from the embedding direction, any NSM (by ORIGINAL class, prior
  -- to W1) immediately following a modified bracket inherits the
  -- bracket's new class. Walks forward from `idx` skipping BN-class
  -- records until the first non-BN; updates that record only if it
  -- is an original NSM.
  let propagateToFollowingNSM (out : List CharRecord) (idx : Nat)
      (cls : BidiClass) : List CharRecord :=
    let rec go (j : Nat) (acc : List CharRecord) : List CharRecord :=
      if h : j < acc.length then
        let r := acc[j]'h
        match r.origClass with
        | .BN => go (j + 1) acc
        | .NSM => acc.set j { r with resolvedClass := cls }
        | .L | .R | .AL | .EN | .ES | .ET | .AN | .CS
        | .B | .S | .WS | .ON
        | .LRE | .LRO | .RLE | .RLO | .PDF
        | .LRI | .RLI | .FSI | .PDI => acc
      else acc
    termination_by acc.length - j
    go (idx + 1) out
  let setBoth (cls : BidiClass) : List CharRecord :=
    let withOpen :=
      if openIdx < records.length then
        records.set openIdx { records[openIdx]! with resolvedClass := cls }
      else records
    let withBoth :=
      if closeIdx < withOpen.length then
        withOpen.set closeIdx { withOpen[closeIdx]! with resolvedClass := cls }
      else withOpen
    -- N0 post-processing — only when the bracket direction differs
    -- from the embedding direction at this level.
    let embedClass : BidiClass :=
      match embeddingDirection level with | .LTR => .L | .RTL => .R
    if cls = embedClass then withBoth
    else
      propagateToFollowingNSM
        (propagateToFollowingNSM withBoth openIdx cls)
        closeIdx cls
  -- N0(b): a strong type matching the embedding direction inside the
  -- pair sets both brackets to the embedding direction.
  if sawEmbed then
    setBoth (toClass embed)
  -- N0(c): only opposite-direction strong types inside. Walk backwards
  -- from openIdx looking for the first strong type before the opening
  -- bracket. If that preceding strong is opposite the embedding
  -- direction, the bracket pair takes the opposite direction; otherwise
  -- (preceding matches the embedding direction or no preceding strong
  -- exists, in which case sos = embed direction by convention) the
  -- bracket pair takes the embedding direction.
  else if sawOpp then
    let beforeOpen := records.take openIdx
    let precedingDir : Direction :=
      beforeOpen.foldl
        (fun acc r =>
          match asN0Dir r.resolvedClass with
          | some d => d
          | none   => acc)
        embed
    if precedingDir = embed then
      setBoth (toClass embed)
    else
      setBoth (toClass precedingDir)
  -- N0(d): no strong types inside; brackets keep their original class
  -- and fall through to N1 / N2.
  else
    records

/-- N0: apply bracket-pair resolution paragraph-wide. -/
def applyN0 (records : List CharRecord) (level : Level) : List CharRecord :=
  -- UAX #9 N0: process bracket pairs in opening-position order. The
  -- pairs returned by `findBracketPairs` are emitted in closing
  -- order; reindex them into a `closeAt[openIdx]` map and then walk
  -- the records in source order to recover open-order processing.
  let pairs := findBracketPairs records
  let n := records.length
  let closeAt : List (Option Nat) :=
    pairs.foldl
      (fun acc p =>
        if p.1 < acc.length then acc.set p.1 (some p.2) else acc)
      (List.replicate n none)
  (List.range n).foldl
    (fun acc i =>
      match closeAt[i]? with
      | some (some c) => resolveBracketPair acc level i c
      | some none     => acc
      | none          => acc)
    records

/-- Direction projection at index `i`, falling back to the right-side
    boundary when the index is out of range. -/
def directionAt (records : List CharRecord) (eosDir : Direction) (i : Nat) : Direction :=
  if h : i < records.length then
    match asNDir (records[i]'h).resolvedClass with
    | some d => d
    | none   => eosDir
  else eosDir

/-- For each index, the strong direction immediately to the left
    (skipping neutral / isolate formatting); falls back to `sosDir` at
    the start. Implemented as a forward foldl. -/
def leftStrongDir (sosDir : Direction) (records : List CharRecord) : List Direction :=
  Prod.fst <| records.foldl
    (fun (acc : List Direction × Direction) r =>
      let (out, prev) := acc
      let cur :=
        match asNDir r.resolvedClass with
        | some d => d
        | none   => prev
      (out ++ [prev], cur))
    ([], sosDir)

/-- For each index, the strong direction immediately to the right
    (skipping neutrals); falls back to `eosDir` at the end. Implemented
    as a forward foldl over the reversed array, then re-reversed. -/
def rightStrongDir (eosDir : Direction) (records : List CharRecord) : List Direction :=
  let reversed := records.reverse
  let revFlags := Prod.fst <| reversed.foldl
    (fun (acc : List Direction × Direction) r =>
      let (out, prev) := acc
      let cur :=
        match asNDir r.resolvedClass with
        | some d => d
        | none   => prev
      (out ++ [prev], cur))
    ([], eosDir)
  revFlags.reverse

/-- N1 + N2: replace each NI with its surrounding strong direction (N1
    when both sides agree, N2 with the embedding direction otherwise). -/
def applyN1N2 (sosDir eosDir : Direction) (level : Level)
    (records : List CharRecord) : List CharRecord :=
  let lefts  := leftStrongDir sosDir records
  let rights := rightStrongDir eosDir records
  let embed  := embeddingDirection level
  records.mapIdx (fun i r =>
    if isNeutralOrIsolate r.resolvedClass then
      let l := lefts[i]?.getD sosDir
      let rg := rights[i]?.getD eosDir
      let target := if l = rg then l else embed
      let cls := match target with | .LTR => BidiClass.L | .RTL => BidiClass.R
      { r with resolvedClass := cls }
    else r)

/-- Apply N0, N1, N2 in order. -/
def applyNeutralRules (sosDir eosDir : Direction) (level : Level)
    (records : List CharRecord) : List CharRecord :=
  applyN1N2 sosDir eosDir level (applyN0 records level)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §9 IMPLICIT LEVELS — I1 / I2
-- ═══════════════════════════════════════════════════════════════════════════════

/-- I1 + I2: bump the embedding level based on resolved class.

    Even level (LTR): R → +1 ; AN/EN → +2 ; else → 0.
    Odd  level (RTL): L/AN/EN → +1 ; else → 0. -/
def applyImplicitLevels (records : List CharRecord) : List CharRecord :=
  records.map (fun r =>
    let lvl := r.level
    let bump :=
      if lvl % 2 = 0 then
        match r.resolvedClass with
        | .R         => 1
        | .AN | .EN  => 2
        | .L | .AL | .ES | .ET | .CS | .NSM | .BN | .B | .S | .WS | .ON
        | .LRE | .LRO | .RLE | .RLO | .PDF | .LRI | .RLI | .FSI | .PDI => 0
      else
        match r.resolvedClass with
        | .L | .AN | .EN => 1
        | .R | .AL | .ES | .ET | .CS | .NSM | .BN | .B | .S | .WS | .ON
        | .LRE | .LRO | .RLE | .RLO | .PDF | .LRI | .RLI | .FSI | .PDI => 0
    { r with level := lvl + bump })

-- ═══════════════════════════════════════════════════════════════════════════════
-- §10 LINE-LEVEL RULES — L1 / L2 / L4
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True for the classes whose level resets to the paragraph level under
    L1: WS and the four isolate-formatting classes. -/
def l1WhitespaceLike (bc : BidiClass) : Bool :=
  match bc with
  | .WS | .FSI | .LRI | .RLI | .PDI => true
  | .L | .R | .AL | .EN | .ES | .ET | .AN | .CS | .NSM | .BN
  | .B | .S | .ON | .LRE | .LRO | .RLE | .RLO | .PDF => false

/-- L1: reset the level of:
      (a) segment / paragraph separators (B / S);
      (b) WS / isolate-formatting characters preceding (a);
      (c) WS / isolate-formatting characters at the end of the line.

    Implemented via two forward passes that update a running "trailing
    WS run" tracker, then a backward pass for the line-end tail. -/
def applyL1 (paragraphLvl : Level) (records : List CharRecord) : List CharRecord :=
  -- Forward pass: for each B / S, retroactively reset preceding WS-like
  -- run AND the B / S itself. Whether the cursor is inside a WS-like
  -- prefix segment is tracked via a state index.
  let n := records.length
  -- Step 1: build a Bool array marking each index that needs the
  -- paragraph-level reset.
  let resetMaskA := Prod.fst <| records.foldl
    (fun (acc : List Bool × Nat × Nat) r =>
      let (mask, i, runStart) := acc
      match r.origClass with
      | .B | .S =>
        -- Mark [runStart, i] for reset by folding over the index range.
        let mask' :=
          if runStart ≤ i then
            (List.range (i - runStart + 1)).foldl
              (fun a j =>
                let idx := runStart + j
                if idx < a.length then a.set idx true else a)
              mask
          else mask
        let mask'' := if i < mask'.length then mask'.set i true else mask'
        (mask'', i + 1, i + 1)
      | .L | .R | .AL | .EN | .ES | .ET | .AN | .CS | .NSM | .BN
      | .WS | .ON | .LRE | .LRO | .RLE | .RLO | .PDF
      | .LRI | .RLI | .FSI | .PDI =>
        if l1WhitespaceLike r.origClass then
          (mask, i + 1, runStart)
        else
          (mask, i + 1, i + 1))
    (List.replicate n false, 0, 0)
  -- Step 2: scan from the end backwards to mark trailing WS-like.
  let resetMaskB :=
    let pairs := records.mapIdx (fun i r => (i, r))
    let revPairs := pairs.reverse
    Prod.fst <| revPairs.foldl
      (fun (acc : List Bool × Bool) ⟨i, r⟩ =>
        let (mask, stillTrailing) := acc
        if stillTrailing ∧ l1WhitespaceLike r.origClass then
          let mask' := if i < mask.length then mask.set i true else mask
          (mask', true)
        else
          (mask, false))
      (resetMaskA, true)
  records.mapIdx (fun i r =>
    if (resetMaskB[i]?.getD false) then
      { r with level := paragraphLvl }
    else r)

/-- Reverse a sub-array `[lo, hi)` by index swap. -/
def reverseSlice (records : List CharRecord) (lo hi : Nat) : List CharRecord :=
  records.mapIdx (fun i r =>
    if lo ≤ i ∧ i < hi then
      records[lo + hi - 1 - i]!
    else r)

/-- Maximum level over a record array. -/
def maxLevel (records : List CharRecord) : Level :=
  records.foldl (fun m r => Nat.max m r.level) 0

/-- Smallest odd level ≥ 1 in the records, or `none` if no odd level. -/
def minOddLevel (records : List CharRecord) : Option Level :=
  records.foldl
    (fun acc r =>
      if r.level % 2 = 1 then
        match acc with
        | none   => some r.level
        | some m => some (Nat.min m r.level)
      else acc)
    none

/-- Reverse all sub-sequences at level ≥ `lvl`. Walks left to right
    collecting maximal `[start, end)` ranges and reversing each. -/
def reverseAtLevel (records : List CharRecord) (lvl : Level) : List CharRecord :=
  let n := records.length
  -- Collect ranges to reverse.
  let res := records.foldl
    (fun (acc : List (Nat × Nat) × Nat × Option Nat) r =>
      let (ranges, idx, curStart) := acc
      if r.level ≥ lvl then
        match curStart with
        | some startIdx => (ranges, idx + 1, some startIdx)
        | none          => (ranges, idx + 1, some idx)
      else
        match curStart with
        | some s => (ranges ++ [(s, idx)], idx + 1, none)
        | none   => (ranges, idx + 1, none))
    (([] : List (Nat × Nat)), 0, none)
  let ranges := res.1
  let lastStart := res.2.2
  let allRanges :=
    match lastStart with
    | some s => ranges ++ [(s, n)]
    | none   => ranges
  allRanges.foldl (fun acc ⟨lo, hi⟩ => reverseSlice acc lo hi) records

/-- L2: from the highest level down to the smallest odd level, reverse
    every maximal sub-sequence at or above that level. -/
def applyL2 (records : List CharRecord) : List CharRecord :=
  match minOddLevel records with
  | none => records
  | some minOdd =>
    let maxLvl := maxLevel records
    -- Apply reverseAtLevel for each level from maxLvl down to minOdd.
    let levels := (List.range (maxLvl + 1 - minOdd)).map (fun k => maxLvl - k)
    levels.foldl (fun acc lvl => reverseAtLevel acc lvl) records

/-- L4: mirror lookup. Returns the mirror codepoint when the input has
    a `Bidi_Mirroring_Glyph` entry; the input unchanged otherwise. -/
def mirrorChar (cp : Nat) : Nat :=
  match BidiMirroring.lookup? cp with
  | some m => m
  | none   => cp

-- ═══════════════════════════════════════════════════════════════════════════════
-- §11 DRIVER
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Output of the paragraph pipeline. -/
structure ParagraphResult where
  records        : List CharRecord
  paragraphLevel : Level
  deriving Repr, Inhabited

/-- Compute the sos and eos directions for one isolating run sequence.
    UAX #9 §3.3.4: sos direction corresponds to the higher of (the
    level of the character immediately preceding the IRS in the post-
    X9 records, or the paragraph embedding level if none) and (the
    level of the first character in the IRS). eos is the symmetric
    case at the right boundary, with one important exception: when
    the IRS ends with an unmatched isolate initiator (LRI / RLI /
    FSI whose matching PDI is missing in the source), eos uses the
    paragraph embedding level rather than the level of the next
    character — the unmatched initiator's "scope" notionally
    extends to end-of-paragraph for boundary purposes. -/
def computeIRSBoundaries (records : List CharRecord) (paragraphLevel : Level)
    (irs : List Nat) : Direction × Direction :=
  if irs.isEmpty then
    let dir := embeddingDirection paragraphLevel
    (dir, dir)
  else
    let firstIdx := irs[0]!
    let lastIdx  := irs[irs.length - 1]!
    let firstInIRSLevel := (records[firstIdx]!).level
    let lastInIRSLevel  := (records[lastIdx]!).level
    let precedingLevel :=
      if firstIdx = 0 then paragraphLevel
      else (records[firstIdx - 1]!).level
    let lastIsIsolateInit :=
      match (records[lastIdx]!).resolvedClass with
      | .LRI | .RLI | .FSI => true
      | .L | .R | .AL | .EN | .ES | .ET | .AN | .CS | .NSM | .BN
      | .B | .S | .WS | .ON
      | .LRE | .LRO | .RLE | .RLO | .PDF | .PDI => false
    let followingLevel :=
      if lastIsIsolateInit then paragraphLevel
      else if lastIdx + 1 = records.length then paragraphLevel
      else (records[lastIdx + 1]!).level
    let sosLevel := max precedingLevel firstInIRSLevel
    let eosLevel := max followingLevel lastInIRSLevel
    (embeddingDirection sosLevel, embeddingDirection eosLevel)

/-- Apply W- and N-rules to one IRS in the records array. Extracts
    the subset of records identified by `irs`, runs W1–W7 then
    N0 / N1 / N2 over that subset using the IRS-specific sos / eos
    directions, and merges the resolved subset back at the original
    indices. -/
def applyWAndNToIRS (paragraphLevel : Level) (records : List CharRecord)
    (irs : List Nat) : List CharRecord :=
  if irs.isEmpty then records
  else
    let (sos, eos) := computeIRSBoundaries records paragraphLevel irs
    let firstIdx := irs[0]!
    let level := (records[firstIdx]!).level
    let irsRecords := irs.map (fun i => records[i]!)
    let sosClass : BidiClass := match sos with | .LTR => .L | .RTL => .R
    let weak    := applyWeakRules sosClass irsRecords
    let neutral := applyNeutralRules sos eos level weak
    -- Merge back: for each j in 0..irs.length, write neutral[j] into
    -- records[irs[j]].
    Prod.fst <| irs.foldl
      (fun (acc : List CharRecord × Nat) recIdx =>
        let (out, j) := acc
        if hj : j < neutral.length then
          if recIdx < out.length then
            (out.set recIdx (neutral[j]'hj), j + 1)
          else (out, j + 1)
        else (out, j + 1))
      (records, 0)

/-- Full Bidi pipeline driven by an explicit paragraph base level.
    Use when the caller already knows the paragraph direction
    (e.g. UAX #9 conformance tests where the paragraph level is
    given by the test row, not auto-detected). Applies the W- and
    N-rules per isolating run sequence as required by UAX #9
    §3.3.6. -/
def bidiParagraphAt (cps : List Nat) (pLevel : Level) : ParagraphResult :=
  let assigned := assignLevelsAt cps pLevel
  let irses := computeIRSes assigned
  let resolved := irses.foldl
    (fun acc irs => applyWAndNToIRS pLevel acc irs)
    assigned
  let implicit := applyImplicitLevels resolved
  -- UAX #9 L1 paragraph-level reset for segment / paragraph separators
  -- and trailing whitespace / isolate-formatting characters. Applied
  -- here so the paragraph-level output matches what reordering would
  -- consume on a single-line paragraph; per-line resets in
  -- `reorderLine` apply on top of this for shorter lines.
  let withL1 := applyL1 pLevel implicit
  { records := withL1, paragraphLevel := pLevel }

/-- Full Bidi pipeline with paragraph base level discovered from
    P2/P3. -/
def bidiParagraph (cps : List Nat) : ParagraphResult :=
  bidiParagraphAt cps (paragraphLevel cps)

/-- Bidi class is removed by UAX #9 X9 (RLE / LRE / RLO / LRO / PDF / BN).
    Removed-class characters do not contribute to embedding-level
    resolution and have no level in the conformance output (the
    `BidiCharacterTest.txt` 'x' marker). -/
def isX9Removed (bc : BidiClass) : Bool :=
  match bc with
  | .RLE | .LRE | .RLO | .LRO | .PDF | .BN => true
  | .L | .R | .AL | .EN | .ES | .ET | .AN | .CS | .NSM
  | .B | .S | .WS | .ON
  | .LRI | .RLI | .FSI | .PDI => false

/-- Align the per-record levels in `result` to the original input
    array. Returns `none` at every X9-removed input position; returns
    `some level` at every retained position, in the order produced by
    the X-rules driver. Used by UAX #9 conformance test harnesses
    where expected output is keyed by input position. -/
def levelsAlignedToInput (cps : List Nat) (result : ParagraphResult) :
    List (Option Nat) :=
  Prod.fst <| cps.foldl
    (fun (acc : List (Option Nat) × Nat) cp =>
      let (out, recIdx) := acc
      let bc := lookupBidiClass cp
      if isX9Removed bc then
        (out ++ [none], recIdx)
      else if h : recIdx < result.records.length then
        let lvl := (result.records[recIdx]'h).level
        (out ++ [some lvl], recIdx + 1)
      else
        (out ++ [none], recIdx))
    ([], 0)

/-- The original input indices retained after X9 stripping. The
    `i`-th entry is the position in the original `cps` array that
    corresponds to the `i`-th post-X9 record. -/
def originalInputIndices (cps : List Nat) : List Nat :=
  Prod.fst <| cps.foldl
    (fun (acc : List Nat × Nat) cp =>
      let (out, idx) := acc
      let bc := lookupBidiClass cp
      if isX9Removed bc then (out, idx + 1)
      else (out ++ [idx], idx + 1))
    ([], 0)

/-- Compute the visual-order reordering of input indices per UAX #9
    L1 + L2. Returns input indices in display (visual) order; X9-
    removed input positions are skipped. The implementation re-runs
    the L1 / L2 reorder logic over a parallel record array whose
    `codepoint` field is hijacked to carry the original input index;
    the output `.codepoint` projection reads back the index permuted
    into visual order. The original `result.records` is unmodified. -/
def reorderedInputIndices (cps : List Nat) (result : ParagraphResult) :
    List Nat :=
  let inputIndices := originalInputIndices cps
  let indexedRecords : List CharRecord :=
    result.records.mapIdx (fun i r =>
      { r with codepoint := inputIndices[i]?.getD 0 })
  let l1 := applyL1 result.paragraphLevel indexedRecords
  let l2 := applyL2 l1
  l2.map (·.codepoint)

/-- L1 + L2 reorder for one line `[lineStart, lineEnd)`. Returns the
    reordered codepoints; the caller may apply `mirrorChar` for L4. -/
def reorderLine (result : ParagraphResult) (lineStart lineEnd : Nat) : List Nat :=
  let slice := (result.records.take lineEnd).drop lineStart
  let l1    := applyL1 result.paragraphLevel slice
  let l2    := applyL2 l1
  l2.map (fun r => r.codepoint)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §12 TEST VECTORS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Pure ASCII paragraph has level 0. -/
theorem paragraphLevel_ascii :
    paragraphLevel [0x0048, 0x0069] = 0 := by decide  -- "Hi"

/-- Pure Hebrew paragraph (R class on first char) has level 1. -/
theorem paragraphLevel_hebrew :
    paragraphLevel [0x05D0, 0x05D1] = 1 := by decide

/-- Empty paragraph defaults to level 0. -/
theorem paragraphLevel_empty :
    paragraphLevel [] = 0 := by decide

/-- Bracket lookup finds LEFT PARENTHESIS as Open with pair RIGHT PAREN. -/
theorem bracket_lookup_lparen :
    (lookupBracket 0x0028).map (fun r => (r.pair, r.bracketType))
      = some (0x0029, .Open) := by decide

/-- Mirror lookup: LEFT PAREN ↔ RIGHT PAREN. -/
theorem mirror_lparen : mirrorChar 0x0028 = 0x0029 := by decide

/-- Mirror returns input unchanged for non-mirroring codepoints. -/
theorem mirror_letter_a : mirrorChar 0x0041 = 0x0041 := by decide

/-- Pure-ASCII paragraph after the full pipeline: paragraph level 0. -/
theorem bidiParagraph_ascii :
    (bidiParagraph [0x0048, 0x0069]).paragraphLevel = 0 := by decide

/-- X5c — FSI followed by Hebrew (RTL strong) inside scope resolves to RLI. -/
theorem resolveFSI_hebrew_inner :
    resolveFSI [0x2068, 0x05D0, 0x05D1, 0x2069] = [0x2067, 0x05D0, 0x05D1, 0x2069]
    := by decide

/-- X5c — FSI followed by ASCII (LTR strong) inside scope resolves to LRI. -/
theorem resolveFSI_ascii_inner :
    resolveFSI [0x2068, 0x0048, 0x0069, 0x2069] = [0x2066, 0x0048, 0x0069, 0x2069]
    := by decide

/-- X5c — FSI with no strong character in scope defaults to LRI. -/
theorem resolveFSI_neutral_inner :
    resolveFSI [0x2068, 0x0020, 0x2069] = [0x2066, 0x0020, 0x2069]
    := by decide

/-- X5c — empty FSI scope (immediate matching PDI) defaults to LRI. -/
theorem resolveFSI_empty_inner :
    resolveFSI [0x2068, 0x2069] = [0x2066, 0x2069]
    := by decide

/-- X5c — nested isolate's interior is ignored when scanning the outer FSI's
    scope. Outer FSI sees only "L" outside the inner LRI...PDI scope. -/
theorem resolveFSI_nested_isolate_skipped :
    resolveFSI [0x2068, 0x2066, 0x05D0, 0x2069, 0x0041, 0x2069]
      = [0x2066, 0x2066, 0x05D0, 0x2069, 0x0041, 0x2069]
    := by decide

/-- X5c — FSI with no matching PDI scans to end of array; first strong
    character (Hebrew here) selects RLI. -/
theorem resolveFSI_unmatched_pdi :
    resolveFSI [0x2068, 0x05D0] = [0x2067, 0x05D0]
    := by decide

/-- `resolveFSI` is the identity on arrays containing no FSI. -/
theorem resolveFSI_identity_no_fsi :
    resolveFSI [0x0048, 0x0069, 0x2066, 0x05D0, 0x2069] =
      [0x0048, 0x0069, 0x2066, 0x05D0, 0x2069]
    := by decide

end Unicode.Bidi.Algorithm
