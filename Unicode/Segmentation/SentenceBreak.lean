/-
  Unicode.Segmentation.SentenceBreak

  Default Sentence Break algorithm per UAX #29 §5 (R29).

  Unlike UAX #29 §3 (grapheme) and §4 (word) where the default
  rule SB999 (or its equivalents) is "break", the sentence-break
  default SB998 is "do not break". Sentence boundaries are produced
  by the explicit break-eligible rules (SB1, SB2, SB4, SB11), with
  SB6..SB10 / SB8a inhibiting breaks within terminator chains.

  Rule order is the canonical order in UAX #29 §5 R29 — SB1 .. SB998.
  SB5 ("Ignore Format and Extend characters") is realised by working
  with effective neighbours, defined as the most-recent non-absorbed
  class strictly before the current position. SB8 requires forward
  lookahead through neutral characters until a `Lower` is found
  (or a disruptor terminates the scan).
-/

import Unicode.Generated.SentenceBreakProperty

namespace Unicode.Segmentation.SentenceBreak

open Unicode.Generated.SentenceBreakProperty

/-- True iff a class is absorbed by SB5, i.e. one of `Extend`,
    `Format`. -/
def isAbsorbable (c : SBClass) : Bool :=
  c == .Extend || c == .Format

/-- Phase of the running terminator chain. The chain matches
    `(STerm | ATerm) Close* Sp* (Sep | CR | LF)?` and the phase
    records which suffix has been consumed so far. The atomic
    transitions are summarised in `advance` below. -/
inductive ChainPhase where
  | none           -- not in a terminator chain
  | aterm          -- (effective) ATerm just consumed
  | atermClose     -- ATerm Close+
  | atermSp        -- ATerm Close* Sp+
  | atermSep       -- ATerm Close* Sp* (Sep|CR|LF)
  | sterm          -- (effective) STerm just consumed
  | stermClose     -- STerm Close+
  | stermSp        -- STerm Close* Sp+
  | stermSep       -- STerm Close* Sp* (Sep|CR|LF)
  deriving DecidableEq, Repr, Inhabited

/-- Per-position state used by `shouldBreakBefore`. -/
structure StateAt where
  phase     : ChainPhase
  /-- Whether the most recent ATerm was effective-immediately
      preceded by `Upper` or `Lower`. Only meaningful when
      `phase = .aterm`. Required by SB7. -/
  sb7AtermEligible : Bool
  deriving Inhabited

/-- True iff the phase represents an active terminator chain that
    has not yet seen its terminating (Sep|CR|LF). -/
def ChainPhase.activeNoSep (p : ChainPhase) : Bool :=
  p == .aterm || p == .atermClose || p == .atermSp ||
  p == .sterm || p == .stermClose || p == .stermSp

/-- True iff the phase represents an active ATerm-rooted chain
    that has not yet seen its terminating (Sep|CR|LF). Used by
    the SB8 fast path. -/
def ChainPhase.atermActiveNoSep (p : ChainPhase) : Bool :=
  p == .aterm || p == .atermClose || p == .atermSp

/-- True iff the phase is at most `(STerm|ATerm) Close*` (i.e.
    we have not yet entered the Sp* or (Sep|CR|LF) suffix). -/
def ChainPhase.beforeSps (p : ChainPhase) : Bool :=
  p == .aterm || p == .atermClose || p == .sterm || p == .stermClose

/-- True iff the phase represents any active or just-completed
    chain — used by the SB11 fall-through which fires whenever no
    earlier rule kept the chain alive. -/
def ChainPhase.anyActive (p : ChainPhase) : Bool :=
  p != .none

/-- One state-machine step on a non-absorbable input class. The
    SB7 eligibility flag is recomputed when entering `.aterm`
    (the only state that uses it). -/
def transition (phase : ChainPhase) (c : SBClass)
    (effPrev : Option SBClass) (sb7Elig : Bool) :
    ChainPhase × Bool :=
  if c == .STerm then (.sterm, sb7Elig)
  else if c == .ATerm then
    let elig :=
      match effPrev with
      | some previous => previous == .Upper || previous == .Lower
      | none => false
    (.aterm, elig)
  else if c == .Close then
    if phase == .aterm || phase == .atermClose then (.atermClose, sb7Elig)
    else if phase == .sterm || phase == .stermClose then (.stermClose, sb7Elig)
    else (.none, sb7Elig)
  else if c == .Sp then
    if phase == .aterm || phase == .atermClose || phase == .atermSp then
      (.atermSp, sb7Elig)
    else if phase == .sterm || phase == .stermClose || phase == .stermSp then
      (.stermSp, sb7Elig)
    else
      (.none, sb7Elig)
  else if c == .Sep || c == .CR || c == .LF then
    if phase == .aterm || phase == .atermClose || phase == .atermSp then
      (.atermSep, sb7Elig)
    else if phase == .sterm || phase == .stermClose || phase == .stermSp then
      (.stermSep, sb7Elig)
    else
      (.none, sb7Elig)
  else
    (.none, sb7Elig)

/-- Build the per-position state array. `out[i]` is the chain state
    after consuming positions `0 .. i-1` (i.e. the state available to
    the break-decision at position `i`). -/
def buildStates (lits : List SBClass) : List StateAt :=
  let go : List StateAt × ChainPhase × Bool × Option SBClass
         → SBClass
         → List StateAt × ChainPhase × Bool × Option SBClass :=
    fun (out, phase, elig, effPrev) c =>
      let out' := out ++ [{ phase := phase, sb7AtermEligible := elig }]
      if isAbsorbable c then
        -- `.atermSep` / `.stermSep` are completed-chain states: the
        -- (Sep|CR|LF) has been consumed and SB4 has already fired
        -- between that (Sep|CR|LF) and any subsequent character
        -- (including an absorbable one — SB4 wins over SB5 in the
        -- canonical rule order). The chain is therefore over, and
        -- the absorbable belongs to the next segment, so reset to
        -- `.none`. Other phases retain their state across absorbed
        -- characters per SB5.
        if phase == .atermSep || phase == .stermSep then
          (out', .none, elig, effPrev)
        else (out', phase, elig, effPrev)
      else
        let (phase', elig') := transition phase c effPrev elig
        (out', phase', elig', some c)
  (lits.foldl go ([], .none, false, none)).1

/-- SB8 forward scan from position `i`. Returns `true` if a `Lower`
    is found before any disruptor (`OLetter`, `Upper`, `Sep`, `CR`,
    `LF`, `STerm`, `ATerm`). Absorbable and neutral classes are
    skipped. The fuel parameter must be at least `lits.length - i`. -/
def sb8Scan (lits : List SBClass) (i fuel : Nat) : Bool :=
  match fuel with
  | 0      => false
  | fuel'+1 =>
    if h : i < lits.length then
      let c := lits[i]
      if c == .Lower then true
      else if c == .OLetter || c == .Upper || c == .Sep ||
              c == .CR || c == .LF || c == .STerm || c == .ATerm then
        false
      else sb8Scan lits (i+1) fuel'
    else false

/-- Decide whether a sentence break occurs immediately before
    position `i`. -/
def shouldBreakBefore
    (lits   : List SBClass)
    (states : List StateAt)
    (i : Nat) : Bool :=
  if i = 0 then true                         -- SB1
  else if i ≥ lits.length then true            -- SB2 (caller adds eot)
  else
    let lp := lits[i-1]!
    let lc := lits[i]!
    -- SB3: CR × LF
    if lp == .CR && lc == .LF then false
    -- SB4: (Sep | CR | LF) ÷
    else if lp == .Sep || lp == .CR || lp == .LF then true
    -- SB5: × (Extend | Format)
    else if isAbsorbable lc then false
    else
      let s := states[i]!
      let phase := s.phase
      -- SB6: ATerm × Numeric
      if phase == .aterm && lc == .Numeric then false
      -- SB7: (Upper|Lower) ATerm × Upper
      else if phase == .aterm && s.sb7AtermEligible && lc == .Upper then false
      -- SB8: ATerm Close* Sp* × (¬{OLetter,Upper,Lower,Sep,CR,LF,STerm,ATerm})* Lower
      else if phase.atermActiveNoSep &&
              sb8Scan lits i (lits.length - i + 1) then false
      -- SB8a: (STerm|ATerm) Close* Sp* × (SContinue | STerm | ATerm)
      else if phase.activeNoSep &&
              (lc == .SContinue || lc == .STerm || lc == .ATerm) then false
      -- SB9: (STerm|ATerm) Close* × (Close | Sp | Sep | CR | LF)
      else if phase.beforeSps &&
              (lc == .Close || lc == .Sp || lc == .Sep ||
               lc == .CR    || lc == .LF) then false
      -- SB10: (STerm|ATerm) Close* Sp* × (Sp | Sep | CR | LF)
      else if phase.activeNoSep &&
              (lc == .Sp || lc == .Sep || lc == .CR || lc == .LF) then false
      -- SB11: terminator chain otherwise ends here
      else if phase.anyActive then true
      -- SB998: × Any (do not break)
      else false

/-- Boolean array of length `cps.size + 1`. Entry `i` is `true`
    when a sentence break occurs immediately before position `i`. -/
def sentenceBreaks (cps : List Nat) : List Bool :=
  let lits   := cps.map lookupSB
  let states := buildStates lits
  let n := cps.length
  let go : List Bool → Nat → List Bool :=
    fun bs i => bs ++ [shouldBreakBefore lits states i]
  let bs := (List.range n).foldl go []
  bs ++ [true]                               -- SB2: eot

end Unicode.Segmentation.SentenceBreak
