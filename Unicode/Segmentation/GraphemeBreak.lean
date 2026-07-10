/-
  Unicode.Segmentation.GraphemeBreak

  Default Grapheme Cluster Break algorithm per UAX #29 §3 (R26).

  The algorithm scans a codepoint sequence left-to-right and, for
  every position from 0 (string start) to n (string end), decides
  whether a grapheme cluster break occurs there. The decision uses
  Grapheme_Cluster_Break property values from
  `Unicode.Generated.GraphemeBreakProperty`, the
  Extended_Pictographic property from `Unicode.Generated.EmojiData`,
  and the Indic_Conjunct_Break sub-property from
  `Unicode.Generated.IndicConjunctBreak`.

  Rule order is the canonical order in UAX #29 §3 R26 — GB1 .. GB999.
  First match wins; the trailing GB999 catches every unmatched pair
  with a break.
-/

import Unicode.Generated.GraphemeBreakProperty
import Unicode.Generated.EmojiData
import Unicode.Generated.IndicConjunctBreak

namespace Unicode.Segmentation.GraphemeBreak

open Unicode.Generated.GraphemeBreakProperty
open Unicode.Generated.EmojiData
open Unicode.Generated.IndicConjunctBreak

/-- GB11 left-context state: tracks whether the prefix matches
    `Extended_Pictographic Extend*` (in which case a ZWJ would arm
    the GB11 pattern), or `Extended_Pictographic Extend* ZWJ` (in
    which case the next Extended_Pictographic fires GB11). -/
inductive EPicState where
  | none           -- no relevant prefix
  | afterEP        -- saw Extended_Pictographic, possibly followed by Extend*
  | afterEPZWJ     -- saw Extended_Pictographic Extend* ZWJ
  deriving DecidableEq, Repr, Inhabited

/-- GB9c left-context state: tracks the InCB chain
    `Consonant (Extend|Linker)*` and whether at least one Linker
    has appeared in the chain. -/
inductive InCBState where
  | none           -- no relevant prefix
  | consonant      -- saw Consonant followed by 0+ Extend (no Linker yet)
  | linker         -- saw Consonant (Extend|Linker)* Linker (Extend|Linker)*
  deriving DecidableEq, Repr, Inhabited

/-- Running state threaded through the left-to-right scan. -/
structure State where
  prevClass : Option GCBClass
  epicState : EPicState
  inCBState : InCBState
  riRun     : Nat                 -- consecutive RegionalIndicator run length
  deriving Inhabited

def State.initial : State :=
  { prevClass := none, epicState := .none, inCBState := .none, riRun := 0 }

/-- Decide whether a grapheme cluster break occurs immediately before
    codepoint `cp` given the running state. Implements UAX #29 R26
    rules GB1 .. GB999 in canonical order. -/
def shouldBreakBefore (cp : Nat) (s : State) : Bool :=
  let bc    := lookupGCB cp
  let inCB  := lookupInCB cp
  let isEP  := isExtendedPictographic cp
  match s.prevClass with
  | none =>
    -- GB1: sot ÷ Any
    true
  | some pc =>
    -- GB3: CR × LF
    if pc = .CR ∧ bc = .LF then false
    -- GB4: (Control | CR | LF) ÷
    else if pc = .Control ∨ pc = .CR ∨ pc = .LF then true
    -- GB5: ÷ (Control | CR | LF)
    else if bc = .Control ∨ bc = .CR ∨ bc = .LF then true
    -- GB6: L × (L | V | LV | LVT)
    else if pc = .L ∧ (bc = .L ∨ bc = .V ∨ bc = .LV ∨ bc = .LVT) then false
    -- GB7: (LV | V) × (V | T)
    else if (pc = .LV ∨ pc = .V) ∧ (bc = .V ∨ bc = .T) then false
    -- GB8: (LVT | T) × T
    else if (pc = .LVT ∨ pc = .T) ∧ bc = .T then false
    -- GB9: × (Extend | ZWJ)
    else if bc = .Extend ∨ bc = .ZWJ then false
    -- GB9a: × SpacingMark
    else if bc = .SpacingMark then false
    -- GB9b: Prepend ×
    else if pc = .Prepend then false
    -- GB9c: Consonant (Extend|Linker)* Linker (Extend|Linker)* × Consonant
    else if s.inCBState = .linker ∧ inCB = .Consonant then false
    -- GB11: Extended_Pictographic Extend* ZWJ × Extended_Pictographic
    else if s.epicState = .afterEPZWJ ∧ isEP then false
    -- GB12 / GB13: an odd-parity Regional_Indicator run extends with no break
    else if bc = .Regional_Indicator ∧ s.riRun % 2 = 1 then false
    -- GB999: Any ÷ Any
    else true

/-- Update running state after consuming codepoint `cp`. The update
    is pre-computed independent of the break decision, so the caller
    can record the break and move on. -/
def advance (cp : Nat) (s : State) : State :=
  let bc    := lookupGCB cp
  let inCB  := lookupInCB cp
  let isEP  := isExtendedPictographic cp
  let epicState' :=
    if isEP then EPicState.afterEP
    else if s.epicState = .afterEP && bc = .Extend then EPicState.afterEP
    else if s.epicState = .afterEP && bc = .ZWJ then EPicState.afterEPZWJ
    else EPicState.none
  let inCBState' :=
    if inCB = .Consonant then InCBState.consonant
    else if s.inCBState = .consonant && inCB = .Linker then InCBState.linker
    else if s.inCBState = .consonant && inCB = .Extend then InCBState.consonant
    else if s.inCBState = .linker && inCB = .Linker then InCBState.linker
    else if s.inCBState = .linker && inCB = .Extend then InCBState.linker
    else InCBState.none
  let riRun' :=
    if bc = .Regional_Indicator then s.riRun + 1 else 0
  { prevClass := some bc
    epicState := epicState'
    inCBState := inCBState'
    riRun     := riRun' }

/-- Boolean array of length `cps.size + 1`. Entry `i` is `true` when
    a grapheme cluster break occurs immediately before position `i`
    (so entry `0` is GB1's sot break and entry `cps.size` is GB2's
    eot break, both always `true`). -/
def graphemeBreaks (cps : Array Nat) : Array Bool :=
  let init : Array Bool × State := (#[], State.initial)
  let (bs, finalState) := cps.foldl
    (fun (acc : Array Bool × State) cp =>
      let (bs, s) := acc
      let breakHere := shouldBreakBefore cp s
      let bs' := bs.push breakHere
      let s' := advance cp s
      (bs', s'))
    init
  -- GB2: eot break is always true.
  Function.const State (bs.push true) finalState

end Unicode.Segmentation.GraphemeBreak
