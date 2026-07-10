/-
  Unicode.Segmentation.WordBreak

  Default Word Break algorithm per UAX #29 §4 (R28).

  The algorithm scans a codepoint sequence left-to-right and decides,
  for every position from 0 (string start) to n (string end), whether
  a word boundary occurs there. The decision uses Word_Break property
  values from `Unicode.Generated.WordBreakProperty` and the
  Extended_Pictographic property from `Unicode.Generated.EmojiData`.

  Rule order is the canonical order in UAX #29 §4 R28 — WB1 .. WB999.
  WB4 ("Ignore Format and Extend characters") is realised by working
  with effective neighbours, defined as the most-recent
  non-{Extend,Format,ZWJ} class strictly before the current position
  (and analogously the next effective class for the lookahead rules
  WB6 and WB12).
-/

import Unicode.Generated.WordBreakProperty
import Unicode.Generated.EmojiData

namespace Unicode.Segmentation.WordBreak

open Unicode.Generated.WordBreakProperty
open Unicode.Generated.EmojiData

/-- True iff a class is absorbed by WB4 ("Ignore Format and Extend
    characters"), i.e. one of `Extend`, `Format`, `ZWJ`. -/
def isAbsorbable (c : WBClass) : Bool :=
  c == .Extend || c == .Format || c == .ZWJ

/-- Effective-prev pair at every position. The fold returns
    (effPrevAtI, effPrevPrevAtI) where `effPrev` is the class of the
    most-recent non-absorbable position strictly before `i`, and
    `effPrevPrev` is the class of the second-most-recent such
    position. Both are `none` when there are too few non-absorbable
    positions before `i`. -/
def buildEffPrev (lits : Array WBClass) :
    Array (Option WBClass × Option WBClass) :=
  let go : Array (Option WBClass × Option WBClass) × Option WBClass × Option WBClass
         → WBClass
         → Array (Option WBClass × Option WBClass) × Option WBClass × Option WBClass :=
    fun (out, cur, prev) c =>
      let out' := out.push (cur, prev)
      if isAbsorbable c then (out', cur, prev)
      else (out', some c, cur)
  (lits.foldl go (#[], none, none)).1

/-- Effective-next class at every position: the class of the
    most-recent non-absorbable position strictly AFTER `i`. -/
def buildEffNext (lits : Array WBClass) : Array (Option WBClass) :=
  -- Reverse, fold computing "effective prev" of the reversed sequence,
  -- then reverse the result. Each element of the reversed-fold output
  -- corresponds to "effective next" in the original direction.
  let rev := lits.reverse
  let go : Array (Option WBClass) × Option WBClass → WBClass
         → Array (Option WBClass) × Option WBClass :=
    fun (out, cur) c =>
      let out' := out.push cur
      if isAbsorbable c then (out', cur)
      else (out', some c)
  ((rev.foldl go (#[], none)).1).reverse

/-- Effective Regional_Indicator run length ending at the most-recent
    non-absorbable position strictly before each position `i`. Used
    by WB15 / WB16. -/
def buildEffRiRun (lits : Array WBClass) : Array Nat :=
  let go : Array Nat × Nat → WBClass → Array Nat × Nat :=
    fun (out, cur) c =>
      let out' := out.push cur
      if isAbsorbable c then (out', cur)
      else if c == .Regional_Indicator then (out', cur + 1)
      else (out', 0)
  (lits.foldl go (#[], 0)).1

/-- Decide whether a word break occurs immediately before position
    `i`. Implements UAX #29 R28 rules WB1 .. WB999 in canonical
    order, using effective neighbours for the WB5+ rules. -/
def shouldBreakBefore
    (cps  : Array Nat)
    (lits : Array WBClass)
    (eps  : Array Bool)
    (effP : Array (Option WBClass × Option WBClass))
    (effN : Array (Option WBClass))
    (riR  : Array Nat)
    (i : Nat) : Bool :=
  if i = 0 then true                        -- WB1: sot ÷
  else if i ≥ cps.size then true            -- WB2: ÷ eot (caller adds eot)
  else
    let lp := lits[i-1]!
    let lc := lits[i]!
    let isEPCurr := eps[i]!
    -- WB3: CR × LF
    if lp == .CR && lc == .LF then false
    -- WB3a: (Newline | CR | LF) ÷
    else if lp == .Newline || lp == .CR || lp == .LF then true
    -- WB3b: ÷ (Newline | CR | LF)
    else if lc == .Newline || lc == .CR || lc == .LF then true
    -- WB3c: ZWJ × Extended_Pictographic
    else if lp == .ZWJ && isEPCurr then false
    -- WB3d: WSegSpace × WSegSpace
    else if lp == .WSegSpace && lc == .WSegSpace then false
    -- WB4: × (Extend | Format | ZWJ) — except after sot / hard break
    -- (which are caught above). The current class is absorbed.
    else if isAbsorbable lc then false
    else
      -- For WB5+, use the effective prev (skipping any WB4-absorbed
      -- run between i-1 and the most recent non-absorbable position).
      -- If there is no effective prev (sequence began with a run of
      -- absorbable characters), all WB5+ rules fail to match and we
      -- fall through to WB999.
      let (effPrev, effPrevPrev) := effP[i]!
      let effNext := effN[i]!
      let prevRi  := riR[i]!
      match effPrev with
      | none => true                                   -- WB999
      | some ep =>
        let isAH := fun (c : WBClass) => c == .ALetter || c == .Hebrew_Letter
        let isMid := fun (c : WBClass) =>
          c == .MidLetter || c == .MidNumLet || c == .Single_Quote
        let isMidNum := fun (c : WBClass) =>
          c == .MidNum || c == .MidNumLet || c == .Single_Quote
        let nextIsAH : Bool :=
          match effNext with | some n => isAH n | none => false
        let nextIsHL : Bool :=
          match effNext with | some n => n == .Hebrew_Letter | none => false
        let nextIsNum : Bool :=
          match effNext with | some n => n == .Numeric | none => false
        let prevPrevIsAH : Bool :=
          match effPrevPrev with | some pp => isAH pp | none => false
        let prevPrevIsHL : Bool :=
          match effPrevPrev with | some pp => pp == .Hebrew_Letter | none => false
        let prevPrevIsNum : Bool :=
          match effPrevPrev with | some pp => pp == .Numeric | none => false
        -- WB5: (ALetter | Hebrew_Letter) × (ALetter | Hebrew_Letter)
        if isAH ep && isAH lc then false
        -- WB6: (AL|HL) × (ML|MNL|SQ) (AL|HL)
        else if isAH ep && isMid lc && nextIsAH then false
        -- WB7: (AL|HL) (ML|MNL|SQ) × (AL|HL)
        else if isMid ep && isAH lc && prevPrevIsAH then false
        -- WB7a: Hebrew_Letter × Single_Quote
        else if ep == .Hebrew_Letter && lc == .Single_Quote then false
        -- WB7b: Hebrew_Letter × Double_Quote Hebrew_Letter
        else if ep == .Hebrew_Letter && lc == .Double_Quote && nextIsHL then false
        -- WB7c: Hebrew_Letter Double_Quote × Hebrew_Letter
        else if ep == .Double_Quote && lc == .Hebrew_Letter && prevPrevIsHL then false
        -- WB8: Numeric × Numeric
        else if ep == .Numeric && lc == .Numeric then false
        -- WB9: (AL|HL) × Numeric
        else if isAH ep && lc == .Numeric then false
        -- WB10: Numeric × (AL|HL)
        else if ep == .Numeric && isAH lc then false
        -- WB11: Numeric (MN|MNL|SQ) × Numeric
        else if isMidNum ep && lc == .Numeric && prevPrevIsNum then false
        -- WB12: Numeric × (MN|MNL|SQ) Numeric
        else if ep == .Numeric && isMidNum lc && nextIsNum then false
        -- WB13: Katakana × Katakana
        else if ep == .Katakana && lc == .Katakana then false
        -- WB13a: (AL|HL|N|Kat|ENL) × ExtendNumLet
        else if (isAH ep || ep == .Numeric || ep == .Katakana || ep == .ExtendNumLet) &&
                lc == .ExtendNumLet then false
        -- WB13b: ExtendNumLet × (AL|HL|N|Kat)
        else if ep == .ExtendNumLet &&
                (isAH lc || lc == .Numeric || lc == .Katakana) then false
        -- WB15 / WB16: odd-parity Regional_Indicator joins with no break
        else if lc == .Regional_Indicator && prevRi % 2 == 1 then false
        -- WB999: Any ÷ Any
        else true

/-- Boolean array of length `cps.size + 1`. Entry `i` is `true` when
    a word break occurs immediately before position `i`. -/
def wordBreaks (cps : Array Nat) : Array Bool :=
  let lits := cps.map lookupWB
  let eps  := cps.map isExtendedPictographic
  let effP := buildEffPrev lits
  let effN := buildEffNext lits
  let riR  := buildEffRiRun lits
  let n := cps.size
  let go : Array Bool → Nat → Array Bool :=
    fun bs i => bs.push (shouldBreakBefore cps lits eps effP effN riR i)
  let bs := (List.range n).foldl go #[]
  bs.push true  -- WB2: eot

end Unicode.Segmentation.WordBreak
