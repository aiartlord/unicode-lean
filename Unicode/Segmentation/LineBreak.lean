/-
  Unicode.Segmentation.LineBreak

  Default Line Break algorithm per UAX #14 R7.

  The algorithm scans a codepoint sequence left-to-right and decides,
  for every position from 0 (string start) to n (string end), whether
  a line break opportunity occurs there.  The decision uses
  Line_Break property values (resolved per LB1) from
  `Unicode.Generated.LineBreakProperty`, the Extended_Pictographic
  property from `Unicode.Generated.EmojiData`, and the General_Category
  from `Unicode.Generated.DerivedGeneralCategory` (used for Pi/Pf
  quote sub-classification by LB15a/LB15b).

  Rule order is the canonical order in UAX #14 R7 — LB1 .. LB31.
  LB1 is applied at lookup time. LB9 ("Treat X CM*/ZWJ* as if it
  were X" for X ∉ {BK, CR, LF, NL, SP, ZW}) is realised by working
  with effective neighbours, defined as the most-recent non-CM/non-ZWJ
  class strictly before the current position. LB10 ("Treat any
  remaining CM/ZWJ as if it were AL") is implemented as a fallback
  when an effective class would otherwise be missing.

  The per-position decision is `shouldBreakBefore`, returning `true`
  for a break opportunity (÷) and `false` for no-break (×).
-/

import Unicode.Generated.LineBreakProperty
import Unicode.Generated.EmojiData
import Unicode.Generated.DerivedGeneralCategory
import Unicode.Generated.EastAsianWidth

namespace Unicode.Segmentation.LineBreak

open Unicode.Generated.LineBreakProperty
open Unicode.Generated.EmojiData
open Unicode.Generated.DerivedGeneralCategory
open Unicode.Generated.EastAsianWidth

/-- A class is "absorbed" by LB9 when it is `CM` or `ZWJ`. The
    absorption is conditional on the preceding effective class not
    being one of `BK`, `CR`, `LF`, `NL`, `SP`, `ZW`. -/
def isCMZWJ (c : LBClass) : Bool := c == .CM || c == .ZWJ

/-- LB9 anchor: classes after which CM/ZWJ are NOT absorbed. -/
def lb9BlocksAbsorb (c : LBClass) : Bool :=
  c == .BK || c == .CR || c == .LF || c == .NL || c == .SP || c == .ZW

/-- Pi (Initial_Punctuation) quote refinement of `QU`. Used by LB15a. -/
def isPiQuote (cp : Nat) (lb : LBClass) : Bool :=
  lb == .QU && Unicode.Generated.DerivedGeneralCategory.lookup cp == .Pi

/-- Pf (Final_Punctuation) quote refinement of `QU`. Used by LB15b. -/
def isPfQuote (cp : Nat) (lb : LBClass) : Bool :=
  lb == .QU && Unicode.Generated.DerivedGeneralCategory.lookup cp == .Pf

/-- True iff `cp` is U+2010 HYPHEN. The character used to be class
    `HY` and is now class `HH` in UCD 17.0; LB20a / LB21a name it
    explicitly. -/
def isU2010 (cp : Nat) : Bool := cp == 0x2010

/-- Effective-class snapshot at a position. -/
structure EffSnapshot where
  /-- Class of the most-recent non-{CM,ZWJ} character strictly
      before this position. -/
  effPrev : Option LBClass
  /-- Codepoint of the most-recent non-{CM,ZWJ} character. Needed
      for LB20a / LB21a / LB28a which name U+2010 / U+25CC. -/
  effPrevCp : Option Nat
  /-- Class of the most-recent non-{CM,ZWJ,SP} character. -/
  effPrevNoSp : Option LBClass
  /-- Was a SP encountered between `effPrevNoSp` and the current
      position? -/
  spSinceNoSp : Bool
  /-- Class of the second-most-recent non-{CM,ZWJ} character. -/
  effPrevPrev : Option LBClass
  /-- Codepoint of the second-most-recent non-{CM,ZWJ} character. -/
  effPrevPrevCp : Option Nat
  /-- Whether the most recent significant context starts a Pi-quote
      window. -/
  inPiQuoteWindow : Bool
  /-- Effective Regional_Indicator run length (LB30a). -/
  riRun : Nat
  /-- Effective NU-chain detection for LB25. -/
  inNuChain : Bool
  deriving Inhabited

def EffSnapshot.initial : EffSnapshot :=
  { effPrev          := none
    effPrevCp        := none
    effPrevNoSp      := none
    spSinceNoSp      := false
    effPrevPrev      := none
    effPrevPrevCp    := none
    inPiQuoteWindow  := false
    riRun            := 0
    inNuChain        := false }

/-- Build a snapshot at every position using a single left-to-right
    fold. `out[i]` is the snapshot AT position `i` (state available
    to the break-decision at position `i` — derived from positions
    `0 .. i-1`). -/
def buildSnapshots
    (cps : List Nat) (lits : List LBClass) : List EffSnapshot :=
  let go : List EffSnapshot × EffSnapshot → Nat × LBClass
         → List EffSnapshot × EffSnapshot :=
    fun (out, s) (i, c) =>
      let out' := out ++ [s]
      let cReal :=
        if isCMZWJ c then
          match s.effPrev with
          | none    => LBClass.AL
          | some ep => if lb9BlocksAbsorb ep then LBClass.AL else c
        else c
      if isCMZWJ cReal then
        (out', s)
      else
        let cp := cps[i]!
        let isPi := isPiQuote cp cReal
        let effPrevPrev'   := s.effPrev
        let effPrevPrevCp' := s.effPrevCp
        let effPrev'       := some cReal
        let effPrevCp'     := some cp
        let effPrevNoSp'   :=
          if cReal == .SP then s.effPrevNoSp else some cReal
        let spSinceNoSp'   := cReal == .SP
        let riRun'         := if cReal == .RI then s.riRun + 1 else 0
        -- LB15a left-context: a Pi-quote opens the no-break window
        -- only when preceded by sot|BK|CR|LF|NL|OP|QU|GL|SP|ZW;
        -- otherwise the Pi sub-class doesn't suppress later breaks.
        let piLeftCtxOK : Bool :=
          match s.effPrev with
          | none   => true
          | some c =>
            c == .BK || c == .CR || c == .LF || c == .NL ||
            c == .OP || c == .QU || c == .GL || c == .SP ||
            c == .ZW
        let inPiQuoteWindow' :=
          if isPi && piLeftCtxOK then true
          else if cReal == .SP then s.inPiQuoteWindow
          else false
        let inNuChain' :=
          if cReal == .NU then true
          else if s.inNuChain &&
                  (cReal == .SY || cReal == .IS ||
                   cReal == .CL || cReal == .CP ||
                   cReal == .PR) then true
          else false
        let s' : EffSnapshot :=
          { effPrev          := effPrev'
            effPrevCp        := effPrevCp'
            effPrevNoSp      := effPrevNoSp'
            spSinceNoSp      := spSinceNoSp'
            effPrevPrev      := effPrevPrev'
            effPrevPrevCp    := effPrevPrevCp'
            inPiQuoteWindow  := inPiQuoteWindow'
            riRun            := riRun'
            inNuChain        := inNuChain' }
        (out', s')
  let indexed := (List.range cps.length).zip lits
  (indexed.foldl go ([], EffSnapshot.initial)).1

/-- Whether `o` is `some c` with `c` equal to one of the listed classes. -/
def epEq (o : Option LBClass) (target : LBClass) : Bool :=
  match o with
  | some c => c == target
  | none   => false

def epEq2 (o : Option LBClass) (a b : LBClass) : Bool :=
  match o with
  | some c => c == a || c == b
  | none   => false

def epEq3 (o : Option LBClass) (a b d : LBClass) : Bool :=
  match o with
  | some c => c == a || c == b || c == d
  | none   => false

def epEq4 (o : Option LBClass) (a b d e : LBClass) : Bool :=
  match o with
  | some c => c == a || c == b || c == d || c == e
  | none   => false

def epEq5 (o : Option LBClass) (a b d e f : LBClass) : Bool :=
  match o with
  | some c => c == a || c == b || c == d || c == e || c == f
  | none   => false

def epEq7 (o : Option LBClass) (a b d e f g h : LBClass) : Bool :=
  match o with
  | some c => c == a || c == b || c == d || c == e ||
              c == f || c == g || c == h
  | none   => false

/-- Decide whether a line break opportunity exists immediately
    before position `i`. -/
def shouldBreakBefore
    (cps  : List Nat)
    (lits : List LBClass)
    (snaps : List EffSnapshot)
    (i : Nat) : Bool :=
  if i = 0 then false                        -- LB2
  else if i ≥ lits.length then true            -- LB3
  else
    let lp := lits[i-1]!
    let lc := lits[i]!
    let s  := snaps[i]!
    let lcEff : LBClass :=
      if isCMZWJ lc then
        match s.effPrev with
        | none    => .AL
        | some ep => if lb9BlocksAbsorb ep then .AL else lc
      else lc
    let ep : Option LBClass :=
      if isCMZWJ lp then s.effPrev else some lp
    -- LB4
    if lp == .BK then true
    -- LB5
    else if lp == .CR && lc == .LF then false
    else if lp == .CR || lp == .LF || lp == .NL then true
    -- LB6
    else if lc == .BK || lc == .CR || lc == .LF || lc == .NL then false
    -- LB7
    else if lc == .SP || lc == .ZW then false
    -- LB8
    else if s.effPrevNoSp == some .ZW then true
    -- LB8a
    else if lp == .ZWJ then false
    -- LB9
    else if isCMZWJ lc &&
            (match s.effPrev with
             | none => false
             | some prev => ! lb9BlocksAbsorb prev) then false
    -- LB11
    else if lcEff == .WJ then false
    else if epEq ep .WJ then false
    -- LB12
    else if epEq ep .GL then false
    -- LB12a
    else if lcEff == .GL &&
            (match ep with
             | some c => c != .SP && c != .BA && c != .HY && c != .HH
             | none   => true) then false
    -- LB15c (UCD 17.0 priority: above LB13 / LB15d):
    -- SP ÷ IS NU. Break before an `IS` that begins a number and
    -- follows a space, e.g. "equals .35".
    else if lp == .SP && lcEff == .IS &&
            (i + 1 < cps.length && lits[i+1]! == .NU) then true
    -- LB13
    else if lcEff == .CL || lcEff == .CP || lcEff == .EX ||
            lcEff == .IS || lcEff == .SY then false
    -- LB14
    else if s.effPrevNoSp == some .OP then false
    -- LB15a
    else if s.inPiQuoteWindow then false
    -- LB15b
    else if isPfQuote (cps[i]!) lcEff &&
            (i + 1 ≥ cps.length ||
             (let nxt := lits[i+1]!
              nxt == .SP || nxt == .GL || nxt == .WJ || nxt == .CL ||
              nxt == .QU || nxt == .CP || nxt == .EX || nxt == .IS ||
              nxt == .SY || nxt == .BK || nxt == .CR || nxt == .LF ||
              nxt == .NL || nxt == .ZW)) then false
    -- LB15d: × IS (subsumed above by LB13's `× IS` after the LB15c
    -- carve-out, but kept here for canonical clarity)
    else if lcEff == .IS then false
    -- LB16
    else if lcEff == .NS &&
            (s.effPrevNoSp == some .CL || s.effPrevNoSp == some .CP) then false
    -- LB17
    else if lcEff == .B2 && s.effPrevNoSp == some .B2 then false
    -- LB18
    else if lp == .SP then true
    -- LB19 / LB19a (UCD 17.0): × QU and QU × fire no-break, with
    -- a CJK-tailored exception on each OUTER side of a Pi/Pf quote.
    -- The exception only fires when ALL THREE consecutive
    -- characters — left-context, the quote, and right-context —
    -- are East_Asian_Width ∈ {F, W, H, A} (treating Ambiguous as
    -- East-Asian). In that case the no-break rule is suppressed
    -- and the default break applies, allowing line breaks at
    -- quote boundaries inside contiguous CJK content.
    --
    -- The INNER side of each quote (`QU(Pi) ×`, `× QU(Pf)`) is
    -- still always × — that's the boundary inside the quote scope.
    else if lcEff == .QU &&
            ! (isPiQuote (cps[i]!) lcEff &&
               (let prevCp := cps[i-1]!
                let qCp    := cps[i]!
                let nextEA :=
                  if i + 1 < cps.length then
                    let w := Unicode.Generated.EastAsianWidth.lookup (cps[i+1]!)
                    w == .F || w == .W || w == .H || w == .A
                  else false
                let wp := Unicode.Generated.EastAsianWidth.lookup prevCp
                let wq := Unicode.Generated.EastAsianWidth.lookup qCp
                (wp == .F || wp == .W || wp == .H || wp == .A) &&
                (wq == .F || wq == .W || wq == .H || wq == .A) &&
                nextEA)) then false
    else if epEq ep .QU &&
            ! (let qCp := s.effPrevCp.getD 0
               isPfQuote qCp .QU &&
               (let currCp := cps[i]!
                let prevPrevEA :=
                  match s.effPrevPrevCp with
                  | some cp =>
                    let w := Unicode.Generated.EastAsianWidth.lookup cp
                    w == .F || w == .W || w == .H || w == .A
                  | none => false
                let wq := Unicode.Generated.EastAsianWidth.lookup qCp
                let wc := Unicode.Generated.EastAsianWidth.lookup currCp
                prevPrevEA &&
                (wq == .F || wq == .W || wq == .H || wq == .A) &&
                (wc == .F || wc == .W || wc == .H || wc == .A))) then false
    -- LB20
    else if lcEff == .CB then true
    else if epEq ep .CB then true
    -- LB20.1 (UCD 17.0): (sot|BK|CR|LF|NL|SP|ZW|CB|GL) HH × (AL|HL).
    -- An explicit-hyphen punctuation joins to a following letter
    -- only when its own left context is "outside a word" — i.e.,
    -- the same start-of-segment context that LB20a requires for
    -- the regular hyphen / U+2010 case. Mid-word HH (after another
    -- letter) falls through to the default LB31 break.
    else if epEq ep .HH && (lcEff == .AL || lcEff == .HL) &&
            (match s.effPrevPrev with
             | none => true
             | some c =>
               c == .BK || c == .CR || c == .LF || c == .NL ||
               c == .SP || c == .ZW || c == .CB || c == .GL) then false
    -- LB20a / LB20.1 (UCD 17.0):
    --   (sot | BK | CR | LF | NL | SP | ZW | CB | GL)
    --   (HY | HH | U+2010) × (AL | HL)
    -- The right-side letter set was broadened in UCD 17.0 to
    -- include HL alongside AL. The hyphen position uses
    -- `s.effPrevCp` / `s.effPrev` to look through any LB9-absorbed
    -- combining marks; the left context is `s.effPrevPrev`.
    else if (lcEff == .AL || lcEff == .HL) &&
            (let c := s.effPrevCp.getD 0
             let cls := s.effPrev.getD .XX
             cls == .HY || cls == .HH || isU2010 c) &&
            (match s.effPrevPrev with
             | none => true
             | some c =>
               c == .BK || c == .CR || c == .LF || c == .NL ||
               c == .SP || c == .ZW || c == .CB || c == .GL) then false
    -- LB21
    else if lcEff == .BA || lcEff == .HY || lcEff == .HH ||
            lcEff == .NS then false
    else if epEq ep .BB then false
    -- LB21a: HL (HY | U+2010) × [^HL]. The pattern is restricted
    -- to HY-class hyphens and U+2010 specifically; BA does not
    -- glue an HL letter to the following character.
    else if s.effPrevPrev == some .HL &&
            (let c := s.effPrevCp.getD 0
             let cls := s.effPrev.getD .XX
             cls == .HY || isU2010 c) &&
            lcEff != .HL then false
    -- LB21b
    else if lcEff == .HL && epEq ep .SY then false
    -- LB22
    else if lcEff == .IN then false
    -- LB23
    else if lcEff == .NU && epEq2 ep .AL .HL then false
    else if (lcEff == .AL || lcEff == .HL) && epEq ep .NU then false
    -- LB23a
    else if (lcEff == .ID || lcEff == .EB || lcEff == .EM) &&
            epEq ep .PR then false
    else if lcEff == .PO && epEq3 ep .ID .EB .EM then false
    -- LB24
    else if (lcEff == .AL || lcEff == .HL) && epEq2 ep .PR .PO then false
    else if (lcEff == .PR || lcEff == .PO) && epEq2 ep .AL .HL then false
    -- LB25 chain close: NU/SY/IS (CL/CP)? × (PO/PR).
    -- The NU-chain state already tracks NU SY IS continuations;
    -- include CL/CP suffix here.
    else if s.inNuChain &&
            (lcEff == .CL || lcEff == .CP ||
             lcEff == .PO || lcEff == .PR) then false
    -- LB25 chain start: (PR | PO | HY | OP | IS) × NU
    else if lcEff == .NU && epEq5 ep .PR .PO .HY .OP .IS then false
    -- LB25 chain body: NU × NU
    else if lcEff == .NU && epEq ep .NU then false
    -- LB25 chain extension: SY × NU (only inside an active chain)
    else if lcEff == .NU && epEq ep .SY && s.inNuChain then false
    -- LB25 chain-prefix bracketing: PR × OP × NU.
    -- Three-character pattern: a PR connects to an OP only when the
    -- OP is itself followed by a NU (so the OP-NU pair starts a
    -- number that the PR labels). Both the PR and the OP must be
    -- non-East_Asian_Width F/W/H.
    else if lcEff == .OP && epEq ep .PR &&
            ! Unicode.Generated.EastAsianWidth.isEastAsianFWH (cps[i]!) &&
            ! Unicode.Generated.EastAsianWidth.isEastAsianFWH
                (s.effPrevCp.getD 0) &&
            (i + 1 < lits.length && lits[i+1]! == .NU) then false
    -- LB26
    else if epEq ep .JL &&
            (lcEff == .JL || lcEff == .JV || lcEff == .H2 ||
             lcEff == .H3) then false
    else if epEq2 ep .JV .H2 && (lcEff == .JV || lcEff == .JT) then false
    else if epEq2 ep .JT .H3 && lcEff == .JT then false
    -- LB27
    else if epEq5 ep .JL .JV .JT .H2 .H3 &&
            (lcEff == .IN || lcEff == .PO) then false
    else if epEq ep .PR &&
            (lcEff == .JL || lcEff == .JV || lcEff == .JT ||
             lcEff == .H2 || lcEff == .H3) then false
    -- LB28
    else if (lcEff == .AL || lcEff == .HL) && epEq2 ep .AL .HL then false
    -- LB28a: AP × (AK | ◌U+25CC | AS); (AK|◌|AS) × (VF|VI);
    --        (AK|◌|AS) VI × (AK|◌); (AK|◌|AS) × (AK|◌|AS) VF
    --        (◌ here is U+25CC, class AL). Effective lookback uses
    --        s.effPrevCp / s.effPrevPrevCp under LB9.
    else if epEq ep .AP &&
            (lcEff == .AK || lcEff == .AS || cps[i]! == 0x25CC) then false
    else if (epEq2 ep .AK .AS ||
             (s.effPrevCp == some 0x25CC && s.effPrev == some .AL)) &&
            (lcEff == .VF || lcEff == .VI) then false
    else if (s.effPrev == some .VI ∧
             (s.effPrevPrev == some .AK ∨ s.effPrevPrev == some .AS ∨
              s.effPrevPrevCp == some 0x25CC)) &&
            (lcEff == .AK || cps[i]! == 0x25CC) then false
    -- LB28a fourth sub-rule: (AK|◌|AS) × (AK|◌|AS) VF — three-char
    -- aksara cluster sequence. Requires the EFFECTIVE prev to be
    -- (AK|◌|AS), the CURRENT to be (AK|◌|AS), and the NEXT
    -- (skipping any LB9-absorbed CM/ZWJ) to be VF.
    else if (epEq2 ep .AK .AS ||
             (s.effPrevCp == some 0x25CC && s.effPrev == some .AL)) &&
            (lcEff == .AK || lcEff == .AS || cps[i]! == 0x25CC) &&
            (let scan : Nat → Nat → Bool := fun startIdx fuel =>
               let rec go (j fuel : Nat) : Bool :=
                 match fuel with
                 | 0     => false
                 | f + 1 =>
                   if j ≥ lits.length then false
                   else
                     let cls := lits[j]!
                     if cls == .CM || cls == .ZWJ then go (j+1) f
                     else cls == .VF
               go startIdx fuel
             scan (i+1) (lits.length - i + 1)) then false
    -- LB29
    else if (lcEff == .AL || lcEff == .HL) && epEq ep .IS then false
    -- LB30: (AL|HL|NU) × OP and CP × (AL|HL|NU), but only when the
    -- OP/CP is NOT East_Asian_Width F/W/H.
    else if lcEff == .OP && epEq3 ep .AL .HL .NU &&
            ! Unicode.Generated.EastAsianWidth.isEastAsianFWH (cps[i]!) then false
    else if (lcEff == .AL || lcEff == .HL || lcEff == .NU) &&
            epEq ep .CP &&
            ! Unicode.Generated.EastAsianWidth.isEastAsianFWH (cps[i-1]!) then false
    -- LB30a
    else if lcEff == .RI && s.riRun % 2 == 1 then false
    -- LB30b: EB × EM; [\p{Extended_Pictographic} & \p{Cn}] × EM.
    -- The codepoint check uses `s.effPrevCp` so it sees through any
    -- LB9-absorbed combining marks.
    else if lcEff == .EM && epEq ep .EB then false
    else if lcEff == .EM &&
            (let prevCp := s.effPrevCp.getD 0
             isExtendedPictographic prevCp &&
             Unicode.Generated.DerivedGeneralCategory.lookup prevCp == .Cn) then false
    -- LB31
    else true

/-- Boolean array of length `cps.length + 1`. Entry `i` is `true` when
    a line break opportunity occurs immediately before position `i`.
    `bs[0] = false` per LB2; `bs[cps.length] = true` per LB3. -/
def lineBreaks (cps : List Nat) : List Bool :=
  let lits  := cps.map lookupResolved
  let snaps := buildSnapshots cps lits
  let n := cps.length
  let go : List Bool → Nat → List Bool :=
    fun bs i => bs ++ [shouldBreakBefore cps lits snaps i]
  let bs := (List.range n).foldl go []
  bs ++ [true]                               -- LB3

end Unicode.Segmentation.LineBreak
