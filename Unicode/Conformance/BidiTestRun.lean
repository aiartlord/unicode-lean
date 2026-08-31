/-
  Unicode.Conformance.BidiTestRun

  An evaluated run of the published `BidiTest.txt` against
  `Unicode.Bidi.Algorithm`, the companion to
  `Unicode.Conformance.BidiCharacterTestRun`.

  `BidiTest.txt` states its cases in `Bidi_Class` names rather than codepoints,
  and carries the expected answers in directives that apply to the rows beneath
  them:

      @Levels:  1 1 0 x
      @Reorder: 1 0 2
      L LRE R PDF; 7

  The trailing bitset names which paragraph directions the row is asserted for:
  bit 0 the P2/P3 reading, bit 1 left-to-right, bit 2 right-to-left. A row with
  `7` is therefore three cases, which is why the file's case count exceeds its
  row count.

  Because the rows name classes, each class needs a codepoint carrying it.
  Those come from `explicitRanges`, the same pinned table the algorithm reads,
  rather than being transcribed: the representative for a class is the lowest
  codepoint of its first range, so the mapping cannot drift from the table the
  algorithm resolves against.
-/

import Unicode.Bidi.Algorithm

namespace Unicode.Conformance.BidiTestRun

open Unicode.Bidi.Algorithm
open Unicode.Generated.DerivedBidiClass (BidiClass explicitRanges)

def trimS (s : String) : String := (String.trimAscii s).toString

def parseDecChars (cs : List Char) : Nat :=
  cs.foldl (fun acc c =>
    let n := c.toNat
    if n ≥ 48 && n ≤ 57 then acc * 10 + (n - 48) else acc) 0

def spaceFields (field : String) : List String :=
  ((trimS field).splitOn " ").filter (fun s => s ≠ "")

/-- The class names `BidiTest.txt` uses, paired with the constructor each one
    names. A lookup rather than a match, so every name is listed explicitly and
    an unknown name simply finds nothing. -/
def classNames : List (String × BidiClass) :=
  [ ("L", .L), ("R", .R), ("AL", .AL), ("EN", .EN), ("ES", .ES), ("ET", .ET)
  , ("AN", .AN), ("CS", .CS), ("NSM", .NSM), ("BN", .BN), ("B", .B), ("S", .S)
  , ("WS", .WS), ("ON", .ON), ("LRE", .LRE), ("LRO", .LRO), ("RLE", .RLE)
  , ("RLO", .RLO), ("PDF", .PDF), ("LRI", .LRI), ("RLI", .RLI), ("FSI", .FSI)
  , ("PDI", .PDI) ]

def classOfName (name : String) : Option BidiClass :=
  (classNames.find? (fun pair => pair.1 == name)).map (fun pair => pair.2)

/-- A codepoint carrying `bc`, taken from the algorithm's own pinned table so
    the two cannot disagree. -/
def representativeFor (bc : BidiClass) : Option Nat :=
  (explicitRanges.find? (fun entry => entry.2.2 == bc)).map (fun entry => entry.1)

def codepointsOfClasses (names : List String) : Option (List Nat) :=
  names.foldl
    (fun acc name =>
      acc.bind fun sofar =>
        (classOfName name).bind fun bc =>
          (representativeFor bc).map (fun cp => sofar ++ [cp]))
    (some [])

/-- Expected answers currently in force, set by the `@Levels` and `@Reorder`
    directives above the rows they apply to. -/
structure Directives where
  levels : List (Option Nat) := []
  order  : List Nat := []
  deriving Inhabited

def levelList (field : String) : List (Option Nat) :=
  (spaceFields field).map (fun s =>
    if s == "x" then none else some (parseDecChars s.toList))

def orderList (field : String) : List Nat :=
  (spaceFields field).map (fun s => parseDecChars s.toList)

inductive Judgement where
  | pass
  | fail
  deriving Inhabited, DecidableEq

structure Tally where
  passed : Nat := 0
  failed : Nat := 0
  deriving Inhabited

def Tally.add (t : Tally) : Judgement → Tally
  | .pass => { t with passed := t.passed + 1 }
  | .fail => { t with failed := t.failed + 1 }

/-- Resolved levels in input order, `none` at each position X9 removes. -/
def actualLevels (cps : List Nat) (result : ParagraphResult) : List (Option Nat) :=
  Prod.fst <| cps.foldl
    (fun (acc : List (Option Nat) × List Nat) cp =>
      let (out, remaining) := acc
      if isX9Removed (lookupBidiClass cp) then (out ++ [none], remaining)
      else
        match remaining with
        | lvl :: rest => (out ++ [some lvl], rest)
        | [] => (out ++ [none], []))
    ([], result.records.map (fun rec => rec.level))

/-- Judge one case: one row under one paragraph direction. `dir` is 0 for the
    P2/P3 reading, 1 for left-to-right and 2 for right-to-left, matching the
    bits the file's bitset sets. -/
def judgeCase (cps : List Nat) (d : Directives) (dir : Nat) : Judgement :=
  let result :=
    if dir == 0 then bidiParagraph cps
    else if dir == 1 then bidiParagraphAt cps 0
    else bidiParagraphAt cps 1
  let levelsOk := actualLevels cps result == d.levels
  let orderOk := reorderedInputIndices cps result == d.order
  if levelsOk && orderOk then Judgement.pass else Judgement.fail

/-- The paragraph directions a bitset selects, as the file defines the bits. -/
def directionsOf (bitset : Nat) : List Nat :=
  let auto := if bitset % 2 == 1 then [0] else []
  let ltr := if (bitset / 2) % 2 == 1 then [1] else []
  let rtl := if (bitset / 4) % 2 == 1 then [2] else []
  auto ++ ltr ++ rtl

structure State where
  directives : Directives := {}
  tally      : Tally := {}
  cases      : Nat := 0
  deriving Inhabited

/-- Judge one data row under every direction its bitset selects. -/
def judgeRowLine (st : State) (line : String) : State :=
  let fields := line.splitOn ";"
  let advanced : Option State :=
    fields[0]?.bind fun classesF =>
    fields[1]?.bind fun bitsF =>
      (codepointsOfClasses (spaceFields classesF)).map fun cps =>
        (directionsOf (parseDecChars (trimS bitsF).toList)).foldl
          (fun acc dir =>
            { acc with
                tally := acc.tally.add (judgeCase cps st.directives dir),
                cases := acc.cases + 1 })
          st
  advanced.getD st

/-- Fold one line of the file into the running state. Directive lines update
    the expected answers; data rows are judged against them. -/
def step (st : State) (rawLine : String) : State :=
  let line := trimS rawLine
  if line == "" then st
  else if line.startsWith "#" then st
  else if line.startsWith "@Levels:" then
    { st with directives := { st.directives with levels := levelList (line.drop 8).toString } }
  else if line.startsWith "@Reorder:" then
    { st with directives := { st.directives with order := orderList (line.drop 9).toString } }
  else judgeRowLine st line

def bidiTestRaw : String :=
  include_str "../Ucd/BidiTest.txt"

def lines : List String := bidiTestRaw.splitOn "\n"

def runOn (sample : List String) : State :=
  sample.foldl step {}

def reportOn (sample : List String) : String :=
  let st := runOn sample
  s!"BidiTest: {st.cases} cases judged from {sample.length} lines read\n" ++
  s!"  levels and reorder: passed {st.tally.passed}, failed {st.tally.failed}, skipped 0"

def report : String := reportOn lines

def reportFirst (n : Nat) : String := reportOn (lines.take n)

end Unicode.Conformance.BidiTestRun
