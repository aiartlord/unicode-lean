/-
  Unicode.Conformance.BidiCharacterTestRun

  An evaluated run of the published `BidiCharacterTest.txt` against
  `Unicode.Bidi.Algorithm`, in the shape `Unicode.Conformance.IdnaTestV2`
  already uses: parse every row of the shipped file, judge each one, and tally
  the judgements into a report that states how many rows it read.

  This is the executed counterpart to the kernel-proved vectors in
  `Unicode.Conformance.BidiCharacterTest`. Those prove a handful of paragraph
  levels inside the kernel; this folds the whole corpus through the algorithm
  and reports pass and fail per column. Neither replaces the other: the proofs
  say the algorithm is right about the cases they name, and the run says it
  agrees with the Consortium's published answers on every row of the file.

  Each row is

      codepoints;direction;paragraph level;levels;visual order

  where `direction` is 0 for LTR, 1 for RTL and 2 for the P2/P3 reading,
  `levels` gives one entry per input character with `x` where the algorithm
  removes it, and `visual order` lists the surviving input indices in display
  order.
-/

import Unicode.Bidi.Algorithm

namespace Unicode.Conformance.BidiCharacterTestRun

open Unicode.Bidi.Algorithm

/-- One parsed row. `levels` carries `none` where the file writes `x`. -/
structure Row where
  codepoints     : List Nat
  direction      : Nat
  paragraphLevel : Nat
  levels         : List (Option Nat)
  order          : List Nat
  deriving Inhabited

def trimS (s : String) : String := (String.trimAscii s).toString

def hexDigitVal (c : Char) : Nat :=
  let n := c.toNat
  if n ≥ 48 && n ≤ 57 then n - 48
  else if n ≥ 65 && n ≤ 70 then n - 55
  else if n ≥ 97 && n ≤ 102 then n - 87
  else 0

def parseHexChars (cs : List Char) : Nat :=
  cs.foldl (fun acc c => acc * 16 + hexDigitVal c) 0

def parseDecChars (cs : List Char) : Nat :=
  cs.foldl (fun acc c =>
    let n := c.toNat
    if n ≥ 48 && n ≤ 57 then acc * 10 + (n - 48) else acc) 0

/-- Split a field on ASCII space, dropping empties. -/
def spaceFields (field : String) : List String :=
  ((trimS field).splitOn " ").filter (fun s => s ≠ "")

def hexList (field : String) : List Nat :=
  (spaceFields field).map (fun s => parseHexChars s.toList)

def decList (field : String) : List Nat :=
  (spaceFields field).map (fun s => parseDecChars s.toList)

/-- The levels column, where `x` marks a character X9 removes. -/
def levelList (field : String) : List (Option Nat) :=
  (spaceFields field).map (fun s =>
    if s == "x" then none else some (parseDecChars s.toList))

def bidiCharacterTestRaw : String :=
  include_str "../Ucd/BidiCharacterTest.txt"

/-- Parse one line. A line that is blank, a comment, or not five
    semicolon-separated fields carries no row, which the `Option` chain
    expresses without a catch-all. -/
def parseRow (rawLine : String) : Option Row :=
  let line := trimS rawLine
  if line == "" then none
  else if line.startsWith "#" then none
  else
    let fields := line.splitOn ";"
    fields[0]?.bind fun cpsF =>
    fields[1]?.bind fun dirF =>
    fields[2]?.bind fun plF =>
    fields[3]?.bind fun lvlF =>
    fields[4]?.bind fun ordF =>
      let cps := hexList cpsF
      if cps.isEmpty then none
      else
        some { codepoints := cps
               direction := parseDecChars (trimS dirF).toList
               paragraphLevel := parseDecChars (trimS plF).toList
               levels := levelList lvlF
               order := decList ordF }

def rows : List Row :=
  (bidiCharacterTestRaw.splitOn "\n").filterMap parseRow

/-- What to ask the algorithm, given the row's direction column. `2` means
    resolve the level by P2/P3; `0` and `1` pin it. -/
def resultFor (r : Row) : ParagraphResult :=
  if r.direction == 2 then bidiParagraph r.codepoints
  else bidiParagraphAt r.codepoints r.direction

/-- Resolved levels in input order, `none` at each position X9 removes.
    `ParagraphResult.records` already excludes the removed characters, so the
    surviving levels are re-paired against the input here. -/
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

def Tally.line (t : Tally) (label : String) : String :=
  s!"  {label}: passed {t.passed}, failed {t.failed}, skipped 0"

/-- Judge one row on the three columns the file publishes. -/
def judgeRow (r : Row) : Judgement × Judgement × Judgement :=
  let result := resultFor r
  let paraJ :=
    if result.paragraphLevel == r.paragraphLevel then Judgement.pass else Judgement.fail
  let levelJ :=
    if actualLevels r.codepoints result == r.levels then Judgement.pass else Judgement.fail
  let orderJ :=
    if reorderedInputIndices r.codepoints result == r.order then Judgement.pass
    else Judgement.fail
  (paraJ, levelJ, orderJ)

def talliesOf (sample : List Row) : Tally × Tally × Tally :=
  sample.foldl
    (fun (acc : Tally × Tally × Tally) r =>
      let (p, l, o) := judgeRow r
      (acc.1.add p, acc.2.1.add l, acc.2.2.add o))
    (default, default, default)

/-- Index of the first row failing any column, for the failure line the run
    report is expected to carry. -/
def firstFailIdxOf (sample : List Row) : Option Nat :=
  Prod.snd <| sample.foldl
    (fun (acc : Nat × Option Nat) r =>
      let (i, found) := acc
      if found.isSome then (i + 1, found)
      else
        let (p, l, o) := judgeRow r
        if p == .fail || l == .fail || o == .fail then (i + 1, some i)
        else (i + 1, none))
    (0, none)

/-- Report over `sample`, stating how many rows it judged so a bounded run is
    never mistaken for the whole file. -/
def reportOn (sample : List Row) : String :=
  let (paraT, lvlT, ordT) := talliesOf sample
  let head := s!"BidiCharacterTest: {sample.length} rows judged of {rows.length} published"
  let body :=
    String.intercalate "\n"
      [ paraT.line "paragraph level"
      , lvlT.line "resolved levels"
      , ordT.line "visual order" ]
  match firstFailIdxOf sample with
  | none => head ++ "\n" ++ body
  | some i => head ++ "\n" ++ body ++ s!"\n  first failing row index: {i}"

def report : String := reportOn rows

def reportFirst (n : Nat) : String := reportOn (rows.take n)

end Unicode.Conformance.BidiCharacterTestRun
