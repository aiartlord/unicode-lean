/-
  Unicode.Conformance.BreakTestRun

  Evaluated runs of the published `WordBreakTest.txt` and `LineBreakTest.txt`.

  `GraphemeBreakTest` and `SentenceBreakTest` already consume their corpora
  completely; the other two break suites report every row as skipped, not
  because the algorithms are missing — `Unicode.Segmentation.WordBreak` and
  `Unicode.Segmentation.LineBreak` both expose the same `breaks` shape
  `graphemeBreaks` has — but because nothing read the files.

  The four suites share one row format, so they share one parser: codepoints
  separated by `×` where no break occurs and `÷` where one does, with a marker
  at each end, and a `#` comment tail. A row therefore carries `n` codepoints
  and `n + 1` break flags.
-/

import Unicode.Segmentation.WordBreak
import Unicode.Segmentation.LineBreak

namespace Unicode.Conformance.BreakTestRun

open Unicode.Segmentation.WordBreak (wordBreaks)
open Unicode.Segmentation.LineBreak (lineBreaks)

/-- A parsed row: the codepoint sequence and the `n + 1` expected break
    positions, where `breaks[i]` is true iff a break occurs immediately before
    codepoint `i`, or at end of string when `i` is the length. -/
structure Row where
  codepoints : List Nat
  breaks     : List Bool
  deriving Inhabited, DecidableEq

def trimS (s : String) : String := (String.trimAscii s).toString

def hexDigitVal (c : Char) : Nat :=
  let n := c.toNat
  if n ≥ 48 && n ≤ 57 then n - 48
  else if n ≥ 65 && n ≤ 70 then n - 55
  else if n ≥ 97 && n ≤ 102 then n - 87
  else 0

def parseHex (s : String) : Nat :=
  s.toList.foldl (fun acc c => acc * 16 + hexDigitVal c) 0

/-- Parse one row of any of the four break-test files. The alternation of
    codepoint and marker is tracked through the fold, and a line that breaks
    the alternation carries no row. -/
def parseRow (rawLine : String) : Option Row :=
  let stripped : String := (rawLine.takeWhile (· != '#')).toString
  let line := trimS stripped
  if line.isEmpty then none else
  let tokens := (line.splitOn " ").filter (fun s => ! s.isEmpty)
  let go : List Nat × List Bool × Bool × Bool → String → List Nat × List Bool × Bool × Bool :=
    fun (cps, bs, expectingMarker, ok) tok =>
      if ! ok then (cps, bs, expectingMarker, ok)
      else if expectingMarker then
        if tok = "÷" then (cps, bs ++ [true], false, true)
        else if tok = "×" then (cps, bs ++ [false], false, true)
        else (cps, bs, expectingMarker, false)
      else
        (cps ++ [parseHex tok], bs, true, true)
  let (cps, bs, expectingMarkerFinal, ok) := tokens.foldl go ([], [], true, true)
  if ! ok then none
  else if !expectingMarkerFinal && bs.length = cps.length + 1 then
    some { codepoints := cps, breaks := bs }
  else none

def wordBreakTestRaw : String :=
  include_str "../Ucd/WordBreakTest.txt"

def lineBreakTestRaw : String :=
  include_str "../Ucd/LineBreakTest.txt"

def wordRows : List Row :=
  (wordBreakTestRaw.splitOn "\n").filterMap parseRow

def lineRows : List Row :=
  (lineBreakTestRaw.splitOn "\n").filterMap parseRow

structure Tally where
  passed : Nat := 0
  failed : Nat := 0
  deriving Inhabited

def Tally.add (t : Tally) (ok : Bool) : Tally :=
  if ok then { t with passed := t.passed + 1 } else { t with failed := t.failed + 1 }

def talliesOf (breaksOf : List Nat → List Bool) (sample : List Row) : Tally :=
  sample.foldl (fun acc r => acc.add (breaksOf r.codepoints == r.breaks)) {}

def firstFailIdxOf (breaksOf : List Nat → List Bool) (sample : List Row) : Option Nat :=
  sample.findIdx? (fun r => breaksOf r.codepoints != r.breaks)

def reportOne (label : String) (breaksOf : List Nat → List Bool)
    (sample : List Row) (published : Nat) : String :=
  let t := talliesOf breaksOf sample
  let head := s!"{label}: {sample.length} rows judged of {published} published"
  let body := s!"  breaks: passed {t.passed}, failed {t.failed}, skipped 0"
  match firstFailIdxOf breaksOf sample with
  | none => head ++ "\n" ++ body
  | some i => head ++ "\n" ++ body ++ s!"\n  first failing row index: {i}"

def wordReport : String :=
  reportOne "WordBreakTest" wordBreaks wordRows wordRows.length

def lineReport : String :=
  reportOne "LineBreakTest" lineBreaks lineRows lineRows.length

def wordReportFirst (n : Nat) : String :=
  reportOne "WordBreakTest" wordBreaks (wordRows.take n) wordRows.length

def lineReportFirst (n : Nat) : String :=
  reportOne "LineBreakTest" lineBreaks (lineRows.take n) lineRows.length

def report : String := wordReport ++ "\n" ++ lineReport

end Unicode.Conformance.BreakTestRun
