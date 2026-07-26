/-
  Unicode.Conformance.LineBreakTest

  UAX #14 conformance: every test row in
  `lemma/lean/Unicode/Ucd/LineBreakTest.txt` (UCD 17.0.0) is parsed
  into a (codepoints, expected breaks) pair, then
  `Unicode.Segmentation.LineBreak.lineBreaks` is invoked on the
  codepoints and compared against the expected breaks. The bundled
  `theorem all_pass` is closed by `decide` over every row.
-/

import Unicode.Segmentation.LineBreak

namespace Unicode.Conformance.LineBreakTest

open Unicode.Segmentation.LineBreak

structure Row where
  codepoints : List Nat
  breaks     : List Bool
  deriving Inhabited, Repr

@[inline]
def trimS (s : String) : String := (String.trimAscii s).toString

def hexDigitVal (c : Char) : Nat :=
  let n := c.toNat
  if n ≥ 0x30 ∧ n ≤ 0x39 then n - 0x30
  else if n ≥ 0x61 ∧ n ≤ 0x66 then n - 0x61 + 10
  else if n ≥ 0x41 ∧ n ≤ 0x46 then n - 0x41 + 10
  else 0

def parseHex (s : String) : Nat :=
  s.foldl (fun acc c => acc * 16 + hexDigitVal c) 0

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

def lineBreakTestRaw : String :=
  include_str "../Ucd/LineBreakTest.txt"

def rows : List Row :=
  ((lineBreakTestRaw.splitOn "\n").filterMap parseRow)

def verifyRow (r : Row) : Bool :=
  lineBreaks r.codepoints == r.breaks

def firstFailIdx : Option Nat :=
  rows.findIdx? (fun r => ! verifyRow r)

/-- HEADLINE: every row in `LineBreakTest.txt` passes. -/
theorem all_pass : rows.all verifyRow = true := by decide

end Unicode.Conformance.LineBreakTest
