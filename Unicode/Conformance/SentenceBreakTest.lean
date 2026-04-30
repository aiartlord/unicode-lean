/-
  Unicode.Conformance.SentenceBreakTest

  UAX #29 §5 conformance: every test row in
  `lemma/lean/Unicode/Ucd/SentenceBreakTest.txt` (UCD 17.0.0) is
  parsed into a (codepoints, expected breaks) pair, then
  `Unicode.Segmentation.SentenceBreak.sentenceBreaks` is invoked on
  the codepoints and compared against the expected breaks. The
  bundled `theorem all_pass` is closed by `native_decide` over
  every row.
-/

import Unicode.Segmentation.SentenceBreak

namespace Unicode.Conformance.SentenceBreakTest

open Unicode.Segmentation.SentenceBreak

structure Row where
  codepoints : Array Nat
  breaks     : Array Bool
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
  let go : Array Nat × Array Bool × Bool × Bool → String → Array Nat × Array Bool × Bool × Bool :=
    fun (cps, bs, expectingMarker, ok) tok =>
      if ! ok then (cps, bs, expectingMarker, ok)
      else if expectingMarker then
        if tok = "÷" then (cps, bs.push true, false, true)
        else if tok = "×" then (cps, bs.push false, false, true)
        else (cps, bs, expectingMarker, false)
      else
        (cps.push (parseHex tok), bs, true, true)
  let (cps, bs, _, ok) := tokens.foldl go (#[], #[], true, true)
  if ! ok then none
  else if bs.size = cps.size + 1 then some { codepoints := cps, breaks := bs }
  else none

def sentenceBreakTestRaw : String :=
  include_str "../Ucd/SentenceBreakTest.txt"

def rows : Array Row :=
  ((sentenceBreakTestRaw.splitOn "\n").filterMap parseRow).toArray

def verifyRow (r : Row) : Bool :=
  sentenceBreaks r.codepoints == r.breaks

def firstFailIdx : Option Nat :=
  rows.findIdx? (fun r => ! verifyRow r)

theorem all_pass : rows.all verifyRow = true := by native_decide

end Unicode.Conformance.SentenceBreakTest
