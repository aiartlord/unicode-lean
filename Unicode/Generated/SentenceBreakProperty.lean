/-
  Unicode.Generated.SentenceBreakProperty

  Sentence_Break ranges from
  `lemma/lean/Unicode/Ucd/SentenceBreakProperty.txt` (UCD 17.0.0),
  embedded as a String constant via `include_str` and parsed once at
  module load. Pattern follows `fgdorais/lean4-unicode-basic`.

  Semantics (UAX #29 §5): each row assigns a Sentence_Break property
  value to one closed codepoint interval. Codepoints not covered by
  any row default to `Other` per the source file's
  `@missing: 0000..10FFFF; Other` header.
-/

import Unicode.Generated.SentenceBreakPropertyData

namespace Unicode.Generated.SentenceBreakProperty


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

def parseRange (s : String) : Nat × Nat :=
  match String.splitOn s ".." with
  | [single]  => let n := parseHex single; (n, n)
  | [a, b]    => (parseHex a, parseHex b)
  | irregularRange => Function.const (List String) (0, 0) irregularRange

def parseSB? : String → Option SBClass
  | "CR"        => some .CR
  | "LF"        => some .LF
  | "Extend"    => some .Extend
  | "Sep"       => some .Sep
  | "Format"    => some .Format
  | "Sp"        => some .Sp
  | "Lower"     => some .Lower
  | "Upper"     => some .Upper
  | "OLetter"   => some .OLetter
  | "Numeric"   => some .Numeric
  | "ATerm"     => some .ATerm
  | "SContinue" => some .SContinue
  | "STerm"     => some .STerm
  | "Close"     => some .Close
  | unknownSb   => Function.const String none unknownSb

def parseRow (rawLine : String) : Option (Nat × Nat × SBClass) :=
  let stripped : String := (rawLine.takeWhile (· != '#')).toString
  let line := trimS stripped
  if line.isEmpty then none else
  let fields : Array String := (String.splitOn line ";").toArray
  if fields.size ≥ 2 then
    let rngField := fields[0]!
    let clsField := fields[1]!
    let (lo, hi) := parseRange (trimS rngField)
    match parseSB? (trimS clsField) with
    | some c => some (lo, hi, c)
    | none   => none
  else
    none

def sentenceBreakPropertyRaw : String :=
  include_str "../Ucd/SentenceBreakProperty.txt"

def rangesParsed : Array (Nat × Nat × SBClass) :=
  ((sentenceBreakPropertyRaw.splitOn "\n").filterMap parseRow).toArray

/-- The materialized Sentence_Break range table. -/
def ranges : Array (Nat × Nat × SBClass) := rangesList.toArray

def lookupSB (cp : Nat) : SBClass :=
  match rangesList.find? (fun r => r.1 ≤ cp ∧ cp ≤ r.2.1) with
  | some r => r.2.2
  | none   => .Other

-- `rangesList` mirrors a fresh parse of the fixture, checked at build time.
#eval do
  unless rangesList.toArray == rangesParsed do
    throw (IO.userError "SentenceBreakProperty drift: list ≠ parsed")

end Unicode.Generated.SentenceBreakProperty
