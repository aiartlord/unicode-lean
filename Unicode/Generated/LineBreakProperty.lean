/-
  Unicode.Generated.LineBreakProperty

  Line_Break ranges from `Unicode/Ucd/LineBreak.txt`
  (UCD 17.0.0), embedded as a String constant via `include_str` and
  parsed once at module load. Pattern follows
  `fgdorais/lean4-unicode-basic`.

  Semantics (UAX #14 §6): each row assigns a Line_Break property
  value to one closed codepoint interval. Codepoints not covered by
  any row default to `XX` per the source file's
  `@missing: 0000..10FFFF; XX` header.

  This module exposes both:

    * `lookupRaw cp`     — the raw Line_Break class straight from the
                           source data, including the tailorable
                           `AI`, `CJ`, `SA`, `SG`, `XX` values.
    * `lookupResolved cp`— the Line_Break class after applying
                           UAX #14 LB1 ("Resolve `AI`, `CJ`, `SA`,
                           `SG`, and `XX` into other line breaking
                           classes depending on criteria outside the
                           scope of this algorithm"). The resolution
                           mapping is:
                             AI → AL
                             CJ → NS
                             SA → CM  if General_Category ∈ {Mn, Mc}
                             SA → AL  otherwise
                             SG → AL
                             XX → AL

    The conformance harness uses `lookupResolved`, the algorithm in
    `Unicode.Segmentation.LineBreak` consumes already-resolved
    classes.
-/

import Unicode.Generated.DerivedGeneralCategory
import Unicode.Generated.EastAsianWidth
import Unicode.Generated.LineBreakPropertyData

namespace Unicode.Generated.LineBreakProperty

open Unicode.Generated.DerivedGeneralCategory

-- `LBClass` and the materialized `rangesList` are defined in
-- `Unicode.Generated.LineBreakPropertyData`; the parser below is retained only to
-- audit that list against a fresh parse of the embedded fixture (the drift gate),
-- keeping per-codepoint lookup free of the String parser's axioms.

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

def parseLB? : String → Option LBClass
  | "AI"  => some .AI  | "AK"  => some .AK  | "AL"  => some .AL
  | "AP"  => some .AP  | "AS"  => some .AS  | "B2"  => some .B2
  | "BA"  => some .BA  | "BB"  => some .BB  | "BK"  => some .BK
  | "CB"  => some .CB  | "CJ"  => some .CJ  | "CL"  => some .CL
  | "CM"  => some .CM  | "CP"  => some .CP  | "CR"  => some .CR
  | "EB"  => some .EB  | "EM"  => some .EM  | "EX"  => some .EX
  | "GL"  => some .GL  | "H2"  => some .H2  | "H3"  => some .H3
  | "HH"  => some .HH  | "HL"  => some .HL  | "HY"  => some .HY
  | "ID"  => some .ID  | "IN"  => some .IN  | "IS"  => some .IS
  | "JL"  => some .JL  | "JT"  => some .JT  | "JV"  => some .JV
  | "LF"  => some .LF  | "NL"  => some .NL  | "NS"  => some .NS
  | "NU"  => some .NU  | "OP"  => some .OP  | "PO"  => some .PO
  | "PR"  => some .PR  | "QU"  => some .QU  | "RI"  => some .RI
  | "SA"  => some .SA  | "SG"  => some .SG  | "SP"  => some .SP
  | "SY"  => some .SY  | "VF"  => some .VF  | "VI"  => some .VI
  | "WJ"  => some .WJ  | "XX"  => some .XX  | "ZW"  => some .ZW
  | "ZWJ" => some .ZWJ
  | unknownLb => Function.const String none unknownLb

def parseRow (rawLine : String) : Option (Nat × Nat × LBClass) :=
  let stripped : String := (rawLine.takeWhile (· != '#')).toString
  let line := trimS stripped
  if line.isEmpty then none else
  let fields : List String := String.splitOn line ";"
  if fields.length ≥ 2 then
    let rngField := fields[0]!
    let clsField := fields[1]!
    let (lo, hi) := parseRange (trimS rngField)
    match parseLB? (trimS clsField) with
    | some c => some (lo, hi, c)
    | none   => none
  else
    none

def lineBreakRaw : String :=
  include_str "../Ucd/LineBreak.txt"

/-- A fresh parse of the embedded fixture. Uses the String primitives (hence
    `Classical.choice` in its trusted base); consumed only by the drift gate,
    never by `lookupRaw`. -/
def rangesParsed : List (Nat × Nat × LBClass) :=
  ((lineBreakRaw.splitOn "\n").filterMap parseRow)

/-- The Line_Break range table used by lookup: the materialized `rangesList`. -/
def ranges : List (Nat × Nat × LBClass) := rangesList

/-- Raw Line_Break class for `cp`, returning `XX` for codepoints
    not covered by any explicit range (per the source's
    `@missing: 0000..10FFFF; XX`). -/
def lookupRaw (cp : Nat) : LBClass :=
  match rangesList.find? (fun r => r.1 ≤ cp ∧ cp ≤ r.2.1) with
  | some r => r.2.2
  | none   => .XX

/-- Resolve LB1 tailorable classes (`AI`, `CJ`, `SA`, `SG`, `XX`)
    into the algorithm's working alphabet:

      AI  →  AL
      CJ  →  NS
      SA  →  CM  if General_Category ∈ {Mn, Mc}
      SA  →  AL  otherwise
      SG  →  AL
      XX  →  AL
-/
def resolve (cp : Nat) (raw : LBClass) : LBClass :=
  match raw with
  | .AI => .AL
  | .CJ => .NS
  | .SG => .AL
  | .XX => .AL
  | .SA =>
    let gc := DerivedGeneralCategory.lookup cp
    if gc = .Mn ∨ gc = .Mc then .CM else .AL
  | resolvedClass => resolvedClass

/-- LB1-resolved Line_Break class for `cp`. -/
def lookupResolved (cp : Nat) : LBClass :=
  resolve cp (lookupRaw cp)

-- Drift gate: the materialized `rangesList` mirrors a fresh parse of the
-- embedded fixture, checked at build time (not a kernel theorem).
#eval do
  unless rangesList == rangesParsed do
    throw (IO.userError "LineBreakProperty drift: rangesList ≠ rangesParsed")

end Unicode.Generated.LineBreakProperty
