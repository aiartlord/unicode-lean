/-
  Unicode.Generated.VerticalOrientation

  UAX #50 Vertical Text Layout — the `Vertical_Orientation` (Vo)
  property. Each codepoint takes one of four values when displayed
  in vertical text:

    * U  — Upright (same orientation as in the code charts).
    * R  — Rotated 90° clockwise relative to the code charts.
    * Tu — Transformed typographically; falls back to Upright when
           the renderer doesn't apply OpenType vertical features.
    * Tr — Transformed typographically; falls back to Rotated.

  Codepoints not listed in `VerticalOrientation.txt` default to `R`
  per UAX #44 missing-row convention; specific large ranges
  (notably CJK ideographs) default to `U` and are listed
  individually in the file.
-/

import Unicode.Generated.VerticalOrientationData

namespace Unicode.Generated.VerticalOrientation


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

def parseVo? : String → Option Vo
  | "U"  => some .U
  | "R"  => some .R
  | "Tu" => some .Tu
  | "Tr" => some .Tr
  | unknownVo => Function.const String none unknownVo

/-- Parse one row of `VerticalOrientation.txt`. Returns `none` for
    blank or comment-only lines. -/
def parseRow (rawLine : String) : Option (Nat × Nat × Vo) :=
  let stripped : String := (rawLine.takeWhile (· != '#')).toString
  let line := trimS stripped
  if line.isEmpty then none else
  match String.splitOn line ";" with
  | [rngField, voField] =>
    let (lo, hi) := parseRange (trimS rngField)
    match parseVo? (trimS voField) with
    | some v => some (lo, hi, v)
    | none   => none
  | irregularSplit => Function.const (List String) none irregularSplit

/-- Raw text of `VerticalOrientation.txt`, embedded at compile time. -/
def verticalOrientationRaw : String := include_str "../Ucd/VerticalOrientation.txt"

/-- Per-range Vertical_Orientation assignments, in source order. -/
def verticalOrientationRanges : List (Nat × Nat × Vo) :=
  ((verticalOrientationRaw.splitOn "\n").filterMap parseRow)

/-- Default `Vo` value for codepoints not covered by any explicit
    range, per UAX #44 missing-row convention. -/
def defaultVo : Vo := .R

/-- Look up the Vertical_Orientation of `cp`. Returns the matching
    range's value, or `defaultVo` (`.R`) when no range covers `cp`. -/
def lookupVo (cp : Nat) : Vo :=
  match verticalOrientationRangesList.findSome? (fun ⟨lo, hi, v⟩ =>
          if lo ≤ cp ∧ cp ≤ hi then some v else none) with
  | some v => v
  | none   => defaultVo

-- Build-time drift gate.
#eval do
  unless verticalOrientationRangesList == verticalOrientationRanges do
    throw (IO.userError "VerticalOrientation drift: list ≠ parsed")

end Unicode.Generated.VerticalOrientation
