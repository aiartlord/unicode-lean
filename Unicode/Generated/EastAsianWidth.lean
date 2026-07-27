/-
  Unicode.Generated.EastAsianWidth

  East_Asian_Width ranges from `lemma/lean/Unicode/Ucd/EastAsianWidth.txt`
  (UCD 17.0.0). The property values and the pinned `List` range tables
  (`explicitRangesList` / `defaultRangesList`) live in
  `Unicode.Generated.EastAsianWidthData`; per-codepoint `lookup` consults
  those `List`s so it reduces in the kernel. This module keeps the
  `include_str` source and the parser, and a build-time drift gate
  (`#eval`) proves the materialized tables match a fresh parse of the
  source file.

  Semantics (UAX #11): each explicit range assigns an East_Asian_Width
  property value to a closed codepoint interval. Codepoints not covered
  by the explicit ranges fall back to the LAST default range whose
  interval contains them, matching the `@missing` header in the source
  file.
-/

import Unicode.Generated.EastAsianWidthData

namespace Unicode.Generated.EastAsianWidth

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

def parseEAW? : String → Option EastAsianWidthClass
  | "A"  => some .A
  | "F"  => some .F
  | "H"  => some .H
  | "N"  => some .N
  | "Na" => some .Na
  | "W"  => some .W
  | unknownEawClass => Function.const String none unknownEawClass

/-- Parse one EastAsianWidth.txt explicit row. Returns `none` for
    blank/comment lines or unrecognised width classes. -/
def parseExplicitRow
    (rawLine : String) : Option (Nat × Nat × EastAsianWidthClass) :=
  let stripped : String := (rawLine.takeWhile (· != '#')).toString
  let line := trimS stripped
  if line.isEmpty then none else
  match String.splitOn line ";" with
  | [rngField, classField] =>
    let (lo, hi) := parseRange (trimS rngField)
    match parseEAW? (trimS classField) with
    | some cls => some (lo, hi, cls)
    | none     => none
  | irregularSplit => Function.const (List String) none irregularSplit

/-- Parse one `@missing:` directive from a comment line. Format:
    `# @missing: <range>; <class>`. -/
def parseMissingRow
    (rawLine : String) : Option (Nat × Nat × EastAsianWidthClass) :=
  let line := trimS rawLine
  -- Expect lines like `# @missing: 0000..10FFFF; N`
  if !line.startsWith "# @missing:" then none else
  let body := trimS (line.drop "# @missing:".length).toString
  match String.splitOn body ";" with
  | [rngField, classField] =>
    let (lo, hi) := parseRange (trimS rngField)
    match parseEAW? (trimS classField) with
    | some cls => some (lo, hi, cls)
    | none     => none
  | irregularSplit => Function.const (List String) none irregularSplit

/-- Raw text of `EastAsianWidth.txt`, embedded at compile time. -/
def eastAsianWidthRaw : String := include_str "../Ucd/EastAsianWidth.txt"

/-! Per-range East_Asian_Width property assignments. -/
def explicitRanges : List (Nat × Nat × EastAsianWidthClass) :=
  ((eastAsianWidthRaw.splitOn "\n").filterMap parseExplicitRow)

/-! Default ranges from `@missing:` directives in the source header,
    in source order. The LAST entry whose range contains a codepoint
    wins. -/
def defaultRanges : List (Nat × Nat × EastAsianWidthClass) :=
  ((eastAsianWidthRaw.splitOn "\n").filterMap parseMissingRow)

/-- East_Asian_Width lookup: explicit ranges first, then the latest
    `@missing:` default range whose interval contains `cp`, then the
    UAX #11 default of `N` (Neutral). Consults the materialized `List`
    tables so a per-codepoint query reduces linearly in the kernel. -/
def lookup (cp : Nat) : EastAsianWidthClass :=
  match explicitRangesList.find? (fun r => decide (r.1 ≤ cp ∧ cp ≤ r.2.1)) with
  | some r => r.2.2
  | none =>
    let go : EastAsianWidthClass → Nat × Nat × EastAsianWidthClass
           → EastAsianWidthClass :=
      fun current entry =>
        if entry.1 ≤ cp ∧ cp ≤ entry.2.1 then entry.2.2
        else current
    defaultRangesList.foldl go .N

-- ═══════════════════════════════════════════════════════════════════════════════
-- DRIFT GATE
--
-- Build-time assertion (compiled `#eval`, not a kernel proof) that the
-- materialized `List` tables in `EastAsianWidthData` agree exactly with a
-- fresh parse of the pinned `EastAsianWidth.txt`. A mismatch — an
-- unintended edit to the literal or a source-file swap — aborts the build.
-- ═══════════════════════════════════════════════════════════════════════════════

#eval do
  unless explicitRangesList == explicitRanges do
    throw (IO.userError "EastAsianWidth drift: explicitRangesList ≠ parsed explicitRanges")
  unless defaultRangesList == defaultRanges do
    throw (IO.userError "EastAsianWidth drift: defaultRangesList ≠ parsed defaultRanges")

/-- True iff `cp` is East_Asian_Width F (Fullwidth), W (Wide), or
    H (Halfwidth). UAX #14 LB30 excludes these from the
    `(AL | HL | NU) × OP` and `CP × (AL | HL | NU)` rules. -/
def isEastAsianFWH (cp : Nat) : Bool :=
  let w := lookup cp
  w == .F || w == .W || w == .H

end Unicode.Generated.EastAsianWidth
