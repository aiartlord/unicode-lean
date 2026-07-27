/-
  Unicode.Generated.SpecialCasing

  UAX #44 § 5.10 Special Casing — full case mappings for codepoints
  whose lowercase / titlecase / uppercase form is not a single
  codepoint or is dependent on context or locale.

  File format (each row, semicolon-separated):

      code; lower; title; upper; condition_list?; # comment

  `code`, `lower`, `title`, and `upper` are space-separated lists of
  hex codepoints (multi-codepoint mappings are common — e.g.
  U+00DF lowercase to itself but uppercases to "SS"). The optional
  `condition_list` carries language IDs (tr, az, lt) and casing
  contexts (Final_Sigma, More_Above, After_Soft_Dotted, etc.).
  Rows without a condition list are unconditional full case
  mappings; the condition_list rows specialise behaviour for
  particular locales or surrounding contexts.
-/

import Unicode.Generated.SpecialCasingData

namespace Unicode.Generated.SpecialCasing

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

/-- Parse a space-separated list of hex codepoints into an
    `List Nat`. Empty input yields `[]`. -/
def parseCodepoints (s : String) : List Nat :=
  ((s.splitOn " ").filterMap (fun tok =>
    let t := trimS tok
    if t.isEmpty then none else some (parseHex t)))

/-- Parse a `condition_list` token into a `Condition` (the type is
    defined in `SpecialCasingData`). Locale tokens are 2-letter language
    codes; context tokens describe the surrounding characters. -/
def parseCondition : String → Condition
  | "tr"                => .LangTr
  | "az"                => .LangAz
  | "lt"                => .LangLt
  | "Final_Sigma"       => .FinalSigma
  | "Not_Final_Sigma"   => .NotFinalSigma
  | "After_Soft_Dotted" => .AfterSoftDotted
  | "More_Above"        => .MoreAbove
  | "Not_Before_Dot"    => .NotBeforeDot
  | "After_I"           => .AfterI
  | other               => .Other other


/-- Parse one row of SpecialCasing.txt. Returns `none` for blank,
    comment-only, or malformed lines. -/
def parseRow (rawLine : String) : Option Row :=
  let stripped : String := (rawLine.takeWhile (· ≠ '#')).toString
  let line := trimS stripped
  if line.isEmpty then none else
  let fields : List String :=
    ((line.splitOn ";").map trimS)
  if fields.size < 4 then none
  else
    let code  := parseHex fields[0]!
    let lower := parseCodepoints fields[1]!
    let title := parseCodepoints fields[2]!
    let upper := parseCodepoints fields[3]!
    let conditions := if fields.size ≤ 4 ∨ fields[4]!.isEmpty then #[]
      else (((fields[4]!).splitOn " ").filterMap (fun tok =>
        let t := trimS tok
        if t.isEmpty then none else some (parseCondition t)))
    some ⟨code, lower, title, upper, conditions⟩

/-- Raw text of `SpecialCasing.txt`, embedded at compile time. -/
def specialCasingRaw : String := include_str "../Ucd/SpecialCasing.txt"

/-- All parsed SpecialCasing rows. -/
def parsedRowsParsed : List Row :=
  ((specialCasingRaw.splitOn "\n").filterMap parseRow)

/-- All parsed SpecialCasing rows — the materialized view. -/
def parsedRows : List Row := parsedRowsList

/-- Rows applicable unconditionally (no `condition_list`). -/
def unconditionalRows : List Row :=
  parsedRows.filter (fun r => r.conditions.isEmpty)

-- Build-time drift gate.
#eval do
  unless parsedRowsList == parsedRowsParsed do
    throw (IO.userError "SpecialCasing drift: list ≠ parsed")

end Unicode.Generated.SpecialCasing
