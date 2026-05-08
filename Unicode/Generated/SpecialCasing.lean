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
    `Array Nat`. Empty input yields `#[]`. -/
def parseCodepoints (s : String) : Array Nat :=
  ((s.splitOn " ").filterMap (fun tok =>
    let t := trimS tok
    if t.isEmpty then none else some (parseHex t))).toArray

/-- The recognised condition tokens from the SpecialCasing.txt
    `condition_list` field. Locale tokens are 2-letter language
    codes; context tokens describe the surrounding characters. -/
inductive Condition where
  | LangTr
  | LangAz
  | LangLt
  | FinalSigma
  | NotFinalSigma
  | AfterSoftDotted
  | MoreAbove
  | NotBeforeDot
  | AfterI
  | Other (token : String)
  deriving Repr, Inhabited

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

/-- One row from SpecialCasing.txt. -/
structure Row where
  code       : Nat
  lower      : Array Nat
  title      : Array Nat
  upper      : Array Nat
  conditions : Array Condition
  deriving Repr, Inhabited

/-- Parse one row of SpecialCasing.txt. Returns `none` for blank,
    comment-only, or malformed lines. -/
def parseRow (rawLine : String) : Option Row :=
  let stripped : String := (rawLine.takeWhile (· ≠ '#')).toString
  let line := trimS stripped
  if line.isEmpty then none else
  let fields : Array String :=
    ((line.splitOn ";").map trimS).toArray
  if fields.size < 4 then none
  else
    let code  := parseHex fields[0]!
    let lower := parseCodepoints fields[1]!
    let title := parseCodepoints fields[2]!
    let upper := parseCodepoints fields[3]!
    let conditions := if fields.size ≤ 4 ∨ fields[4]!.isEmpty then #[]
      else (((fields[4]!).splitOn " ").filterMap (fun tok =>
        let t := trimS tok
        if t.isEmpty then none else some (parseCondition t))).toArray
    some ⟨code, lower, title, upper, conditions⟩

/-- Raw text of `SpecialCasing.txt`, embedded at compile time. -/
def specialCasingRaw : String := include_str "../Ucd/SpecialCasing.txt"

/-- All parsed SpecialCasing rows. -/
def parsedRows : Array Row :=
  ((specialCasingRaw.splitOn "\n").filterMap parseRow).toArray

/-- Rows applicable unconditionally (no `condition_list`). -/
def unconditionalRows : Array Row :=
  parsedRows.filter (fun r => r.conditions.isEmpty)

end Unicode.Generated.SpecialCasing
