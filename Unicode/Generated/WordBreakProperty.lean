/-
  Unicode.Generated.WordBreakProperty

  Word_Break ranges from `lemma/lean/Unicode/Ucd/WordBreakProperty.txt`
  (UCD 17.0.0), embedded as a String constant via `include_str` and
  parsed once at module load. Pattern follows
  `fgdorais/lean4-unicode-basic`.

  Semantics (UAX #29 §4): each row assigns a Word_Break property
  value to one closed codepoint interval. Codepoints not covered by
  any row default to `Other` per the source file's
  `@missing: 0000..10FFFF; Other` header.
-/

namespace Unicode.Generated.WordBreakProperty

/-- The 18 explicit Word_Break values per UAX #29 plus the implicit
    `Other` default. -/
inductive WBClass where
  | Other
  | CR
  | LF
  | Newline
  | Extend
  | ZWJ
  | Regional_Indicator
  | Format
  | Katakana
  | Hebrew_Letter
  | ALetter
  | Single_Quote
  | Double_Quote
  | MidNumLet
  | MidLetter
  | MidNum
  | Numeric
  | ExtendNumLet
  | WSegSpace
  deriving DecidableEq, Repr, Inhabited

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

def parseWB? : String → Option WBClass
  | "CR"                 => some .CR
  | "LF"                 => some .LF
  | "Newline"            => some .Newline
  | "Extend"             => some .Extend
  | "ZWJ"                => some .ZWJ
  | "Regional_Indicator" => some .Regional_Indicator
  | "Format"             => some .Format
  | "Katakana"           => some .Katakana
  | "Hebrew_Letter"      => some .Hebrew_Letter
  | "ALetter"            => some .ALetter
  | "Single_Quote"       => some .Single_Quote
  | "Double_Quote"       => some .Double_Quote
  | "MidNumLet"          => some .MidNumLet
  | "MidLetter"          => some .MidLetter
  | "MidNum"             => some .MidNum
  | "Numeric"            => some .Numeric
  | "ExtendNumLet"       => some .ExtendNumLet
  | "WSegSpace"          => some .WSegSpace
  | unknownWbClass       => Function.const String none unknownWbClass

/-- Parse one row. Returns `none` for blank/comment lines or
    unrecognised classes. -/
def parseRow (rawLine : String) : Option (Nat × Nat × WBClass) :=
  let stripped : String := (rawLine.takeWhile (· != '#')).toString
  let line := trimS stripped
  if line.isEmpty then none else
  match String.splitOn line ";" with
  | rngField :: clsField :: _ =>
    let (lo, hi) := parseRange (trimS rngField)
    match parseWB? (trimS clsField) with
    | some c => some (lo, hi, c)
    | none   => none
  | irregularSplit => Function.const (List String) none irregularSplit

/-- Raw text of `WordBreakProperty.txt`, embedded at compile time. -/
def wordBreakPropertyRaw : String :=
  include_str "../Ucd/WordBreakProperty.txt"

/-- Parsed (lo, hi, class) ranges from the source file. -/
def ranges : Array (Nat × Nat × WBClass) :=
  ((wordBreakPropertyRaw.splitOn "\n").filterMap parseRow).toArray

/-- Look up the Word_Break class for a codepoint. Returns `Other`
    for codepoints not covered by any explicit range. -/
def lookupWB (cp : Nat) : WBClass :=
  match ranges.find? (fun r => r.1 ≤ cp ∧ cp ≤ r.2.1) with
  | some r => r.2.2
  | none   => .Other

end Unicode.Generated.WordBreakProperty
