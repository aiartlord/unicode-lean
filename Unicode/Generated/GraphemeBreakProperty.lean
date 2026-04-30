/-
  Unicode.Generated.GraphemeBreakProperty

  Grapheme_Cluster_Break ranges from
  `lemma/lean/Unicode/Ucd/GraphemeBreakProperty.txt` (UCD 17.0.0),
  embedded as a String constant via `include_str` and parsed once at
  module load. Pattern follows `fgdorais/lean4-unicode-basic`.

  Semantics (UAX #29 §3): each row assigns a Grapheme_Cluster_Break
  property value to one closed codepoint interval. Codepoints not
  covered by any row default to `Other` per the source file's
  `@missing: 0000..10FFFF; Other` header.
-/

namespace Unicode.Generated.GraphemeBreakProperty

/-- The 13 Grapheme_Cluster_Break property values per UAX #29
    plus the implicit `Other` default. -/
inductive GCBClass where
  | Other
  | CR
  | LF
  | Control
  | Extend
  | ZWJ
  | Regional_Indicator
  | Prepend
  | SpacingMark
  | L
  | V
  | T
  | LV
  | LVT
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

def parseGCB? : String → Option GCBClass
  | "CR"                 => some .CR
  | "LF"                 => some .LF
  | "Control"            => some .Control
  | "Extend"             => some .Extend
  | "ZWJ"                => some .ZWJ
  | "Regional_Indicator" => some .Regional_Indicator
  | "Prepend"            => some .Prepend
  | "SpacingMark"        => some .SpacingMark
  | "L"                  => some .L
  | "V"                  => some .V
  | "T"                  => some .T
  | "LV"                 => some .LV
  | "LVT"                => some .LVT
  | unknownGcbClass      => Function.const String none unknownGcbClass

/-- Parse one row of GraphemeBreakProperty.txt. Returns `none` for
    blank/comment lines or unrecognised classes. -/
def parseRow (rawLine : String) : Option (Nat × Nat × GCBClass) :=
  let stripped : String := (rawLine.takeWhile (· != '#')).toString
  let line := trimS stripped
  if line.isEmpty then none else
  match String.splitOn line ";" with
  | rngField :: clsField :: _ =>
    let (lo, hi) := parseRange (trimS rngField)
    match parseGCB? (trimS clsField) with
    | some c => some (lo, hi, c)
    | none   => none
  | irregularSplit => Function.const (List String) none irregularSplit

/-- Raw text of `GraphemeBreakProperty.txt`, embedded at compile time. -/
def graphemeBreakPropertyRaw : String :=
  include_str "../Ucd/GraphemeBreakProperty.txt"

/-- Parsed (lo, hi, class) ranges from the source file. -/
def ranges : Array (Nat × Nat × GCBClass) :=
  ((graphemeBreakPropertyRaw.splitOn "\n").filterMap parseRow).toArray

/-- Look up the Grapheme_Cluster_Break class for a codepoint, returning
    `Other` for codepoints not covered by any explicit range. -/
def lookupGCB (cp : Nat) : GCBClass :=
  match ranges.find? (fun r => r.1 ≤ cp ∧ cp ≤ r.2.1) with
  | some r => r.2.2
  | none   => .Other

end Unicode.Generated.GraphemeBreakProperty
