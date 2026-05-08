/-
  Unicode.Generated.UnihanVariants

  UAX #38 Unihan variant relationships parsed from
  `Unihan_Variants.txt`. Six variant properties:

    * kSimplifiedVariant         — the Simplified Chinese form.
    * kTraditionalVariant        — the Traditional Chinese form.
    * kSemanticVariant           — semantically equivalent variant.
    * kSpecializedSemanticVariant — restricted-context variant.
    * kSpoofingVariant           — confusable variant.
    * kZVariant                  — graphical (z-axis) variant.

  The Variants file format is tab-separated:

      U+XXXX  kProperty  value

  Values for variant properties are codepoint references in the
  same `U+XXXX` form, optionally with a `<source>` attribution
  tail (e.g. `U+4E94<kMatthews`). Multiple variant codepoints can
  appear separated by spaces. The parser strips attribution tails
  and returns each cited codepoint.
-/

namespace Unicode.Generated.UnihanVariants

inductive VariantProperty where
  | SimplifiedVariant
  | TraditionalVariant
  | SemanticVariant
  | SpecializedSemanticVariant
  | SpoofingVariant
  | ZVariant
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

/-- Parse a `U+XXXX` codepoint reference, optionally with a
    `<source>` attribution tail. Returns the codepoint number;
    attributions are dropped. -/
def parseCodepointRef (s : String) : Option Nat :=
  let t := trimS s
  -- Drop everything from the first '<' (attribution tail).
  let head := (t.takeWhile (· ≠ '<')).toString
  let h := trimS head
  if h.startsWith "U+" then
    let hexPart := (h.drop 2).toString
    if hexPart.isEmpty then none else some (parseHex hexPart)
  else
    none

/-- Parse a space-separated list of `U+XXXX` codepoint references. -/
def parseCodepointList (s : String) : Array Nat :=
  ((s.splitOn " ").filterMap parseCodepointRef).toArray

def parseProperty? : String → Option VariantProperty
  | "kSimplifiedVariant"          => some .SimplifiedVariant
  | "kTraditionalVariant"         => some .TraditionalVariant
  | "kSemanticVariant"            => some .SemanticVariant
  | "kSpecializedSemanticVariant" => some .SpecializedSemanticVariant
  | "kSpoofingVariant"            => some .SpoofingVariant
  | "kZVariant"                   => some .ZVariant
  | unknownProperty               => Function.const String none unknownProperty

structure Row where
  source   : Nat
  property : VariantProperty
  targets  : Array Nat
  deriving Repr, Inhabited

/-- Parse one tab-separated row of `Unihan_Variants.txt`. Returns
    `none` for blank, comment, or unrecognised-property lines. -/
def parseRow (rawLine : String) : Option Row :=
  let stripped : String := (rawLine.takeWhile (· ≠ '#')).toString
  let line := trimS stripped
  if line.isEmpty then none else
  let fields : Array String := (line.splitOn "\t").toArray
  if fields.size < 3 then none
  else
    match parseCodepointRef fields[0]!, parseProperty? (trimS fields[1]!) with
    | some src, some prop =>
      let tgts := parseCodepointList (trimS fields[2]!)
      if tgts.isEmpty then none else some ⟨src, prop, tgts⟩
    | _, _ => none

/-- Raw text of `Unihan_Variants.txt`, embedded at compile time. -/
def variantsRaw : String := include_str "../Ucd/Unihan_Variants.txt"

/-- All parsed Unihan variant rows, in source order. -/
def parsedRows : Array Row :=
  ((variantsRaw.splitOn "\n").filterMap parseRow).toArray

/-- Look up the targets for a given (source codepoint, variant
    property) pair. Returns the parsed target codepoints, or
    `#[]` if no row matches. -/
def lookup (cp : Nat) (prop : VariantProperty) : Array Nat :=
  parsedRows.foldl (fun acc r =>
    if r.source = cp ∧ r.property = prop then acc ++ r.targets else acc) #[]

end Unicode.Generated.UnihanVariants
