/-
  Unicode.Generated.UnihanVariants

  UAX #38 Unihan variant relationships parsed from
  `Unihan_Variants.txt`. Six variant properties:

    * kSimplifiedVariant          — the Simplified Chinese form.
    * kTraditionalVariant         — the Traditional Chinese form.
    * kSemanticVariant            — semantically equivalent variant.
    * kSpecializedSemanticVariant — restricted-context variant.
    * kSpoofingVariant            — confusable variant.
    * kZVariant                   — graphical (z-axis) variant.

  The Variants file format is tab-separated:

      U+XXXX  kProperty  value

  Values for variant properties are codepoint references in the
  same `U+XXXX` form, optionally with a `<source>` attribution
  tail (e.g. `U+4E94<kMatthews`). Multiple variant codepoints can
  appear separated by spaces. The parser strips attribution tails
  and returns each cited codepoint.
-/

import Unicode.Generated.UnihanVariantTypes
import Unicode.Generated.UnihanVariantsData

namespace Unicode.Generated.UnihanVariants

set_option maxRecDepth 100000

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
def parseCodepointList (s : String) : List Nat :=
  ((s.splitOn " ").filterMap parseCodepointRef)

def parseProperty? : String → Option VariantProperty
  | "kSimplifiedVariant"          => some .SimplifiedVariant
  | "kTraditionalVariant"         => some .TraditionalVariant
  | "kSemanticVariant"            => some .SemanticVariant
  | "kSpecializedSemanticVariant" => some .SpecializedSemanticVariant
  | "kSpoofingVariant"            => some .SpoofingVariant
  | "kZVariant"                   => some .ZVariant
  | unknownProperty               => Function.const String none unknownProperty

/-- Parse one tab-separated row of `Unihan_Variants.txt`. Returns
    `none` for blank, comment, or unrecognised-property lines. -/
def parseRow (rawLine : String) : Option Row :=
  let stripped : String := (rawLine.takeWhile (· ≠ '#')).toString
  let line := trimS stripped
  if line.isEmpty then none else
  let fields : List String := (line.splitOn "\t")
  if fields.length < 3 then none
  else
    match parseCodepointRef fields[0]!, parseProperty? (trimS fields[1]!) with
    | some src, some prop =>
      let tgts := parseCodepointList (trimS fields[2]!)
      if tgts.isEmpty then none else some ⟨src, prop, tgts⟩
    | some srcOnly, none => Function.const Nat none srcOnly
    | none, propOnly => Function.const (Option VariantProperty) none propOnly

/-- Raw text of `Unihan_Variants.txt`, embedded at compile time. -/
def variantsRaw : String := include_str "../Ucd/Unihan_Variants.txt"

/-- All Unihan variant rows as re-derived from the embedded source
    text at every build. `rowsList` (the literal table in
    `UnihanVariantsData`) is what proofs and the lookup consume; this
    parse exists so the drift gate below can compare the two. -/
def parsedRows : List Row :=
  ((variantsRaw.splitOn "\n").filterMap parseRow)

/-- Look up the targets for a given (source codepoint, variant
    property) pair over the literal row table. Returns `[]` if no
    row matches. -/
def lookup (cp : Nat) (prop : VariantProperty) : List Nat :=
  rowsList.foldl (fun acc r =>
    if r.source = cp ∧ r.property = prop then acc ++ r.targets else acc) []

/- Drift gate: the literal table equals the parse of the SHA-pinned
   source. Elaboration of this module fails on any mismatch. -/
#eval show IO Unit from do
  unless rowsList == parsedRows do
    throw <| IO.userError
      "Unicode.Generated.UnihanVariants: literal rows differ from parsed Unihan_Variants.txt"

-- ═══════════════════════════════════════════════════════════════════════════════
-- TEST VECTORS
-- Anchor lookups in both directions of the simplified/traditional
-- relationship, at codepoints with a single target each way.
-- ═══════════════════════════════════════════════════════════════════════════════

theorem lookup_u6F22_simplified :
    lookup 0x6F22 .SimplifiedVariant = [0x6C49] := by decide +kernel

theorem lookup_u6C49_traditional :
    lookup 0x6C49 .TraditionalVariant = [0x6F22] := by decide +kernel

theorem lookup_u56FD_traditional :
    lookup 0x56FD .TraditionalVariant = [0x570B] := by decide +kernel

end Unicode.Generated.UnihanVariants
