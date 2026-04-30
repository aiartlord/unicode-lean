/-
  Unicode.Generated.IndicConjunctBreak

  Indic_Conjunct_Break (InCB) sub-property ranges from
  `lemma/lean/Unicode/Ucd/DerivedCoreProperties.txt` (UCD 17.0.0),
  embedded as a String constant via `include_str` and parsed once at
  module load. Pattern follows `fgdorais/lean4-unicode-basic`.

  Semantics (UAX #29 GB9c): the InCB property partitions a subset of
  combining-mark and Brahmic-script consonants into three sub-classes:

    * `Linker`    — virama / halant signs that join consonants
    * `Extend`    — combining marks that participate in conjuncts
    * `Consonant` — Brahmic-script consonant letters

  GB9c forbids breaks within `Consonant (Extend|Linker)* Linker
  (Extend|Linker)* Consonant`.  Codepoints not listed in the source
  file have InCB value `None` per the source `@missing` header.

  This module parses the same DerivedCoreProperties.txt as
  `Unicode.Generated.DerivedCoreProperties`; the two parsers are
  independent so adding InCB does not perturb the existing
  identifier-property exports.
-/

namespace Unicode.Generated.IndicConjunctBreak

/-- The three explicit InCB values per UAX #29; codepoints absent
    from the source file have value `None`. -/
inductive InCBClass where
  | None
  | Linker
  | Extend
  | Consonant
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

def parseInCB? : String → Option InCBClass
  | "Linker"    => some .Linker
  | "Extend"    => some .Extend
  | "Consonant" => some .Consonant
  | unknownInCB => Function.const String none unknownInCB

/-- Parse one row that carries the `InCB` property tag. The DCP source
    file uses three semicolon-separated fields for InCB rows
    (`range ; InCB ; value`); rows for unrelated properties have only
    two fields and are filtered out by the `InCB` literal match. -/
def parseRow (rawLine : String) : Option (Nat × Nat × InCBClass) :=
  let stripped : String := (rawLine.takeWhile (· != '#')).toString
  let line := trimS stripped
  if line.isEmpty then none else
  match String.splitOn line ";" with
  | rngField :: tagField :: valField :: _ =>
    if trimS tagField = "InCB" then
      let (lo, hi) := parseRange (trimS rngField)
      match parseInCB? (trimS valField) with
      | some v => some (lo, hi, v)
      | none   => none
    else none
  | irregularSplit => Function.const (List String) none irregularSplit

/-- Raw text of `DerivedCoreProperties.txt`, embedded at compile time. -/
def derivedCorePropertiesRaw : String :=
  include_str "../Ucd/DerivedCoreProperties.txt"

/-- All explicit InCB rows from the source file. -/
def ranges : Array (Nat × Nat × InCBClass) :=
  ((derivedCorePropertiesRaw.splitOn "\n").filterMap parseRow).toArray

/-- Look up the InCB class for a codepoint. Returns `None` for
    codepoints not listed in the source file. -/
def lookupInCB (cp : Nat) : InCBClass :=
  match ranges.find? (fun r => r.1 ≤ cp ∧ cp ≤ r.2.1) with
  | some r => r.2.2
  | none   => .None

end Unicode.Generated.IndicConjunctBreak
