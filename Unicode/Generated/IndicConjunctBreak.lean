/-
  Unicode.Generated.IndicConjunctBreak

  Indic_Conjunct_Break (InCB) sub-property ranges from
  `Unicode/Ucd/DerivedCoreProperties.txt` (UCD 17.0.0),
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

  The property values and the pinned `List` range table (`rangesList`)
  live in `Unicode.Generated.IndicConjunctBreakData`; `lookupInCB`
  consults that `List` so it reduces in the kernel. A build-time drift
  gate (`#eval`) proves the materialized table matches a fresh parse.
-/

import Unicode.Generated.IndicConjunctBreakData

namespace Unicode.Generated.IndicConjunctBreak

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
  let fields : List String := String.splitOn line ";"
  if fields.length ≥ 3 then
    let rngField := fields[0]!
    let tagField := fields[1]!
    let valField := fields[2]!
    if trimS tagField = "InCB" then
      let (lo, hi) := parseRange (trimS rngField)
      match parseInCB? (trimS valField) with
      | some v => some (lo, hi, v)
      | none   => none
    else none
  else
    none

/-- Raw text of `DerivedCoreProperties.txt`, embedded at compile time. -/
def derivedCorePropertiesRaw : String :=
  include_str "../Ucd/DerivedCoreProperties.txt"

/-- All explicit InCB rows from the source file. -/
def ranges : List (Nat × Nat ×InCBClass) :=
  ((derivedCorePropertiesRaw.splitOn "\n").filterMap parseRow)

/-- Look up the InCB class for a codepoint. Returns `None` for
    codepoints not listed in the source file. Consults the materialized
    `List` so a per-codepoint query reduces linearly in the kernel. -/
def lookupInCB (cp : Nat) : InCBClass :=
  match rangesList.find? (fun r => decide (r.1 ≤ cp ∧ cp ≤ r.2.1)) with
  | some r => r.2.2
  | none   => .None

-- ═══════════════════════════════════════════════════════════════════════════════
-- DRIFT GATE
--
-- Build-time assertion (compiled `#eval`) that the materialized
-- `rangesList` agrees exactly with a fresh parse of the pinned
-- `DerivedCoreProperties.txt`. A mismatch aborts the build.
-- ═══════════════════════════════════════════════════════════════════════════════

#eval do
  unless rangesList == ranges do
    throw (IO.userError "IndicConjunctBreak drift: rangesList ≠ parsed ranges")

end Unicode.Generated.IndicConjunctBreak
