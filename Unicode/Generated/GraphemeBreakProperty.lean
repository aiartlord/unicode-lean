/-
  Unicode.Generated.GraphemeBreakProperty

  Grapheme_Cluster_Break ranges from
  `lemma/lean/Unicode/Ucd/GraphemeBreakProperty.txt` (UCD 17.0.0). The
  property values and the pinned `List` range table (`rangesList`) live
  in `Unicode.Generated.GraphemeBreakPropertyData`; `lookupGCB` consults
  that `List` so it reduces in the kernel. This module keeps the
  `include_str` source and the parser, and a build-time drift gate
  (`#eval`) proves the materialized table matches a fresh parse.

  Semantics (UAX #29 §3): each row assigns a Grapheme_Cluster_Break
  property value to one closed codepoint interval. Codepoints not
  covered by any row default to `Other` per the source file's
  `@missing: 0000..10FFFF; Other` header.
-/

import Unicode.Generated.GraphemeBreakPropertyData

namespace Unicode.Generated.GraphemeBreakProperty

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
  let fields : Array String := (String.splitOn line ";").toArray
  if fields.size ≥ 2 then
    let rngField := fields[0]!
    let clsField := fields[1]!
    let (lo, hi) := parseRange (trimS rngField)
    match parseGCB? (trimS clsField) with
    | some c => some (lo, hi, c)
    | none   => none
  else
    none

/-- Raw text of `GraphemeBreakProperty.txt`, embedded at compile time. -/
def graphemeBreakPropertyRaw : String :=
  include_str "../Ucd/GraphemeBreakProperty.txt"

/-- Parsed (lo, hi, class) ranges from the source file. -/
def ranges : Array (Nat × Nat × GCBClass) :=
  ((graphemeBreakPropertyRaw.splitOn "\n").filterMap parseRow).toArray

/-- Look up the Grapheme_Cluster_Break class for a codepoint, returning
    `Other` for codepoints not covered by any explicit range. Consults
    the materialized `List` so a per-codepoint query reduces linearly in
    the kernel. -/
def lookupGCB (cp : Nat) : GCBClass :=
  match rangesList.find? (fun r => decide (r.1 ≤ cp ∧ cp ≤ r.2.1)) with
  | some r => r.2.2
  | none   => .Other

-- ═══════════════════════════════════════════════════════════════════════════════
-- DRIFT GATE
--
-- Build-time assertion (compiled `#eval`) that the materialized
-- `rangesList` agrees exactly with a fresh parse of the pinned
-- `GraphemeBreakProperty.txt`. A mismatch aborts the build.
-- ═══════════════════════════════════════════════════════════════════════════════

#eval do
  unless rangesList.toArray == ranges do
    throw (IO.userError "GraphemeBreakProperty drift: rangesList ≠ parsed ranges")

end Unicode.Generated.GraphemeBreakProperty
