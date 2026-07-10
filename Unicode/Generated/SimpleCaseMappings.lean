/-
  Unicode.Generated.SimpleCaseMappings

  UAX #44 simple case mappings parsed from `UnicodeData.txt`
  fields 12 (Simple_Uppercase_Mapping) and 13
  (Simple_Lowercase_Mapping) and 14 (Simple_Titlecase_Mapping).
  Each row maps one codepoint to its single-codepoint case
  counterpart; full case mappings (one-to-many, locale-conditional)
  live in `SpecialCasing.txt` and are parsed separately.

  This module is independent of `Generated.UnicodeData` so it can
  carry the case-specific subset without disturbing the
  NFC-relevant row struct that file exposes.
-/

import Unicode.Generated.SimpleCaseMappingsData

namespace Unicode.Generated.SimpleCaseMappings

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

/-- Parse a hex codepoint, treating an empty field as `0`. -/
def parseHexOrZero (s : String) : Nat :=
  let t := trimS s
  if t.isEmpty then 0 else parseHex t


/-- Parse one UnicodeData.txt row's case-mapping fields. Returns
    `none` for blank lines and for rows where all three case fields
    are empty (no mapping). -/
def parseRow (rawLine : String) : Option CaseRow :=
  let line := trimS rawLine
  if line.isEmpty then none else
  let fields := String.splitOn line ";"
  if fields.length < 14 then none else
  let cp    := parseHex (trimS fields[0]!)
  let upper := parseHexOrZero fields[12]!
  let lower := parseHexOrZero fields[13]!
  let titleRaw := parseHexOrZero fields[14]!
  -- Field 14 is empty when titlecase = uppercase per UAX #44 §4.2.
  let title := if titleRaw = 0 then upper else titleRaw
  if upper = 0 ∧ lower = 0 ∧ titleRaw = 0 then none
  else some ⟨cp, upper, lower, title⟩

/-- Raw text of `UnicodeData.txt`, embedded at compile time. -/
def unicodeDataRaw : String := include_str "../Ucd/UnicodeData.txt"

/-- All parsed simple-case rows. -/
def rowsParsed : Array CaseRow :=
  ((unicodeDataRaw.splitOn "\n").filterMap parseRow).toArray

/-- All parsed simple-case rows — the materialized view. -/
def rows : Array CaseRow := rowsList.toArray

/-- Look up the simple-uppercase mapping of `cp`. Returns `cp`
    itself when no mapping exists. -/
def simpleUppercase (cp : Nat) : Nat :=
  match rowsList.findSome? (fun r => if r.codepoint = cp then some r else none) with
  | some r => if r.upper = 0 then cp else r.upper
  | none   => cp

/-- Look up the simple-lowercase mapping of `cp`. -/
def simpleLowercase (cp : Nat) : Nat :=
  match rowsList.findSome? (fun r => if r.codepoint = cp then some r else none) with
  | some r => if r.lower = 0 then cp else r.lower
  | none   => cp

/-- Look up the simple-titlecase mapping of `cp`. -/
def simpleTitlecase (cp : Nat) : Nat :=
  match rowsList.findSome? (fun r => if r.codepoint = cp then some r else none) with
  | some r => if r.title = 0 then cp else r.title
  | none   => cp

-- Build-time drift gate.
#eval do
  unless rowsList.toArray == rowsParsed do
    throw (IO.userError "SimpleCaseMappings drift: list ≠ parsed")

end Unicode.Generated.SimpleCaseMappings
