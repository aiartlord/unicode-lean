/-
  Unicode.Generated.PropertyAliases

  UAX #44 § 5.10.3 property name aliases parsed from
  `PropertyAliases.txt`. Each row provides:

      short ; long [; alias [; alias ...]]

  for one Unicode character property. Either spelling can be used
  in regex `\p{...}` queries, programmatic lookups, or XML serial-
  isations of the UCD.

  The parsed table maps every alias (short, long, and any
  additional spellings) to a canonical short name, so callers can
  normalise a user-supplied property name to the canonical form
  before lookup.
-/

import Unicode.Generated.PropertyAliasesData

namespace Unicode.Generated.PropertyAliases

@[inline]
def trimS (s : String) : String := (String.trimAscii s).toString


/-- Parse one row of `PropertyAliases.txt`. Returns `none` for
    blank or comment-only lines. -/
def parseRow (rawLine : String) : Option PropertyRow :=
  let stripped : String := (rawLine.takeWhile (· ≠ '#')).toString
  let line := trimS stripped
  if line.isEmpty then none else
  let fields : List String :=
    ((line.splitOn ";").map trimS)
  if fields.size < 2 then none
  else
    let short := fields[0]!
    let long  := fields[1]!
    let others := if fields.size ≤ 2 then #[]
                  else fields.extract 2 fields.size
    some ⟨short, long, others⟩

/-- Raw text of `PropertyAliases.txt`, embedded at compile time. -/
def propertyAliasesRaw : String := include_str "../Ucd/PropertyAliases.txt"

/-- All parsed property-alias rows, in source order. -/
def parsedRowsParsed : List PropertyRow :=
  ((propertyAliasesRaw.splitOn "\n").filterMap parseRow)

/-- All parsed property-alias rows — the materialized view. -/
def parsedRows : List PropertyRow := parsedRowsList

/-- Look up the canonical short name for a property given any of
    its aliases (short / long / additional). Returns `none` if the
    name is not in the alias table. Comparison is case-sensitive
    per UAX #44 LM4 (loose-match would lowercase and strip
    underscores; that's a separate normaliser layer). -/
def shortNameOf? (alias : String) : Option String :=
  parsedRowsList.findSome? (fun r =>
    if r.short = alias then some r.short
    else if r.long = alias then some r.short
    else if r.others.contains alias then some r.short
    else none)

/-- Look up the canonical long name for a property given any of
    its aliases. -/
def longNameOf? (alias : String) : Option String :=
  parsedRowsList.findSome? (fun r =>
    if r.short = alias ∨ r.long = alias ∨ r.others.contains alias
      then some r.long else none)

-- Build-time drift gate.
#eval do
  unless parsedRowsList == parsedRowsParsed do
    throw (IO.userError "PropertyAliases drift: list ≠ parsed")

end Unicode.Generated.PropertyAliases
