/-
  Unicode.Generated.PropertyValueAliases

  UAX #44 § 5.10.4 property value aliases parsed from
  `PropertyValueAliases.txt`. Each row carries the property
  short-name, plus aliases for one of its values:

      <propShort> ; <valShort> ; <valLong> [; <valAlias> ...]

  Use cases mirror PropertyAliases — a regex `\p{Bidi_Class=AL}`
  parser must accept `bc=AL`, `Bidi_Class=Arabic_Letter`, etc.,
  all of which resolve to the same canonical (Bidi_Class, AL)
  pair via this table.
-/

namespace Unicode.Generated.PropertyValueAliases

@[inline]
def trimS (s : String) : String := (String.trimAscii s).toString

structure PropertyValueRow where
  /-- The short name of the property (e.g. "bc" for Bidi_Class). -/
  property : String
  /-- The short name of the value (e.g. "AL" for Arabic_Letter). -/
  short    : String
  /-- The long name of the value (e.g. "Arabic_Letter"). -/
  long     : String
  /-- Any additional aliases for the value. -/
  others   : Array String
  deriving Repr, Inhabited

/-- Parse one row of `PropertyValueAliases.txt`. Returns `none`
    for blank or comment-only lines, and for the special
    `n/a` placeholder rows used by enumerated boolean values. -/
def parseRow (rawLine : String) : Option PropertyValueRow :=
  let stripped : String := (rawLine.takeWhile (· ≠ '#')).toString
  let line := trimS stripped
  if line.isEmpty then none else
  let fields : Array String :=
    ((line.splitOn ";").map trimS).toArray
  if fields.size < 3 then none
  else
    let prop  := fields[0]!
    let short := fields[1]!
    let long  := fields[2]!
    if short = "n/a" ∨ long = "n/a" then none
    else
      let others := if fields.size ≤ 3 then #[]
                    else fields.extract 3 fields.size
      some ⟨prop, short, long, others⟩

/-- Raw text of `PropertyValueAliases.txt`, embedded at compile time. -/
def propertyValueAliasesRaw : String :=
  include_str "../Ucd/PropertyValueAliases.txt"

/-- All parsed property-value-alias rows, in source order. -/
def parsedRows : Array PropertyValueRow :=
  ((propertyValueAliasesRaw.splitOn "\n").filterMap parseRow).toArray

/-- Look up the canonical short value name for a (property,
    value-alias) pair. Returns `none` if the alias is not in the
    table for that property. -/
def shortValueOf? (property valueAlias : String) : Option String :=
  parsedRows.findSome? (fun r =>
    if r.property ≠ property then none
    else if r.short = valueAlias ∨ r.long = valueAlias
            ∨ r.others.contains valueAlias then some r.short
    else none)

/-- Look up the canonical long value name. -/
def longValueOf? (property valueAlias : String) : Option String :=
  parsedRows.findSome? (fun r =>
    if r.property ≠ property then none
    else if r.short = valueAlias ∨ r.long = valueAlias
            ∨ r.others.contains valueAlias then some r.long
    else none)

end Unicode.Generated.PropertyValueAliases
