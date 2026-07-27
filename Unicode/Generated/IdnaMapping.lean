/-
  Unicode.Generated.IdnaMapping

  IDNA mapping table from `lemma/lean/Unicode/Ucd/IdnaMappingTable.txt`
  (UTS #46 17.0.0 — IDNA Compatibility Processing), embedded as a
  String constant via `include_str` and parsed once at module load.
  Pattern follows `fgdorais/lean4-unicode-basic`.

  Semantics (UTS #46): each row maps a codepoint range to one of five
  IDNA processing dispositions, optionally with a mapping target
  sequence and an IDNA2008 status flag.

  Dispositions:
    * `Valid`       — admissible without modification.
    * `Mapped`      — replace with the `mapping` sequence.
    * `Ignored`     — drop from the processed string.
    * `Deviation`   — admitted in transitional processing, mapped in
                      non-transitional. The `mapping` sequence applies.
    * `Disallowed`  — reject the input string.

  IDNA2008 status (column 4 of the source):
    * `NV8` — Not valid in IDNA2008 (was valid in IDNA2003).
    * `XV8` — Excluded from valid in IDNA2008 by general exclusion.
    * `none` — IDNA2008 status matches IDNA2003 default for the row.

  Counts: 9185 ranges.
-/

import Unicode.Generated.IdnaMappingData

namespace Unicode.Generated.IdnaMapping




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

def parseDisposition? : String → Option IdnaDisposition
  | "valid"      => some .Valid
  | "mapped"     => some .Mapped
  | "ignored"    => some .Ignored
  | "deviation"  => some .Deviation
  | "disallowed" => some .Disallowed
  | unknownDisposition => Function.const String none unknownDisposition

def parseIdna2008? : String → Option IdnaIdna2008Status
  | "NV8" => some .NV8
  | "XV8" => some .XV8
  | unknownIdna2008Status => Function.const String none unknownIdna2008Status

/-- Parse the codepoint-range field. Returns `(min, max)`; for a
    single-codepoint row, `min = max`. -/
def parseRange (s : String) : Nat × Nat :=
  match String.splitOn s ".." with
  | [single]  => let n := parseHex single; (n, n)
  | [a, b]    => (parseHex a, parseHex b)
  | irregularRange => Function.const (List String) (0, 0) irregularRange

/-- Parse a space-separated list of hex codepoints (the `mapping`
    column for Mapped / Deviation rows). -/
def parseCodepoints (s : String) : List Nat :=
  (s.splitOn " ").filterMap (fun tok =>
    let t := trimS tok
    if t.isEmpty then none else some (parseHex t))

/-- Parse one IdnaMappingTable.txt row. Returns `none` for blank or
    comment lines. -/
def parseIdnaRow (rawLine : String) : Option IdnaRow := Id.run do
  let stripped : String := (rawLine.takeWhile (· != '#')).toString
  let line := trimS stripped
  if line.isEmpty then return none
  let fields := String.splitOn line ";"
  if fields.length < 2 then return none
  let (lo, hi) := parseRange (trimS fields[0]!)
  match parseDisposition? (trimS fields[1]!) with
  | none => none
  | some disp =>
    let mapping :=
      if fields.length ≥ 3 then parseCodepoints (trimS fields[2]!)
      else []
    let idna2008 :=
      if fields.length ≥ 4 then parseIdna2008? (trimS fields[3]!)
      else none
    some ⟨lo, hi, disp, mapping, idna2008⟩

/-- Raw text of `IdnaMappingTable.txt`, embedded at compile time. -/
def idnaMappingRaw : String := include_str "../Ucd/IdnaMappingTable.txt"

/-- Range table mapping codepoint ranges to their IDNA disposition.
    Stored in source order (already sorted by `min` per the UCD
    file convention), so binary search by `min` is correct. -/
def idnaMappingRangesParsed : List IdnaRow :=
  (idnaMappingRaw.splitOn "\n").filterMap parseIdnaRow

/-- The materialized range table, pinned in source (sorted) order. -/
def idnaMappingRanges : List IdnaRow := idnaMappingRangesList

/-- Binary search the sorted-by-`min` `idnaMappingRanges` for a row
    whose `[min, max]` interval contains `cp`. Fuel-bounded for
    `decide` evaluability; `arr.length` is always a sufficient bound
    on the probe count. Returns `none` for codepoints outside every
    range (caller maps that to the table's "Disallowed" default). -/
def binarySearchRange (arr : List IdnaRow) (cp : Nat)
    (left right fuel : Nat) : Option IdnaRow :=
  match fuel with
  | 0          => none
  | fuel' + 1 =>
    if left < right then
      let mid   := (left + right) / 2
      let entry := arr[mid]!
      if cp < entry.min then
        binarySearchRange arr cp left mid fuel'
      else if entry.max < cp then
        binarySearchRange arr cp (mid + 1) right fuel'
      else
        some entry
    else
      none

/-- Look up `cp`'s row by binary search over `idnaMappingRanges`,
    halving the probe interval by `min`-key comparison. Called once
    per codepoint by `mapNonTransitional` / `mapTransitional` /
    `decodedLabelValidV6`. -/
def lookupRowBinary (cp : Nat) : Option IdnaRow :=
  binarySearchRange idnaMappingRanges cp 0 idnaMappingRanges.length
    (idnaMappingRanges.length + 1)

/-- Kernel-reducible linear lookup over the pinned `List` (the
    binary search is the runtime path; this is for `decide` proofs). -/
def lookupRowList? (cp : Nat) : Option IdnaRow :=
  idnaMappingRangesList.find? (fun r => decide (r.min ≤ cp ∧ cp ≤ r.max))

-- Build-time drift gate.
#eval do
  unless idnaMappingRangesList == idnaMappingRangesParsed do
    throw (IO.userError "IdnaMapping drift: list ≠ parsed")

end Unicode.Generated.IdnaMapping
