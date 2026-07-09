/-
  Unicode.Generated.DerivedJoiningType

  Derived `Joining_Type` table from
  `Unicode/Ucd/extracted/DerivedJoiningType.txt` (Unicode 17.0.0),
  embedded as a String constant via `include_str` and parsed once at
  module load. Pattern follows `fgdorais/lean4-unicode-basic`.

  Each row maps a codepoint range to one of six joining types. Per
  the file's `@missing` directive, codepoints not covered by any
  row default to `NonJoining` (U).

  Use sites: UTS #46 §A.1 (CONTEXTJ for ZWNJ) regex inspects the
  Joining_Type of characters around U+200C.
-/

import Unicode.Generated.DerivedJoiningTypeData

namespace Unicode.Generated.DerivedJoiningType

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

def parseJoiningType? : String → Option JoiningType
  | "R" => some .RightJoining
  | "L" => some .LeftJoining
  | "D" => some .DualJoining
  | "C" => some .JoinCausing
  | "T" => some .Transparent
  | "U" => some .NonJoining
  | unknownJoiningType => Function.const String none unknownJoiningType

/-- Parse the codepoint-range field. Returns `(min, max)`; for a
    single-codepoint row, `min = max`. -/
def parseRange (s : String) : Nat × Nat :=
  match String.splitOn s ".." with
  | [single] => let n := parseHex single; (n, n)
  | [a, b]   => (parseHex a, parseHex b)
  | irregularRange => Function.const (List String) (0, 0) irregularRange

/-- Parse one DerivedJoiningType.txt row. Returns `none` for blank or
    comment lines. -/
def parseRow (rawLine : String) : Option JoiningRow := Id.run do
  let stripped : String := (rawLine.takeWhile (· != '#')).toString
  let line := trimS stripped
  if line.isEmpty then return none
  let fields := String.splitOn line ";"
  if fields.length < 2 then return none
  let (lo, hi) := parseRange (trimS fields[0]!)
  match parseJoiningType? (trimS fields[1]!) with
  | none      => none
  | some jt   => some ⟨lo, hi, jt⟩

/-- Raw text of `DerivedJoiningType.txt`, embedded at compile time. -/
def derivedJoiningTypeRaw : String := include_str "../Ucd/DerivedJoiningType.txt"

/-- All Joining_Type rows from the derived table. Codepoints not
    covered default to `NonJoining` per the file's `@missing` directive. -/
def joiningRangesParsed : Array JoiningRow :=
  ((derivedJoiningTypeRaw.splitOn "\n").filterMap parseRow).toArray

/-- Look up the Joining_Type of `cp`, returning `NonJoining` for
    codepoints outside the table coverage (the @missing default). -/
def joiningType (cp : Nat) : JoiningType :=
  match joiningRangesList.findSome? (fun row =>
      if row.min ≤ cp ∧ cp ≤ row.max then some row.joiningType else none) with
  | some jt => jt
  | none    => .NonJoining

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 KNOWN-CODEPOINT JOINING TYPES
-- ═══════════════════════════════════════════════════════════════════════════════

/-- ARABIC TATWEEL is the canonical Joining_Causing character. -/
theorem joiningType_tatweel : joiningType 0x0640 = .JoinCausing := by decide +kernel

/-- ZERO WIDTH JOINER is Joining_Causing. -/
theorem joiningType_zwj : joiningType 0x200D = .JoinCausing := by decide +kernel

/-- KASHMIRI YEH is Dual_Joining. -/
theorem joiningType_kashmiri_yeh : joiningType 0x0620 = .DualJoining := by decide +kernel

/-- HEBREW LETTER ALEF is the default — Non_Joining (despite being RTL). -/
theorem joiningType_hebrew_alef : joiningType 0x05D0 = .NonJoining := by decide +kernel

/-- LATIN CAPITAL A is the default — Non_Joining. -/
theorem joiningType_A : joiningType 0x0041 = .NonJoining := by decide +kernel

-- Build-time drift gate.
#eval do
  unless joiningRangesList.toArray == joiningRangesParsed do
    throw (IO.userError "DerivedJoiningType drift: list ≠ parsed")

end Unicode.Generated.DerivedJoiningType
