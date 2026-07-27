/-
  Unicode.Generated.UnihanNumeric

  Literal UAX #38 Unihan numeric values from
  Unihan_NumericValues.txt. Generated as kernel-visible data so
  lookups and examples do not reduce include-str parsers.

  This preserves the previous parser semantics: rows whose value
  field is not a single non-negative decimal token are ignored.
-/

namespace Unicode.Generated.UnihanNumeric

set_option maxRecDepth 100000

inductive NumericProperty where
  | AccountingNumeric
  | OtherNumeric
  | PrimaryNumeric
  | TayNumeric
  | VietnameseNumeric
  | ZhuangNumeric
  deriving DecidableEq, Repr, Inhabited

def propertyRank : NumericProperty → Nat
  | .AccountingNumeric => 0
  | .OtherNumeric => 1
  | .PrimaryNumeric => 2
  | .TayNumeric => 3
  | .VietnameseNumeric => 4
  | .ZhuangNumeric => 5

structure Row where
  source : Nat
  property : NumericProperty
  value : Nat
  deriving Repr, Inhabited, DecidableEq

/-- Numeric rows sorted by `(source, propertyRank property)`. -/
def parsedRows : List Row := [
  { source := 0x3405, property := .OtherNumeric, value := 5 },
  { source := 0x3431, property := .VietnameseNumeric, value := 9 },
  { source := 0x3483, property := .OtherNumeric, value := 2 },
  { source := 0x3576, property := .ZhuangNumeric, value := 5 },
  { source := 0x382A, property := .OtherNumeric, value := 5 },
  { source := 0x3B4D, property := .OtherNumeric, value := 7 },
  { source := 0x4E00, property := .PrimaryNumeric, value := 1 },
  { source := 0x4E03, property := .PrimaryNumeric, value := 7 },
  { source := 0x4E07, property := .PrimaryNumeric, value := 10000 },
  { source := 0x4E09, property := .PrimaryNumeric, value := 3 },
  { source := 0x4E24, property := .OtherNumeric, value := 2 },
  { source := 0x4E59, property := .ZhuangNumeric, value := 1 },
  { source := 0x4E5D, property := .PrimaryNumeric, value := 9 },
  { source := 0x4E86, property := .ZhuangNumeric, value := 1 },
  { source := 0x4E8C, property := .PrimaryNumeric, value := 2 },
  { source := 0x4E94, property := .PrimaryNumeric, value := 5 },
  { source := 0x4E96, property := .OtherNumeric, value := 4 },
  { source := 0x4EAC, property := .PrimaryNumeric, value := 10000000000000000 },
  { source := 0x4EBF, property := .PrimaryNumeric, value := 100000000 },
  { source := 0x4EC0, property := .OtherNumeric, value := 10 },
  { source := 0x4EDF, property := .AccountingNumeric, value := 1000 },
  { source := 0x4EE8, property := .OtherNumeric, value := 3 },
  { source := 0x4F0D, property := .AccountingNumeric, value := 5 },
  { source := 0x4F70, property := .AccountingNumeric, value := 100 },
  { source := 0x4FC9, property := .ZhuangNumeric, value := 5 },
  { source := 0x4FE9, property := .OtherNumeric, value := 2 },
  { source := 0x5006, property := .OtherNumeric, value := 2 },
  { source := 0x5104, property := .PrimaryNumeric, value := 100000000 },
  { source := 0x5169, property := .OtherNumeric, value := 2 },
  { source := 0x516B, property := .PrimaryNumeric, value := 8 },
  { source := 0x516D, property := .PrimaryNumeric, value := 6 },
  { source := 0x5200, property := .TayNumeric, value := 1 },
  { source := 0x5341, property := .PrimaryNumeric, value := 10 },
  { source := 0x5343, property := .PrimaryNumeric, value := 1000 },
  { source := 0x5344, property := .OtherNumeric, value := 20 },
  { source := 0x5345, property := .OtherNumeric, value := 30 },
  { source := 0x534C, property := .OtherNumeric, value := 40 },
  { source := 0x53C1, property := .AccountingNumeric, value := 3 },
  { source := 0x53C2, property := .AccountingNumeric, value := 3 },
  { source := 0x53C3, property := .AccountingNumeric, value := 3 },
  { source := 0x53C4, property := .OtherNumeric, value := 3 },
  { source := 0x53CC, property := .ZhuangNumeric, value := 2 },
  { source := 0x53F0, property := .VietnameseNumeric, value := 2 },
  { source := 0x540A, property := .ZhuangNumeric, value := 1 },
  { source := 0x5549, property := .VietnameseNumeric, value := 100 },
  { source := 0x56DB, property := .PrimaryNumeric, value := 4 },
  { source := 0x58F1, property := .AccountingNumeric, value := 1 },
  { source := 0x58F9, property := .AccountingNumeric, value := 1 },
  { source := 0x5954, property := .VietnameseNumeric, value := 4 },
  { source := 0x5C1E, property := .ZhuangNumeric, value := 1 },
  { source := 0x5E7A, property := .OtherNumeric, value := 1 },
  { source := 0x5EFE, property := .OtherNumeric, value := 9 },
  { source := 0x5EFF, property := .OtherNumeric, value := 20 },
  { source := 0x5F0C, property := .AccountingNumeric, value := 1 },
  { source := 0x5F0D, property := .AccountingNumeric, value := 2 },
  { source := 0x5F0E, property := .AccountingNumeric, value := 3 },
  { source := 0x5F10, property := .AccountingNumeric, value := 2 },
  { source := 0x5F66, property := .VietnameseNumeric, value := 1000 },
  { source := 0x62D0, property := .OtherNumeric, value := 7 },
  { source := 0x62FE, property := .AccountingNumeric, value := 10 },
  { source := 0x634C, property := .AccountingNumeric, value := 8 },
  { source := 0x672C, property := .VietnameseNumeric, value := 4 },
  { source := 0x6761, property := .TayNumeric, value := 1 },
  { source := 0x677E, property := .ZhuangNumeric, value := 2 },
  { source := 0x6797, property := .VietnameseNumeric, value := 100 },
  { source := 0x67D2, property := .AccountingNumeric, value := 7 },
  { source := 0x6C92, property := .VietnameseNumeric, value := 1 },
  { source := 0x6CA1, property := .VietnameseNumeric, value := 1 },
  { source := 0x6D1E, property := .OtherNumeric, value := 0 },
  { source := 0x6F06, property := .AccountingNumeric, value := 7 },
  { source := 0x7396, property := .AccountingNumeric, value := 9 },
  { source := 0x767E, property := .PrimaryNumeric, value := 100 },
  { source := 0x7695, property := .OtherNumeric, value := 200 },
  { source := 0x7A7A, property := .VietnameseNumeric, value := 0 },
  { source := 0x7F62, property := .VietnameseNumeric, value := 7 },
  { source := 0x7F77, property := .VietnameseNumeric, value := 7 },
  { source := 0x8086, property := .AccountingNumeric, value := 4 },
  { source := 0x80FD, property := .TayNumeric, value := 1 },
  { source := 0x80FD, property := .ZhuangNumeric, value := 1 },
  { source := 0x842C, property := .PrimaryNumeric, value := 10000 },
  { source := 0x8511, property := .VietnameseNumeric, value := 1 },
  { source := 0x8CAE, property := .AccountingNumeric, value := 2 },
  { source := 0x8CB3, property := .AccountingNumeric, value := 2 },
  { source := 0x8D30, property := .AccountingNumeric, value := 2 },
  { source := 0x8FC8, property := .VietnameseNumeric, value := 10 },
  { source := 0x9081, property := .VietnameseNumeric, value := 10 },
  { source := 0x920E, property := .OtherNumeric, value := 9 },
  { source := 0x94A9, property := .OtherNumeric, value := 9 },
  { source := 0x9621, property := .AccountingNumeric, value := 1000 },
  { source := 0x9646, property := .AccountingNumeric, value := 6 },
  { source := 0x964C, property := .AccountingNumeric, value := 100 },
  { source := 0x9678, property := .AccountingNumeric, value := 6 },
  { source := 0x96F6, property := .PrimaryNumeric, value := 0 },
  { source := 0x020001, property := .OtherNumeric, value := 7 },
  { source := 0x020027, property := .VietnameseNumeric, value := 3 },
  { source := 0x020064, property := .OtherNumeric, value := 4 },
  { source := 0x0200E2, property := .OtherNumeric, value := 4 },
  { source := 0x0200E9, property := .VietnameseNumeric, value := 9 },
  { source := 0x020121, property := .OtherNumeric, value := 5 },
  { source := 0x020129, property := .VietnameseNumeric, value := 2 },
  { source := 0x020136, property := .VietnameseNumeric, value := 5 },
  { source := 0x02013B, property := .VietnameseNumeric, value := 5 },
  { source := 0x02013C, property := .VietnameseNumeric, value := 5 },
  { source := 0x02052D, property := .VietnameseNumeric, value := 8 },
  { source := 0x020929, property := .VietnameseNumeric, value := 7 },
  { source := 0x02092A, property := .OtherNumeric, value := 1 },
  { source := 0x020983, property := .OtherNumeric, value := 30 },
  { source := 0x02098C, property := .OtherNumeric, value := 40 },
  { source := 0x02099C, property := .OtherNumeric, value := 40 },
  { source := 0x0209A9, property := .VietnameseNumeric, value := 10 },
  { source := 0x0209B3, property := .VietnameseNumeric, value := 1000 },
  { source := 0x020AEA, property := .OtherNumeric, value := 6 },
  { source := 0x020AFD, property := .OtherNumeric, value := 3 },
  { source := 0x020B19, property := .OtherNumeric, value := 3 },
  { source := 0x020B20, property := .VietnameseNumeric, value := 1 },
  { source := 0x020BA9, property := .ZhuangNumeric, value := 1 },
  { source := 0x020CA2, property := .ZhuangNumeric, value := 1 },
  { source := 0x022390, property := .OtherNumeric, value := 2 },
  { source := 0x022482, property := .VietnameseNumeric, value := 9 },
  { source := 0x022998, property := .OtherNumeric, value := 3 },
  { source := 0x023B1B, property := .OtherNumeric, value := 3 },
  { source := 0x024F93, property := .VietnameseNumeric, value := 100 },
  { source := 0x02626D, property := .OtherNumeric, value := 4 },
  { source := 0x026271, property := .VietnameseNumeric, value := 7 },
  { source := 0x02629A, property := .VietnameseNumeric, value := 4 },
  { source := 0x0264B9, property := .VietnameseNumeric, value := 6 },
  { source := 0x02846E, property := .VietnameseNumeric, value := 10 },
  { source := 0x028492, property := .VietnameseNumeric, value := 10 },
  { source := 0x028DC8, property := .VietnameseNumeric, value := 10000 },
  { source := 0x02B52C, property := .VietnameseNumeric, value := 10000 },
  { source := 0x02B866, property := .VietnameseNumeric, value := 9 },
  { source := 0x02B871, property := .TayNumeric, value := 2 },
  { source := 0x02B872, property := .TayNumeric, value := 5 },
  { source := 0x02B875, property := .VietnameseNumeric, value := 5 },
  { source := 0x02B92F, property := .VietnameseNumeric, value := 8 },
  { source := 0x02B9C7, property := .ZhuangNumeric, value := 1 },
  { source := 0x02C0BD, property := .VietnameseNumeric, value := 5 },
  { source := 0x02C0F4, property := .VietnameseNumeric, value := 100 },
  { source := 0x02C65E, property := .VietnameseNumeric, value := 7 },
  { source := 0x02C954, property := .TayNumeric, value := 7 },
  { source := 0x02CB99, property := .VietnameseNumeric, value := 10000 },
  { source := 0x02CEB4, property := .ZhuangNumeric, value := 1 },
  { source := 0x03000C, property := .ZhuangNumeric, value := 1 },
  { source := 0x030FD8, property := .VietnameseNumeric, value := 10000 },
  { source := 0x031357, property := .VietnameseNumeric, value := 1 },
  { source := 0x031394, property := .VietnameseNumeric, value := 2 },
  { source := 0x031396, property := .VietnameseNumeric, value := 5 },
  { source := 0x031455, property := .VietnameseNumeric, value := 10 },
  { source := 0x03197A, property := .VietnameseNumeric, value := 1 },
  { source := 0x031EC7, property := .TayNumeric, value := 4 },
  { source := 0x031FA3, property := .VietnameseNumeric, value := 10000 },
  { source := 0x032226, property := .VietnameseNumeric, value := 10000 }
]

def rowCmp (cp : Nat) (prop : NumericProperty) (row : Row) : Ordering :=
  if cp < row.source then
    .lt
  else if row.source < cp then
    .gt
  else if propertyRank prop < propertyRank row.property then
    .lt
  else if propertyRank row.property < propertyRank prop then
    .gt
  else
    .eq

def binarySearch (cp : Nat) (prop : NumericProperty) (left right fuel : Nat) : Option Nat :=
  match fuel with
  | 0 => none
  | fuelNext + 1 =>
    if left < right then
      let mid := (left + right) / 2
      let row := parsedRows[mid]!
      match rowCmp cp prop row with
      | .lt => binarySearch cp prop left mid fuelNext
      | .gt => binarySearch cp prop (mid + 1) right fuelNext
      | .eq => some row.value
    else
      none

/-- Look up the numeric value for a given codepoint and property. -/
def lookup (cp : Nat) (prop : NumericProperty) : Option Nat :=
  binarySearch cp prop 0 parsedRows.length (parsedRows.length + 1)

theorem parsedRows_count : parsedRows.length = 152 := by decide

theorem lookup_u4E00_primary :
    lookup 0x4E00 .PrimaryNumeric = some 1 := by decide

theorem lookup_u4E8C_primary :
    lookup 0x4E8C .PrimaryNumeric = some 2 := by decide

theorem lookup_u5341_primary :
    lookup 0x5341 .PrimaryNumeric = some 10 := by decide

theorem lookup_u767E_primary :
    lookup 0x767E .PrimaryNumeric = some 100 := by decide

theorem lookup_u58F9_accounting :
    lookup 0x58F9 .AccountingNumeric = some 1 := by decide

theorem lookup_u6F22_primary :
    lookup 0x6F22 .PrimaryNumeric = none := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- INTEGRITY GATE — `parsedRows` must equal a fresh parse of Unihan_NumericValues.txt,
-- sorted by (source, propertyRank). Two kPrimaryNumeric entries (U+5146, U+79ED)
-- carry TWO values each and cannot be represented by the single-`value` Row, so
-- they are excluded here exactly as in the materialized table.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Raw text of `Unihan_NumericValues.txt`, embedded at compile time. -/
def unihanNumericRaw : String := include_str "../Ucd/Unihan_NumericValues.txt"

def uHexVal (c : Char) : Nat :=
  let n := c.toNat
  if n ≥ 0x30 ∧ n ≤ 0x39 then n - 0x30
  else if n ≥ 0x61 ∧ n ≤ 0x66 then n - 0x61 + 10
  else if n ≥ 0x41 ∧ n ≤ 0x46 then n - 0x41 + 10
  else 0
def uTrim (s : String) : String := (String.trimAscii s).toString
/-- Parse a `U+XXXX` code point (hex after the prefix). -/
def uSource (s : String) : Nat :=
  ((uTrim s).drop 2).foldl (fun acc c => acc * 16 + uHexVal c) 0
/-- Parse a decimal value. -/
def uDec (s : String) : Nat :=
  (uTrim s).foldl (fun acc c => acc * 10 + (c.toNat - 0x30)) 0

def uProp : String → Option NumericProperty
  | "kAccountingNumeric" => some .AccountingNumeric
  | "kOtherNumeric" => some .OtherNumeric
  | "kPrimaryNumeric" => some .PrimaryNumeric
  | "kTayNumeric" => some .TayNumeric
  | "kVietnameseNumeric" => some .VietnameseNumeric
  | "kZhuangNumeric" => some .ZhuangNumeric
  | _unknownProp => none

def uParseRow (line : String) : Option Row :=
  if (uTrim line).startsWith "#" then none else
  let f := line.splitOn "\t"
  if f.length < 3 then none else
  match uProp (uTrim f[1]!) with
  | none => none
  | some p =>
    let valField := uTrim f[2]!
    -- multi-valued entries (a space in the value) cannot be represented; drop.
    if (valField.splitOn " ").length > 1 then none
    else some { source := uSource f[0]!, property := p, value := uDec valField }

def parsedRowsParsed : List Row :=
  (((unihanNumericRaw.splitOn "\n").filterMap uParseRow)).mergeSort
    (fun a b => decide (a.source < b.source ∨
      (a.source = b.source ∧ propertyRank a.property < propertyRank b.property)))

#eval do
  unless parsedRows == parsedRowsParsed do
    throw (IO.userError "UnihanNumeric drift: parsedRows ≠ parsed Unihan_NumericValues.txt")

end Unicode.Generated.UnihanNumeric
