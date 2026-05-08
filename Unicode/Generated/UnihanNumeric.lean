/-
  Unicode.Generated.UnihanNumeric

  UAX #38 Unihan numeric values parsed from
  `Unihan_NumericValues.txt`. Six properties:

    * kAccountingNumeric   — value in formal-banking script
                             (e.g. 壹 = 1).
    * kOtherNumeric        — non-canonical numeric meaning.
    * kPrimaryNumeric      — canonical numeric value
                             (e.g. 一 = 1, 二 = 2, 十 = 10, 百 = 100).
    * kTayNumeric          — value in the Tay (Tai Don) script.
    * kVietnameseNumeric   — value in Vietnamese numeric usage.
    * kZhuangNumeric       — value in Zhuang script.

  Values are arbitrary-precision integers in the source. Most
  practical numeric usage (arithmetic, parsing CJK numbers) keys
  on `kPrimaryNumeric` and `kAccountingNumeric`; the others are
  niche script-specific lookups. The parser stores values as
  `Int` because the format permits negative numbers in principle
  (none currently appear, but the type accommodates it).
-/

namespace Unicode.Generated.UnihanNumeric

inductive NumericProperty where
  | AccountingNumeric
  | OtherNumeric
  | PrimaryNumeric
  | TayNumeric
  | VietnameseNumeric
  | ZhuangNumeric
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

/-- Parse a `U+XXXX` codepoint reference. -/
def parseCodepointRef (s : String) : Option Nat :=
  let t := trimS s
  if t.startsWith "U+" then
    let hexPart := (t.drop 2).toString
    if hexPart.isEmpty then none else some (parseHex hexPart)
  else
    none

/-- Parse a non-negative decimal integer. -/
def parseDecimalNat (s : String) : Option Nat :=
  let t := trimS s
  if t.isEmpty then none
  else
    let allDigits := t.all (fun c =>
      Nat.ble 0x30 c.toNat && Nat.ble c.toNat 0x39)
    if allDigits then
      some (t.foldl (fun acc c => acc * 10 + (c.toNat - 0x30)) 0)
    else
      none

def parseProperty? : String → Option NumericProperty
  | "kAccountingNumeric"  => some .AccountingNumeric
  | "kOtherNumeric"       => some .OtherNumeric
  | "kPrimaryNumeric"     => some .PrimaryNumeric
  | "kTayNumeric"         => some .TayNumeric
  | "kVietnameseNumeric"  => some .VietnameseNumeric
  | "kZhuangNumeric"      => some .ZhuangNumeric
  | unknownNumericProp    => Function.const String none unknownNumericProp

structure Row where
  source   : Nat
  property : NumericProperty
  value    : Nat
  deriving Repr, Inhabited

/-- Parse one tab-separated row of `Unihan_NumericValues.txt`. -/
def parseRow (rawLine : String) : Option Row :=
  let stripped : String := (rawLine.takeWhile (· ≠ '#')).toString
  let line := trimS stripped
  if line.isEmpty then none else
  let fields : Array String := (line.splitOn "\t").toArray
  if fields.size < 3 then none
  else
    match parseCodepointRef fields[0]!,
          parseProperty? (trimS fields[1]!),
          parseDecimalNat fields[2]! with
    | some src, some prop, some v => some ⟨src, prop, v⟩
    | _, _, _ => none

/-- Raw text of `Unihan_NumericValues.txt`, embedded at compile time. -/
def numericRaw : String := include_str "../Ucd/Unihan_NumericValues.txt"

/-- All parsed Unihan numeric-value rows. -/
def parsedRows : Array Row :=
  ((numericRaw.splitOn "\n").filterMap parseRow).toArray

/-- Look up the numeric value for a given (codepoint, property) pair. -/
def lookup (cp : Nat) (prop : NumericProperty) : Option Nat :=
  parsedRows.findSome? (fun r =>
    if r.source = cp ∧ r.property = prop then some r.value else none)

end Unicode.Generated.UnihanNumeric
