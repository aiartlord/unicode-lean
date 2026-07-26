/-
  Unicode.Generated.CompositionExclusions

  Literal codepoints excluded from canonical composition (UCD 17.0.0).
-/

namespace Unicode.Generated.CompositionExclusions

/-- Sorted array of codepoints excluded from canonical composition. -/
def codepoints : List Nat := [
  0x0958,
  0x0959,
  0x095A,
  0x095B,
  0x095C,
  0x095D,
  0x095E,
  0x095F,
  0x09DC,
  0x09DD,
  0x09DF,
  0x0A33,
  0x0A36,
  0x0A59,
  0x0A5A,
  0x0A5B,
  0x0A5E,
  0x0B5C,
  0x0B5D,
  0x0F43,
  0x0F4D,
  0x0F52,
  0x0F57,
  0x0F5C,
  0x0F69,
  0x0F76,
  0x0F78,
  0x0F93,
  0x0F9D,
  0x0FA2,
  0x0FA7,
  0x0FAC,
  0x0FB9,
  0xFB1D,
  0xFB1F,
  0xFB2A,
  0xFB2B,
  0xFB2C,
  0xFB2D,
  0xFB2E,
  0xFB2F,
  0xFB30,
  0xFB31,
  0xFB32,
  0xFB33,
  0xFB34,
  0xFB35,
  0xFB36,
  0xFB38,
  0xFB39,
  0xFB3A,
  0xFB3B,
  0xFB3C,
  0xFB3E,
  0xFB40,
  0xFB41,
  0xFB43,
  0xFB44,
  0xFB46,
  0xFB47,
  0xFB48,
  0xFB49,
  0xFB4A,
  0xFB4B,
  0xFB4C,
  0xFB4D,
  0xFB4E,
  0x2ADC,
  0x01D15E,
  0x01D15F,
  0x01D160,
  0x01D161,
  0x01D162,
  0x01D163,
  0x01D164,
  0x01D1BB,
  0x01D1BC,
  0x01D1BD,
  0x01D1BE,
  0x01D1BF,
  0x01D1C0
]

-- ═══════════════════════════════════════════════════════════════════════════════
-- INTEGRITY GATE — `codepoints` must equal a fresh parse of the pinned
-- CompositionExclusions.txt.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Raw text of `CompositionExclusions.txt`, embedded at compile time. -/
def compositionExclusionsRaw : String := include_str "../Ucd/CompositionExclusions.txt"

def ceHexVal (c : Char) : Nat :=
  let n := c.toNat
  if n ≥ 0x30 ∧ n ≤ 0x39 then n - 0x30
  else if n ≥ 0x61 ∧ n ≤ 0x66 then n - 0x61 + 10
  else if n ≥ 0x41 ∧ n ≤ 0x46 then n - 0x41 + 10
  else 0

def ceHex (s : String) : Nat := s.foldl (fun acc c => acc * 16 + ceHexVal c) 0

def ceParseRow (line : String) : Option Nat :=
  let stripped := (line.takeWhile (· != '#')).toString
  let t := (String.trimAscii stripped).toString
  if t.isEmpty then none else some (ceHex t)

/-- Fresh parse of the pinned source, used only by the drift gate. -/
def codepointsParsed : List Nat :=
  ((compositionExclusionsRaw.splitOn "\n").filterMap ceParseRow)

#eval do
  unless codepoints == codepointsParsed do
    throw (IO.userError "CompositionExclusions drift: codepoints ≠ parsed CompositionExclusions.txt")

end Unicode.Generated.CompositionExclusions
