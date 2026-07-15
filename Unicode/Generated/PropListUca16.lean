/-
  Unicode.Generated.PropListUca16

  PropList from Unicode 16.0.0, version-matched to UCA 16.0.0's
  `allkeys.txt` and the `CollationTest_*.txt` conformance files.

  The UCA implicit-weight rule (UTS #10 §10.1.3 / Table 16) gates
  the Han Core (FB40) and Han Other (FB80) tiers on the
  `Unified_Ideograph` property. That property changes between
  Unicode releases — for example, UCD 17.0 adds U+2B73A..U+2B73F to
  the `Unified_Ideograph` set inside the previously-reserved gap at
  the end of CJK Extension C, while UCD 16.0 leaves them
  unassigned. Using the 17.0 property set against the 16.0 DUCET
  produces collation orders that disagree with the published 16.0
  conformance test by exactly the count of newly-classified
  codepoints.

  This module loads the 16.0 `PropList.txt` strictly for the UCA
  pipeline. The general-purpose `Unicode.Generated.PropList` loader
  (which uses 17.0 data alongside the rest of the UCD) is kept
  separate so the rest of the library tracks the latest UCD.
-/

import Unicode.Generated.PropListUca16Data

namespace Unicode.Generated.PropListUca16

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

/-- Parse the codepoint-range field. Returns `(min, max)`; for a
    single-codepoint row, `min = max`. -/
def parseRange? (s : String) : Option (Nat × Nat) :=
  match String.splitOn s ".." with
  | [] => none
  | [single] => let n := parseHex single; some (n, n)
  | [a, b] => some (parseHex a, parseHex b)
  | _first :: _second :: _third :: _rest => none

/-- Parse one row of `PropList.txt`, keeping only `Unified_Ideograph`
    entries. Returns `(min, max)` of an inclusive Unified_Ideograph
    range, or `none` for any other row (including comments, blanks,
    and other binary-property entries). -/
def parseUnifiedIdeographRow (rawLine : String) : Option (Nat × Nat) :=
  let stripped : String := (rawLine.takeWhile (· != '#')).toString
  let line := trimS stripped
  if line.isEmpty then none
  else
    match String.splitOn line ";" with
    | [] => none
    | [_onlyRange] => none
    | [rangeField, propField] =>
      if trimS propField = "Unified_Ideograph" then
        parseRange? (trimS rangeField)
      else
        none
    | _rangeField :: _propField :: _extraField :: _rest => none

/-- Raw text of `PropListUca16.txt`, embedded at compile time. -/
def propListRaw : String := include_str "../Ucd/PropListUca16.txt"

/-- Inclusive ranges of codepoints with `Unified_Ideograph = Yes` in
    Unicode 16.0. Used by `Unicode.Uca.Lookup.implicitBaseFor` to
    gate the Han Core / Han Other tiers per UTS #10 §10.1.3 /
    Table 16. -/
def unifiedIdeographRangesParsed : Array (Nat × Nat) :=
  ((propListRaw.splitOn "\n").filterMap parseUnifiedIdeographRow).toArray

/-- True iff `cp` has `Unified_Ideograph = Yes` per UCD 16.0. -/
def isUnifiedIdeograph (cp : Nat) : Bool :=
  unifiedIdeographRangesList.any
    (fun lh => decide (lh.fst ≤ cp ∧ cp ≤ lh.snd))

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 SHAPE CHECKS — version-distinguishing codepoints
-- ═══════════════════════════════════════════════════════════════════════════════

/-- 0x2B73A is unassigned in UCD 16.0 (the UCD 17.0 ranges extend
    Ext C to cover it). The UCA 16.0 conformance test orders 0x2B73A
    with the unassigned-tier (FBC0) primary base — this loader
    produces the 16.0 answer. -/
theorem isUnifiedIdeograph_2B73A : isUnifiedIdeograph 0x2B73A = false := by decide +kernel

/-- 0x2B739 is the last assigned codepoint in CJK Ext C per
    UCD 16.0. -/
theorem isUnifiedIdeograph_2B739 : isUnifiedIdeograph 0x2B739 = true := by decide +kernel

/-- 0x4E00 (start of CJK Unified Ideographs) is Unified_Ideograph in
    every UCD version. -/
theorem isUnifiedIdeograph_4E00 : isUnifiedIdeograph 0x4E00 = true := by decide +kernel

/-- 0x2A6E0 is in the reserved gap between Ext B and Ext C — not
    Unified_Ideograph in any UCD version. -/
theorem isUnifiedIdeograph_2A6E0 : isUnifiedIdeograph 0x2A6E0 = false := by decide +kernel

-- Build-time drift gate.
#eval do
  unless unifiedIdeographRangesList.toArray == unifiedIdeographRangesParsed do
    throw (IO.userError "PropListUca16 drift: list ≠ parsed")

end Unicode.Generated.PropListUca16
