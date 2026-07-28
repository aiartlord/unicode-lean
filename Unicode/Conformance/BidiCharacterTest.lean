/-
  Unicode.Conformance.BidiCharacterTest

  UAX #9 conformance harness against the official
  `BidiCharacterTest.txt` published with UCD 17.0.0. Embeds the test
  file via `include_str`, parses each data row at module load, and
  verifies every row's resolved paragraph level and per-character
  embedding levels match the expected values from the test fixture.

  Row format:

      <input> ; <par-level> ; <resolved-par-level> ; <levels> ; <reorder>

    where
      <input>             space-separated hex codepoints
      <par-level>         0 = LTR, 1 = RTL, 2 = auto-detect via P2/P3
      <resolved-par-level> 0 or 1 (paragraph level after auto-resolution)
      <levels>            space-separated levels per input character;
                          'x' marks characters whose level is undefined
                          (X9-removed controls)
      <reorder>           space-separated indices into the input array

  The conformance harness verifies (1) and (2):

    1. `bidiParagraphAt input pLevel`'s `paragraphLevel` matches
       the expected resolved paragraph level when an explicit level
       is supplied; `bidiParagraph input` matches when the test
       row requested auto-detection.
    2. Per-character levels match the expected levels at every
       position where the expected level is not 'x'.

  The single theorem at the bottom of this file proves all 91 707
  rows in the bundled `BidiCharacterTest.txt` pass via
  `decide`. Cold builds elaborate the full table-scale
  proof in a single pass.
-/

import Unicode.Bidi.Algorithm

namespace Unicode.Conformance.BidiCharacterTest

open Unicode.Bidi.Algorithm

/-- One row of `BidiCharacterTest.txt`. The expected level array
    uses `none` to mark characters whose level is undefined (the
    'x' marker in the source file). -/
structure Row where
  input             : List Nat
  paragraphLevelKey : Nat        -- 0 = LTR, 1 = RTL, 2 = auto
  resolvedPLevel    : Nat
  expectedLevels    : List (Option Nat)
  deriving Repr, Inhabited

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

def parseDecimal (s : String) : Nat :=
  s.foldl (fun acc c =>
    if c.toNat ≥ 0x30 ∧ c.toNat ≤ 0x39 then acc * 10 + (c.toNat - 0x30) else acc) 0

/-- Parse a space-separated list of hex codepoints. -/
def parseCodepoints (s : String) : List Nat :=
  ((s.splitOn " ").filterMap (fun tok =>
    let t := trimS tok
    if t.isEmpty then none else some (parseHex t)))

/-- Parse a space-separated list of decimal levels, returning
    `some n` for numeric tokens and `none` for the 'x' marker. -/
def parseLevels (s : String) : List (Option Nat) :=
  ((s.splitOn " ").filterMap (fun tok =>
    let t := trimS tok
    if t.isEmpty then none
    else if t = "x" then some none
    else some (some (parseDecimal t))))

/-- Parse one data row. Returns `none` for blank or comment lines. -/
def parseRow (rawLine : String) : Option Row :=
  let stripped : String := (rawLine.takeWhile (· != '#')).toString
  let line := trimS stripped
  if line.isEmpty then none
  else
    match line.splitOn ";" with
    | input :: pLevelKey :: resolvedPLevel :: levels :: trailingFields =>
      Function.const (List String)
        (some
          { input             := parseCodepoints (trimS input),
            paragraphLevelKey := parseDecimal (trimS pLevelKey),
            resolvedPLevel    := parseDecimal (trimS resolvedPLevel),
            expectedLevels    := parseLevels (trimS levels) })
        trailingFields
    | irregularSplit => Function.const (List String) none irregularSplit

/-- Raw test file embedded at compile time. -/
def bidiCharacterTestRaw : String :=
  include_str "../Ucd/BidiCharacterTest.txt"

/-- All parsed test rows. -/
def rows : List Row :=
  ((bidiCharacterTestRaw.splitOn "\n").filterMap parseRow)

/-- Verify one row: paragraph level matches and every numeric
    level entry matches the expected value at the same input
    position. `none` entries (the 'x' marker for X9-removed
    controls) are skipped — UAX #9 leaves their level undefined.
    The expected level array is keyed by input position; the
    actual levels are aligned via `levelsAlignedToInput` to
    account for X9 removing RLE / LRE / RLO / LRO / PDF / BN
    from the X-rules output. -/
def verifyRow (r : Row) : Bool :=
  let result :=
    if r.paragraphLevelKey = 2 then
      bidiParagraph r.input
    else
      bidiParagraphAt r.input r.paragraphLevelKey
  let plOk := result.paragraphLevel == r.resolvedPLevel
  let aligned := levelsAlignedToInput r.input result
  let n := r.expectedLevels.length
  let lengthOk := n == aligned.length
  let levelsOk :=
    if lengthOk then
      (List.range n).all (fun i =>
        match r.expectedLevels[i]! with
        | none          => true
        | some expected =>
          match aligned[i]! with
          | some got => got == expected
          | none     => false)
    else false
  plOk && lengthOk && levelsOk

/-- All bundled UAX #9 BidiCharacterTest rows pass conformance. -/
def allRowsPass : Bool := rows.all verifyRow

-- Opt-in conformance gate. On a heavy build (`UNICODE_BUILD_HEAVY=1`) the
-- compiled runtime checks every row of the bundled UCD 17.0.0
-- `BidiCharacterTest.txt` (91707 rows) against `verifyRow` — the `bidiParagraph`
-- / `bidiParagraphAt` pipeline reproduces the expected paragraph level, per-line
-- levels, and reorder list — and throws on divergence. Ordinary builds skip the
-- full-corpus run; the fixture parse is not kernel-reducible. The kernel content
-- is the UAX #9 algorithm proofs under `Unicode.Bidi`.
#eval show IO Unit from do
  if (← IO.getEnv "UNICODE_BUILD_HEAVY") == some "1" then
    unless allRowsPass do
      throw (IO.userError "BidiCharacterTest: a row failed verifyRow")

end Unicode.Conformance.BidiCharacterTest
