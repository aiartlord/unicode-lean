/-
  Unicode.Conformance.BidiTest

  UAX #9 conformance harness against the official `BidiTest.txt`
  published with UCD 17.0.0. Verifies both the resolved embedding
  levels and the L1 / L2 reorder against every `@Levels:` /
  `@Reorder:` directive block in the test fixture.

  Format:

      @Levels:    <levels-or-x>
      @Reorder:   <indices>

      <bidi-class-codes>; <par-level-bitmask>
      <bidi-class-codes>; <par-level-bitmask>
      ...

  Each data row inherits the most-recent `@Levels:` and `@Reorder:`
  directives. The bitmask selects which paragraph-level settings
  to test: bit 0 (1) = auto, bit 1 (2) = LTR, bit 2 (4) = RTL.

  Bidi-class codes are mapped to representative codepoints whose
  `Bidi_Class` (per `DerivedBidiClass.txt`) matches the requested
  class — an `L` token becomes U+0041, an `R` token becomes
  U+05D0, and so on. The `lookupBidiClass`-based pipeline then
  produces the same trace it would have on the input class
  sequence directly.
-/

import Unicode.Bidi.Algorithm

namespace Unicode.Conformance.BidiTest

open Unicode.Bidi.Algorithm

/-- Map a Bidi class name to a representative codepoint that
    `Unicode.Bidi.Algorithm.lookupBidiClass` resolves to that
    class. The mapping is fixed across the test suite. -/
def classToCodepoint (cls : String) : Nat :=
  match cls with
  | "L"   => 0x0041 -- LATIN CAPITAL LETTER A
  | "R"   => 0x05D0 -- HEBREW LETTER ALEF
  | "AL"  => 0x0627 -- ARABIC LETTER ALEF
  | "EN"  => 0x0030 -- DIGIT ZERO
  | "ES"  => 0x002B -- PLUS SIGN
  | "ET"  => 0x0024 -- DOLLAR SIGN
  | "AN"  => 0x0660 -- ARABIC-INDIC DIGIT ZERO
  | "CS"  => 0x002C -- COMMA
  | "NSM" => 0x0301 -- COMBINING ACUTE ACCENT
  | "BN"  => 0xFEFF -- ZERO WIDTH NO-BREAK SPACE
  | "B"   => 0x2029 -- PARAGRAPH SEPARATOR
  | "S"   => 0x0009 -- HORIZONTAL TAB
  | "WS"  => 0x0020 -- SPACE
  | "ON"  => 0x0021 -- EXCLAMATION MARK
  | "LRE" => 0x202A
  | "RLE" => 0x202B
  | "PDF" => 0x202C
  | "LRO" => 0x202D
  | "RLO" => 0x202E
  | "LRI" => 0x2066
  | "RLI" => 0x2067
  | "FSI" => 0x2068
  | "PDI" => 0x2069
  | unknownClass => Function.const String 0 unknownClass

@[inline]
def trimS (s : String) : String := (String.trimAscii s).toString

def parseDecimal (s : String) : Nat :=
  s.foldl (fun acc c =>
    if c.toNat ≥ 0x30 ∧ c.toNat ≤ 0x39 then acc * 10 + (c.toNat - 0x30) else acc) 0

/-- Parse a space- (or tab-) separated list of bidi-class tokens
    into the corresponding codepoint sequence. -/
def parseClassRow (s : String) : Array Nat :=
  ((s.splitOn " ").filterMap (fun tok =>
    let t := trimS tok
    if t.isEmpty then none else some (classToCodepoint t))).toArray

/-- Parse the `@Levels:` directive value: space-separated decimal
    levels with `x` for X9-removed positions. -/
def parseLevelsDirective (s : String) : Array (Option Nat) :=
  let normalised := s.replace "\t" " "
  ((normalised.splitOn " ").filterMap (fun tok =>
    let t := trimS tok
    if t.isEmpty then none
    else if t = "x" then some none
    else some (some (parseDecimal t)))).toArray

/-- Parse the `@Reorder:` directive value: space-separated decimal
    indices into the input class array. -/
def parseReorderDirective (s : String) : Array Nat :=
  let normalised := s.replace "\t" " "
  ((normalised.splitOn " ").filterMap (fun tok =>
    let t := trimS tok
    if t.isEmpty then none else some (parseDecimal t))).toArray

/-- Strip a trailing comment introduced by `#` and trim whitespace. -/
def stripCommentAndTrim (line : String) : String :=
  let withoutComment := (line.takeWhile (· != '#')).toString
  trimS withoutComment

/-- One parsed test row carrying the inherited @Levels / @Reorder
    directives and the input class sequence. -/
structure Row where
  classes         : Array Nat        -- representative codepoints
  expectedLevels  : Array (Option Nat)
  expectedReorder : Array Nat
  pLevelBits      : Nat              -- 1 = auto, 2 = LTR, 4 = RTL
  deriving Repr, Inhabited

/-- Walk the file once, threading the most-recent `@Levels:` and
    `@Reorder:` directives forward into the data rows that follow. -/
def parseRows (raw : String) : Array Row :=
  Prod.fst <| (raw.splitOn "\n").foldl
    (fun (acc : Array Row × Array (Option Nat) × Array Nat) line =>
      let (rows, curLevels, curReorder) := acc
      let stripped := stripCommentAndTrim line
      if stripped.isEmpty then (rows, curLevels, curReorder)
      else if stripped.startsWith "@Levels:" then
        let body := (stripped.drop "@Levels:".length).toString
        (rows, parseLevelsDirective body, curReorder)
      else if stripped.startsWith "@Reorder:" then
        let body := (stripped.drop "@Reorder:".length).toString
        (rows, curLevels, parseReorderDirective body)
      else
        match stripped.splitOn ";" with
        | classField :: bitsField :: trailingFields =>
          let row : Row :=
            { classes         := parseClassRow (trimS classField),
              expectedLevels  := curLevels,
              expectedReorder := curReorder,
              pLevelBits      := parseDecimal (trimS bitsField) }
          Function.const (List String) (rows.push row, curLevels, curReorder)
            trailingFields
        | irregularSplit =>
          Function.const (List String) (rows, curLevels, curReorder)
            irregularSplit)
    (#[], #[], #[])

/-- Raw test file embedded at compile time. -/
def bidiTestRaw : String :=
  include_str "../Ucd/BidiTest.txt"

/-- All parsed test rows. -/
def rows : Array Row := parseRows bidiTestRaw

/-- Verify the given row at the supplied paragraph-level setting:
      0 → forced LTR
      1 → forced RTL
      2 → auto-detect via P2 / P3
    Returns `true` when the per-input-position levels match
    `expectedLevels` (skipping `none` / 'x' positions) AND the
    L1 / L2 reorder of input indices matches `expectedReorder`. -/
def verifyAtLevel (r : Row) (pLevelKey : Nat) : Bool :=
  let result :=
    if pLevelKey = 2 then bidiParagraph r.classes
    else bidiParagraphAt r.classes pLevelKey
  let aligned := levelsAlignedToInput r.classes result
  let n := r.expectedLevels.size
  let lengthOk := n == aligned.size
  let levelsOk :=
    if lengthOk then
      (Array.range n).all (fun i =>
        match r.expectedLevels[i]! with
        | none          => true
        | some expected =>
          match aligned[i]! with
          | some got => got == expected
          | none     => false)
    else false
  let reordered := reorderedInputIndices r.classes result
  let reorderOk := reordered == r.expectedReorder
  lengthOk && levelsOk && reorderOk

/-- Verify a row against every paragraph-level setting selected by
    its `pLevelBits` mask. -/
def verifyRow (r : Row) : Bool :=
  let testAuto := r.pLevelBits &&& 1 = 0 || verifyAtLevel r 2
  let testLTR  := r.pLevelBits &&& 2 = 0 || verifyAtLevel r 0
  let testRTL  := r.pLevelBits &&& 4 = 0 || verifyAtLevel r 1
  testAuto && testLTR && testRTL

/-- All bundled UAX #9 BidiTest rows pass conformance. -/
def allRowsPass : Bool := rows.all verifyRow

/-- Index of the first failing row, or `none` if all pass. -/
def firstFailingRow : Option Nat :=
  Id.run do
    for i in [0:rows.size] do
      if h : i < rows.size then
        if !verifyRow rows[i] then return some i
    return none

/-- Number of passing rows out of the first `limit`. -/
def countPassing (limit : Nat) : Nat :=
  Id.run do
    let mut count : Nat := 0
    for i in [0:limit] do
      if h : i < rows.size then
        if verifyRow rows[i] then count := count + 1
    return count

/-- **Strict UAX #9 BidiTest conformance.** Every one of the
    490,846 parser-accepted rows of the official `BidiTest.txt`
    test suite produces the exact expected per-codepoint
    embedding levels and L1/L2 reorder array under the bidi
    algorithm. -/
theorem bidi_test_strict_conformance : allRowsPass = true := by
  decide

end Unicode.Conformance.BidiTest
