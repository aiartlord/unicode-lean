/-
  Unicode.Conformance.CollationTest

  Conformance against UCA 16.0.0's CollationTest_*_SHORT.txt files.
  Each non-blank, non-comment line is a sequence of hex codepoints
  representing one test string. The conformance invariant: for every
  adjacent pair `(rows[i], rows[i+1])` we must have
  `sortKey(rows[i]) ≤ sortKey(rows[i+1])` under the policy named in
  the filename.

  Two policies are checked:

    * NON_IGNORABLE — variable elements keep their primary weights.
    * SHIFTED       — variable elements have L1 zeroed and are
                      tracked at L4 instead.

  The full-file theorems compile via `native_decide`, mirroring the
  BidiTest / LineBreakTest / WordBreakTest / SentenceBreakTest /
  GraphemeBreakTest pattern.
-/

import Unicode.Uca.SortKey

namespace Unicode.Conformance.CollationTest

open Unicode.Uca.SortKey

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 LINE PARSER
-- ═══════════════════════════════════════════════════════════════════════════════

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

/-- Strip a trailing `# comment` from a line. -/
def stripComment (line : String) : String :=
  (line.takeWhile (· ≠ '#')).toString

/-- Parse one row: a sequence of space-separated hex codepoints.
    Returns `none` for blank, comment, or directive lines. -/
def parseRow (rawLine : String) : Option (Array Nat) :=
  let stripped := stripComment rawLine
  let trimmed := trimS stripped
  if trimmed.isEmpty then none
  else
    let toks := (stripped.splitOn " ").filterMap (fun tok =>
      let t := trimS tok
      if t.isEmpty then none else some (parseHex t))
    if toks.isEmpty then none else some toks.toArray

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 ROW LOADING
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Raw text of the NON_IGNORABLE conformance file. -/
def rawNonIgnorable : String := include_str "../Ucd/CollationTest_NON_IGNORABLE_SHORT.txt"

/-- Raw text of the SHIFTED conformance file. -/
def rawShifted : String := include_str "../Ucd/CollationTest_SHIFTED_SHORT.txt"

/-- All parsed rows from the NON_IGNORABLE conformance file. -/
def rowsNonIgnorable : Array (Array Nat) :=
  ((rawNonIgnorable.splitOn "\n").filterMap parseRow).toArray

/-- All parsed rows from the SHIFTED conformance file. -/
def rowsShifted : Array (Array Nat) :=
  ((rawShifted.splitOn "\n").filterMap parseRow).toArray

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 VERIFICATION
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `sortKey(a) ≤ sortKey(b)` under the chosen policy. -/
def pairOk (handling : VariableHandling) (a b : Array Nat) : Bool :=
  match ucaCompare handling a b with
  | .lt => true
  | .eq => true
  | .gt => false

/-- True iff every adjacent pair in `rows` is ordered. -/
def adjacentOrdered (handling : VariableHandling) (rows : Array (Array Nat)) :
    Bool := Id.run do
  let n := rows.size
  if n ≤ 1 then return true
  for i in [0:n - 1] do
    if hi : i < n ∧ i + 1 < n then
      if !pairOk handling (rows[i]'hi.1) (rows[i + 1]'hi.2) then
        return false
  return true

/-- Index of the first adjacent pair that fails ordering, or `none`. -/
def firstFailingPair (handling : VariableHandling) (rows : Array (Array Nat)) :
    Option Nat := Id.run do
  let n := rows.size
  if n ≤ 1 then return none
  for i in [0:n - 1] do
    if hi : i < n ∧ i + 1 < n then
      if !pairOk handling (rows[i]'hi.1) (rows[i + 1]'hi.2) then
        return some i
  return none

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 BOOLEAN ENTRY POINTS  (closed by `native_decide`)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff the entire NON_IGNORABLE test file sorts correctly under
    our `sortKey .nonIgnorable` implementation. -/
def nonIgnorableOrdered : Bool := adjacentOrdered .nonIgnorable rowsNonIgnorable

/-- True iff the entire SHIFTED test file sorts correctly under our
    `sortKey .shifted` implementation. -/
def shiftedOrdered : Bool := adjacentOrdered .shifted rowsShifted

/-- Convenience: ordering of the first `n` rows of the NON_IGNORABLE
    file. Used to bisect a partial failure of `nonIgnorableOrdered`. -/
def nonIgnorableOrderedFirstN (n : Nat) : Bool :=
  adjacentOrdered .nonIgnorable (rowsNonIgnorable.extract 0 n)

/-- Convenience: ordering of the first `n` rows of the SHIFTED file. -/
def shiftedOrderedFirstN (n : Nat) : Bool :=
  adjacentOrdered .shifted (rowsShifted.extract 0 n)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 SMOKE TESTS  (small slices — fast feedback that the pipeline runs)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Every adjacent pair in the official UCA NON_IGNORABLE conformance
    file sorts correctly under our `sortKey .nonIgnorable`. -/
theorem nonIgnorable_conformance : nonIgnorableOrdered = true := by native_decide

/-- Every adjacent pair in the official UCA SHIFTED conformance file
    sorts correctly under our `sortKey .shifted`. -/
theorem shifted_conformance : shiftedOrdered = true := by native_decide

end Unicode.Conformance.CollationTest
