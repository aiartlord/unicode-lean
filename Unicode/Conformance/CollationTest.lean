/-
  Unicode.Conformance.CollationTest

  Conformance against UCA 16.0.0's `CollationTest_NON_IGNORABLE*.txt`
  and `CollationTest_SHIFTED*.txt` files. Upstream ships each test in
  two forms with identical row content but different annotation:

    * `*_SHORT.txt` — one hex codepoint sequence per row, no
                      annotation. ~206k rows (NON_IGNORABLE) and
                      ~228k rows (SHIFTED).
    * `*.txt`       — same rows plus an inline expected sort key
                      after `#` in the form
                      `[<L1> | <L2> | <L3> [| <L4>] |]`. The hex
                      groups give the spec-blessed weights at each
                      level and let an implementation be checked
                      byte-equal against the spec, not just ordered.

  Two policies are checked:

    * NON_IGNORABLE — variable elements keep their primary weights.
    * SHIFTED       — variable elements have L1/L2/L3 zeroed and
                      their primary demoted to L4.

  Four theorems close the file via `native_decide`:

    1. `nonIgnorable_conformance` — adjacent ordering on the SHORT
       NON_IGNORABLE file (every adjacent pair `(rows[i], rows[i+1])`
       satisfies `sortKey(rows[i]) ≤ sortKey(rows[i+1])`).
    2. `shifted_conformance` — same, on the SHORT SHIFTED file.
    3. `nonIgnorable_sortkey_full_conformance` — for every row of the
       FULL NON_IGNORABLE file, our `sortKey .nonIgnorable` output is
       byte-equal to the expected key parsed from the row's
       `[| ... |]` annotation. Strictly stronger than (1).
    4. `shifted_sortkey_full_conformance` — same, on the FULL SHIFTED
       file. Strictly stronger than (2).

  Theorems (1)/(2) and (3)/(4) verify the same conformance through
  independent paths: ordering vs byte-exact equality. Together they
  pin our `Uca.SortKey` to the UCA spec at both an algebraic
  (lexicographic ordering) and representational (per-level weight)
  level.
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

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 FULL-FORMAT BYTE-EQUAL CONFORMANCE
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Parse the inline weights segment of a FULL-format row — a string
    of the form `<L1> | <L2> | ... | <Lₙ> |` — into the flat
    representation produced by `sortKey`: each level's weights, in
    order, joined by the separator `0` between levels. The trailing
    `|` produces an empty trailing segment that is dropped before
    joining. Empty levels (e.g. an empty L1 for combining-mark-only
    rows) are preserved as zero-length segments between separators,
    exactly as `sortKey` would emit them. -/
def flattenLevels (s : String) : Array Nat := Id.run do
  let segments := s.splitOn "|"
  let levels := segments.dropLast
  let mut acc : Array Nat := #[]
  let mut first : Bool := true
  for seg in levels do
    if first then first := false else acc := acc.push sep
    for tok in seg.splitOn " " do
      let t := trimS tok
      if !t.isEmpty then acc := acc.push (parseHex t)
  return acc

/-- Parse one FULL-format row into `(codepoints, expectedFlatKey)`.
    The expected key is in the same flat-`Array Nat` shape returned by
    `sortKey`, so byte-equality can be checked with `==` directly.

    The line shape is:
      `<cps>;\t# <name>\t[<L1> | <L2> | <L3> [| <L4>] |]`

    The inline-weights block is identified as the LAST `[...]` group
    on the line — not the first. This sidesteps the trap where the
    first `[` is inside a `(<glyph>)` comment (e.g. U+005B's LEFT
    SQUARE BRACKET shows the literal `[` in its glyph-quote).

    Returns `none` for blank, comment, or otherwise non-FULL lines. -/
def parseFullRow (rawLine : String) : Option (Array Nat × Array Nat) :=
  let line := trimS rawLine
  if line.isEmpty then none
  else if line.startsWith "#" then none
  else if !line.contains ';' then none
  else if !line.contains '[' ∨ !line.contains ']' then none
  else
    let cpsField := (line.takeWhile (· ≠ ';')).toString
    let cps := ((cpsField.splitOn " ").filterMap (fun tok =>
      let t := trimS tok
      if t.isEmpty then none else some (parseHex t))).toArray
    if cps.isEmpty then none else
    let afterLastOpen := (line.splitOn "[").getLast?.getD ""
    let inside := (afterLastOpen.splitOn "]").head?.getD ""
    some (cps, flattenLevels inside)

/-- Raw text of the FULL NON_IGNORABLE conformance file. -/
def rawNonIgnorableFull : String :=
  include_str "../Ucd/CollationTest_NON_IGNORABLE.txt"

/-- Raw text of the FULL SHIFTED conformance file. -/
def rawShiftedFull : String :=
  include_str "../Ucd/CollationTest_SHIFTED.txt"

/-- All `(codepoints, expectedKey)` pairs from the FULL NON_IGNORABLE
    file. -/
def fullNonIgnorableRows : Array (Array Nat × Array Nat) :=
  ((rawNonIgnorableFull.splitOn "\n").filterMap parseFullRow).toArray

/-- All `(codepoints, expectedKey)` pairs from the FULL SHIFTED
    file. -/
def fullShiftedRows : Array (Array Nat × Array Nat) :=
  ((rawShiftedFull.splitOn "\n").filterMap parseFullRow).toArray

/-- True iff our `sortKey .nonIgnorable cps` is byte-equal to the
    expected key for every FULL NON_IGNORABLE row. -/
def nonIgnorableSortKeyMatches : Bool :=
  fullNonIgnorableRows.all (fun pair =>
    sortKey .nonIgnorable pair.1 == pair.2)

/-- True iff our `sortKey .shifted cps` is byte-equal to the expected
    key for every FULL SHIFTED row. -/
def shiftedSortKeyMatches : Bool :=
  fullShiftedRows.all (fun pair =>
    sortKey .shifted pair.1 == pair.2)

/-- Every row of the official UCA NON_IGNORABLE conformance file
    (FULL form) produces a sort key byte-equal to the expected
    `[L1 ‖ 0 ‖ L2 ‖ 0 ‖ L3]` weights given inline in the spec. -/
theorem nonIgnorable_sortkey_full_conformance :
    nonIgnorableSortKeyMatches = true := by native_decide

/-- Every row of the official UCA SHIFTED conformance file (FULL
    form) produces a sort key byte-equal to the expected
    `[L1 ‖ 0 ‖ L2 ‖ 0 ‖ L3 ‖ 0 ‖ L4]` weights given inline in the
    spec. -/
theorem shifted_sortkey_full_conformance :
    shiftedSortKeyMatches = true := by native_decide

end Unicode.Conformance.CollationTest
