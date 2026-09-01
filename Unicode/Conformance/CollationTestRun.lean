/-
  Unicode.Conformance.CollationTestRun

  An evaluated run of the published `CollationTest_*_SHORT.txt` files against
  `Unicode.Uca.SortKey`.

  Each file lists strings already in the order the Unicode Collation Algorithm
  puts them in, one per line as a run of hex codepoints. The conformance
  condition is a statement about adjacent lines: the sort key of a line is less
  than or equal to the sort key of the line beneath it. Judging every adjacent
  pair judges the whole file.

  The two files fix the two variable-handling policies the algorithm exposes to
  the conformance suite. `CollationTest_NON_IGNORABLE_SHORT.txt` is read under
  `nonIgnorable` and `CollationTest_SHIFTED_SHORT.txt` under `shifted`, so a
  policy that produced the right order under one and the wrong order under the
  other is caught.

  The `_SHORT` files carry the same rows as their long counterparts. The long
  files add each row's expected sort key as a trailing comment, which restates
  in the fixture what the algorithm under test computes; the order relation the
  rows are in is the property being checked.
-/

import Unicode.Uca.SortKey

namespace Unicode.Conformance.CollationTestRun

open Unicode.Uca.SortKey

/-- The numeric value of a hexadecimal digit, or `none` for any other
    character. -/
def hexDigit? (c : Char) : Option Nat :=
  let n := c.toNat
  if n ≥ 48 && n ≤ 57 then some (n - 48)
  else if n ≥ 65 && n ≤ 70 then some (n - 55)
  else if n ≥ 97 && n ≤ 102 then some (n - 87)
  else none

/-- A run of hexadecimal digits read as one codepoint, or `none` if the run is
    empty or holds a character that is not a hex digit. -/
def hexField? (field : String) : Option Nat :=
  let cs := field.toList
  if cs.isEmpty then none
  else
    cs.foldl
      (fun acc c => acc.bind fun v => (hexDigit? c).map fun d => v * 16 + d)
      (some 0)

/-- The codepoint sequence a data line states, or `none` if any field on the
    line is not a hexadecimal codepoint. A line that fails to parse is a
    failure of the run rather than a row to pass over. -/
def parseRow? (line : String) : Option (List Nat) :=
  let fields := ((String.trimAscii line).toString.splitOn " ").filter (· ≠ "")
  if fields.isEmpty then none
  else fields.foldr (fun f acc => acc.bind fun rest =>
        (hexField? f).map fun cp => cp :: rest) (some [])

/-- True of the lines that carry a row: the file's comments start with `#` and
    its blank lines separate sections. -/
def isDataLine (line : String) : Bool :=
  let t := (String.trimAscii line).toString
  t ≠ "" && ! t.startsWith "#"

/-- The rows of a corpus, each paired with the line it came from so a row that
    fails to parse is reported with its text. -/
def rowsOf (raw : String) : List (String × Option (List Nat)) :=
  (raw.splitOn "\n").filter isDataLine |>.map (fun l => (l, parseRow? l))

structure Tally where
  passed : Nat := 0
  failed : Nat := 0
  deriving Inhabited

def Tally.add (t : Tally) (ok : Bool) : Tally :=
  if ok then { t with passed := t.passed + 1 } else { t with failed := t.failed + 1 }

def Tally.line (t : Tally) (label : String) : String :=
  s!"  {label}: passed {t.passed}, failed {t.failed}, skipped 0"

/-- Whether the pair `prev`, `curr` is in the order the file asserts under
    `handling`: the sort key of a line is less than or equal to the sort key of
    the line beneath it.

    Equal sort keys satisfy the condition. Two lines can carry the same key and
    still be distinct strings, and the file orders such a group by a criterion
    outside the algorithm, so requiring the codepoint sequences to ascend as
    well would assert more than the corpus states. -/
def pairInOrder (handling : VariableHandling) (prev curr : List Nat) : Bool :=
  ucaCompare handling prev curr != .gt

/-- Judge every adjacent pair of a corpus under `handling`. A line that did not
    parse counts as a failed pair, so the tally's denominator is the number of
    adjacent pairs the file publishes rather than the number that happened to
    read cleanly. -/
def talliesOf (handling : VariableHandling)
    (sample : List (String × Option (List Nat))) : Tally :=
  Prod.snd <| sample.foldl
    (fun (acc : Option (List Nat) × Tally) row =>
      let (prev, t) := acc
      match row.snd with
      | none => (none, t.add false)
      | some cps =>
        match prev with
        | none      => (some cps, t)
        | some before => (some cps, t.add (pairInOrder handling before cps)))
    (none, {})

/-- Index of the first adjacent pair that is out of order, counting from the
    first row of the corpus. -/
def firstFailIdxOf (handling : VariableHandling)
    (sample : List (String × Option (List Nat))) : Option Nat :=
  Prod.snd <| Prod.fst <| sample.foldl
    (fun (acc : (Nat × Option Nat) × Option (List Nat)) row =>
      let ((i, found), prev) := acc
      if found.isSome then ((i + 1, found), prev)
      else
        match row.snd with
        | none => ((i + 1, some i), none)
        | some cps =>
          match prev with
          | none        => ((i + 1, none), some cps)
          | some before =>
            if pairInOrder handling before cps then ((i + 1, none), some cps)
            else ((i + 1, some i), some cps))
    ((0, none), none)

def nonIgnorableRaw : String :=
  include_str "../Ucd/CollationTest_NON_IGNORABLE_SHORT.txt"

def shiftedRaw : String :=
  include_str "../Ucd/CollationTest_SHIFTED_SHORT.txt"

def nonIgnorableRows : List (String × Option (List Nat)) := rowsOf nonIgnorableRaw

def shiftedRows : List (String × Option (List Nat)) := rowsOf shiftedRaw

/-- The number of adjacent pairs a corpus of `n` rows publishes. -/
def pairCount (n : Nat) : Nat := n - 1

def reportOne (label : String) (handling : VariableHandling)
    (sample : List (String × Option (List Nat))) (published : Nat) : String :=
  let t := talliesOf handling sample
  let head :=
    s!"{label}: {pairCount sample.length} adjacent pairs judged of " ++
    s!"{pairCount published} published"
  match firstFailIdxOf handling sample with
  | none   => head ++ "\n" ++ t.line "order"
  | some i => head ++ "\n" ++ t.line "order" ++ s!"\n  first out-of-order row index: {i}"

def nonIgnorableReport : String :=
  reportOne "CollationTest_NON_IGNORABLE" .nonIgnorable nonIgnorableRows
    nonIgnorableRows.length

def shiftedReport : String :=
  reportOne "CollationTest_SHIFTED" .shifted shiftedRows shiftedRows.length

def nonIgnorableReportFirst (n : Nat) : String :=
  reportOne "CollationTest_NON_IGNORABLE" .nonIgnorable (nonIgnorableRows.take n)
    nonIgnorableRows.length

def shiftedReportFirst (n : Nat) : String :=
  reportOne "CollationTest_SHIFTED" .shifted (shiftedRows.take n) shiftedRows.length

def report : String := nonIgnorableReport ++ "\n" ++ shiftedReport

/-- The verdict of a run over `sample` under `handling`: the pairs judged, the
    pairs that held, and the pairs that did not. `scripts/conformance-execute.sh`
    reads these three numbers into `fixtures/conformance/executed-runs.json`
    beside the SHA-256 of the file they were taken from.

    This suite records its run rather than elaborating it. The sibling suites
    close a `#eval` gate over their whole corpus during the build, which costs
    seconds to a couple of minutes each. A collation pair carries an NFD pass
    and a DUCET collation-element walk before its sort key exists, and the two
    files publish 437,928 pairs between them, which is hours rather than
    minutes — long enough that putting it in the build would stop the build
    being run. The digest is what keeps the record honest: `conformance-run.py`
    drops a record whose corpus no longer hashes to the file it was taken
    against, so a regenerated or upgraded corpus invalidates the pass instead
    of inheriting it. -/
def verdictOf (handling : VariableHandling)
    (sample : List (String × Option (List Nat))) : Nat × Nat × Nat :=
  let t := talliesOf handling sample
  (pairCount sample.length, t.passed, t.failed)

/-- The two runs as `scripts/conformance-execute.sh` reads them, one line each:
    the suite name, the pairs judged, the pairs that held, the pairs that did
    not. -/
def executedReport : String :=
  let (nonIgnorableJudged, nonIgnorablePassed, nonIgnorableFailed) :=
    verdictOf .nonIgnorable nonIgnorableRows
  let (shiftedJudged, shiftedPassed, shiftedFailed) :=
    verdictOf .shifted shiftedRows
  s!"CollationTest_NON_IGNORABLE_SHORT {nonIgnorableJudged} " ++
  s!"{nonIgnorablePassed} {nonIgnorableFailed}\n" ++
  s!"CollationTest_SHIFTED_SHORT {shiftedJudged} {shiftedPassed} {shiftedFailed}"

-- ═══════════════════════════════════════════════════════════════════════════
-- §2 THE RUN, REPORTED AS IT GOES
-- ═══════════════════════════════════════════════════════════════════════════

/-- Sum of two tallies, for combining the chunks of one corpus. -/
def Tally.append (a b : Tally) : Tally :=
  { passed := a.passed + b.passed, failed := a.failed + b.failed }

/-- Judge `rows` in chunks of `chunk` rows, printing a line as each completes,
    and return the tally over the whole corpus.

    `executedReport` computes the same numbers as one pure value, which prints
    only once the last pair is judged. Over corpora this size that is hours of
    silence, during which a run that has died and a run that is working look
    identical, and a death discards every pair already judged rather than
    naming the chunk to resume from. Reporting per chunk costs nothing and
    answers both.

    Consecutive chunks overlap by one row so the pair straddling a boundary is
    judged exactly once: a chunk of `chunk` rows starting at `offset` covers
    the pairs `offset..offset+chunk`, and the next starts at `offset+chunk`. -/
partial def runChunked (handling : VariableHandling) (label : String)
    (rows : List (String × Option (List Nat))) (chunk : Nat) : IO Tally := do
  let total := pairCount rows.length
  let mut acc : Tally := {}
  let mut offset : Nat := 0
  while offset < total do
    let slice := (rows.drop offset).take (chunk + 1)
    let t := talliesOf handling slice
    acc := acc.append t
    offset := offset + chunk
    let done := min offset total
    IO.println
      s!"  {label}: {done}/{total} pairs, passed {acc.passed}, failed {acc.failed}"
    let stdout ← IO.getStdout
    stdout.flush
  return acc

/-- Fold both corpora, reporting progress, and print the two record lines
    `scripts/conformance-execute.sh` parses.

    The record lines are printed last and are the only lines with four
    whitespace-separated fields, so the progress lines above them cannot be
    mistaken for a result. -/
def executeReporting (chunk : Nat) : IO Unit := do
  IO.println s!"folding CollationTest_NON_IGNORABLE_SHORT in chunks of {chunk}"
  let nonIgnorableT ← runChunked .nonIgnorable "NON_IGNORABLE" nonIgnorableRows chunk
  IO.println s!"folding CollationTest_SHIFTED_SHORT in chunks of {chunk}"
  let shiftedT ← runChunked .shifted "SHIFTED" shiftedRows chunk
  IO.println
    (s!"CollationTest_NON_IGNORABLE_SHORT {pairCount nonIgnorableRows.length} " ++
     s!"{nonIgnorableT.passed} {nonIgnorableT.failed}")
  IO.println
    (s!"CollationTest_SHIFTED_SHORT {pairCount shiftedRows.length} " ++
     s!"{shiftedT.passed} {shiftedT.failed}")

end Unicode.Conformance.CollationTestRun
