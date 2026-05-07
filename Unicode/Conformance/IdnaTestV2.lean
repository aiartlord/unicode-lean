/-
  Unicode.Conformance.IdnaTestV2

  UTS #46 conformance against the official `IdnaTestV2.txt` test
  suite. Each test row encodes a source string plus the expected
  results of `toUnicode`, `toAsciiN` (non-transitional), and
  `toAsciiT` (transitional), each paired with a status column
  listing the error codes the implementation should report.

  Format (per the IdnaTestV2.txt header):

      source ; toUnicode ; toUnicodeStatus
             ; toAsciiN  ; toAsciiNStatus
             ; toAsciiT  ; toAsciiTStatus     # comment

  Blank columns inherit from the previous column per the format
  spec; an explicit `""` means the empty string; an explicit `[]`
  means no errors. Source strings may contain `\uXXXX` BMP escapes
  and `\x{XXXXXX}` supplementary escapes.

  This harness verifies our pipeline on rows whose status is empty
  for the relevant operation. Rows with expected error status are
  enumerated separately — they pin down work that remains pending
  on CheckJoiners (CONTEXTJ), CheckBidi, and explicit error
  reporting; reporting their behaviour at all is intentionally
  conservative for now.
-/

import Unicode.Idna.Process

namespace Unicode.Conformance.IdnaTestV2

open Unicode.Idna.Process
open Unicode.Idna.Map (Result)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 ESCAPE DECODING
-- ═══════════════════════════════════════════════════════════════════════════════

/-- One hex-digit value, or `none` if `c` is not a hex digit. -/
def hexDigit? (c : Char) : Option Nat :=
  let n := c.toNat
  if '0'.toNat ≤ n ∧ n ≤ '9'.toNat then some (n - '0'.toNat)
  else if 'a'.toNat ≤ n ∧ n ≤ 'f'.toNat then some (n - 'a'.toNat + 10)
  else if 'A'.toNat ≤ n ∧ n ≤ 'F'.toNat then some (n - 'A'.toNat + 10)
  else none

/-- Parse a leading run of hex digits into a `Nat`, stopping at the
    first non-hex character. -/
def parseHexChars : List Char → Nat → Nat
  | [], acc => acc
  | c :: rest, acc =>
    match hexDigit? c with
    | none   => acc
    | some d => parseHexChars rest (acc * 16 + d)

/-- Decode `\uXXXX` and `\x{XXXXXX}` escapes from `xs`, returning the
    underlying codepoint sequence. Non-escape characters are passed
    through by their `Char.toNat`. The `fuel` parameter is bounded
    by the input length and supplied by the caller. -/
def decodeEscapesGo : Nat → List Char → Array Nat → Array Nat
  | 0,      xs,        acc => Function.const (List Char) acc xs
  | fuel+1, [],        acc => Function.const Nat acc fuel
  | fuel+1, '\\' :: 'u' :: a :: b :: c :: d :: rest, acc =>
    decodeEscapesGo fuel rest (acc.push (parseHexChars [a, b, c, d] 0))
  | fuel+1, '\\' :: 'x' :: '{' :: rest, acc =>
    let (hexs, rest1) := rest.span (· ≠ '}')
    let rest2 := rest1.dropWhile (· = '}')
    decodeEscapesGo fuel rest2 (acc.push (parseHexChars hexs 0))
  | fuel+1, c :: rest, acc =>
    decodeEscapesGo fuel rest (acc.push c.toNat)

/-- Decode all `\uXXXX` and `\x{XXXXXX}` escapes in `s`. -/
def decodeEscapes (s : String) : Array Nat :=
  let xs := s.toList
  decodeEscapesGo (xs.length + 1) xs #[]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 LINE PARSER
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Trim ASCII whitespace from both ends of `s`. -/
def trimAsciiBoth (s : String) : String := (String.trimAscii s).toString

/-- Split a column. Returns `none` for an empty (blank) column,
    `some #[]` for an explicit `""`, otherwise the decoded sequence. -/
def parseField (s : String) : Option (Array Nat) :=
  let t := trimAsciiBoth s
  if t.isEmpty then none
  else if t = "\"\"" then some #[]
  else some (decodeEscapes t)

/-- True iff a status column has any error code. `none` means
    inherit; `some true` means explicit error; `some false` means
    explicit `[]` (no errors). -/
def parseStatus (s : String) : Option Bool :=
  let t := trimAsciiBoth s
  if t.isEmpty then none
  else if t = "[]" then some false
  else some true

structure Row where
  source           : Array Nat
  unicode          : Array Nat
  asciiN           : Array Nat
  asciiT           : Array Nat
  unicodeHasErrors : Bool
  asciiNHasErrors  : Bool
  asciiTHasErrors  : Bool
  deriving Inhabited, Repr

/-- Strip a trailing `# comment` from a line. -/
def stripComment (line : String) : String :=
  (line.takeWhile (· ≠ '#')).toString

/-- Parse a single test row. Returns `none` if the line is a comment,
    is blank, or has fewer than the seven expected columns. -/
def parseRow (rawLine : String) : Option Row :=
  let stripped := stripComment rawLine
  let trimmed := trimAsciiBoth stripped
  if trimmed.isEmpty then none
  else
    let cols : Array String := (stripped.splitOn ";").toArray
    let getCol (i : Nat) : String := (cols[i]?).getD ""
    let c0 := getCol 0
    let c1 := getCol 1
    let c2 := getCol 2
    let c3 := getCol 3
    let c4 := getCol 4
    let c5 := getCol 5
    let c6 := getCol 6
    if cols.size < 4 then none
    else
      let source := (parseField c0).getD #[]
      let unicode := (parseField c1).getD source
      let uniErr := (parseStatus c2).getD false
      let asciiN := (parseField c3).getD unicode
      let asNErr := (parseStatus c4).getD uniErr
      let asciiT := (parseField c5).getD asciiN
      let asTErr := (parseStatus c6).getD asNErr
      some ⟨source, unicode, asciiN, asciiT, uniErr, asNErr, asTErr⟩

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 ROW LOADING
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Raw text of `IdnaTestV2.txt`, embedded at compile time. -/
def idnaTestRaw : String := include_str "../Ucd/IdnaTestV2.txt"

/-- All parsed rows from `IdnaTestV2.txt`. -/
def rows : Array Row :=
  ((idnaTestRaw.splitOn "\n").filterMap parseRow).toArray

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 ROW VERIFICATION
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Per-operation strict check: the pipeline must produce exactly
    the expected codepoint sequence and report errors if and only if
    the spec row records any error codes. UTS #46 §4.5 permits an
    implementation to either reject on error or proceed with errors
    flagged; this harness commits to the latter, so output must
    match in both cases. -/
def verifyOp (expectedHasErrors : Bool) (expected : Array Nat)
    (actual : Result) : Bool :=
  actual.output == expected && actual.hasErrors == expectedHasErrors

/-- Verify a row across all three pipelines (toUnicode, toAscii
    non-transitional, toAscii transitional). -/
def verifyRow (r : Row) : Bool :=
  verifyOp r.unicodeHasErrors r.unicode (toUnicode r.source)
    && verifyOp r.asciiNHasErrors r.asciiN (toAscii r.source)
    && verifyOp r.asciiTHasErrors r.asciiT (toAsciiTransitional r.source)

/-- Number of rows whose strict verification passes (output and
    error-flag must both match). -/
def passingCount : Nat :=
  rows.foldl (fun acc r => if verifyRow r then acc + 1 else acc) 0

/-- Number of rows whose status columns are all empty (no error
    codes expected from any operation). -/
def strictRowCount : Nat :=
  rows.foldl (fun acc r =>
    if !(r.unicodeHasErrors || r.asciiNHasErrors || r.asciiTHasErrors) then
      acc + 1
    else acc) 0

/-- Number of strict (no-error-expected) rows whose verification passes. -/
def strictPassingCount : Nat :=
  rows.foldl (fun acc r =>
    if !(r.unicodeHasErrors || r.asciiNHasErrors || r.asciiTHasErrors)
      && verifyRow r then acc + 1 else acc) 0

/-- Number of rows that report any expected errors. -/
def errorRowCount : Nat :=
  rows.foldl (fun acc r =>
    if r.unicodeHasErrors || r.asciiNHasErrors || r.asciiTHasErrors then
      acc + 1
    else acc) 0

/-- Number of error-expected rows whose verification passes. -/
def errorPassingCount : Nat :=
  rows.foldl (fun acc r =>
    if (r.unicodeHasErrors || r.asciiNHasErrors || r.asciiTHasErrors)
      && verifyRow r then acc + 1 else acc) 0

/-- Index of the first row that fails strict verification. -/
def firstFailing : Option Nat := Id.run do
  for h : i in [0:rows.size] do
    if !verifyRow rows[i] then return some i
  return none

/-- Per-operation failure breakdown for a single `Row`: each field
    flags whether the corresponding pipeline (toUnicode / toAsciiN /
    toAsciiT) had an output mismatch or a `hasErrors` mismatch
    against the test row. -/
structure OpFailures where
  uOutMis  : Bool
  uErrMis  : Bool
  anOutMis : Bool
  anErrMis : Bool
  atOutMis : Bool
  atErrMis : Bool

def opFailureBreakdown (r : Row) : OpFailures :=
  let uni   := toUnicode r.source
  let an    := toAscii r.source
  let atr   := toAsciiTransitional r.source
  { uOutMis  := uni.output    != r.unicode
    uErrMis  := uni.hasErrors != r.unicodeHasErrors
    anOutMis := an.output     != r.asciiN
    anErrMis := an.hasErrors  != r.asciiNHasErrors
    atOutMis := atr.output    != r.asciiT
    atErrMis := atr.hasErrors != r.asciiTHasErrors }

/-- Count rows where any pipeline's output mismatched. -/
def outputMismatchCount : Nat :=
  rows.foldl (fun acc r =>
    let f := opFailureBreakdown r
    if f.uOutMis || f.anOutMis || f.atOutMis then acc + 1 else acc) 0

/-- Count rows where every pipeline's output matched but at least
    one `hasErrors` flag mismatched. The "pure error-detection
    miss" subset — output is right, the gap is in error reporting. -/
def errorOnlyMismatchCount : Nat :=
  rows.foldl (fun acc r =>
    let f := opFailureBreakdown r
    if !f.uOutMis && !f.anOutMis && !f.atOutMis
        && (f.uErrMis || f.anErrMis || f.atErrMis) then acc + 1 else acc) 0

/-- Count rows where toUnicode hasErrors mismatched. -/
def unicodeErrMismatchCount : Nat :=
  rows.foldl (fun acc r =>
    if (opFailureBreakdown r).uErrMis then acc + 1 else acc) 0

/-- Count rows where toAsciiN hasErrors mismatched. -/
def asciiNErrMismatchCount : Nat :=
  rows.foldl (fun acc r =>
    if (opFailureBreakdown r).anErrMis then acc + 1 else acc) 0

/-- Count rows where toAsciiT hasErrors mismatched. -/
def asciiTErrMismatchCount : Nat :=
  rows.foldl (fun acc r =>
    if (opFailureBreakdown r).atErrMis then acc + 1 else acc) 0

#eval s!"total rows: {rows.size}"
#eval s!"strict (no-error) rows: {strictRowCount}"
#eval s!"strict passing: {strictPassingCount}"
#eval s!"error-expected rows: {errorRowCount}"
#eval s!"error-expected passing: {errorPassingCount}"
#eval s!"all passing: {passingCount}"
#eval s!"output-mismatch rows: {outputMismatchCount}"
#eval s!"errors-only-mismatch rows: {errorOnlyMismatchCount}"
#eval s!"  unicode err mismatch: {unicodeErrMismatchCount}"
#eval s!"  asciiN err mismatch:  {asciiNErrMismatchCount}"
#eval s!"  asciiT err mismatch:  {asciiTErrMismatchCount}"
#eval s!"first failing row: {firstFailing}"
#eval match firstFailing with
      | none => "no failures"
      | some i =>
        if h : i < rows.size then
          let r := rows[i]
          s!"row {i}:\n  source            = {r.source}\n  expected unicode  = {r.unicode}  errors? {r.unicodeHasErrors}\n  got unicode       = {toUnicode r.source}\n  expected asciiN   = {r.asciiN}  errors? {r.asciiNHasErrors}\n  got asciiN        = {toAscii r.source}\n  expected asciiT   = {r.asciiT}  errors? {r.asciiTHasErrors}\n  got asciiT        = {toAsciiTransitional r.source}"
        else "row index out of bounds"

end Unicode.Conformance.IdnaTestV2
