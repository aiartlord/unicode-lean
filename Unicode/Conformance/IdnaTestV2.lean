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
    the expected codepoint sequence and report errors iff the
    spec row records any error codes. UTS #46 §4.5 permits an
    implementation to either reject on error or proceed with
    errors flagged; this harness commits to the latter. -/
def verifyOp (expectedHasErrors : Bool) (expected : Array Nat)
    (actual : Result) : Bool :=
  actual.output == expected && actual.hasErrors == expectedHasErrors

/-- Per-operation failure breakdown for a single `Row`. -/
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

/-- Aggregated metrics across all rows. Computed in a single fold
    so the conformance build avoids re-running the per-row
    pipeline-trio nine times (once per metric). -/
structure Summary where
  total                    : Nat
  strictRowCount           : Nat
  strictPassingCount       : Nat
  errorRowCount            : Nat
  errorPassingCount        : Nat
  passingCount             : Nat
  outputMismatchCount      : Nat
  errorOnlyMismatchCount   : Nat
  unicodeErrMismatchCount  : Nat
  asciiNErrMismatchCount   : Nat
  asciiTErrMismatchCount   : Nat
  /-- All failing-row indices in source order. -/
  allFailingRows           : Array Nat
  /-- All rows where output mismatched (subset of allFailingRows). -/
  allOutputMismatches      : Array Nat
  deriving Repr, Inhabited

/-- Mutable accumulator state for the single-pass summary fold. -/
private structure Acc where
  index             : Nat
  total             : Nat
  strictTotal       : Nat
  strictPass        : Nat
  errorTotal        : Nat
  errorPass         : Nat
  totalPass         : Nat
  outputMis         : Nat
  errorOnlyMis      : Nat
  uniErrMis         : Nat
  anErrMis          : Nat
  atErrMis          : Nat
  allFailing        : Array Nat
  allOutput         : Array Nat
  deriving Inhabited

/-- Step the accumulator through one row. -/
private def stepAcc (acc : Acc) (r : Row) : Acc :=
  let i := acc.index
  let isStrict :=
    ! (r.unicodeHasErrors || r.asciiNHasErrors || r.asciiTHasErrors)
  let strictTotal' := if isStrict then acc.strictTotal + 1 else acc.strictTotal
  let errorTotal'  := if isStrict then acc.errorTotal else acc.errorTotal + 1
  let f := opFailureBreakdown r
  let outBad := f.uOutMis || f.anOutMis || f.atOutMis
  let errBad := f.uErrMis || f.anErrMis || f.atErrMis
  let rowBad := outBad || errBad
  let totalPass'  := if rowBad then acc.totalPass else acc.totalPass + 1
  let strictPass' := if !rowBad ∧ isStrict
                      then acc.strictPass + 1 else acc.strictPass
  let errorPass'  := if !rowBad ∧ !isStrict
                      then acc.errorPass + 1 else acc.errorPass
  let allFailing' := if rowBad then acc.allFailing.push i else acc.allFailing
  let outputMis'  := if outBad then acc.outputMis + 1 else acc.outputMis
  let allOutput'  := if outBad then acc.allOutput.push i else acc.allOutput
  let errorOnlyMis' := if !outBad ∧ errBad
                        then acc.errorOnlyMis + 1 else acc.errorOnlyMis
  let uniErrMis' := if f.uErrMis then acc.uniErrMis + 1 else acc.uniErrMis
  let anErrMis'  := if f.anErrMis then acc.anErrMis + 1 else acc.anErrMis
  let atErrMis'  := if f.atErrMis then acc.atErrMis + 1 else acc.atErrMis
  { index        := i + 1
    total        := acc.total + 1
    strictTotal  := strictTotal'
    strictPass   := strictPass'
    errorTotal   := errorTotal'
    errorPass    := errorPass'
    totalPass    := totalPass'
    outputMis    := outputMis'
    errorOnlyMis := errorOnlyMis'
    uniErrMis    := uniErrMis'
    anErrMis     := anErrMis'
    atErrMis     := atErrMis'
    allFailing   := allFailing'
    allOutput    := allOutput' }

/-- Compute every summary metric in a single fold over `rows`. -/
def computeSummary : Summary :=
  let initial : Acc :=
    { index := 0, total := 0, strictTotal := 0, strictPass := 0
      errorTotal := 0, errorPass := 0, totalPass := 0
      outputMis := 0, errorOnlyMis := 0
      uniErrMis := 0, anErrMis := 0, atErrMis := 0
      allFailing := #[], allOutput := #[] }
  let final := rows.foldl stepAcc initial
  { total                    := final.total
    strictRowCount           := final.strictTotal
    strictPassingCount       := final.strictPass
    errorRowCount            := final.errorTotal
    errorPassingCount        := final.errorPass
    passingCount             := final.totalPass
    outputMismatchCount      := final.outputMis
    errorOnlyMismatchCount   := final.errorOnlyMis
    unicodeErrMismatchCount  := final.uniErrMis
    asciiNErrMismatchCount   := final.anErrMis
    asciiTErrMismatchCount   := final.atErrMis
    allFailingRows           := final.allFailing
    allOutputMismatches      := final.allOutput }

/-- The single shared computation; downstream `#eval`s project from
    here so the heavy fold runs once. -/
def summary : Summary := computeSummary

/-- Pretty-print one failing row's diagnostic info. -/
def diagnosticFor (i : Nat) : String :=
  if h : i < rows.size then
    let r := rows[i]
    let uni := toUnicode r.source
    let an  := toAscii r.source
    let atr := toAsciiTransitional r.source
    s!"row {i}: src={r.source}\n" ++
    s!"  toU exp={r.unicode} err?{r.unicodeHasErrors}  got out={uni.output} err?{uni.hasErrors}\n" ++
    s!"  toAN exp={r.asciiN} err?{r.asciiNHasErrors}  got out={an.output} err?{an.hasErrors}\n" ++
    s!"  toAT exp={r.asciiT} err?{r.asciiTHasErrors}  got out={atr.output} err?{atr.hasErrors}"
  else
    s!"row {i}: out of bounds"

/-- Render the full summary as a multi-line string. Used by the
    out-of-band conformance reporter (`scripts/idna-conformance.sh`)
    so the build itself stays cheap — `summary` is a single fold
    over 6389 rows × 3 pipelines and runs to completion only when
    callers explicitly request the report, not on every CI build. -/
def report : String :=
  let s := summary
  let head :=
    s!"total rows: {s.total}\n" ++
    s!"strict (no-error) rows: {s.strictRowCount}\n" ++
    s!"strict passing: {s.strictPassingCount}\n" ++
    s!"error-expected rows: {s.errorRowCount}\n" ++
    s!"error-expected passing: {s.errorPassingCount}\n" ++
    s!"all passing: {s.passingCount}\n" ++
    s!"output-mismatch rows: {s.outputMismatchCount}\n" ++
    s!"errors-only-mismatch rows: {s.errorOnlyMismatchCount}\n" ++
    s!"  unicode err mismatch: {s.unicodeErrMismatchCount}\n" ++
    s!"  asciiN err mismatch:  {s.asciiNErrMismatchCount}\n" ++
    s!"  asciiT err mismatch:  {s.asciiTErrMismatchCount}\n"
  let outBlock :=
    s!"\nall output mismatches ({s.allOutputMismatches.size}): {s.allOutputMismatches}\n" ++
    String.intercalate "\n" (s.allOutputMismatches.toList.map diagnosticFor)
  let failBlock :=
    s!"\n\nall failing rows ({s.allFailingRows.size}): {s.allFailingRows}\n" ++
    String.intercalate "\n" (s.allFailingRows.toList.map diagnosticFor)
  head ++ outBlock ++ failBlock

end Unicode.Conformance.IdnaTestV2
