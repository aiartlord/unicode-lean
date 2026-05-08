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
  /-- Indices of the first 10 failing rows in source order. -/
  firstTenFailingRows      : Array Nat
  /-- Indices of the first 10 rows where output mismatched
      (subset of `firstTenFailingRows`). -/
  firstTenOutputMismatches : Array Nat
  deriving Repr, Inhabited

/-- Compute every summary metric in a single fold over `rows`. -/
def computeSummary : Summary := Id.run do
  let mut total                  : Nat := rows.size
  let mut strictTotal            : Nat := 0
  let mut strictPass             : Nat := 0
  let mut errorTotal             : Nat := 0
  let mut errorPass              : Nat := 0
  let mut totalPass              : Nat := 0
  let mut outputMis              : Nat := 0
  let mut errorOnlyMis           : Nat := 0
  let mut uniErrMis              : Nat := 0
  let mut anErrMis               : Nat := 0
  let mut atErrMis               : Nat := 0
  let mut firstTen               : Array Nat := #[]
  let mut firstTenOut            : Array Nat := #[]
  for h : i in [0:rows.size] do
    let r := rows[i]
    let isStrict :=
      ! (r.unicodeHasErrors || r.asciiNHasErrors || r.asciiTHasErrors)
    if isStrict then strictTotal := strictTotal + 1
    else errorTotal := errorTotal + 1
    let f := opFailureBreakdown r
    let outBad := f.uOutMis || f.anOutMis || f.atOutMis
    let errBad := f.uErrMis || f.anErrMis || f.atErrMis
    let rowBad := outBad || errBad
    if ! rowBad then
      totalPass := totalPass + 1
      if isStrict then strictPass := strictPass + 1
      else errorPass := errorPass + 1
    else
      if firstTen.size < 10 then firstTen := firstTen.push i
    if outBad then
      outputMis := outputMis + 1
      if firstTenOut.size < 10 then firstTenOut := firstTenOut.push i
    else if errBad then
      errorOnlyMis := errorOnlyMis + 1
    if f.uErrMis  then uniErrMis := uniErrMis + 1
    if f.anErrMis then anErrMis := anErrMis + 1
    if f.atErrMis then atErrMis := atErrMis + 1
  return
    { total                    := total
      strictRowCount           := strictTotal
      strictPassingCount       := strictPass
      errorRowCount            := errorTotal
      errorPassingCount        := errorPass
      passingCount             := totalPass
      outputMismatchCount      := outputMis
      errorOnlyMismatchCount   := errorOnlyMis
      unicodeErrMismatchCount  := uniErrMis
      asciiNErrMismatchCount   := anErrMis
      asciiTErrMismatchCount   := atErrMis
      firstTenFailingRows      := firstTen
      firstTenOutputMismatches := firstTenOut }

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

#eval s!"total rows: {summary.total}"
#eval s!"strict (no-error) rows: {summary.strictRowCount}"
#eval s!"strict passing: {summary.strictPassingCount}"
#eval s!"error-expected rows: {summary.errorRowCount}"
#eval s!"error-expected passing: {summary.errorPassingCount}"
#eval s!"all passing: {summary.passingCount}"
#eval s!"output-mismatch rows: {summary.outputMismatchCount}"
#eval s!"errors-only-mismatch rows: {summary.errorOnlyMismatchCount}"
#eval s!"  unicode err mismatch: {summary.unicodeErrMismatchCount}"
#eval s!"  asciiN err mismatch:  {summary.asciiNErrMismatchCount}"
#eval s!"  asciiT err mismatch:  {summary.asciiTErrMismatchCount}"

#eval s!"first 10 output mismatches: {summary.firstTenOutputMismatches}"
#eval String.intercalate "\n"
        (summary.firstTenOutputMismatches.toList.map diagnosticFor)

#eval s!"first 10 failing rows: {summary.firstTenFailingRows}"
#eval String.intercalate "\n"
        (summary.firstTenFailingRows.toList.map diagnosticFor)

end Unicode.Conformance.IdnaTestV2
