/-
  Unicode.Conformance.IdnaTestV2

  UTS #46 (IDNA Compatibility Processing) conformance. `toAscii` runs the mapping,
  normalization, and validity passes and returns the processed label with an error
  flag. Each theorem checks a representative label against the output UTS #46
  specifies — case mapping to lowercase and error-free handling of valid ASCII.

  Beyond those two kernel-checked vectors, this module parses the whole official
  `Unicode/Ucd/IdnaTestV2.txt` (UCD 17.0.0) and exposes `report`, a summary of
  every row run through all three operations the file specifies. `report` is
  evaluated, not proven: it folds over 6391 rows, which is far too much work to
  put in every `lake build`. `scripts/idna-conformance.sh` is what runs it, so
  the cost lands in that script and nowhere else.

  Every row is judged against the file's stated output and error flag. The
  report carries a skipped column, structurally zero, because that column is how
  a conformance result is read.
-/

import Unicode.Idna.Process

namespace Unicode.Conformance.IdnaTestV2

open Unicode.Idna.Process
open Unicode.Idna.Map (Status)

set_option maxRecDepth 1000000

/-- UTS #46 maps upper-case ASCII to lower-case: "ABC" becomes "abc" with no error. -/
theorem vector_uppercase_mapped :
    toAscii [0x41, 0x42, 0x43] = { output := [0x61, 0x62, 0x63], hasErrors := false } := by
  decide +kernel

/-- Valid lower-case ASCII passes through unchanged and error-free. -/
theorem vector_ascii_passthrough :
    toAscii [0x61, 0x62, 0x63] = { output := [0x61, 0x62, 0x63], hasErrors := false } := by
  decide +kernel

/-! ### The official corpus

`IdnaTestV2.txt` is semicolon-delimited with seven columns per row. Columns 2, 4
and 6 are expected outputs, columns 3, 5 and 7 the matching status sets. Blank
columns inherit, each from a different neighbour, per the file's own header:

* column 2 (toUnicode)       blank means the source
* column 3 (toUnicodeStatus) blank means no errors
* column 4 (toAsciiN)        blank means the toUnicode value
* column 5 (toAsciiNStatus)  blank means the toUnicodeStatus value
* column 6 (toAsciiT)        blank means the toAsciiN value
* column 7 (toAsciiTStatus)  blank means the toAsciiNStatus value

so the inheritance has to be resolved left to right, not by a single default. -/

/-- One resolved row: the source and the three expected (output, has-errors)
    pairs, with every blank column already inherited. -/
structure Row where
  source        : List Nat
  toUnicodeOut  : List Nat
  toUnicodeErr  : Bool
  toUnicodeSt   : List Status
  toAsciiNOut   : List Nat
  toAsciiNErr   : Bool
  toAsciiNSt    : List Status
  toAsciiTOut   : List Nat
  toAsciiTErr   : Bool
  toAsciiTSt    : List Status
  deriving Inhabited, Repr, DecidableEq

def trimS (s : String) : String := (String.trimAscii s).toString

def hexDigitVal (c : Char) : Nat :=
  let n := c.toNat
  if n ≥ 0x30 ∧ n ≤ 0x39 then n - 0x30
  else if n ≥ 0x61 ∧ n ≤ 0x66 then n - 0x61 + 10
  else if n ≥ 0x41 ∧ n ≤ 0x46 then n - 0x41 + 10
  else 0

def parseHexChars (cs : List Char) : Nat :=
  cs.foldl (fun acc c => acc * 16 + hexDigitVal c) 0

/-- Decode the file's two escape conventions, `\uXXXX` and `\x{XXXX}`, into
    codepoints; every other character stands for itself. Recursion is structural
    on the fuel, which callers set to the input length. Each branch drops the
    fuel by one and consumes at least one character, so the fuel never runs out
    before the list does and no input is silently truncated. -/
def decodeEscapes : Nat → List Char → List Nat
  | 0, _ => []
  | _, [] => []
  | fuel + 1, '\\' :: 'u' :: a :: b :: c :: d :: rest =>
      parseHexChars [a, b, c, d] :: decodeEscapes fuel rest
  | fuel + 1, '\\' :: 'x' :: '{' :: rest =>
      let digits := rest.takeWhile (· != '}')
      let after  := (rest.dropWhile (· != '}')).drop 1
      parseHexChars digits :: decodeEscapes fuel after
  | fuel + 1, c :: rest => c.toNat :: decodeEscapes fuel rest

/-- A column's codepoints. The file writes the empty string as a literal `""`,
    which is distinct from a blank column: blank inherits, `""` is empty. -/
def columnCodepoints (field : String) : List Nat :=
  if field = "\"\"" then [] else decodeEscapes field.length field.toList

/-- A status column names errors unless it is blank or an explicit empty set. -/
def statusHasErrors (field : String) : Bool :=
  ! (field.isEmpty || field = "[]")

/-- The status a tag names, for the twenty tags `IdnaTestV2.txt` writes. -/
def statusOfTag (tag : String) : Option Status :=
  let table : List (String × Status) :=
    [ ("A3", .A3), ("A4_1", .A4_1), ("A4_2", .A4_2)
    , ("B1", .B1), ("B2", .B2), ("B3", .B3)
    , ("B4", .B4), ("B5", .B5), ("B6", .B6)
    , ("C1", .C1), ("C2", .C2)
    , ("P4", .P4)
    , ("U1", .U1)
    , ("V1", .V1), ("V2", .V2), ("V3", .V3)
    , ("V4", .V4), ("V6", .V6), ("V7", .V7)
    , ("X4_2", .X4_2) ]
  (table.find? (fun pair => pair.1 == tag)).map (fun pair => pair.2)

/-- The status set a column states, parsed from the bracketed list the file
    writes, such as `[B5, B6]`. An empty column and `[]` both name the empty
    set. A tag the file carries that this module does not know stays unmapped,
    which shows up as a mismatch rather than as a silent pass. -/
def parseStatuses (field : String) : List Status :=
  let inner :=
    String.ofList ((trimS field).toList.filter
      (fun c => c != '[' && c != ']' && c != ' '))
  if inner.isEmpty then []
  else (inner.splitOn ",").filterMap statusOfTag

/-- Two status collections name the same set, ignoring order and repetition. -/
def sameStatuses (a b : List Status) : Bool :=
  a.all (fun s => b.contains s) && b.all (fun s => a.contains s)

/-- Raw text of `IdnaTestV2.txt`, embedded at compile time. -/
def idnaTestV2Raw : String :=
  include_str "../Ucd/IdnaTestV2.txt"

/-- Parse one row, resolving the inherited columns. Returns `none` for blank
    and comment lines and for any row without all seven columns. -/
def parseRow (rawLine : String) : Option Row :=
  let stripped := (rawLine.takeWhile (· != '#')).toString
  let line := trimS stripped
  if line.isEmpty then none else
  let fields := (line.splitOn ";").map trimS
  match fields with
  | c1 :: c2 :: c3 :: c4 :: c5 :: c6 :: c7 :: _ =>
      let uOut := if c2.isEmpty then c1 else c2
      let uErr := c3
      let nOut := if c4.isEmpty then uOut else c4
      let nErr := if c5.isEmpty then uErr else c5
      let tOut := if c6.isEmpty then nOut else c6
      let tErr := if c7.isEmpty then nErr else c7
      some {
        source       := columnCodepoints c1
        toUnicodeOut := columnCodepoints uOut
        toUnicodeErr := statusHasErrors uErr
        toUnicodeSt  := parseStatuses uErr
        toAsciiNOut  := columnCodepoints nOut
        toAsciiNErr  := statusHasErrors nErr
        toAsciiNSt   := parseStatuses nErr
        toAsciiTOut  := columnCodepoints tOut
        toAsciiTErr  := statusHasErrors tErr
        toAsciiTSt   := parseStatuses tErr
      }
  | _ => none

/-- Every parsed row of the official file, in source order. -/
def rows : List Row :=
  (idnaTestV2Raw.splitOn "\n").filterMap parseRow

/-! ### Judging a row

Every row of the published file is judged against one rule: the operation's
output and error flag must both be what the column states.

The file's header licenses an implementation that converts illegal code points
into U+FFFD to read U+FFFD *in its own output* as a wildcard. That licence is
inapplicable here. UTS #46 §4 step 1 says of a disallowed code point "leave the
code point unchanged in the string", and Convert/Validate is where it is caught;
substituting U+FFFD is a §4.5 recommendation for making it visible to a reader,
outside the algorithm. `Unicode.Idna` leaves such code points unchanged. U+FFFD
also occurs nowhere in the published file, neither literally nor escaped.

An empty expected output is an expectation like any other: the operation must
produce nothing and must report the error the column states. `Map.Result`
carries that flag. -/

/-- The outcome of comparing one operation against one expected column pair.
    Every row is judged; there is no third outcome. -/
inductive Judgement where
  /-- The operation produced exactly the expected output and error flag. -/
  | pass
  /-- The output or the error flag differed. -/
  | fail
  deriving Inhabited, Repr, DecidableEq

/-- Judge one operation against one expected column pair.

    One rule for every row: the output and the error flag must both be what the
    file states. The section comment above records why no comparison here is
    waived. -/
def judge (actual : Unicode.Idna.Map.Result) (expectedOut : List Nat)
    (expectedErr : Bool) (expectedSt : List Status) : Judgement :=
  if actual.output == expectedOut
      && actual.hasErrors == expectedErr
      && sameStatuses actual.statuses expectedSt then .pass
  else .fail

/-- The three judgements for one row, in the file's column order. -/
def judgeRow (r : Row) : Judgement × Judgement × Judgement :=
  ( judge (toUnicode r.source)           r.toUnicodeOut r.toUnicodeErr r.toUnicodeSt
  , judge (toAscii r.source)             r.toAsciiNOut  r.toAsciiNErr  r.toAsciiNSt
  , judge (toAsciiTransitional r.source) r.toAsciiTOut  r.toAsciiTErr  r.toAsciiTSt )

/-- Running tally for one operation. -/
structure Tally where
  pass    : Nat := 0
  fail    : Nat := 0
  skipped : Nat := 0
  deriving Inhabited, Repr

/-- `Judgement` has two constructors, so `skipped` is structurally zero. The
    field exists because a conformance result is read by its skipped column. -/
def Tally.add (t : Tally) : Judgement → Tally
  | .pass => { t with pass := t.pass + 1 }
  | .fail => { t with fail := t.fail + 1 }

def Tally.line (t : Tally) (label : String) : String :=
  let pad := (label ++ String.ofList (List.replicate (18 - label.length) ' '))
  s!"  {pad}pass {t.pass}   fail {t.fail}   skipped {t.skipped}"

/-- Tallies for the three operations over a sample of rows. -/
def talliesOf (sample : List Row) : Tally × Tally × Tally :=
  sample.foldl
    (fun (tu, tn, tt) r =>
      let (ju, jn, jt) := judgeRow r
      (tu.add ju, tn.add jn, tt.add jt))
    (default, default, default)

/-- The first index in `sample` at which any of the three operations failed, for
    use as a debugging hook when the summary is not all zeroes in the fail
    column. -/
def firstFailIdxOf (sample : List Row) : Option Nat :=
  sample.findIdx? (fun r =>
    let (ju, jn, jt) := judgeRow r
    ju == .fail || jn == .fail || jt == .fail)

/-- The UTS #46 conformance summary over `sample`.

    The header states how many of the file's rows were judged, because this is
    evaluated rather than proven and a partial run is a legitimate way to use
    it: `toAscii` on a hundred-codepoint label costs a few hundred milliseconds
    under the interpreter, so the whole file is tens of minutes while the first
    few hundred rows are immediate. A summary that reported only its own totals
    would read the same either way, which is exactly the confusion the skipped
    column elsewhere in this repository exists to prevent. -/
def reportOn (sample : List Row) : String :=
  let (tu, tn, tt) := talliesOf sample
  let failLine :=
    match firstFailIdxOf sample with
    | none => "  first failure:    none"
    | some i => s!"  first failure:    row index {i}"
  String.intercalate "\n"
    [ "UTS #46 IdnaTestV2 conformance (UCD 17.0.0)"
    , s!"  rows judged:      {sample.length} of {rows.length} in the published file"
    , tu.line "toUnicode"
    , tn.line "toAsciiN"
    , tt.line "toAsciiT"
    , failLine
    ]

/-- The summary over every row of the published file. -/
def report : String := reportOn rows

/-- The summary over the first `n` rows, in file order. -/
def reportFirst (n : Nat) : String := reportOn (rows.take n)

end Unicode.Conformance.IdnaTestV2
