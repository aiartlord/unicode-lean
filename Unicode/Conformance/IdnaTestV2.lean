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

  The counts `report` prints keep failures and skips in separate columns. A skip
  is a row this module declines to judge, never a row that passed — see
  `Judgement` for the two reasons a row is skipped.
-/

import Unicode.Idna.Process

namespace Unicode.Conformance.IdnaTestV2

open Unicode.Idna.Process

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
  toAsciiNOut   : List Nat
  toAsciiNErr   : Bool
  toAsciiTOut   : List Nat
  toAsciiTErr   : Bool
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
        toAsciiNOut  := columnCodepoints nOut
        toAsciiNErr  := statusHasErrors nErr
        toAsciiTOut  := columnCodepoints tOut
        toAsciiTErr  := statusHasErrors tErr
      }
  | _ => none

/-- Every parsed row of the official file, in source order. -/
def rows : List Row :=
  (idnaTestV2Raw.splitOn "\n").filterMap parseRow

/-! ### Judging a row

The file's header states that an implementation which maps illegal codepoints to
U+FFFD may treat U+FFFD in its own output as a wildcard. This module does not
take that licence: rather than count a wildcard match as a pass, it skips the
row, so no row is ever reported as passing on a comparison that was waived.

The other skip is structural. `Map.Result` carries one `hasErrors` flag, not the
status-code set the file's columns name. A row whose expected output is empty
*because* it errors therefore has nothing left to compare beyond that flag, and
calling it a pass would be crediting this module for a check it did not make. -/

/-- Why a row was not judged, or that it was. -/
inductive Judgement where
  /-- Compared, and the operation produced exactly the expected output. -/
  | pass
  /-- Compared, and the output or the error flag differed. -/
  | fail
  /-- Expected output contains U+FFFD, which the file allows to be read as a
      wildcard; declining that licence rather than passing on it. -/
  | skipWildcard
  /-- Errors are expected and no output is specified, leaving only the error
      flag, which is weaker than the status set the column names. -/
  | skipStatusOnly
  deriving Inhabited, Repr, DecidableEq

def isSkip : Judgement → Bool
  | .skipWildcard | .skipStatusOnly => true
  | _ => false

/-- Judge one operation against one expected column pair. -/
def judge (actual : Unicode.Idna.Map.Result) (expectedOut : List Nat) (expectedErr : Bool) :
    Judgement :=
  if expectedOut.contains 0xFFFD then .skipWildcard
  else if expectedErr && expectedOut.isEmpty then .skipStatusOnly
  else if actual.output == expectedOut && actual.hasErrors == expectedErr then .pass
  else .fail

/-- The three judgements for one row, in the file's column order. -/
def judgeRow (r : Row) : Judgement × Judgement × Judgement :=
  ( judge (toUnicode r.source)            r.toUnicodeOut r.toUnicodeErr
  , judge (toAscii r.source)              r.toAsciiNOut  r.toAsciiNErr
  , judge (toAsciiTransitional r.source)  r.toAsciiTOut  r.toAsciiTErr )

/-- Running tally for one operation. -/
structure Tally where
  pass    : Nat := 0
  fail    : Nat := 0
  skipped : Nat := 0
  deriving Inhabited, Repr

def Tally.add (t : Tally) : Judgement → Tally
  | .pass => { t with pass := t.pass + 1 }
  | .fail => { t with fail := t.fail + 1 }
  | j     => if isSkip j then { t with skipped := t.skipped + 1 } else t

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
