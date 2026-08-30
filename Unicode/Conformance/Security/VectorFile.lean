/-
  Unicode.Conformance.Security.VectorFile

  Parser for the `Unicode/Ucd/Security/*Test.txt` detector vector files, so a
  harness can be tied to the file it cites rather than merely accompanied by it.

  The vector files are hash-pinned by `scripts/check-security-hashes.sh`, which
  establishes that their bytes are the bytes that were reviewed. It does not
  establish that any detector was run over them: a harness proving a set of
  vectors written into itself agrees with its file only by inspection. The gate
  this module supports is the one `Unicode/Conformance/GraphemeBreakTest.lean`
  already applies to its own corpus — a materialized row list, mirrored at build
  time against a fresh parse of the embedded file — so a row added to, removed
  from, or edited in the file makes the build fail until the harness is brought
  back into agreement with it.

  Row grammar, common to every file:

      <hex codepoints>; <classification>; <positions>; <attribution>…  # <name>

  Field 1 is the input, space-separated hexadecimal scalar values. Field 2 is
  the expected verdict, `Clear` or `Hazard:<SubThreatTag>`. Field 3 is the
  expected position list, space-separated decimals, empty for a clear row. The
  remaining fields are per-family attribution counters (`strong_rtl=0`,
  `tag_count=0`, and so on) whose names and arity differ by detector; they are
  the file's own commentary on why a verdict holds and are not parsed here.

  A line whose first non-space character is `#` is a comment, including the
  `@section` and `@level` directives, and a line with fewer than three
  semicolon-separated fields is not a row. Both yield `none`.
-/

namespace Unicode.Conformance.Security.VectorFile

/-- A parsed vector row: the detector input, the expected verdict as the file
    writes it, and the expected positions. -/
structure VectorRow where
  codepoints     : List Nat
  classification : String
  positions      : List Nat
  deriving DecidableEq, Repr, Inhabited

def trimS (s : String) : String := (String.trimAscii s).toString

def hexDigitVal (c : Char) : Nat :=
  let n := c.toNat
  if n ≥ 0x30 ∧ n ≤ 0x39 then n - 0x30
  else if n ≥ 0x61 ∧ n ≤ 0x66 then n - 0x61 + 10
  else if n ≥ 0x41 ∧ n ≤ 0x46 then n - 0x41 + 10
  else 0

def parseHex (s : String) : Nat :=
  s.foldl (fun acc c => acc * 16 + hexDigitVal c) 0

def decDigitVal (c : Char) : Nat :=
  let n := c.toNat
  if n ≥ 0x30 ∧ n ≤ 0x39 then n - 0x30 else 0

def parseDec (s : String) : Nat :=
  s.foldl (fun acc c => acc * 10 + decDigitVal c) 0

/-- Tokens of `s`, separated by spaces or commas, with empty tokens dropped.
    The position column writes both, sometimes in the same row (`0, 3`). -/
def tokens (s : String) : List String :=
  (((s.replace "," " ").splitOn " ").map trimS).filter (fun t => t ≠ "")

/-- Parse one row.  Returns `none` for a comment, a blank line, or a line
    carrying fewer than the three fields every file writes. -/
def parseRow (rawLine : String) : Option VectorRow :=
  let line := trimS rawLine
  if line = "" then none
  else if line.startsWith "#" then none
  else
    let fields := line.splitOn ";"
    if fields.length < 3 then none
    else
      let cps := (tokens (fields[0]?.getD "")).map parseHex
      let cls := trimS (fields[1]?.getD "")
      let poss := (tokens (fields[2]?.getD "")).map parseDec
      if cps.isEmpty then none
      else if cls = "" then none
      else some { codepoints := cps, classification := cls, positions := poss }

/-- Every row of an embedded vector file, in source order. -/
def parseFile (raw : String) : List VectorRow :=
  ((raw.splitOn "\n").filterMap parseRow)

/-- Value of a hex numeral given as characters. -/
def parseHexChars (cs : List Char) : Nat :=
  cs.foldl (fun acc c => acc * 16 + hexDigitVal c) 0

/-- True iff `c` separates tokens in a codepoint list. -/
def isSeparator (c : Char) : Bool := c == ' ' || c == ','

/-- Split characters on spaces and commas, dropping empty groups.  Fuel-bounded
    for structural termination, matching the recursion style the normalization
    modules use.

    This exists beside `tokens` because the two run in different places.
    `tokens` is used while parsing a file under `#eval`, where `String.replace`
    and `String.trimAscii` are fine; a harness that reads an attribution inside
    a `decide +kernel` obligation needs the character-list form, because those
    two string operations do not reduce in the kernel. -/
def charGroups : Nat → List Char → List (List Char)
  | 0, cs => Function.const (List Char) [] cs
  | fuel + 1, [] => Function.const Nat [] fuel
  | fuel + 1, c :: rest =>
    if isSeparator c then charGroups fuel rest
    else
      (c :: rest.takeWhile (fun d => !isSeparator d))
        :: charGroups fuel (rest.dropWhile (fun d => !isSeparator d))

/-- The codepoints a hex-valued attribution names, reducible in the kernel. -/
def attrCodepoints (value : String) : List Nat :=
  let cs := value.toList
  (charGroups cs.length cs).map parseHexChars

/-- The attribution fields of one row: everything after the position column,
    comment stripped, each entry a `key=value` string as the file writes it.
    Returns `none` on exactly the lines `parseRow` rejects, so the two stay
    index-aligned.

    Most families use these only as commentary. `HashInputStability` is the
    exception: its `declaredEnc`, `rfcRule`, `asWritten`, and `serverBytes`
    keys are the `Context` its context-bearing sub-threats need, so its
    harness reads them rather than treating them as prose. -/
def attrFields (rawLine : String) : Option (List String) :=
  match parseRow rawLine with
  | none          => none
  | some parsedRow =>
    Function.const VectorRow
      (let line := trimS rawLine
       let beforeComment := (line.splitOn "#")[0]?.getD line
       let fields := (beforeComment.splitOn ";").drop 3
       ((fields.map trimS).filter (fun f => f ≠ "")))
      parsedRow

/-- The attribution fields of every row, index-aligned with `parseFile`. -/
def parseFileAttrs (raw : String) : List (List String) :=
  ((raw.splitOn "\n").filterMap attrFields)

/-- The value of attribution key `key`, or `none` when the row omits it.
    `attrValue "rfcRule" ["stableSize=1", "rfcRule=pgp9580LineEnding"]`
    is `some "pgp9580LineEnding"`.

    Matching runs over `List Char` rather than `String.startsWith` on a
    computed `key ++ "="`: the character list reduces in the kernel, so a
    harness can close an obligation over these values by `decide +kernel`. -/
def attrValue (key : String) (attrs : List String) : Option String :=
  let keyChars := key.toList ++ ['=']
  let keyLen := keyChars.length
  attrs.findSome? (fun entry =>
    let entryChars := entry.toList
    if entryChars.take keyLen = keyChars then
      some (String.ofList (entryChars.drop keyLen))
    else none)

/-- The sub-threat tag a row expects, or `none` when the row expects a clear
    verdict.  `Hazard:FieldTakeover` yields `some "FieldTakeover"`. -/
def VectorRow.expectedTag (r : VectorRow) : Option String :=
  if r.classification.startsWith "Hazard:" then
    some (r.classification.drop "Hazard:".length).toString
  else none

/-- True iff the row expects a clear verdict. -/
def VectorRow.expectsClear (r : VectorRow) : Bool :=
  r.classification = "Clear"

end Unicode.Conformance.Security.VectorFile
