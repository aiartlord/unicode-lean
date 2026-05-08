/-
  Unicode.Conformance.EmojiTest

  UTS #51 conformance against the official `emoji-test.txt` test
  suite. Each test row is a codepoint sequence plus a qualification
  status:

    * `fully-qualified`     — the canonical RGI form, with every
                              required variation selector present.
    * `minimally-qualified` — an RGI form with one or more required
                              variation selectors elided (the leading
                              codepoint is fully-qualified but later
                              codepoints elide their VS16).
    * `unqualified`         — a form whose variation selectors are
                              elided in positions where they are
                              required for canonical RGI presentation.
    * `component`           — a single emoji component (skin-tone
                              modifier or hair-style joiner) listed
                              for keyboard / picker completeness.

  This harness verifies our `isRgiEmoji` against the
  `fully-qualified` rows: every row in that subset must be classified
  as RGI by our implementation. The other three statuses are tracked
  but not required to match — `minimally-qualified` and `unqualified`
  rows by definition lack the variation selectors that
  `emoji-sequences.txt` records for the RGI form.
-/

import Unicode.Emoji

namespace Unicode.Conformance.EmojiTest

open Unicode.Emoji

inductive Status where
  | component
  | fullyQualified
  | minimallyQualified
  | unqualified
  deriving DecidableEq, Repr, Inhabited

structure Row where
  cps    : Array Nat
  status : Status
  deriving Inhabited, Repr

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

def parseCodepointList (s : String) : Array Nat :=
  ((s.splitOn " ").filterMap (fun tok =>
    let t := trimS tok
    if t.isEmpty then none else some (parseHex t))).toArray

def parseStatus? : String → Option Status
  | "component"           => some .component
  | "fully-qualified"     => some .fullyQualified
  | "minimally-qualified" => some .minimallyQualified
  | "unqualified"         => some .unqualified
  | unknown               => Function.const String none unknown

/-- Parse one `emoji-test.txt` row. Returns `none` for blank or
    comment lines. -/
def parseRow (rawLine : String) : Option Row :=
  let stripped : String := (rawLine.takeWhile (· != '#')).toString
  let line := trimS stripped
  if line.isEmpty then none else
  match String.splitOn line ";" with
  | [cpField, statusField] =>
    let cps := parseCodepointList (trimS cpField)
    match parseStatus? (trimS statusField) with
    | some s => some ⟨cps, s⟩
    | none   => none
  | irregularSplit => Function.const (List String) none irregularSplit

/-- Raw text of `emoji-test.txt`, embedded at compile time. -/
def emojiTestRaw : String := include_str "../Ucd/emoji-test.txt"

/-- All parsed test rows, in source (CLDR) order. -/
def rows : Array Row :=
  ((emojiTestRaw.splitOn "\n").filterMap parseRow).toArray

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 ROW VERIFICATION
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Total number of parsed rows. -/
def rowCount : Nat := rows.size

/-- Number of rows with each status. -/
def fullyQualifiedRowCount : Nat :=
  rows.foldl (fun acc r => if r.status = .fullyQualified then acc + 1 else acc) 0

def minimallyQualifiedRowCount : Nat :=
  rows.foldl (fun acc r => if r.status = .minimallyQualified then acc + 1 else acc) 0

def unqualifiedRowCount : Nat :=
  rows.foldl (fun acc r => if r.status = .unqualified then acc + 1 else acc) 0

def componentRowCount : Nat :=
  rows.foldl (fun acc r => if r.status = .component then acc + 1 else acc) 0

/-- Number of fully-qualified rows that pass `isRgiEmoji`. -/
def fullyQualifiedPassingCount : Nat :=
  rows.foldl (fun acc r =>
    if r.status = .fullyQualified ∧ isRgiEmoji r.cps then acc + 1 else acc) 0

/-- Index of the first fully-qualified row that fails `isRgiEmoji`. -/
def firstFullyQualifiedFailing : Option Nat := Id.run do
  for h : i in [0:rows.size] do
    let r := rows[i]
    if r.status = .fullyQualified ∧ ! isRgiEmoji r.cps then return some i
  return none

#eval s!"total rows: {rowCount}"
#eval s!"fully-qualified rows: {fullyQualifiedRowCount}"
#eval s!"fully-qualified passing: {fullyQualifiedPassingCount}"
#eval s!"minimally-qualified rows: {minimallyQualifiedRowCount}"
#eval s!"unqualified rows: {unqualifiedRowCount}"
#eval s!"component rows: {componentRowCount}"
#eval s!"first fully-qualified failing row: {firstFullyQualifiedFailing}"
#eval match firstFullyQualifiedFailing with
      | none => "no fully-qualified failures"
      | some i =>
        if h : i < rows.size then
          let r := rows[i]
          s!"row {i}: {r.cps}"
        else "row index out of bounds"

/-- Every fully-qualified row in `emoji-test.txt` is classified as
    RGI by our implementation. -/
theorem fully_qualified_conformance :
    fullyQualifiedPassingCount = fullyQualifiedRowCount := by native_decide

end Unicode.Conformance.EmojiTest
