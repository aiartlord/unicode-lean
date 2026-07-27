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

  This harness verifies our `isRgiEmoji` against every row of
  `emoji-test.txt`:

    * Every `fully-qualified` row IS classified as RGI.
    * No `minimally-qualified` row is — the elided required VS16
      removes the row from the registered RGI sequence set.
    * No `unqualified` row is — same reason as above.
    * Every `component` row IS — the 9 component rows are exactly
      the 5 skin-tone modifiers (U+1F3FB..U+1F3FF) and the 4 hair
      components (U+1F9B0..U+1F9B3), all of which are listed as
      Basic_Emoji codepoints in `emoji-sequences.txt`. The
      "component" status in `emoji-test.txt` flags a *usage*
      category (keyboard / picker context), not an RGI exclusion.

  All four directions are closed by `decide` over the bundled
  fixture, giving full UTS #51 ED-27 conformance.
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
  cps    : List Nat
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

def parseCodepointList (s : String) : List Nat :=
  ((s.splitOn " ").filterMap (fun tok =>
    let t := trimS tok
    if t.isEmpty then none else some (parseHex t)))

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
def rows : List Row :=
  ((emojiTestRaw.splitOn "\n").filterMap parseRow)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 ROW VERIFICATION
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Total number of parsed rows. -/
def rowCount : Nat := rows.length

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

/-- Number of minimally-qualified rows that pass `isRgiEmoji`. The
    correct value is 0: a minimally-qualified row by definition has
    one or more required VS16s elided, removing it from the
    registered RGI sequence set. -/
def minimallyQualifiedPassingCount : Nat :=
  rows.foldl (fun acc r =>
    if r.status = .minimallyQualified ∧ isRgiEmoji r.cps then acc + 1 else acc) 0

/-- Number of unqualified rows that pass `isRgiEmoji`. The correct
    value is 0 for the same reason as `minimallyQualifiedPassingCount`. -/
def unqualifiedPassingCount : Nat :=
  rows.foldl (fun acc r =>
    if r.status = .unqualified ∧ isRgiEmoji r.cps then acc + 1 else acc) 0

/-- Number of component rows that pass `isRgiEmoji`. The correct
    value equals `componentRowCount`: the 9 component rows are the
    5 skin-tone modifiers (U+1F3FB..U+1F3FF) and the 4 hair
    components (U+1F9B0..U+1F9B3), all of which are Basic_Emoji
    codepoints. The `component` status here is a usage category,
    not an RGI exclusion. -/
def componentPassingCount : Nat :=
  rows.foldl (fun acc r =>
    if r.status = .component ∧ isRgiEmoji r.cps then acc + 1 else acc) 0

/-- Every fully-qualified row in `emoji-test.txt` is classified as
    RGI by our implementation. -/
theorem fully_qualified_conformance :
    fullyQualifiedPassingCount = fullyQualifiedRowCount := by decide

/-- No minimally-qualified row is classified as RGI: every such row
    has one or more required VS16s elided, removing it from the
    registered RGI sequence set. -/
theorem minimally_qualified_not_rgi :
    minimallyQualifiedPassingCount = 0 := by decide

/-- No unqualified row is classified as RGI: every such row has one
    or more required VS16s elided. -/
theorem unqualified_not_rgi :
    unqualifiedPassingCount = 0 := by decide

/-- Every component row is classified as RGI: the 9 component rows
    are the skin-tone modifiers and hair components, all of which
    are Basic_Emoji codepoints in `emoji-sequences.txt`. -/
theorem component_all_rgi :
    componentPassingCount = componentRowCount := by decide

end Unicode.Conformance.EmojiTest
