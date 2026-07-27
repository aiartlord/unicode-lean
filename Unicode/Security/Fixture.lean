/-
  Unicode.Security.Fixture

  Universal fixture-row parser for Security Conformance Layer test
  files. Every per-family conformance harness (e.g.
  `Unicode/Conformance/Security/VariationSelectorPayloadTest.lean`)
  embeds a `*Test.txt` fixture via `include_str`, splits on newlines,
  filterMaps over `parseRow`, and folds via `decide`.

  ## Fixture row format

      <hex codepoints>; <classification>; <positions>; <attribution>; # <name>

  Five semicolon-separated columns:

    1. **input**           — space-separated hex codepoints (no U+ prefix)
    2. **classification**  — `Clear` or `Hazard:<SubThreat>`
    3. **positions**       — comma-separated 0-indexed hazard positions
                             (empty when `Clear`)
    4. **attribution**     — `key="value"; key2="value2";` semicolon-separated
    5. **name**            — `# <human-readable name + spec citation>`

  Section / level directives:

      # @section <Name>
      # @level <basic|strict|full>

  Carry forward until the next directive. Both default to
  `"<unspecified>"` / `.basic` before any directive appears.

  Pattern mirrors `Unicode.Conformance.EmojiTest.parseRow` and friends
  but specializes columns + adds section/level state.
-/

import Unicode.Security.Calculus

namespace Unicode.Security.Fixture

open Unicode.Security.Calculus

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Low-level lexing utilities (mirrors EmojiTest/CollationTest pattern)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- ASCII whitespace test used for trimming: space, tab, LF, CR. -/
def isSpaceC (c : Char) : Bool :=
  c == ' ' || c == '\t' || c == '\n' || c == '\r'

/-- Drop leading and trailing ASCII whitespace from a char list — the
    `List Char` analogue of `String.trimAscii`.  Every lexing step is
    kept on the char list because the `String` iterators (`splitOn`,
    `foldl`, `trimAscii`, `startsWith`, …) do not reduce under the
    kernel, whereas `String.toList` and the `List Char` combinators do.
    That is what lets the spot-check theorems close by `decide +kernel`
    instead of getting stuck on an unreduced `parseFixture`. -/
def trimC (cs : List Char) : List Char :=
  ((cs.dropWhile isSpaceC).reverse.dropWhile isSpaceC).reverse

/-- Split a char list on a single delimiter, matching `String.splitOn`
    semantics for a one-character separator: empty segments between
    consecutive delimiters and at the ends are retained, and the result
    is always non-empty. -/
def splitOnC (d : Char) : List Char → List (List Char)
  | []        => [[]]
  | c :: rest =>
    let rs := splitOnC d rest
    if c == d then [] :: rs
    else match rs with
      | []          => [[c]]
      | seg :: segs => (c :: seg) :: segs

/-- Join char-list segments with a single separator — the inverse of
    `splitOnC`, matching `String.intercalate` for a one-character sep. -/
def intercalateC (d : Char) : List (List Char) → List Char
  | []             => []
  | [x]            => x
  | x :: y :: rest => x ++ (d :: intercalateC d (y :: rest))

def hexDigitVal (c : Char) : Nat :=
  let n := c.toNat
  if n ≥ 0x30 ∧ n ≤ 0x39 then n - 0x30
  else if n ≥ 0x61 ∧ n ≤ 0x66 then n - 0x61 + 10
  else if n ≥ 0x41 ∧ n ≤ 0x46 then n - 0x41 + 10
  else 0

/-- Parse a hex codepoint from its char list. -/
def parseHexC (cs : List Char) : Nat :=
  cs.foldl (fun acc c => acc * 16 + hexDigitVal c) 0

/-- Decimal digit value, or `none` for a non-digit character. -/
def decDigitVal? (c : Char) : Option Nat :=
  let n := c.toNat
  if n ≥ 0x30 ∧ n ≤ 0x39 then some (n - 0x30) else none

/-- Parse a decimal `Nat` from a char list, matching `String.toNat?`:
    `none` for an empty list or on any non-digit character. -/
def parseDecC : List Char → Option Nat
  | []        => none
  | c :: rest =>
    (c :: rest).foldl (fun acc d =>
      match acc with
      | none   => none
      | some n => match decDigitVal? d with
                  | none   => none
                  | some v => some (n * 10 + v)) (some 0)

/-- Parse a space-separated hex codepoint list (char-list worker).
    Empty tokens are ignored. -/
def parseCodepointListC (cs : List Char) : List Nat :=
  ((splitOnC ' ' cs).filterMap (fun tok =>
    let t := trimC tok
    if t.isEmpty then none else some (parseHexC t)))

/-- Parse a space-separated hex codepoint list. Empty tokens are ignored. -/
def parseCodepointList (s : String) : List Nat :=
  parseCodepointListC s.toList

/-- Parse a comma-separated decimal-`Nat` list (char-list worker).
    Empty tokens are ignored. -/
def parseDecimalListC (cs : List Char) : List Nat :=
  ((splitOnC ',' cs).filterMap (fun tok =>
    let t := trimC tok
    if t.isEmpty then none else parseDecC t))

/-- Parse a comma-separated decimal-`Nat` list. Empty tokens are ignored. -/
def parseDecimalList (s : String) : List Nat :=
  parseDecimalListC s.toList

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Classification + sub-threat parsing
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Parse the classification atom in column 2 (char-list worker).
    Returns the `ClassificationKind` and an optional sub-threat tag. -/
def parseClassificationC (cs : List Char) : Option (ClassificationKind × Option String) :=
  let t := trimC cs
  if t = "Clear".toList then some (.clear, none)
  else if "Hazard:".toList.isPrefixOf t then
    let sub := trimC (t.drop 7)
    if sub.isEmpty then none
    else some (.hazard, some (String.ofList sub))
  else if t = "Compound".toList then some (.compound, none)
  else if "Compound:".toList.isPrefixOf t then
    let sub := trimC (t.drop 9)
    some (.compound, if sub.isEmpty then none else some (String.ofList sub))
  else if t = "Informational".toList then some (.informational, none)
  else none

/-- Parse the classification atom in column 2. Returns the
    `ClassificationKind` and an optional sub-threat tag. -/
def parseClassification (s : String) : Option (ClassificationKind × Option String) :=
  parseClassificationC s.toList

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Attribution parsing (column 4 — key=value; key=value; ...)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Parse one `key="value"` token (char-list worker). Quotes around the
    value are optional but typical. Returns `(key, value)` on success. -/
def parseKeyValueC (cs : List Char) : Option (String × String) :=
  let t := trimC cs
  match splitOnC '=' t with
  | k :: rest =>
    let key := trimC k
    if key.isEmpty then none
    else
      let val := trimC (intercalateC '=' rest)
      -- Strip optional surrounding double quotes.
      let val := if ['"'].isPrefixOf val ∧ ['"'].isSuffixOf val ∧ val.length ≥ 2
                 then (val.drop 1).dropLast
                 else val
      some (String.ofList key, String.ofList val)
  | [] => none

/-- Parse one `key="value"` token. Quotes around value are optional but
    typical. Returns `(key, value)` on success. -/
def parseKeyValue (tok : String) : Option (String × String) :=
  parseKeyValueC tok.toList

/-- Parse the attribution column (char-list worker). Format:
    `key1="v1"; key2="v2"; ...`.  Trailing semicolons and empty tokens
    are tolerated. -/
def parseAttributionC (cs : List Char) : KeyValueAttribution :=
  let entries := (splitOnC ';' cs).filterMap (fun tok =>
    let t := trimC tok
    if t.isEmpty then none else parseKeyValueC t)
  ⟨entries⟩

/-- Parse the attribution column. Format: `key1="v1"; key2="v2"; ...`.
    Trailing semicolons and empty tokens are tolerated. -/
def parseAttribution (s : String) : KeyValueAttribution :=
  parseAttributionC s.toList

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Row + Directive types
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A single fixture row. The `sectionName` and `conformanceLevel` fields
    are carried from the most-recently-encountered `# @section` /
    `# @level` directive during fold-parse.  (Field names avoid the
    Lean reserved tokens `section` and `level`.) -/
structure Row where
  input              : List Nat
  expectedKind       : ClassificationKind
  expectedSubThreat  : Option String
  expectedPositions  : List Nat
  attribution        : KeyValueAttribution
  citation           : String
  sectionName        : String
  conformanceLevel   : ConformanceLevel
  deriving Repr, Inhabited

/-- A directive line encountered during parsing.  Constructor names avoid
    the Lean reserved tokens `section` and `level`. -/
inductive Directive where
  | sectionDir (name : String)
  | levelDir   (lvl : ConformanceLevel)
  | comment
  | blank
  deriving Repr, DecidableEq

/-- Parse a directive line (char-list worker). Returns `.comment` for
    ordinary `#` lines (non-directive comments) and `.blank` for blank
    lines. -/
def parseDirectiveC (cs : List Char) : Option Directive :=
  let t := trimC cs
  if t.isEmpty then some .blank
  else if "# @section".toList.isPrefixOf t then
    let name := trimC (t.drop 10)
    some (.sectionDir (String.ofList name))
  else if "# @level".toList.isPrefixOf t then
    let lvl := String.ofList (trimC (t.drop 8))
    match lvl with
    | "basic"      => some (.levelDir .basic)
    | "strict"     => some (.levelDir .strict)
    | "full"       => some (.levelDir .full)
    | "1"          => some (.levelDir .basic)
    | "2"          => some (.levelDir .strict)
    | "3"          => some (.levelDir .full)
    | unknownLevel => Function.const String none unknownLevel
  else if ['#'].isPrefixOf t then some .comment
  else none

/-- Parse a directive line. Returns `.comment` for ordinary `#` lines
    (non-directive comments) and `.blank` for blank lines. -/
def parseDirective (line : String) : Option Directive :=
  parseDirectiveC line.toList

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Row parsing
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Parse one fixture row given the carried `section` and `level`
    context (char-list worker). Returns `none` for blank, comment, or
    unparseable lines.

    The first three semicolon-separated columns are scalar (input,
    classification, positions). Everything from the fourth column
    onwards is rejoined with `;` and parsed as the attribution dict,
    so attribution entries are free to embed `;` themselves. -/
def parseRowC (currentSection : String) (currentLevel : ConformanceLevel)
    (cs : List Char) : Option Row :=
  let trimmed := trimC cs
  if trimmed.isEmpty then none
  else if ['#'].isPrefixOf trimmed then none
  else
    -- Strip trailing `# <citation>` comment from the row.
    let preComment := cs.takeWhile (· ≠ '#')
    let citation :=
      if cs.contains '#' then
        String.ofList (trimC ((cs.dropWhile (· ≠ '#')).drop 1))
      else ""
    match (splitOnC ';' preComment).map trimC with
    | c1 :: c2 :: c3 :: rest =>
      let attrStr := intercalateC ';' rest
      let input := parseCodepointListC c1
      match parseClassificationC c2 with
      | none => none
      | some (kind, sub) =>
        let positions := parseDecimalListC c3
        let attribution := parseAttributionC attrStr
        some {
          input := input,
          expectedKind := kind,
          expectedSubThreat := sub,
          expectedPositions := positions,
          attribution := attribution,
          citation := citation,
          sectionName := currentSection,
          conformanceLevel := currentLevel
        }
    | tooFewColumns => Function.const (List (List Char)) none tooFewColumns

/-- Parse one fixture row given the carried `section` and `level`
    context. Returns `none` for blank, comment, or unparseable lines. -/
def parseRow (currentSection : String) (currentLevel : ConformanceLevel)
    (line : String) : Option Row :=
  parseRowC currentSection currentLevel line.toList

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 Fold-parse — applies directives + parses rows
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Carry-state during fold-parse. -/
structure ParseState where
  rows           : List Row
  currentSection : String
  currentLevel   : ConformanceLevel
  deriving Inhabited

/-- Parse a full fixture file body. Applies `@section` / `@level`
    directives as carry-state and accumulates rows. -/
def parseFixture (rawText : String) : List Row :=
  let initial : ParseState := {
    rows := [],
    currentSection := "<unspecified>",
    currentLevel := .basic
  }
  let final := (splitOnC '\n' rawText.toList).foldl (init := initial) (fun st lineC =>
    match parseDirectiveC lineC with
    | some .blank         => st
    | some .comment       => st
    | some (.sectionDir s) => { st with currentSection := s }
    | some (.levelDir l)   => { st with currentLevel := l }
    | none =>
      match parseRowC st.currentSection st.currentLevel lineC with
      | some r => { st with rows := st.rows ++ [r] }
      | none   => st)
  final.rows

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 Spot checks (synthetic 5-row fixture)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A synthetic fixture used to validate the parser. Five rows, four
    sections, both conformance levels exercised. -/
def syntheticFixture : String :=
"# Synthetic fixture for parser validation
# UCD version: 17.0.0
# Security-spec version: 0.1.0

# @section Clear
# @level basic

0048 0065 006C 006C 006F; Clear; ; ; # ASCII Hello

# @section Hazard
# @level basic

0061 FE04 FE01; Hazard:DirectPayload; 1,2; decoded=\"A\"; nibble_count=\"2\"; # Single-byte VS payload

# @section Compound
# @level strict

004E 0065 0074 0068 0065 0072 0435 0075 006D; Hazard:SingleCharSub; 6; skeleton=\"004E 0065 0074 0068 0065 0072 0065 0075 006D\"; matched_target=\"Nethereum\"; # NuGet Nethereum Oct 2025

# @level full

0041 FE0F; Hazard:IllegalTarget; 1; target_cp=\"0x0041\"; vs_cp=\"0xFE0F\"; # VS16 on Latin A

# @section CleanNegatives
# @level basic

4E2D 6587; Clear; ; ; # Han text
"

/-- The synthetic parses cleanly, with five rows. -/
theorem synthetic_parses_5_rows :
    (parseFixture syntheticFixture).length = 5 := by decide +kernel

/-- Row 0 is in the "Clear" section at basic level. -/
theorem synthetic_row0_section :
    (parseFixture syntheticFixture)[0]!.sectionName = "Clear" := by decide +kernel

theorem synthetic_row0_level :
    (parseFixture syntheticFixture)[0]!.conformanceLevel = .basic := by decide +kernel

theorem synthetic_row0_kind :
    (parseFixture syntheticFixture)[0]!.expectedKind = .clear := by decide +kernel

theorem synthetic_row0_input :
    (parseFixture syntheticFixture)[0]!.input = [0x48, 0x65, 0x6C, 0x6C, 0x6F] := by
  decide +kernel

/-- Row 1 is in the "Hazard" section, basic level, DirectPayload sub-threat. -/
theorem synthetic_row1_section :
    (parseFixture syntheticFixture)[1]!.sectionName = "Hazard" := by decide +kernel

theorem synthetic_row1_kind :
    (parseFixture syntheticFixture)[1]!.expectedKind = .hazard := by decide +kernel

theorem synthetic_row1_sub :
    (parseFixture syntheticFixture)[1]!.expectedSubThreat = some "DirectPayload" := by
  decide +kernel

theorem synthetic_row1_positions :
    (parseFixture syntheticFixture)[1]!.expectedPositions = [1, 2] := by decide +kernel

theorem synthetic_row1_decoded :
    (parseFixture syntheticFixture)[1]!.attribution.get? "decoded" = some "A" := by
  decide +kernel

/-- Row 2 is the Nethereum compound case (strict level). -/
theorem synthetic_row2_level :
    (parseFixture syntheticFixture)[2]!.conformanceLevel = .strict := by decide +kernel

theorem synthetic_row2_matched_target :
    (parseFixture syntheticFixture)[2]!.attribution.get? "matched_target"
      = some "Nethereum" := by
  decide +kernel

/-- Row 3 inherits the "Compound" section but level=full from the
    interim @level directive. -/
theorem synthetic_row3_section :
    (parseFixture syntheticFixture)[3]!.sectionName = "Compound" := by decide +kernel

theorem synthetic_row3_level :
    (parseFixture syntheticFixture)[3]!.conformanceLevel = .full := by decide +kernel

/-- Row 4 is in the CleanNegatives section, back to basic. -/
theorem synthetic_row4_section :
    (parseFixture syntheticFixture)[4]!.sectionName = "CleanNegatives" := by
  decide +kernel

theorem synthetic_row4_level :
    (parseFixture syntheticFixture)[4]!.conformanceLevel = .basic := by decide +kernel

theorem synthetic_row4_kind :
    (parseFixture syntheticFixture)[4]!.expectedKind = .clear := by decide +kernel

end Unicode.Security.Fixture
