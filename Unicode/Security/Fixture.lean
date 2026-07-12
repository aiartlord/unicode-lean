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

/-- Parse a space-separated hex codepoint list. Empty tokens are ignored. -/
def parseCodepointList (s : String) : Array Nat :=
  ((s.splitOn " ").filterMap (fun tok =>
    let t := trimS tok
    if t.isEmpty then none else some (parseHex t))).toArray

/-- Parse a comma-separated decimal-Nat list. Empty tokens are ignored. -/
def parseDecimalList (s : String) : Array Nat :=
  ((s.splitOn ",").filterMap (fun tok =>
    let t := trimS tok
    if t.isEmpty then none else String.toNat? t)).toArray

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Classification + sub-threat parsing
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Parse the classification atom in column 2. Returns the
    `ClassificationKind` and an optional sub-threat tag. -/
def parseClassification (s : String) : Option (ClassificationKind × Option String) :=
  let t := trimS s
  if t = "Clear" then some (.clear, none)
  else if t.startsWith "Hazard:" then
    let sub := (t.drop 7).trimAscii.toString
    if sub.isEmpty then none
    else some (.hazard, some sub)
  else if t = "Compound" then some (.compound, none)
  else if t.startsWith "Compound:" then
    let sub := (t.drop 9).trimAscii.toString
    some (.compound, if sub.isEmpty then none else some sub)
  else if t = "Informational" then some (.informational, none)
  else none

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Attribution parsing (column 4 — key=value; key=value; ...)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Parse one `key="value"` token. Quotes around value are optional but
    typical. Returns `(key, value)` on success. -/
def parseKeyValue (tok : String) : Option (String × String) :=
  let t := trimS tok
  match t.splitOn "=" with
  | k :: rest =>
    let key := trimS k
    if key.isEmpty then none
    else
      let valRaw := "=".intercalate rest
      let val := trimS valRaw
      -- Strip optional surrounding double quotes.
      let val := if val.startsWith "\"" ∧ val.endsWith "\"" ∧ val.length ≥ 2
                 then (val.drop 1).dropEnd 1
                 else val
      some (key, val.toString)
  | [] => none

/-- Parse the attribution column. Format: `key1="v1"; key2="v2"; ...`.
    Trailing semicolons and empty tokens are tolerated. -/
def parseAttribution (s : String) : KeyValueAttribution :=
  let entries := (s.splitOn ";").filterMap (fun tok =>
    let t := trimS tok
    if t.isEmpty then none else parseKeyValue t)
  ⟨entries⟩

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Row + Directive types
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A single fixture row. The `sectionName` and `conformanceLevel` fields
    are carried from the most-recently-encountered `# @section` /
    `# @level` directive during fold-parse.  (Field names avoid the
    Lean reserved tokens `section` and `level`.) -/
structure Row where
  input              : Array Nat
  expectedKind       : ClassificationKind
  expectedSubThreat  : Option String
  expectedPositions  : Array Nat
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

/-- Parse a directive line. Returns `.comment` for ordinary `#` lines
    (non-directive comments) and `.blank` for blank lines. -/
def parseDirective (line : String) : Option Directive :=
  let t := trimS line
  if t.isEmpty then some .blank
  else if t.startsWith "# @section" then
    let name := (t.drop 10).trimAscii.toString
    some (.sectionDir name)
  else if t.startsWith "# @level" then
    let lvl := (t.drop 8).trimAscii.toString
    match lvl with
    | "basic"  => some (.levelDir .basic)
    | "strict"     => some (.levelDir .strict)
    | "full"       => some (.levelDir .full)
    | "1"          => some (.levelDir .basic)
    | "2"          => some (.levelDir .strict)
    | "3"          => some (.levelDir .full)
    | unknownLevel => Function.const String none unknownLevel
  else if t.startsWith "#" then some .comment
  else none

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Row parsing
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Parse one fixture row given the carried `section` and `level`
    context. Returns `none` for blank, comment, or unparseable lines.

    The first three semicolon-separated columns are scalar (input,
    classification, positions). Everything from the fourth column
    onwards is rejoined with `;` and parsed as the attribution dict,
    so attribution entries are free to embed `;` themselves. -/
def parseRow (currentSection : String) (currentLevel : ConformanceLevel)
    (line : String) : Option Row :=
  let trimmed := trimS line
  if trimmed.isEmpty then none
  else if trimmed.startsWith "#" then none
  else
    -- Strip trailing `# <citation>` comment from the row.
    let preComment := (line.takeWhile (· ≠ '#')).toString
    let citation :=
      if line.contains '#' then
        let after := ((line.dropWhile (· ≠ '#')).drop 1).toString
        trimS after
      else ""
    match (preComment.splitOn ";").map trimS with
    | c1 :: c2 :: c3 :: rest =>
      let attrStr := ";".intercalate rest
      let input := parseCodepointList c1
      match parseClassification c2 with
      | none => none
      | some (kind, sub) =>
        let positions := parseDecimalList c3
        let attribution := parseAttribution attrStr
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
    | tooFewColumns => Function.const (List String) none tooFewColumns

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 Fold-parse — applies directives + parses rows
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Carry-state during fold-parse. -/
private structure ParseState where
  rows           : Array Row
  currentSection : String
  currentLevel   : ConformanceLevel
  deriving Inhabited

/-- Parse a full fixture file body. Applies `@section` / `@level`
    directives as carry-state and accumulates rows. -/
def parseFixture (rawText : String) : Array Row :=
  let initial : ParseState := {
    rows := #[],
    currentSection := "<unspecified>",
    currentLevel := .basic
  }
  let final := (rawText.splitOn "\n").foldl (init := initial) (fun st line =>
    match parseDirective line with
    | some .blank         => st
    | some .comment       => st
    | some (.sectionDir s) => { st with currentSection := s }
    | some (.levelDir l)   => { st with currentLevel := l }
    | none =>
      match parseRow st.currentSection st.currentLevel line with
      | some r => { st with rows := st.rows.push r }
      | none   => st)
  final.rows

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 Spot checks (synthetic 5-row fixture)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A synthetic fixture used to validate the parser. Five rows, four
    sections, both conformance levels exercised. -/
private def syntheticFixture : String :=
"# Synthetic fixture for parser validation
# UCD version: 16.0.0
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
    (parseFixture syntheticFixture).size = 5 := by decide

/-- Row 0 is in the "Clear" section at basic level. -/
theorem synthetic_row0_section :
    (parseFixture syntheticFixture)[0]!.sectionName = "Clear" := by decide

theorem synthetic_row0_level :
    (parseFixture syntheticFixture)[0]!.conformanceLevel = .basic := by decide

theorem synthetic_row0_kind :
    (parseFixture syntheticFixture)[0]!.expectedKind = .clear := by decide

theorem synthetic_row0_input :
    (parseFixture syntheticFixture)[0]!.input = #[0x48, 0x65, 0x6C, 0x6C, 0x6F] := by
  decide

/-- Row 1 is in the "Hazard" section, basic level, DirectPayload sub-threat. -/
theorem synthetic_row1_section :
    (parseFixture syntheticFixture)[1]!.sectionName = "Hazard" := by decide

theorem synthetic_row1_kind :
    (parseFixture syntheticFixture)[1]!.expectedKind = .hazard := by decide

theorem synthetic_row1_sub :
    (parseFixture syntheticFixture)[1]!.expectedSubThreat = some "DirectPayload" := by
  decide

theorem synthetic_row1_positions :
    (parseFixture syntheticFixture)[1]!.expectedPositions = #[1, 2] := by decide

theorem synthetic_row1_decoded :
    (parseFixture syntheticFixture)[1]!.attribution.get? "decoded" = some "A" := by
  decide

/-- Row 2 is the Nethereum compound case (strict level). -/
theorem synthetic_row2_level :
    (parseFixture syntheticFixture)[2]!.conformanceLevel = .strict := by decide

theorem synthetic_row2_matched_target :
    (parseFixture syntheticFixture)[2]!.attribution.get? "matched_target"
      = some "Nethereum" := by
  decide

/-- Row 3 inherits the "Compound" section but level=full from the
    interim @level directive. -/
theorem synthetic_row3_section :
    (parseFixture syntheticFixture)[3]!.sectionName = "Compound" := by decide

theorem synthetic_row3_level :
    (parseFixture syntheticFixture)[3]!.conformanceLevel = .full := by decide

/-- Row 4 is in the CleanNegatives section, back to basic. -/
theorem synthetic_row4_section :
    (parseFixture syntheticFixture)[4]!.sectionName = "CleanNegatives" := by
  decide

theorem synthetic_row4_level :
    (parseFixture syntheticFixture)[4]!.conformanceLevel = .basic := by decide

theorem synthetic_row4_kind :
    (parseFixture syntheticFixture)[4]!.expectedKind = .clear := by decide

end Unicode.Security.Fixture
