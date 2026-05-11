/-
  Unicode.Security.Display.SourceCodeTokenize

  Language-aware tokenization of a codepoint stream into the four
  region kinds D1 cares about: `code`, `stringLiteral`,
  `lineComment`, `blockComment`.  Used by `D1.detectIn` to scope
  Layer-1 / Layer-2 sub-detector firing to the regions where each
  hazard class is meaningful — bidi controls inside a string
  literal are data, not display deception; an unregistered VS
  inside a `// comment` is a documentation choice, not a payload.

  Two language instances ship in v1.5:

  * `cStyleGeneric` — `// line comments`, `/* block comments */`
    (single-level), `"strings"`, `'chars'`, backslash escapes
    inside strings.  Covers Java / Go / C / C++ (modulo
    preprocessor and raw strings) / Kotlin / Swift / C# / JS / TS
    (modulo template literals and regex-context) at the
    first-approximation level.

  * `rust` — strict superset of `cStyleGeneric` that adds:
    (a) nestable `/* /* ... */ */` block comments tracking depth;
    (b) raw strings `r"..."`, `r#"..."#`, `r##"..."##`, … where
    the closing delimiter requires exactly the same number of
    `#` characters as the opening, allowing `"` inside the
    string body.

  Plus a `Language.none` fallback that treats the whole input as
  a single `code` region.  `Language.none` makes `D1.detectIn`
  equivalent to the v1 language-agnostic `D1.detect`, so the
  refactor is backwards-compatible at the verdict level.
-/

namespace Unicode.Security.Display.SourceCodeTokenize

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The four region kinds tokenization produces. -/
inductive TokenKind where
  | code
  | stringLiteral
  | lineComment
  | blockComment
  deriving DecidableEq, Repr, Inhabited

/-- A contiguous half-open `[startPos, endPos)` region of the
    input with a single token kind. -/
structure TokenRegion where
  kind     : TokenKind
  startPos : Nat
  endPos   : Nat
  deriving DecidableEq, Repr, Inhabited

/-- The languages D1 dispatches on.  `none` is the v1
    language-agnostic fallback. -/
inductive Language where
  | none
  | cStyleGeneric
  | rust
  deriving DecidableEq, Repr, Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Scanner state
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Internal scanner state.  Carries the current region kind plus
    whatever auxiliary data the kind needs:

    * `inCode`             — no aux data
    * `inStringLit delim`  — closing delimiter (`"` or `'`)
    * `inRawString hashes` — number of trailing `#` required to
                              close the Rust raw string
    * `inLineComment`      — no aux data; ends at next `\n`
    * `inBlockComment depth` — Rust nestable comments increment /
                                decrement depth; cStyleGeneric
                                holds depth at 1. -/
private inductive ScanState where
  | inCode
  | inStringLit    (delim : Nat)
  | inRawString    (hashes : Nat)
  | inLineComment
  | inBlockComment (depth : Nat)
  deriving DecidableEq, Repr, Inhabited

private def ScanState.toKind : ScanState → TokenKind
  | .inCode                => .code
  | .inStringLit  delim    => Function.const Nat .stringLiteral delim
  | .inRawString  hashes   => Function.const Nat .stringLiteral hashes
  | .inLineComment         => .lineComment
  | .inBlockComment depth  => Function.const Nat .blockComment depth

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Lookahead helpers
-- ═══════════════════════════════════════════════════════════════════════════════

@[inline]
private def at? (input : Array Nat) (pos : Nat) : Option Nat :=
  if h : pos < input.size then some input[pos] else none

/-- True iff `input[pos]` and `input[pos+1]` exist and equal the
    given pair. -/
@[inline]
private def look2 (input : Array Nat) (pos : Nat) (a b : Nat) : Bool :=
  match at? input pos, at? input (pos + 1) with
  | some x, some y => decide (x = a ∧ y = b)
  | look2A, look2B =>
    Function.const (Option Nat × Option Nat) false (look2A, look2B)

/-- Count consecutive `#` characters starting at `pos`. -/
private def countHashesGo (input : Array Nat) (pos : Nat) (acc : Nat)
    (fuel : Nat) : Nat :=
  match fuel with
  | 0           => acc
  | fuel' + 1 =>
    match at? input pos with
    | some 0x23  => countHashesGo input (pos + 1) (acc + 1) fuel'
    | nonHashCp  => Function.const (Option Nat) acc nonHashCp

@[inline]
private def countHashes (input : Array Nat) (pos : Nat) : Nat :=
  countHashesGo input pos 0 input.size

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Transition rules
-- ═══════════════════════════════════════════════════════════════════════════════

/-- One step of the scanner.  Returns `(newState, consumed)` —
    how many input codepoints to advance past.  Bumping by ≥ 2
    on the same call is used for two-character openers (`//`,
    `/*`, `r"`) and for backslash-escapes inside strings, both
    of which must be consumed atomically. -/
private def stepCStyle (input : Array Nat) (pos : Nat)
    (state : ScanState) : ScanState × Nat :=
  match state with
  | .inCode =>
    if look2 input pos 0x2F 0x2F then       -- "//"
      (.inLineComment, 2)
    else if look2 input pos 0x2F 0x2A then  -- "/*"
      (.inBlockComment 1, 2)
    else
      match at? input pos with
      | some 0x22  => (.inStringLit 0x22, 1)  -- '"'
      | some 0x27  => (.inStringLit 0x27, 1)  -- '\''
      | otherInCode =>
        Function.const (Option Nat) (.inCode, 1) otherInCode
  | .inStringLit delim =>
    match at? input pos with
    | some 0x5C =>                            -- '\\' escape
      match at? input (pos + 1) with
      | some followingCp =>
        Function.const Nat (.inStringLit delim, 2) followingCp
      | none             => (.inStringLit delim, 1)
    | some c =>
      if c = delim then (.inCode, 1) else (.inStringLit delim, 1)
    | none      => (.inStringLit delim, 0)
  | .inLineComment =>
    match at? input pos with
    | some 0x0A         => (.inCode, 1)
    | otherInLineComment =>
      Function.const (Option Nat) (.inLineComment, 1) otherInLineComment
  | .inBlockComment depth =>
    if look2 input pos 0x2A 0x2F then       -- "*/"
      (.inCode, 2)
    else
      Function.const Nat (.inBlockComment 1, 1) depth
  | .inRawString hashes =>
    Function.const Nat (.inRawString hashes, 1) hashes

/-- Rust step rules — extend cStyleGeneric with nestable block
    comments and raw strings.  Falls through to `stepCStyle` for
    everything not Rust-specific. -/
private def stepRust (input : Array Nat) (pos : Nat)
    (state : ScanState) : ScanState × Nat :=
  match state with
  | .inCode =>
    -- `r"..."` or `r#"..."#` opening
    if look2 input pos 0x72 0x22 then
      (.inRawString 0, 2)
    else if look2 input pos 0x72 0x23 then
      let hashes := countHashes input (pos + 1)
      match at? input (pos + 1 + hashes) with
      | some 0x22       => (.inRawString hashes, 2 + hashes)
      | rawOpenerOther  =>
        Function.const (Option Nat) (.inCode, 1) rawOpenerOther
    else
      stepCStyle input pos state
  | .inBlockComment depth =>
    if look2 input pos 0x2F 0x2A then       -- "/*" inside block: nest
      (.inBlockComment (depth + 1), 2)
    else if look2 input pos 0x2A 0x2F then  -- "*/" inside block
      if depth ≤ 1 then (.inCode, 2)
      else (.inBlockComment (depth - 1), 2)
    else
      (.inBlockComment depth, 1)
  | .inRawString hashes =>
    -- Closing: `"` followed by exactly `hashes` `#` characters
    match at? input pos with
    | some 0x22 =>
      let following := countHashes input (pos + 1)
      if hashes ≤ following then (.inCode, 1 + hashes)
      else (.inRawString hashes, 1)
    | rawContentOther =>
      Function.const (Option Nat) (.inRawString hashes, 1) rawContentOther
  | otherState => stepCStyle input pos otherState

private def step (lang : Language) (input : Array Nat) (pos : Nat)
    (state : ScanState) : ScanState × Nat :=
  match lang with
  | .none          => Function.const (Array Nat × Nat × ScanState) (.inCode, 1) (input, pos, state)
  | .cStyleGeneric => stepCStyle input pos state
  | .rust          => stepRust input pos state

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Scanner driver
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Drive the per-step scanner across the input.  Conventions:

    * Delimiters belong to the region they bracket — `"abc"`
      tokenizes to one stringLiteral region of length 5, not three
      regions split around the quotes.  Equivalently: on a
      `code → non-code` transition the boundary sits at `pos`
      (the opener is part of the new region); on a
      `non-code → code` transition the boundary sits at
      `pos + consumed` (the closer is part of the old region).

    * Inner state changes that preserve `TokenKind` — e.g. Rust
      block-comment depth going from 1 to 2 — do not emit a
      region boundary.

    * Zero-length regions (would-be `[k, k)` spans) are dropped.

    Fuel bound `input.size + 2` is a strict overestimate because
    every recursive call advances `pos` by at least 1. -/
private def scanGo (lang : Language) (input : Array Nat)
    (pos regionStart : Nat) (state : ScanState)
    (regions : Array TokenRegion) (fuel : Nat) : Array TokenRegion :=
  match fuel with
  | 0           => regions
  | fuel' + 1 =>
    if pos ≥ input.size then
      if regionStart < pos then
        regions.push { kind := state.toKind,
                       startPos := regionStart, endPos := pos }
      else regions
    else
      let (newState, consumed) := step lang input pos state
      let consumed' := if consumed = 0 then 1 else consumed
      let nextPos := pos + consumed'
      if newState.toKind = state.toKind then
        scanGo lang input nextPos regionStart newState regions fuel'
      else
        let boundary :=
          match state, newState with
          | .inCode,    boundaryAfterOpener =>
            Function.const ScanState pos boundaryAfterOpener
          | boundaryBeforeCloser, .inCode =>
            Function.const ScanState nextPos boundaryBeforeCloser
          | boundaryNonCodeFrom, boundaryNonCodeTo =>
            Function.const (ScanState × ScanState) pos
              (boundaryNonCodeFrom, boundaryNonCodeTo)
        let regions' :=
          if regionStart < boundary then
            regions.push
              { kind := state.toKind,
                startPos := regionStart, endPos := boundary }
          else regions
        scanGo lang input nextPos boundary newState regions' fuel'

/-- Tokenize `input` under `lang`, producing a sequence of
    `TokenRegion`s that partition `[0, input.size)` exactly.
    Consecutive regions never share a kind. -/
def tokenize (lang : Language) (input : Array Nat) : Array TokenRegion :=
  match lang with
  | .none =>
    if input.size = 0 then #[]
    else #[{ kind := .code, startPos := 0, endPos := input.size }]
  | langWithGrammar =>
    if input.size = 0 then
      Function.const Language #[] langWithGrammar
    else scanGo langWithGrammar input 0 0 .inCode #[] (input.size + 2)

/-- True iff input position `i` lies inside a region of kind
    `kind` in the tokenization of `input` under `lang`. -/
def positionInRegionKind (lang : Language) (input : Array Nat)
    (i : Nat) (kind : TokenKind) : Bool :=
  (tokenize lang input).any (fun r =>
    decide (r.kind = kind ∧ r.startPos ≤ i ∧ i < r.endPos))

/-- True iff input position `i` lies inside any code region
    (i.e. is NOT inside a string literal, line comment, or
    block comment).  This is the position-level predicate
    `D1.detectIn` uses to decide whether to honour each
    sub-detector's hit at position `i`. -/
@[inline]
def positionInCode (lang : Language) (input : Array Nat) (i : Nat) : Bool :=
  positionInRegionKind lang input i .code

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input tokenizes to no regions. -/
theorem tokenize_empty_none : tokenize .none #[] = #[] := by native_decide

theorem tokenize_empty_cstyle :
    tokenize .cStyleGeneric #[] = #[] := by native_decide

theorem tokenize_empty_rust : tokenize .rust #[] = #[] := by native_decide

/-- `Language.none` produces exactly one code region spanning
    the whole input. -/
theorem tokenize_none_one_region :
    tokenize .none #[0x41, 0x42, 0x43] =
      #[{ kind := .code, startPos := 0, endPos := 3 }] := by native_decide

/-- A plain ASCII expression under cStyleGeneric is one code
    region (no string, no comment). -/
theorem tokenize_cstyle_plain :
    tokenize .cStyleGeneric #[0x41, 0x42, 0x43] =
      #[{ kind := .code, startPos := 0, endPos := 3 }] := by native_decide

/-- `"AB"` under cStyleGeneric: one stringLiteral region spanning
    the opening quote, body, and closing quote — delimiters belong
    to the bracketing region by convention. -/
theorem tokenize_cstyle_string :
    tokenize .cStyleGeneric #[0x22, 0x41, 0x42, 0x22] =
      #[{ kind := .stringLiteral, startPos := 0, endPos := 4 }] := by
  native_decide

/-- `A // B` under cStyleGeneric: code region `A `, line comment
    `// B` running to end-of-input. -/
theorem tokenize_cstyle_line_comment :
    tokenize .cStyleGeneric
        #[0x41, 0x20, 0x2F, 0x2F, 0x20, 0x42] =
      #[{ kind := .code,        startPos := 0, endPos := 2 },
        { kind := .lineComment, startPos := 2, endPos := 6 }] := by
  native_decide

/-- `/* B */` under cStyleGeneric: one blockComment region
    spanning the opener, body, and closer. -/
theorem tokenize_cstyle_block_comment :
    tokenize .cStyleGeneric #[0x2F, 0x2A, 0x42, 0x2A, 0x2F] =
      #[{ kind := .blockComment, startPos := 0, endPos := 5 }] := by
  native_decide

/-- Nested block comment `/* /* x */ */` under Rust: a single
    blockComment region spanning all nine codepoints because the
    Rust scanner tracks depth and only exits on the outer `*/`. -/
theorem tokenize_rust_nested_block :
    tokenize .rust
        #[0x2F, 0x2A, 0x2F, 0x2A, 0x78, 0x2A, 0x2F, 0x2A, 0x2F] =
      #[{ kind := .blockComment, startPos := 0, endPos := 9 }] := by
  native_decide

/-- Same input under cStyleGeneric closes at the FIRST `*/`,
    leaving the trailing `*/` as code — the observable difference
    from Rust. -/
theorem tokenize_cstyle_nested_closes_at_first :
    tokenize .cStyleGeneric
        #[0x2F, 0x2A, 0x2F, 0x2A, 0x78, 0x2A, 0x2F, 0x2A, 0x2F] =
      #[{ kind := .blockComment, startPos := 0, endPos := 7 },
        { kind := .code,         startPos := 7, endPos := 9 }] := by
  native_decide

/-- Rust raw string `r#"a"b"#` (8 codepoints) is a single
    stringLiteral region because the closing `"` requires the
    matching `#` count — the inner `"` does not close the string. -/
theorem tokenize_rust_raw_string_hashed :
    tokenize .rust
        #[0x72, 0x23, 0x22, 0x61, 0x22, 0x62, 0x22, 0x23] =
      #[{ kind := .stringLiteral, startPos := 0, endPos := 8 }] := by
  native_decide

/-- Backslash-escape inside a string consumes both `\` and the
    following character, so `"\""` is a single stringLiteral
    region of length 4 — the inner `"` is escaped, the final `"`
    is the closer. -/
theorem tokenize_cstyle_escape :
    tokenize .cStyleGeneric #[0x22, 0x5C, 0x22, 0x22] =
      #[{ kind := .stringLiteral, startPos := 0, endPos := 4 }] := by
  native_decide

/-- A code → string → code sandwich (`A "B" C`) tokenizes to
    three regions, demonstrating that the delimiter-inclusion
    convention still produces the expected boundaries when the
    string is embedded between code spans. -/
theorem tokenize_cstyle_sandwich :
    tokenize .cStyleGeneric
        #[0x41, 0x20, 0x22, 0x42, 0x22, 0x20, 0x43] =
      #[{ kind := .code,          startPos := 0, endPos := 2 },
        { kind := .stringLiteral, startPos := 2, endPos := 5 },
        { kind := .code,          startPos := 5, endPos := 7 }] := by
  native_decide

/-- Position-in-code predicate: position 0 (`A`) is in code,
    position 3 (the `B` inside `"B"`) is not, position 6 (`C`)
    is back in code. -/
theorem positionInCode_sandwich :
    let input := #[0x41, 0x20, 0x22, 0x42, 0x22, 0x20, 0x43]
    positionInCode .cStyleGeneric input 0 = true ∧
    positionInCode .cStyleGeneric input 3 = false ∧
    positionInCode .cStyleGeneric input 6 = true := by
  native_decide

end Unicode.Security.Display.SourceCodeTokenize
