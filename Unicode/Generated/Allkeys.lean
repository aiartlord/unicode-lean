/-
  Unicode.Generated.Allkeys

  Default Unicode Collation Element Table (DUCET) from
  `Unicode/Ucd/allkeys.txt` (UCA 16.0.0), embedded as a String
  constant via `include_str` and parsed once at module load.

  Each non-comment, non-directive row of `allkeys.txt` has the form

      <key> ; <weights> # <comment>

  where `<key>` is a space-separated sequence of one or more
  hex codepoints (a single codepoint or a contraction), and
  `<weights>` is a non-empty sequence of bracketed collation
  elements `[.PPPP.SSSS.TTTT]` or `[*PPPP.SSSS.TTTT]` (the asterisk
  marks the element as "variable" — typically punctuation and
  symbols whose primary weight is shifted under the SHIFTED
  variable-handling policy).

  The `@implicitweights` directives that introduce algorithmic
  weights for Tangut, Nushu, and Khitan are recorded in a separate
  table; codepoints not covered by either explicit DUCET entries
  or `@implicitweights` blocks fall under the default UCA
  implicit-weight formula in `Unicode.Uca.Algorithm`.
-/

namespace Unicode.Generated.Allkeys

/-- One UCA collation element. The `variable` flag distinguishes
    `[*…]` elements (variable, often punctuation) from `[.…]` ones. -/
structure CollationElement where
  primary   : Nat
  secondary : Nat
  tertiary  : Nat
  isVariable : Bool
  deriving Repr, Inhabited, DecidableEq

/-- One DUCET row: a key sequence (one or more codepoints) and the
    collation elements it expands to. Single-codepoint rows have
    `key.size = 1`; contractions have `key.size ≥ 2`. -/
structure DucetEntry where
  key : Array Nat
  ces : Array CollationElement
  deriving Repr, Inhabited, DecidableEq

/-- An `@implicitweights` directive block. Codepoints `min..max`
    inclusive get the implicit primary weight starting from `base`,
    computed per UCA §10.1.3. -/
structure ImplicitBlock where
  min  : Nat
  max  : Nat
  base : Nat
  deriving Repr, Inhabited

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

/-- Parse a key field — space-separated hex codepoints. -/
def parseKey (s : String) : Array Nat :=
  ((s.splitOn " ").filterMap (fun tok =>
    let t := trimS tok
    if t.isEmpty then none else some (parseHex t))).toArray

/-- Drop the first `n` characters from `s` and return a new String. -/
@[inline]
def stringDrop (s : String) (n : Nat) : String := (s.toRawSubstring.drop n).toString

/-- Drop the last `n` characters from `s` and return a new String. -/
@[inline]
def stringDropRight (s : String) (n : Nat) : String := (s.toRawSubstring.dropRight n).toString

/-- Parse a single bracketed collation element `[.PPPP.SSSS.TTTT]`
    or `[*PPPP.SSSS.TTTT]`. The brackets are already stripped. -/
def parseElementBody (body : String) : Option CollationElement :=
  let (isVar, rest) :=
    if body.startsWith "*" then (true, stringDrop body 1)
    else if body.startsWith "." then (false, stringDrop body 1)
    else (false, body)
  let parts := rest.splitOn "."
  match parts with
  | [p, s, t] => some ⟨parseHex (trimS p), parseHex (trimS s), parseHex (trimS t), isVar⟩
  | malformed => Function.const (List String) none malformed

/-- Parse the weights field — a sequence of `[…]` brackets. -/
def parseWeights (s : String) : Array CollationElement :=
  let trimmed := trimS s
  let chunks : List String :=
    if trimmed.isEmpty then []
    else
      let inner := if trimmed.startsWith "[" then stringDrop trimmed 1 else trimmed
      let inner := if inner.endsWith "]" then stringDropRight inner 1 else inner
      inner.splitOn "]["
  ((chunks.filterMap parseElementBody)).toArray

/-- Parse one DUCET row. Returns `none` for blank lines, comment
    lines, or directive lines (those starting with `@`). -/
def parseRow (rawLine : String) : Option DucetEntry := Id.run do
  let stripped : String := (rawLine.takeWhile (· != '#')).toString
  let line := trimS stripped
  if line.isEmpty then return none
  if line.startsWith "@" then return none
  let fields := String.splitOn line ";"
  match fields with
  | [keyField, weightsField] =>
    let key := parseKey (trimS keyField)
    let ces := parseWeights (trimS weightsField)
    if key.isEmpty ∨ ces.isEmpty then none
    else some ⟨key, ces⟩
  | malformed => Function.const (List String) none malformed

/-- Parse one `@implicitweights min..max; base` directive line. -/
def parseImplicit (rawLine : String) : Option ImplicitBlock :=
  let stripped : String := (rawLine.takeWhile (· != '#')).toString
  let line := trimS stripped
  if !line.startsWith "@implicitweights" then none
  else
    let body := trimS (stringDrop line "@implicitweights".length)
    match body.splitOn ";" with
    | [rangeField, baseField] =>
      match (trimS rangeField).splitOn ".." with
      | [lo, hi] =>
        some ⟨parseHex (trimS lo), parseHex (trimS hi), parseHex (trimS baseField)⟩
      | malformedRange => Function.const (List String) none malformedRange
    | malformed => Function.const (List String) none malformed

/-- Raw text of `allkeys.txt`, embedded at compile time. -/
def allkeysRaw : String := include_str "../Ucd/allkeys.txt"

/-- All explicit DUCET rows. -/
def ducetEntries : Array DucetEntry :=
  ((allkeysRaw.splitOn "\n").filterMap parseRow).toArray

/-- All `@implicitweights` directive blocks. -/
def implicitBlocks : Array ImplicitBlock :=
  ((allkeysRaw.splitOn "\n").filterMap parseImplicit).toArray

/-- Look up the DUCET entry whose key is a single codepoint `cp`,
    or `none` if `cp` is not in the explicit table. Multi-codepoint
    contractions are not exposed here; the algorithm-level lookup
    (in `Unicode.Uca.Lookup`) handles the greedy matching. -/
def lookupSingle (cp : Nat) : Option DucetEntry :=
  ducetEntries.findSome? (fun e =>
    if e.key.size = 1 ∧ e.key[0]? = some cp then some e else none)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 SHAPE CHECKS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The DUCET parses to many thousands of rows. The exact count is
    a useful invariant: `allkeys-16.0.0` ships 39407 explicit rows. -/
theorem ducetEntries_count : ducetEntries.size = 39407 := by native_decide

/-- The 16.0.0 file declares four `@implicitweights` blocks. -/
theorem implicitBlocks_count : implicitBlocks.size = 4 := by native_decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 KNOWN-ENTRY SPOT CHECKS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- LATIN SMALL LETTER A: `[.2380.0020.0002]`. -/
theorem lookup_a :
    lookupSingle 0x0061 = some
      ⟨#[0x0061], #[⟨0x2380, 0x0020, 0x0002, false⟩]⟩ := by native_decide

/-- LATIN CAPITAL A shares the primary with 'a' but uses a different
    tertiary weight (`0x0008`) — this is how UCA encodes case at L3. -/
theorem lookup_A :
    lookupSingle 0x0041 = some
      ⟨#[0x0041], #[⟨0x2380, 0x0020, 0x0008, false⟩]⟩ := by native_decide

/-- SPACE U+0020 is variable-weighted (the asterisk in the source
    file). -/
theorem lookup_space :
    lookupSingle 0x0020 = some
      ⟨#[0x0020], #[⟨0x0209, 0x0020, 0x0002, true⟩]⟩ := by native_decide

/-- LATIN SMALL LETTER A WITH GRAVE expands to two collation
    elements — the base 'a' weight followed by an accent secondary. -/
theorem lookup_agrave :
    lookupSingle 0x00E0 = some
      ⟨#[0x00E0],
       #[⟨0x2380, 0x0020, 0x0002, false⟩,
         ⟨0x0000, 0x0025, 0x0002, false⟩]⟩ := by native_decide

/-- A contraction is parsed with `key.size = 2`. -/
theorem ducet_has_contractions :
    (ducetEntries.filter (fun e => e.key.size ≥ 2)).size = 964 := by native_decide

end Unicode.Generated.Allkeys
