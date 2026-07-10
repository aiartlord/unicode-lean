/-
  Unicode.Generated.EmojiData

  Emoji property ranges from `lemma/lean/Unicode/Ucd/emoji-data.txt`
  (UTS #51 17.0.0). The property values and the pinned `List` of parsed
  rows (`parsedRowsList`) live in `Unicode.Generated.EmojiDataRows`; the
  per-property range tables `filterMap` over that `List` and the `is*`
  membership tests reduce in the kernel. This module keeps the
  `include_str` source and the parser, and a build-time drift gate
  (`#eval`) proves the materialized rows match a fresh parse.

  Semantics (UTS #51): each row assigns one emoji boolean property
  to one closed codepoint interval. Codepoints not covered by any
  row default to absence of the property.
-/

import Unicode.Generated.EmojiDataRows

namespace Unicode.Generated.EmojiData

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

def parseRange (s : String) : Nat × Nat :=
  match String.splitOn s ".." with
  | [single]  => let n := parseHex single; (n, n)
  | [a, b]    => (parseHex a, parseHex b)
  | irregularRange => Function.const (List String) (0, 0) irregularRange

def parseEmojiProp? : String → Option EmojiProp
  | "Emoji"                 => some .Emoji
  | "Emoji_Presentation"    => some .Emoji_Presentation
  | "Emoji_Modifier"        => some .Emoji_Modifier
  | "Emoji_Modifier_Base"   => some .Emoji_Modifier_Base
  | "Emoji_Component"       => some .Emoji_Component
  | "Extended_Pictographic" => some .Extended_Pictographic
  | unknownEmojiProp        => Function.const String none unknownEmojiProp

/-- Parse one row of emoji-data.txt. Returns `none` for blank/comment
    lines or unrecognised property names. -/
def parseRow (rawLine : String) : Option (Nat × Nat × EmojiProp) :=
  let stripped : String := (rawLine.takeWhile (· != '#')).toString
  let line := trimS stripped
  if line.isEmpty then none else
  let fields : Array String := (String.splitOn line ";").toArray
  if fields.size ≥ 2 then
    let rngField := fields[0]!
    let propField := fields[1]!
    let (lo, hi) := parseRange (trimS rngField)
    match parseEmojiProp? (trimS propField) with
    | some p => some (lo, hi, p)
    | none   => none
  else
    none

/-- Raw text of `emoji-data.txt`, embedded at compile time. -/
def emojiDataRaw : String :=
  include_str "../Ucd/emoji-data.txt"

/-- All parsed (lo, hi, prop) rows. -/
def parsedRows : Array (Nat × Nat × EmojiProp) :=
  ((emojiDataRaw.splitOn "\n").filterMap parseRow).toArray

/-- Extended_Pictographic ranges (UAX #29 §3 dependency for GB11).
    Filtered from the materialized `parsedRowsList` so kernel reduction
    stays linear. -/
def extendedPictographic : List (Nat × Nat) :=
  parsedRowsList.filterMap (fun r =>
    if r.2.2 = .Extended_Pictographic then some (r.1, r.2.1) else none)

/-- Emoji ranges. -/
def emoji : List (Nat × Nat) :=
  parsedRowsList.filterMap (fun r =>
    if r.2.2 = .Emoji then some (r.1, r.2.1) else none)

/-- Emoji_Presentation ranges. -/
def emojiPresentation : List (Nat × Nat) :=
  parsedRowsList.filterMap (fun r =>
    if r.2.2 = .Emoji_Presentation then some (r.1, r.2.1) else none)

/-- Emoji_Modifier ranges (the five skin-tone modifiers). -/
def emojiModifier : List (Nat × Nat) :=
  parsedRowsList.filterMap (fun r =>
    if r.2.2 = .Emoji_Modifier then some (r.1, r.2.1) else none)

/-- Emoji_Modifier_Base ranges (codepoints accepting a skin-tone modifier). -/
def emojiModifierBase : List (Nat × Nat) :=
  parsedRowsList.filterMap (fun r =>
    if r.2.2 = .Emoji_Modifier_Base then some (r.1, r.2.1) else none)

/-- Emoji_Component ranges (regional indicators, modifiers, joiners,
    keycap-eligible digits/symbols). -/
def emojiComponent : List (Nat × Nat) :=
  parsedRowsList.filterMap (fun r =>
    if r.2.2 = .Emoji_Component then some (r.1, r.2.1) else none)

/-- True iff `cp` has the Extended_Pictographic property. -/
def isExtendedPictographic (cp : Nat) : Bool :=
  extendedPictographic.any (fun r => r.1 ≤ cp ∧ cp ≤ r.2)

/-- True iff `cp` has the Emoji property (rendered as emoji by default). -/
def isEmoji (cp : Nat) : Bool :=
  emoji.any (fun r => r.1 ≤ cp ∧ cp ≤ r.2)

/-- True iff `cp` has the Emoji_Presentation property (defaults to
    emoji rather than text presentation absent a variation selector). -/
def isEmojiPresentation (cp : Nat) : Bool :=
  emojiPresentation.any (fun r => r.1 ≤ cp ∧ cp ≤ r.2)

/-- True iff `cp` is one of the five Emoji_Modifier skin-tone codepoints
    U+1F3FB..U+1F3FF. -/
def isEmojiModifier (cp : Nat) : Bool :=
  emojiModifier.any (fun r => r.1 ≤ cp ∧ cp ≤ r.2)

/-- True iff `cp` is an Emoji_Modifier_Base — a codepoint that accepts
    a skin-tone modifier immediately following it. -/
def isEmojiModifierBase (cp : Nat) : Bool :=
  emojiModifierBase.any (fun r => r.1 ≤ cp ∧ cp ≤ r.2)

/-- True iff `cp` has the Emoji_Component property — a codepoint
    permitted to appear as a non-leading component of an emoji
    sequence (regional indicators, modifiers, hair-style joiners,
    keycap-eligible digits and symbols). -/
def isEmojiComponent (cp : Nat) : Bool :=
  emojiComponent.any (fun r => r.1 ≤ cp ∧ cp ≤ r.2)

-- ═══════════════════════════════════════════════════════════════════════════════
-- DRIFT GATE
--
-- Build-time assertion (compiled `#eval`) that the materialized
-- `parsedRowsList` agrees exactly with a fresh parse of the pinned
-- `emoji-data.txt`. A mismatch aborts the build.
-- ═══════════════════════════════════════════════════════════════════════════════

#eval do
  unless parsedRowsList.toArray == parsedRows do
    throw (IO.userError "EmojiData drift: parsedRowsList ≠ parsed parsedRows")

end Unicode.Generated.EmojiData
