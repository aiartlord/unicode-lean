/-
  Unicode.Generated.EmojiData

  Emoji property ranges from `lemma/lean/Unicode/Ucd/emoji-data.txt`
  (UTS #51 17.0.0), embedded as a String constant via `include_str`
  and parsed once at module load. Pattern follows
  `fgdorais/lean4-unicode-basic`.

  Semantics (UTS #51): each row assigns one emoji boolean property
  to one closed codepoint interval. Codepoints not covered by any
  row default to absence of the property.

  Only the property values needed by UAX #29 segmentation rules
  (Extended_Pictographic) are exported here. The remaining
  properties (Emoji, Emoji_Component, Emoji_Modifier,
  Emoji_Modifier_Base, Emoji_Presentation) are parsed but not
  re-exported, in line with the project's import-only-what-you-use
  convention.
-/

namespace Unicode.Generated.EmojiData

/-- The six emoji boolean properties per UTS #51. -/
inductive EmojiProp where
  | Emoji
  | Emoji_Presentation
  | Emoji_Modifier
  | Emoji_Modifier_Base
  | Emoji_Component
  | Extended_Pictographic
  deriving DecidableEq, Repr, Inhabited

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
  match String.splitOn line ";" with
  | rngField :: propField :: _ =>
    let (lo, hi) := parseRange (trimS rngField)
    match parseEmojiProp? (trimS propField) with
    | some p => some (lo, hi, p)
    | none   => none
  | irregularSplit => Function.const (List String) none irregularSplit

/-- Raw text of `emoji-data.txt`, embedded at compile time. -/
def emojiDataRaw : String :=
  include_str "../Ucd/emoji-data.txt"

/-- All parsed (lo, hi, prop) rows. -/
def parsedRows : Array (Nat × Nat × EmojiProp) :=
  ((emojiDataRaw.splitOn "\n").filterMap parseRow).toArray

/-- Extended_Pictographic ranges (UAX #29 §3 dependency for GB11). -/
def extendedPictographic : Array (Nat × Nat) :=
  parsedRows.filterMap (fun r =>
    if r.2.2 = .Extended_Pictographic then some (r.1, r.2.1) else none)

/-- True iff `cp` has the Extended_Pictographic property. -/
def isExtendedPictographic (cp : Nat) : Bool :=
  extendedPictographic.any (fun r => r.1 ≤ cp ∧ cp ≤ r.2)

end Unicode.Generated.EmojiData
