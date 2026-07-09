/-
  Unicode.Generated.EmojiSequences

  RGI (Recommended for General Interchange) emoji sequence tables
  parsed from `emoji-sequences.txt` and `emoji-zwj-sequences.txt`
  (UTS #51 Emoji 17.0). The two files together enumerate every
  fully-qualified emoji sequence the Unicode Consortium recommends
  for keyboards and pickers; downstream renderers should produce a
  single emoji glyph for any sequence in this set.

  The five sequence types in `emoji-sequences.txt`:

    * Basic_Emoji                  — single codepoints (and
                                     codepoint + VS16 pairs) that
                                     are emoji on their own.
    * Emoji_Keycap_Sequence        — base + U+FE0F + U+20E3.
    * RGI_Emoji_Flag_Sequence      — two regional indicators that
                                     name a registered country/region.
    * RGI_Emoji_Modifier_Sequence  — base + skin-tone modifier.
    * RGI_Emoji_Tag_Sequence       — base + tag-spec* + cancel-tag,
                                     covering the registered
                                     subdivision flags (e.g. England,
                                     Scotland, Wales).

  Plus the ZWJ-sequence file's single type:

    * RGI_Emoji_ZWJ_Sequence       — base sequences joined by U+200D
                                     ZERO WIDTH JOINER. Includes
                                     family/couple sequences,
                                     profession sequences, gender
                                     variants, hair-component bases,
                                     and direction variants.

  Basic_Emoji rows often use a `lo..hi` range; every other type
  carries an explicit codepoint sequence. The parser below treats
  ranges as a special case alongside fixed-length sequences.

  The property types, the `SequenceRow` structure, and the pinned `List`
  of parsed rows (`parsedRowsList`) live in
  `Unicode.Generated.EmojiSequencesData`; the per-type sequence tables
  derive from that `List` and the membership tests reduce in the kernel.
  This module keeps the `include_str` sources and the parsers, and a
  build-time drift gate (`#eval`) proves the materialized rows match a
  fresh parse.
-/

import Unicode.Generated.EmojiSequencesData

namespace Unicode.Generated.EmojiSequences

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

def parseType? : String → Option RgiSequenceType
  | "Basic_Emoji"                 => some .Basic_Emoji
  | "Emoji_Keycap_Sequence"       => some .Emoji_Keycap_Sequence
  | "RGI_Emoji_Flag_Sequence"     => some .RGI_Emoji_Flag_Sequence
  | "RGI_Emoji_Modifier_Sequence" => some .RGI_Emoji_Modifier_Sequence
  | "RGI_Emoji_Tag_Sequence"      => some .RGI_Emoji_Tag_Sequence
  | "RGI_Emoji_ZWJ_Sequence"      => some .RGI_Emoji_ZWJ_Sequence
  | unknown                       => Function.const String none unknown

/-- Parse a whitespace-separated list of hex codepoints into an
    `Array Nat`. Empty tokens are skipped. -/
def parseCodepointList (s : String) : Array Nat :=
  ((s.splitOn " ").filterMap (fun tok =>
    let t := trimS tok
    if t.isEmpty then none else some (parseHex t))).toArray


/-- Parse one sequence-file row. Returns `none` for blank or
    comment lines, or for rows whose type field is unrecognised. -/
def parseRow (rawLine : String) : Option SequenceRow :=
  let stripped : String := (rawLine.takeWhile (· != '#')).toString
  let line := trimS stripped
  if line.isEmpty then none else
  let fields : Array String := (String.splitOn line ";").toArray
  if fields.size ≥ 2 then
    let cpField := fields[0]!
    let typeField := fields[1]!
    match parseType? (trimS typeField) with
    | none => none
    | some t =>
      let trimmedCp := trimS cpField
      let rangeParts : Array String := (String.splitOn trimmedCp "..").toArray
      if rangeParts.size = 1 then
        -- Either one codepoint or a space-separated sequence.
        some ⟨parseCodepointList rangeParts[0]!, t, 0⟩
      else if rangeParts.size = 2 then
        let loN := parseHex (trimS rangeParts[0]!)
        let hiN := parseHex (trimS rangeParts[1]!)
        some ⟨#[loN], t, hiN⟩
      else
        none
  else
    none

/-- Raw text of `emoji-sequences.txt`, embedded at compile time. -/
def emojiSequencesRaw : String := include_str "../Ucd/emoji-sequences.txt"

/-- Raw text of `emoji-zwj-sequences.txt`, embedded at compile time. -/
def emojiZwjSequencesRaw : String := include_str "../Ucd/emoji-zwj-sequences.txt"

/-- All parsed rows from both sequence files, in source order. -/
def parsedRows : Array SequenceRow :=
  ((emojiSequencesRaw.splitOn "\n").filterMap parseRow).toArray
    ++ ((emojiZwjSequencesRaw.splitOn "\n").filterMap parseRow).toArray

/-- Filter rows by type, over the materialized `List` so downstream
    membership tests reduce linearly in the kernel. -/
def rowsOfType (t : RgiSequenceType) : List SequenceRow :=
  parsedRowsList.filter (fun r => r.type = t)

/-- Basic_Emoji rows. -/
def basicEmojiRows : List SequenceRow := rowsOfType .Basic_Emoji

/-- Keycap sequences. -/
def keycapSequences : List (Array Nat) :=
  (rowsOfType .Emoji_Keycap_Sequence).map (·.seq)

/-- Flag sequences. -/
def flagSequences : List (Array Nat) :=
  (rowsOfType .RGI_Emoji_Flag_Sequence).map (·.seq)

/-- Modifier sequences. -/
def modifierSequences : List (Array Nat) :=
  (rowsOfType .RGI_Emoji_Modifier_Sequence).map (·.seq)

/-- Tag sequences (subdivision flags). -/
def tagSequences : List (Array Nat) :=
  (rowsOfType .RGI_Emoji_Tag_Sequence).map (·.seq)

/-- ZWJ sequences. -/
def zwjSequences : List (Array Nat) :=
  (rowsOfType .RGI_Emoji_ZWJ_Sequence).map (·.seq)

/-- True iff `cp` matches a Basic_Emoji single-codepoint or range
    row. Sequences that include a variation selector (`cp + VS16`)
    count as Basic_Emoji at the codepoint level — the VS16 follow-up
    is handled by `isBasicEmojiSequence`. -/
def isBasicEmojiCodepoint (cp : Nat) : Bool :=
  basicEmojiRows.any (fun r =>
    if r.rangeMax > 0 then
      (match r.seq[0]? with
       | some lo => lo ≤ cp ∧ cp ≤ r.rangeMax
       | none    => false)
    else
      r.seq = #[cp])

/-- True iff `cps` matches some Basic_Emoji multi-codepoint row
    (e.g. `cp + U+FE0F`). -/
def isBasicEmojiSequence (cps : Array Nat) : Bool :=
  basicEmojiRows.any (fun r => r.rangeMax = 0 ∧ r.seq = cps)

/-- True iff `cps` is exactly a registered RGI keycap sequence. -/
def isRegisteredKeycapSequence (cps : Array Nat) : Bool :=
  keycapSequences.any (fun s => s = cps)

/-- True iff `cps` is exactly a registered RGI flag (region) sequence. -/
def isRegisteredFlagSequence (cps : Array Nat) : Bool :=
  flagSequences.any (fun s => s = cps)

/-- True iff `cps` is exactly a registered RGI modifier sequence. -/
def isRegisteredModifierSequence (cps : Array Nat) : Bool :=
  modifierSequences.any (fun s => s = cps)

/-- True iff `cps` is exactly a registered RGI tag (subdivision) sequence. -/
def isRegisteredTagSequence (cps : Array Nat) : Bool :=
  tagSequences.any (fun s => s = cps)

/-- True iff `cps` is exactly a registered RGI ZWJ sequence. -/
def isRegisteredZwjSequence (cps : Array Nat) : Bool :=
  zwjSequences.any (fun s => s = cps)

/-- The codepoint *alphabet* of the RGI ZWJ-sequence set: every
    distinct codepoint that occurs at any position of any
    registered RGI ZWJ sequence, excluding the ZWJ U+200D itself.

    This is the canonical "what can flank a ZWJ?" question
    answered against the Standard's own data file rather than
    approximated via the `Emoji_Presentation` property bit.
    Computed once at module load via a fold-and-dedup over
    `zwjSequences`.

    Used by `Unicode.Security.Identity.EmojiZwjIntegrity` (the I3
    detector) to decide whether a non-RGI ZWJ-containing input is
    a valid sequence shape, distinguishing keycap-eligible ASCII
    digits / `#` / `*` (which carry the `Emoji` property but do
    not appear in any registered ZWJ sequence) from legitimate
    ZWJ participants like `U+2764 HEAVY BLACK HEART` (which
    appears in registered couple-with-heart sequences but does
    not carry `Emoji_Presentation`). -/
def zwjAlphabet : Array Nat :=
  zwjSequences.foldl (init := (#[] : Array Nat)) (fun acc seq =>
    seq.foldl (init := acc) (fun a cp =>
      if cp = 0x200D then a
      else if a.contains cp then a
      else a.push cp))

/-- True iff `cp` appears at some position of a registered RGI
    ZWJ sequence (excluding the ZWJ joiner itself).  Membership
    against the pinned `zwjAlphabetList` (kernel-reducible; the
    build-time gate below proves it equals `zwjAlphabet`). -/
def isInZwjAlphabet (cp : Nat) : Bool :=
  zwjAlphabetList.contains cp

-- Build-time gate: the pinned ZWJ alphabet equals the fold-and-dedup.
#eval do
  unless zwjAlphabetList.toArray == zwjAlphabet do
    throw (IO.userError "EmojiSequences drift: zwjAlphabetList ≠ zwjAlphabet fold")

-- ═══════════════════════════════════════════════════════════════════════════════
-- DRIFT GATE
--
-- Build-time assertion (compiled `#eval`) that the materialized
-- `parsedRowsList` agrees exactly with a fresh parse of the pinned
-- `emoji-sequences.txt` + `emoji-zwj-sequences.txt`. A mismatch aborts
-- the build.
-- ═══════════════════════════════════════════════════════════════════════════════

#eval do
  unless parsedRowsList.toArray == parsedRows do
    throw (IO.userError "EmojiSequences drift: parsedRowsList ≠ parsed parsedRows")

end Unicode.Generated.EmojiSequences
