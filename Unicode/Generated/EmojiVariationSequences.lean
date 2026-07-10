/-
  Unicode.Generated.EmojiVariationSequences

  Parses `Unicode/Ucd/emoji-variation-sequences.txt` (UCD 17.0.0)
  and exposes membership predicates over the codepoints that the
  Unicode Standard sanctions as carrying *both* a text-style
  (`U+FE0E`) and an emoji-style (`U+FE0F`) variation.

  Background.  Per UTS #51, the codepoints listed in
  `emoji-variation-sequences.txt` are the *exact set* for which
  appending `U+FE0E` forces text-style rendering and appending
  `U+FE0F` forces emoji-style rendering.  Any other codepoint
  combined with VS15 / VS16 has, per the Standard, no defined
  rendering effect — and is therefore a security event in
  identifier / source-code / IDN contexts.

  File format.  Every non-comment line has shape

      CP VS ; <style>; # <name>

  where `CP` is a hex codepoint, `VS` is either `FE0E` or `FE0F`,
  and `<style>` is `text style` or `emoji style`.  Each base
  codepoint appears twice (once with each VS).  UCD 17.0.0 has
  742 rows = 371 base codepoints.

  Pattern follows `Unicode.Generated.StandardizedVariants`:
  `include_str` of the bundled UCD file, parse once at module
  load, expose membership predicates.
-/

import Unicode.Generated.EmojiVariationSequencesData

namespace Unicode.Generated.EmojiVariationSequences

set_option maxRecDepth 100000

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

/-- Parse one row.  Returns `some (base, vs)` for a well-formed
    `BASE VS; ...` row, `none` for blank / comment lines. -/
def parseRow (rawLine : String) : Option (Nat × Nat) :=
  let stripped : String := (rawLine.takeWhile (· != '#')).toString
  let line := trimS stripped
  if line.isEmpty then none
  else
    let fields : Array String := (String.splitOn line ";").toArray
    if fields.isEmpty then none
    else
      let cpField := fields[0]!
      let toks : Array String :=
        ((cpField.splitOn " ").filterMap (fun t =>
          let tt := trimS t
          if tt.isEmpty then none else some tt)).toArray
      if toks.size = 2 then
        some (parseHex toks[0]!, parseHex toks[1]!)
      else
        none

/-- Raw text of `emoji-variation-sequences.txt`, embedded at compile time. -/
def rawText : String :=
  include_str "../Ucd/emoji-variation-sequences.txt"

/-- Fresh parse of the pinned source, used only by the drift gate. -/
def parsedPairsParsed : Array (Nat × Nat) :=
  ((rawText.splitOn "\n").filterMap parseRow).toArray

/-- All parsed `(base, vs)` pairs in file order — the materialized view. -/
def parsedPairs : Array (Nat × Nat) := parsedPairsList.toArray

/-- The set of base codepoints that have a registered emoji-style
    variation (`base + U+FE0F`).  Derived from `parsedPairs`. -/
def emojiStyleBases : Array Nat :=
  parsedPairs.filterMap (fun p => if p.2 = 0xFE0F then some p.1 else none)

/-- The set of base codepoints that have a registered text-style
    variation (`base + U+FE0E`).  Per UTS #51 every emoji-style
    entry has a matching text-style entry, so this is the same
    underlying set as `emojiStyleBases`. -/
def textStyleBases : Array Nat :=
  parsedPairs.filterMap (fun p => if p.2 = 0xFE0E then some p.1 else none)

/-- True iff `(base, U+FE0F)` is a registered emoji-style
    variation sequence per UCD 17.0.0
    `emoji-variation-sequences.txt`. -/
def hasRegisteredEmojiPresentation (base : Nat) : Bool :=
  emojiStyleBases.contains base

/-- True iff `(base, U+FE0E)` is a registered text-style variation
    sequence. -/
def hasRegisteredTextPresentation (base : Nat) : Bool :=
  textStyleBases.contains base

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- UCD 17.0.0 has 742 rows = 371 base codepoints × 2 VS each. -/
theorem rowCount : parsedPairs.size = 742 := by decide +kernel

/-- 371 distinct base codepoints carry a registered emoji-style. -/
theorem emojiStyleCount : emojiStyleBases.size = 371 := by decide +kernel

theorem textStyleCount : textStyleBases.size = 371 := by decide +kernel

/-- `U+2764 HEAVY BLACK HEART` has a registered emoji presentation. -/
theorem heart_has_emoji_pres :
    hasRegisteredEmojiPresentation 0x2764 = true := by decide +kernel

/-- `U+1F600 GRINNING FACE` does NOT — it is `Emoji_Presentation =
    Yes` and so has no need for a `FE0F` variant. -/
theorem grinning_no_emoji_pres :
    hasRegisteredEmojiPresentation 0x1F600 = false := by decide +kernel

/-- ASCII digit `0` has a registered emoji presentation (keycap
    base) — confirms the file does include the keycap-eligible
    digits.  This is the exact codepoint set we care about for
    distinguishing "legitimate FE0F target" from "suspicious VS
    placement". -/
theorem digit_zero_has_emoji_pres :
    hasRegisteredEmojiPresentation 0x0030 = true := by decide +kernel

/-- ASCII Latin `A` has NO registered emoji presentation — so
    `FE0F` on Latin `A` is by definition a suspicious VS use. -/
theorem latin_A_no_emoji_pres :
    hasRegisteredEmojiPresentation 0x0041 = false := by decide +kernel

-- Build-time drift gate.
#eval do
  unless parsedPairsList.toArray == parsedPairsParsed do
    throw (IO.userError "EmojiVariationSequences drift: list ≠ parsed")

end Unicode.Generated.EmojiVariationSequences
