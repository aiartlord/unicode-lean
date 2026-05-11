/-
  Unicode.Generated.StandardizedVariants

  Parses `lemma/lean/Unicode/Ucd/StandardizedVariants.txt`
  (UCD 16.0.0) and exposes a membership predicate over the
  `(base, variation_selector)` pairs that the Unicode Standard
  sanctions as legitimate standardized variation sequences.

  Background.  A variation selector (VS) codepoint following a base
  character signals a glyph variant of that base.  Three classes of
  variation sequence are sanctioned by the Standard:

  1. **Standardized** — listed in this file (`StandardizedVariants.txt`).
     Math symbols, Mongolian, Egyptian hieroglyphs, Phags-pa,
     Manichaean, CJK Compatibility Ideographs, etc.
  2. **Ideographic** — listed in the Ideographic Variation Database
     (registered under UTS #37).  Not loaded here.
  3. **Emoji** — listed in `emoji-variation-sequences.txt`
     (UTS #51, parsed by `Unicode.Generated.EmojiSequences`).

  Any `(base, VS)` pair not in one of the three classes is, per the
  Standard, **not sanctioned** — the VS has no defined visual effect.
  This is the structural fact the C2 covert-channel detector
  (`Unicode.Security.Covert.VariationSelectorPayload`) leans on:
  a VS appearing after a base that has no registered variation
  sequence is, by definition, attempting to use the VS for something
  other than the Standard's stated purpose.

  File format.  Every non-comment line has shape

      BASE_HEX VS_HEX; description; # NAME

  where `BASE_HEX VS_HEX` is a space-separated pair of hex codepoints
  (no `U+` prefix), `description` is the variant-form description,
  and the trailing `# NAME` is the human-readable name.  As of
  UCD 16.0.0 there are 1,306 such rows and 8 distinct VS codepoints
  in use (`U+180B..U+180D`, `U+FE00..U+FE03`, `U+FE06`).

  Pattern follows `Unicode.Generated.EmojiData`: `include_str` of the
  bundled UCD file, parse once at module load, expose a single
  `isStandardizedVariation` predicate.  All checks are
  decidable via `native_decide`.
-/

namespace Unicode.Generated.StandardizedVariants

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

/-- Parse one row of `StandardizedVariants.txt`.  Returns
    `some (base, vs)` for a well-formed sanctioned-variation row,
    `none` for blank / comment / malformed lines. -/
def parseRow (rawLine : String) : Option (Nat × Nat) :=
  -- Strip the trailing `# <name>` comment, then trim.
  let stripped : String := (rawLine.takeWhile (· != '#')).toString
  let line := trimS stripped
  if line.isEmpty then none
  else
    match String.splitOn line ";" with
    | cpField :: _ =>
      -- `cpField` has shape "BASE_HEX VS_HEX" with one or more spaces.
      let toks : List String :=
        (cpField.splitOn " ").filterMap (fun t =>
          let tt := trimS t
          if tt.isEmpty then none else some tt)
      match toks with
      | [b, v] => some (parseHex b, parseHex v)
      | _      => none
    | _ => none

/-- Raw text of `StandardizedVariants.txt`, embedded at compile time. -/
def standardizedVariantsRaw : String :=
  include_str "../Ucd/StandardizedVariants.txt"

/-- All parsed `(base, vs)` pairs in file order. -/
def parsedPairs : Array (Nat × Nat) :=
  ((standardizedVariantsRaw.splitOn "\n").filterMap parseRow).toArray

/-- Membership predicate: is `(base, vs)` a sanctioned standardized
    variation sequence per `StandardizedVariants.txt`?

    Note: emoji VS sequences (`FE0F`) are **not** here — they live in
    `emoji-variation-sequences.txt` and must be checked separately. -/
def isStandardizedVariation (base vs : Nat) : Bool :=
  parsedPairs.any (fun p => p.1 = base ∧ p.2 = vs)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Spot checks — UCD 16.0.0 row count + canonical entries
-- ═══════════════════════════════════════════════════════════════════════════════

/-- UCD 16.0.0 has 1,306 standardized variation sequences. -/
theorem rowCount : parsedPairs.size = 1306 := by native_decide

/-- Digit 0 + VS1 — "short diagonal stroke form" (first row in file). -/
theorem digit_zero_fe00 :
    isStandardizedVariation 0x0030 0xFE00 = true := by native_decide

/-- EMPTY SET + VS1 — math symbol variant. -/
theorem empty_set_fe00 :
    isStandardizedVariation 0x2205 0xFE00 = true := by native_decide

/-- Mongolian Letter A + FVS1 (180B) — second isolate form.
    Mongolian uses the Free Variation Selectors `180B..180D`, not
    `FE00..FE0F`. -/
theorem mongolian_a_fvs1 :
    isStandardizedVariation 0x1820 0x180B = true := by native_decide

/-- Latin Capital A + FE0F — NOT a standardized variation (Latin
    letters have no registered VS sequences). -/
theorem latin_a_fe0f_not_registered :
    isStandardizedVariation 0x0041 0xFE0F = false := by native_decide

/-- ASCII space + VS1 — NOT registered. -/
theorem space_fe00_not_registered :
    isStandardizedVariation 0x0020 0xFE00 = false := by native_decide

end Unicode.Generated.StandardizedVariants
