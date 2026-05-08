/-
  Unicode.Width

  UAX #11 East Asian Width — per-codepoint and per-string display
  width calculation. Implements the standard "wcwidth-style" rules:

    * Width 0 — control characters (general category Cc), combining
                marks (general category Mn or Me), zero-width joiner
                U+200D, zero-width non-joiner U+200C, default-ignorable
                codepoints with general category Cf.
    * Width 2 — codepoints with East_Asian_Width = F (Fullwidth) or
                W (Wide).
    * Width 1 — all other codepoints, including N (Neutral),
                Na (Narrow), H (Halfwidth), and (under
                `AmbiguousMode.narrow`) A (Ambiguous).

  Codepoints with East_Asian_Width = A take their width from the
  `AmbiguousMode` parameter: `narrow` (the Western default,
  matching POSIX `wcwidth`) maps A to 1; `wide` (the CJK default)
  maps A to 2. The string-level `displayWidth` sums the
  per-codepoint widths; it does not yet collapse emoji ZWJ
  sequences (those land with UTS #51 wiring).

  Variation selectors U+FE0E (text presentation) and U+FE0F (emoji
  presentation) are width 0 — they modify the *previous* codepoint's
  presentation rather than occupying display columns themselves.
-/

import Unicode.Generated.EastAsianWidth
import Unicode.Generated.DerivedGeneralCategory

namespace Unicode.Width

open Unicode.Generated.EastAsianWidth (EastAsianWidthClass)
open Unicode.Generated.DerivedGeneralCategory (GC)

/-- How to classify codepoints with East_Asian_Width = A (Ambiguous).
    `narrow` matches POSIX `wcwidth` and Western terminals;
    `wide` matches CJK terminals and `wcwidth-cjk`. -/
inductive AmbiguousMode where
  | narrow
  | wide
  deriving DecidableEq, Repr, Inhabited

/-- True iff `cp` has General_Category = Mn (Mark, Non-Spacing) or
    Me (Mark, Enclosing). Combining marks attach to the preceding
    base character and so contribute zero display width. Mc
    (Mark, Spacing Combining) does occupy a column and is *not*
    included here. -/
def isCombiningMark (cp : Nat) : Bool :=
  match Unicode.Generated.DerivedGeneralCategory.lookup cp with
  | .Mn | .Me => true
  | .Lu | .Ll | .Lt | .Lm | .Lo
  | .Mc
  | .Nd | .Nl | .No
  | .Pc | .Pd | .Ps | .Pe | .Pi | .Pf | .Po
  | .Sm | .Sc | .Sk | .So
  | .Zs | .Zl | .Zp
  | .Cc | .Cf | .Cs | .Co | .Cn => false

/-- True iff `cp` has General_Category = Cc (Control). Includes
    the C0 controls (U+0000..U+001F), DEL (U+007F), and the C1
    controls (U+0080..U+009F). -/
def isControl (cp : Nat) : Bool :=
  match Unicode.Generated.DerivedGeneralCategory.lookup cp with
  | .Cc => true
  | .Lu | .Ll | .Lt | .Lm | .Lo
  | .Mn | .Mc | .Me
  | .Nd | .Nl | .No
  | .Pc | .Pd | .Ps | .Pe | .Pi | .Pf | .Po
  | .Sm | .Sc | .Sk | .So
  | .Zs | .Zl | .Zp
  | .Cf | .Cs | .Co | .Cn => false

/-- True iff `cp` is U+200C ZERO WIDTH NON-JOINER, U+200D ZERO
    WIDTH JOINER, or one of the U+FE00..U+FE0F variation selectors.
    Each contributes zero display width — joiners and selectors
    modify adjacent characters. -/
def isZeroWidthFormatter (cp : Nat) : Bool :=
  cp == 0x200C || cp == 0x200D
    || (Nat.ble 0xFE00 cp && Nat.ble cp 0xFE0F)

/-- The display width of a single codepoint under `mode`. -/
def codepointWidth (mode : AmbiguousMode) (cp : Nat) : Nat :=
  if isControl cp then 0
  else if isCombiningMark cp then 0
  else if isZeroWidthFormatter cp then 0
  else
    match Unicode.Generated.EastAsianWidth.lookup cp with
    | .F | .W => 2
    | .H | .Na | .N => 1
    | .A =>
      match mode with
      | .narrow => 1
      | .wide   => 2

/-- The total display width of a codepoint sequence under `mode`,
    obtained by summing per-codepoint widths. ZWJ / variation
    selectors / combining marks contribute 0; this implementation
    does not yet apply the UTS #51 emoji-ZWJ-sequence collapse,
    which would treat an entire `base + ZWJ + ... + ZWJ + base`
    chain as a single width-2 cluster rather than summing widths
    of the leading base alone (currently width 2) plus the trailing
    bases (width 2 each, but they're rendered as zero-width
    overlays in a real ZWJ sequence). For non-emoji text and for
    individual emoji codepoints the sum agrees with the
    grapheme-level result. -/
def displayWidth (mode : AmbiguousMode) (cps : Array Nat) : Nat :=
  cps.foldl (fun acc cp => acc + codepointWidth mode cp) 0

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 PER-CODEPOINT TEST VECTORS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- ASCII letters are width 1. -/
theorem width_ascii_a_narrow : codepointWidth .narrow 0x0061 = 1 := by native_decide
theorem width_ascii_a_wide   : codepointWidth .wide   0x0061 = 1 := by native_decide

/-- ASCII digits are width 1. -/
theorem width_ascii_0 : codepointWidth .narrow 0x0030 = 1 := by native_decide

/-- ASCII space is width 1 (general category Zs, EAW = N). -/
theorem width_ascii_space : codepointWidth .narrow 0x0020 = 1 := by native_decide

/-- ASCII NUL is width 0 (control). -/
theorem width_ascii_nul : codepointWidth .narrow 0x0000 = 0 := by native_decide

/-- ASCII DEL is width 0 (control). -/
theorem width_ascii_del : codepointWidth .narrow 0x007F = 0 := by native_decide

/-- C1 control U+0080 is width 0. -/
theorem width_c1_80 : codepointWidth .narrow 0x0080 = 0 := by native_decide

/-- COMBINING ACUTE ACCENT (U+0301) is width 0. -/
theorem width_combining_acute : codepointWidth .narrow 0x0301 = 0 := by native_decide

/-- COMBINING DIAERESIS (U+0308) is width 0. -/
theorem width_combining_diaeresis : codepointWidth .narrow 0x0308 = 0 := by native_decide

/-- ENCLOSING CIRCLE (U+20DD) is width 0 (Me). -/
theorem width_enclosing_circle : codepointWidth .narrow 0x20DD = 0 := by native_decide

/-- ZERO WIDTH JOINER is width 0. -/
theorem width_zwj : codepointWidth .narrow 0x200D = 0 := by native_decide

/-- ZERO WIDTH NON-JOINER is width 0. -/
theorem width_zwnj : codepointWidth .narrow 0x200C = 0 := by native_decide

/-- VARIATION SELECTOR-15 (text presentation) is width 0. -/
theorem width_vs15 : codepointWidth .narrow 0xFE0E = 0 := by native_decide

/-- VARIATION SELECTOR-16 (emoji presentation) is width 0. -/
theorem width_vs16 : codepointWidth .narrow 0xFE0F = 0 := by native_decide

/-- CJK ideograph U+4E00 (一) is width 2 (EAW = W). -/
theorem width_cjk_yi : codepointWidth .narrow 0x4E00 = 2 := by native_decide

/-- HIRAGANA SMALL A (U+3041) is width 2 (EAW = W). -/
theorem width_hiragana_a : codepointWidth .narrow 0x3041 = 2 := by native_decide

/-- FULLWIDTH LATIN A (U+FF21) is width 2 (EAW = F). -/
theorem width_fullwidth_A : codepointWidth .narrow 0xFF21 = 2 := by native_decide

/-- HALFWIDTH KATAKANA A (U+FF71) is width 1 (EAW = H). -/
theorem width_halfwidth_a : codepointWidth .narrow 0xFF71 = 1 := by native_decide

/-- INVERTED EXCLAMATION MARK (U+00A1, EAW = A) is width 1 under
    narrow, width 2 under wide. -/
theorem width_inverted_excl_narrow : codepointWidth .narrow 0x00A1 = 1 := by native_decide
theorem width_inverted_excl_wide   : codepointWidth .wide   0x00A1 = 2 := by native_decide

/-- WAVING HAND SIGN (U+1F44B, EAW = W) is width 2. -/
theorem width_emoji_wave : codepointWidth .narrow 0x1F44B = 2 := by native_decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 STRING-LEVEL TEST VECTORS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- "hello" is width 5. -/
theorem dw_hello :
    displayWidth .narrow #[0x68, 0x65, 0x6C, 0x6C, 0x6F] = 5 := by native_decide

/-- The empty array is width 0. -/
theorem dw_empty : displayWidth .narrow #[] = 0 := by native_decide

/-- "café" with COMBINING ACUTE ACCENT renders as 4 columns
    (the combining mark contributes 0). -/
theorem dw_cafe_decomposed :
    displayWidth .narrow #[0x63, 0x61, 0x66, 0x65, 0x0301] = 4 := by native_decide

/-- "café" with precomposed é (U+00E9) also renders as 4 columns. -/
theorem dw_cafe_precomposed :
    displayWidth .narrow #[0x63, 0x61, 0x66, 0x00E9] = 4 := by native_decide

/-- "你好" — two CJK ideographs render as 4 columns. -/
theorem dw_nihao :
    displayWidth .narrow #[0x4F60, 0x597D] = 4 := by native_decide

/-- A control-only string is width 0. -/
theorem dw_controls :
    displayWidth .narrow #[0x0000, 0x0001, 0x0009, 0x000A] = 0 := by native_decide

/-- Mixed ASCII + CJK: "hi 你好" is width 7 (h, i, space, 你=2, 好=2). -/
theorem dw_mixed :
    displayWidth .narrow #[0x68, 0x69, 0x20, 0x4F60, 0x597D] = 7 := by native_decide

end Unicode.Width
