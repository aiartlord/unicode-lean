/-
  Unicode.Vertical

  UAX #50 Unicode Vertical Text Layout. Exposes the
  Vertical_Orientation (`Vo`) property as predicates and a
  rendering hint, plus a string-level "decompose into vertical
  glyph orientations" function for terminal-style vertical layout.

  The four `Vo` values map to two practical outcomes for
  applications that don't implement OpenType vertical typographic
  features:

    * `U`  → glyph is shown upright.
    * `Tu` → glyph is shown upright (transformed-with-fallback-to-Upright).
    * `R`  → glyph is rotated 90° clockwise.
    * `Tr` → glyph is rotated 90° clockwise (transformed-with-fallback-to-Rotated).

  The OpenType feature path (`vert`, `vrt2`) substitutes alternative
  glyphs for `Tu` and `Tr` when the font carries them; renderers
  without that path use the `U` / `R` fallback. `verticalGlyphForm`
  collapses both cases into the rendered orientation (`Upright` /
  `Rotated`) which most consumers want.
-/

import Unicode.Generated.VerticalOrientation

namespace Unicode.Vertical

set_option maxRecDepth 100000

open Unicode.Generated.VerticalOrientation

/-- The two practical orientations for vertical text rendering
    on systems without OpenType vertical-substitution support. -/
inductive Orientation where
  | Upright
  | Rotated
  deriving DecidableEq, Repr, Inhabited

/-- Collapse `Vo` into a rendering `Orientation`: U / Tu render
    upright, R / Tr render rotated 90° clockwise. -/
def voToOrientation : Vo → Orientation
  | .U  => .Upright
  | .Tu => .Upright
  | .R  => .Rotated
  | .Tr => .Rotated

/-- The vertical glyph orientation for `cp`. -/
def verticalGlyphForm (cp : Nat) : Orientation :=
  voToOrientation (lookupVo cp)

/-- True iff `cp` is rendered upright in vertical text. -/
def isUpright (cp : Nat) : Bool :=
  verticalGlyphForm cp = .Upright

/-- True iff `cp` is rendered rotated 90° clockwise in vertical text. -/
def isRotated (cp : Nat) : Bool :=
  verticalGlyphForm cp = .Rotated

/-- True iff `cp`'s `Vo` is one of `Tu` or `Tr`, indicating a
    glyph that should ideally be substituted via OpenType
    `vert` / `vrt2` features. -/
def needsVerticalSubstitution (cp : Nat) : Bool :=
  match lookupVo cp with
  | .Tu | .Tr => true
  | .U  | .R  => false

/-- Map a codepoint sequence to its per-codepoint vertical
    glyph orientations, preserving order. -/
def stringOrientations (cps : Array Nat) : Array Orientation :=
  cps.map verticalGlyphForm

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 TEST VECTORS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- ASCII letter 'A' (Latin, horizontal) rotates 90° clockwise. -/
theorem isRotated_ascii_A : isRotated 0x0041 = true := by decide +kernel

/-- ASCII digit rotates 90° clockwise. -/
theorem isRotated_ascii_0 : isRotated 0x0030 = true := by decide +kernel

/-- CJK ideograph (U+4E00) renders upright in vertical text. -/
theorem isUpright_cjk_yi : isUpright 0x4E00 = true := by decide +kernel

/-- Hiragana (U+3041 SMALL A) is upright in vertical text. -/
theorem isUpright_hiragana : isUpright 0x3041 = true := by decide +kernel

/-- Hangul syllable (U+AC00 GA) is upright. -/
theorem isUpright_hangul : isUpright 0xAC00 = true := by decide +kernel

/-- Fullwidth Latin A (U+FF21) is upright. -/
theorem isUpright_fullwidth_A : isUpright 0xFF21 = true := by decide +kernel

/-- Latin small letter from the basic Latin block — rotates. -/
theorem isRotated_latin_small_a : isRotated 0x0061 = true := by decide +kernel

/-- A handful of mixed codepoints' orientations. -/
theorem stringOrientations_mixed :
    stringOrientations #[0x0041, 0x0042, 0x4E00, 0x4E8C]
      = #[.Rotated, .Rotated, .Upright, .Upright] := by decide +kernel

end Unicode.Vertical
