/-
  Unicode.Conformance.Security.SkinToneVariationForgeryTest

  Conformance certificate for the SkinToneVariationForgery detector (UTS #51 §2.4
  Emoji Modifiers; identity layer).

  Threat model.  An emoji modifier (U+1F3FB..U+1F3FF, the Fitzpatrick skin tones)
  is sanctioned only immediately after an emoji-modifier *base*, exactly once.  An
  adversary who stacks a second tone, attaches a tone to a codepoint that is not a
  modifier base, or forces a text-presentation selector onto an emoji produces a
  sequence whose rendered form is unstable across platforms — one client shows the
  intended pictograph, another shows a tofu box or the base plus a stray swatch —
  which can be exploited to make the same bytes read differently to sender and
  receiver.

  What the detector draws.  A single tone on a legitimate base is clear; every
  malformed modifier shape is classified by its fault — StackedSkinTones for a
  doubled tone, InvalidSkinToneTarget for a tone on a non-base, and ForcedTextStyle
  for a text-presentation selector (VS15) forcing text rendering on an emoji.

  The certificate.  Each `Row` pairs a representative input with the classification
  `tag` its verdict must draw (`none` for a clear verdict); `verifyRow` recomputes
  `detect` and compares, and `all_rows_pass` discharges the table in the kernel.
  A new attack vector is one appended row, so coverage grows with the threat
  catalogue and cannot silently regress.
-/

import Unicode.Security.Identity.SkinToneVariationForgery

namespace Unicode.Conformance.Security.SkinToneVariationForgeryTest

open Unicode.Security.Identity.SkinToneVariationForgery

set_option maxRecDepth 1000000

-- ── §1  The certificate table ───────────────────────────────────────────────

/-- One conformance row: an `input` sequence and the classification `tag` its
    verdict must carry (`none` for a clear verdict). -/
structure Row where
  input : List Nat
  tag : Option String

/-- The representative forgery — and control — vectors this harness certifies. -/
def rows : List Row :=
  [ -- A single Fitzpatrick tone on 👋 is the sanctioned base+modifier shape — clear.
    { input := [0x1F44B, 0x1F3FB], tag := none },
    -- Two tones on one base: a stacked modifier the Standard never sanctions.
    { input := [0x1F44B, 0x1F3FB, 0x1F3FC], tag := some "StackedSkinTones" },
    -- A tone applied to ASCII 'A', which is not an emoji-modifier base — mistargeted.
    { input := [0x0041, 0x1F3FB], tag := some "InvalidSkinToneTarget" },
    -- VS15 forcing text presentation onto an emoji base — a cross-platform display fork.
    { input := [0x1F600, 0xFE0E], tag := some "ForcedTextStyle" } ]

/-- A row passes when `detect` reproduces the classification tag the row prescribes. -/
def verifyRow (r : Row) : Bool :=
  (detect r.input).classify.tag == r.tag

-- ── §2  The closed certificate ──────────────────────────────────────────────

/-- Every certified vector draws exactly the verdict the emoji-modifier grammar
    demands. -/
theorem all_rows_pass : rows.all verifyRow = true := by decide +kernel

end Unicode.Conformance.Security.SkinToneVariationForgeryTest
