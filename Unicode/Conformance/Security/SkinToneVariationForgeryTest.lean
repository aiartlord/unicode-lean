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
import Unicode.Conformance.Security.VectorFile

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

-- ═══════════════════════════════════════════════════════════════════════════════
-- The pinned vector file, executed
--
-- `Unicode/Ucd/Security/SkinToneVariationForgeryTest.txt` is hash-pinned by
-- `scripts/check-security-hashes.sh`, which fixes its bytes.  Running the
-- detector over those bytes is a separate claim, and this section makes it:
-- `rowsList` is mirrored against a fresh parse of the file at build time, and
-- `all_vectors_pass` reduces the detector over every row in the kernel.  A row
-- added to, removed from, or edited in the file fails the build until the
-- harness agrees with it again.
-- ═══════════════════════════════════════════════════════════════════════════════

open Unicode.Conformance.Security.VectorFile (VectorRow parseFile)

/-- Raw text of the pinned vector file, embedded at compile time. -/
def vectorsRaw : String := include_str "../../Ucd/Security/SkinToneVariationForgeryTest.txt"

/-- Every row of the pinned vector file, freshly parsed. -/
def parsedRows : List VectorRow := parseFile vectorsRaw

/-- The pinned rows, materialized so the kernel can reduce over them. -/
def rowsList : List VectorRow := [
  ⟨[0x0048, 0x0065], "Clear", []⟩,
  ⟨[0x1F600], "Clear", []⟩,
  ⟨[0x1F44B, 0x1F3FB], "Clear", []⟩,
  ⟨[0x1F44B, 0x1F3FF], "Clear", []⟩,
  ⟨[0x1F468, 0x1F3FC], "Clear", []⟩,
  ⟨[0x1F469, 0x1F3FD], "Clear", []⟩,
  ⟨[0x4E2D, 0x6587], "Clear", []⟩,
  ⟨[0x1F44B, 0xFE0F], "Clear", []⟩,
  ⟨[0x2764, 0xFE0F], "Clear", []⟩,
  ⟨[0x1F44B, 0x1F3FB, 0x1F3FC], "Hazard:StackedSkinTones", [1, 2]⟩,
  ⟨[0x1F468, 0x1F3FB, 0x1F3FC, 0x1F3FD], "Hazard:StackedSkinTones", [1, 2]⟩,
  ⟨[0x1F44B, 0x1F3FF, 0x1F3FE], "Hazard:StackedSkinTones", [1, 2]⟩,
  ⟨[0x0041, 0x1F3FB], "Hazard:InvalidSkinToneTarget", [1]⟩,
  ⟨[0x1F600, 0x1F3FB], "Hazard:InvalidSkinToneTarget", [1]⟩,
  ⟨[0x4E2D, 0x1F3FB], "Hazard:InvalidSkinToneTarget", [1]⟩,
  ⟨[0x0035, 0x1F3FB], "Hazard:InvalidSkinToneTarget", [1]⟩,
  ⟨[0x2764, 0x1F3FB], "Hazard:InvalidSkinToneTarget", [1]⟩,
  ⟨[0x0430, 0x1F3FB], "Hazard:InvalidSkinToneTarget", [1]⟩,
  ⟨[0x1F600, 0xFE0E], "Hazard:ForcedTextStyle", [1]⟩,
  ⟨[0x1F44B, 0xFE0E], "Hazard:ForcedTextStyle", [1]⟩,
  ⟨[0x1F495, 0xFE0E], "Hazard:ForcedTextStyle", [1]⟩,
  ⟨[0x1F469, 0xFE0E], "Hazard:ForcedTextStyle", [1]⟩,
  ⟨[0x1F468, 0xFE0E], "Hazard:ForcedTextStyle", [1]⟩,
  ⟨[0x1F4BB, 0xFE0E], "Hazard:ForcedTextStyle", [1]⟩
]

-- `rowsList` mirrors a fresh parse of the vector file, checked at build time.
#eval do
  unless rowsList == parsedRows do
    throw (IO.userError "SkinToneVariationForgeryTest drift: rowsList ≠ parsed vector file")

/-- Run the detector over one row and compare with the verdict the file states. -/
def verifyVectorRow (r : VectorRow) : Bool :=
  let v := detect r.codepoints
  if r.expectsClear then v.classify.isClear
  else v.classify.tag == r.expectedTag

/-- Every vector the pinned file states holds of the detector. -/
theorem all_vectors_pass : rowsList.all verifyVectorRow = true := by decide +kernel

end Unicode.Conformance.Security.SkinToneVariationForgeryTest
