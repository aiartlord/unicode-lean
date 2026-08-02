/-
  Unicode.Conformance.Security.CovertDisplayCompoundTest

  Conformance certificate for the CovertDisplayCompound boundary detector, which
  fires when a single input simultaneously carries a covert data channel and a
  display-deception channel.  The covert channel is either an unregistered
  variation selector — a variation sequence with no matching row in
  StandardizedVariants.txt or emoji-variation-sequences.txt — or a tag-block
  codepoint in the range U+E0000..U+E007F.  The deception channel is any of the
  UAX #9 (Unicode Bidirectional Algorithm) format controls, such as U+202E RIGHT-
  TO-LEFT OVERRIDE.

  Threat model.  An adversary hides an executable byte stream inside variation-
  selector or tag bytes that render invisibly, and in the same payload plants
  bidi format controls that reorder the visible text so the bytes appear at a
  position different from where they take effect.  The compound is strictly worse
  than either half: a covert-payload detector alone cannot tell that the visible
  context has been reordered, and a bidi detector alone cannot tell that the input
  is also smuggling hidden bytes.

  The discrimination.  A lone bidi control is not a compound and stays clear here;
  the dedicated bidi detector is responsible for that surface.  The compound
  verdict is drawn only when a bidi control co-occurs with a second channel, and
  the two sub-threats are prioritised: an unregistered variation selector is
  reported as `BidiPlusUnregisteredVs`, and, when no such selector is present, a
  tag-block codepoint is reported as `BidiPlusTagBlock`.

  How to read the certificate.  Each `Row` pairs a representative input with the
  classification `tag` its verdict must carry, where `none` denotes a clear
  verdict (`isClear` holds exactly when the tag is absent, so the tag captures
  both outcomes).  `verifyRow` recomputes `detect` and compares the projected tag;
  `all_rows_pass` discharges the whole table in the kernel.  Appending a vector
  adds one conjunct to the proof obligation, so coverage grows with the threat
  catalogue and cannot silently regress.
-/

import Unicode.Security.Boundary.CovertDisplayCompound

namespace Unicode.Conformance.Security.CovertDisplayCompoundTest

open Unicode.Security.Boundary.CovertDisplayCompound

set_option maxRecDepth 1000000

-- ── §1  The certificate table ───────────────────────────────────────────────

/-- One conformance row: an `input` sequence and the classification `tag` its
    verdict must carry (`none` for a clear verdict). -/
structure Row where
  input : List Nat
  tag : Option String

/-- The representative hazard — and clear — vectors this harness certifies. -/
def rows : List Row :=
  [ -- A lone RLO with no second channel is not a compound: the bidi detector
    -- owns this surface, so the boundary detector must stay clear.
    { input := [0x202E], tag := none },
    -- RLO co-occurring with VS1 attached to ASCII "A" — a variation sequence
    -- absent from every standardized table, so it classifies as suspicious and
    -- the compound fires on the unregistered-VS channel.
    { input := [0x202E, 0x0041, 0xFE00], tag := some "BidiPlusUnregisteredVs" },
    -- RLO co-occurring with U+E0001 LANGUAGE TAG and no suspicious VS — the
    -- second channel is the tag block, exercising the lower-priority sub-threat.
    { input := [0x202E, 0x0041, 0xE0001], tag := some "BidiPlusTagBlock" } ]

/-- A row passes when `detect` reproduces the classification tag the row
    prescribes. -/
def verifyRow (r : Row) : Bool :=
  (detect r.input).classify.tag == r.tag

-- ── §2  The closed certificate ──────────────────────────────────────────────

/-- Every certified vector draws exactly the verdict the compound detector's
    channel-priority logic demands. -/
theorem all_rows_pass : rows.all verifyRow = true := by decide +kernel

end Unicode.Conformance.Security.CovertDisplayCompoundTest
