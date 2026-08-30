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
import Unicode.Conformance.Security.VectorFile

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

-- ═══════════════════════════════════════════════════════════════════════════════
-- The pinned vector file, executed
--
-- `Unicode/Ucd/Security/CovertDisplayCompoundTest.txt` is hash-pinned by
-- `scripts/check-security-hashes.sh`, which fixes its bytes.  Running the
-- detector over those bytes is a separate claim, and this section makes it:
-- `rowsList` is mirrored against a fresh parse of the file at build time, and
-- `all_vectors_pass` reduces the detector over every row in the kernel.  A row
-- added to, removed from, or edited in the file fails the build until the
-- harness agrees with it again.
-- ═══════════════════════════════════════════════════════════════════════════════

open Unicode.Conformance.Security.VectorFile (VectorRow parseFile)

/-- Raw text of the pinned vector file, embedded at compile time. -/
def vectorsRaw : String := include_str "../../Ucd/Security/CovertDisplayCompoundTest.txt"

/-- Every row of the pinned vector file, freshly parsed. -/
def parsedRows : List VectorRow := parseFile vectorsRaw

/-- The pinned rows, materialized so the kernel can reduce over them. -/
def rowsList : List VectorRow := [
  ⟨[0x0048, 0x0065, 0x006C, 0x006C, 0x006F], "Clear", []⟩,
  ⟨[0x202E], "Clear", []⟩,
  ⟨[0x0041, 0xFE00], "Clear", []⟩,
  ⟨[0x202E, 0x1F600, 0xFE0F], "Clear", []⟩,
  ⟨[0x202E, 0x0041, 0x0042, 0x202C], "Clear", []⟩,
  ⟨[0x4E2D, 0x6587], "Clear", []⟩,
  ⟨[0x0041, 0xE0001], "Clear", []⟩,
  ⟨[0x202A, 0x0041, 0x202C], "Clear", []⟩,
  ⟨[0x202E, 0x0041, 0xFE00], "Hazard:BidiPlusUnregisteredVs", [0, 2]⟩,
  ⟨[0x0061, 0x0064, 0x006D, 0x0069, 0x006E, 0x202E, 0x0058, 0xFE00], "Hazard:BidiPlusUnregisteredVs", [5, 7]⟩,
  ⟨[0x2067, 0x0042, 0xFE02], "Hazard:BidiPlusUnregisteredVs", [0, 2]⟩,
  ⟨[0x202A, 0x4E2D, 0xFE05], "Hazard:BidiPlusUnregisteredVs", [0, 2]⟩,
  ⟨[0x2068, 0x0041, 0xE0100], "Hazard:BidiPlusUnregisteredVs", [0, 2]⟩,
  ⟨[0x202B, 0x0430, 0xFE06], "Hazard:BidiPlusUnregisteredVs", [0, 2]⟩,
  ⟨[0x202E, 0x0041, 0xE0001], "Hazard:BidiPlusTagBlock", [0, 2]⟩,
  ⟨[0x0066, 0x006F, 0x006F, 0x002E, 0x0074, 0x202E, 0xE0041], "Hazard:BidiPlusTagBlock", [5, 6]⟩,
  ⟨[0x202E, 0x1F600, 0xFE0F, 0xE0042], "Hazard:BidiPlusTagBlock", [0, 3]⟩,
  ⟨[0x2067, 0x0042, 0xE0001], "Hazard:BidiPlusTagBlock", [0, 2]⟩,
  ⟨[0x2068, 0xE0003], "Hazard:BidiPlusTagBlock", [0, 1]⟩,
  ⟨[0x202A, 0x4E2D, 0xE0021], "Hazard:BidiPlusTagBlock", [0, 2]⟩,
  ⟨[0x202B, 0x4E2D, 0xE0041], "Hazard:BidiPlusTagBlock", [0, 2]⟩
]

-- `rowsList` mirrors a fresh parse of the vector file, checked at build time.
#eval do
  unless rowsList == parsedRows do
    throw (IO.userError "CovertDisplayCompoundTest drift: rowsList ≠ parsed vector file")

/-- Run the detector over one row and compare with the verdict the file states. -/
def verifyVectorRow (r : VectorRow) : Bool :=
  let v := detect r.codepoints
  if r.expectsClear then v.classify.isClear
  else v.classify.tag == r.expectedTag

/-- Every vector the pinned file states holds of the detector. -/
theorem all_vectors_pass : rowsList.all verifyVectorRow = true := by decide +kernel

end Unicode.Conformance.Security.CovertDisplayCompoundTest
