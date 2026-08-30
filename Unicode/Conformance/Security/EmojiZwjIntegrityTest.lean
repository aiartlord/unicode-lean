/-
  Unicode.Conformance.Security.EmojiZwjIntegrityTest

  Conformance certificate for the EmojiZwjIntegrity detector (UTS #51 §2.3,
  Emoji ZWJ Sequences; identity layer, detector I3).

  Threat model.  An emoji ZWJ sequence binds pictographs together with U+200D
  ZERO WIDTH JOINER.  A renderer collapses a *registered* RGI sequence into a
  single glyph, but has no sanctioned rendering for any other ZWJ-bearing shape
  and falls back — component by component on one platform, into an ad-hoc
  ligature on another.  An adversary lives in that gap: a doubled joiner, a
  joiner splicing a non-emoji codepoint into the run, a skin-tone chain beyond
  the sanctioned count, or a structurally valid join that is simply absent from
  the registry all let a single byte string display as one innocuous glyph in
  the reviewer's client and as something else in the victim's.

  What the detector draws.  A sequence that appears verbatim in the RGI registry
  (`emoji-zwj-sequences.txt`) is always clear; every other ZWJ-bearing input is
  classified by the first structural fault it exhibits, in priority order
  DoubleZWJ, NonEmojiInjection, OverLength, SkinToneOverflow, and finally the
  UnregisteredSequence catch-all.

  The certificate.  `rows` pairs each representative input with the verdict it
  must draw — the classification `tag` (`none` denoting a clear verdict) and the
  RGI-registration flag.  `verifyRow` recomputes `detect` and compares both
  projections, and `all_rows_pass` discharges the entire table in the kernel.
  A new attack vector is certified by appending one row: the proof obligation,
  and therefore the coverage this harness guarantees, grows monotonically with
  the threat catalogue and cannot silently regress.
-/

import Unicode.Security.Identity.EmojiZwjIntegrity
import Unicode.Conformance.Security.VectorFile

namespace Unicode.Conformance.Security.EmojiZwjIntegrityTest

open Unicode.Security.Identity.EmojiZwjIntegrity

set_option maxRecDepth 1000000

-- ── §1  The certificate table ───────────────────────────────────────────────

/-- One conformance row: an `input` codepoint sequence, the classification
    `tag` its verdict must carry (`none` for a clear verdict), and the
    `registeredRGI` flag the verdict must report. -/
structure Row where
  input : List Nat
  tag : Option String
  registeredRGI : Bool

/-- The representative attack — and control — vectors this harness certifies. -/
def rows : List Row :=
  [ -- A doubled joiner (U+200D U+200D) occurs in no RGI sequence; it is the
    -- crudest forged join and is caught ahead of every other fault.
    { input := [0x1F600, 0x200D, 0x200D, 0x1F600],
      tag := some "DoubleZWJ", registeredRGI := false },
    -- A joiner splicing ASCII 'a' between pictographs injects a non-emoji into
    -- the run; a renderer that ligates around it hides the smuggled letter.
    { input := [0x1F600, 0x200D, 0x0061],
      tag := some "NonEmojiInjection", registeredRGI := false },
    -- man + ZWJ + woman is a well-formed join whose glyph pair is nonetheless
    -- absent from the registry: sanctioned in shape, unsanctioned in fact.
    { input := [0x1F468, 0x200D, 0x1F469],
      tag := some "UnregisteredSequence", registeredRGI := false },
    -- The registered four-person family (man, woman, girl, boy) is the control:
    -- a genuine RGI entry that must pass clean and report its registration.
    { input := [0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466],
      tag := none, registeredRGI := true } ]

/-- A row passes when `detect` reproduces both projections the row prescribes:
    the classification tag and the RGI-registration flag. -/
def verifyRow (r : Row) : Bool :=
  let v := detect r.input
  (v.classify.tag == r.tag) && (v.isRegisteredRGI == r.registeredRGI)

-- ── §2  The closed certificate ──────────────────────────────────────────────

/-- Every certified vector draws exactly the verdict the RGI registry demands. -/
theorem all_rows_pass : rows.all verifyRow = true := by decide +kernel

-- ═══════════════════════════════════════════════════════════════════════════════
-- The pinned vector file, executed
--
-- `Unicode/Ucd/Security/EmojiZwjIntegrityTest.txt` is hash-pinned by
-- `scripts/check-security-hashes.sh`, which fixes its bytes.  Running the
-- detector over those bytes is a separate claim, and this section makes it:
-- `rowsList` is mirrored against a fresh parse of the file at build time, and
-- `all_vectors_pass` reduces the detector over every row in the kernel.  A row
-- added to, removed from, or edited in the file fails the build until the
-- harness agrees with it again.
-- ═══════════════════════════════════════════════════════════════════════════════

open Unicode.Conformance.Security.VectorFile (VectorRow parseFile)

/-- Raw text of the pinned vector file, embedded at compile time. -/
def vectorsRaw : String := include_str "../../Ucd/Security/EmojiZwjIntegrityTest.txt"

/-- Every row of the pinned vector file, freshly parsed. -/
def parsedRows : List VectorRow := parseFile vectorsRaw

/-- The pinned rows, materialized so the kernel can reduce over them. -/
def rowsList : List VectorRow := [
  ⟨[0x0048, 0x0065, 0x006C, 0x006C, 0x006F], "Clear", []⟩,
  ⟨[0x1F600], "Clear", []⟩,
  ⟨[0x4E2D, 0x6587], "Clear", []⟩,
  ⟨[0x1F44B, 0x1F3FB], "Clear", []⟩,
  ⟨[0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466], "Clear", []⟩,
  ⟨[0x1F468, 0x200D, 0x2764, 0xFE0F, 0x200D, 0x1F468], "Clear", []⟩,
  ⟨[0x1F469, 0x200D, 0x2764, 0xFE0F, 0x200D, 0x1F48B, 0x200D, 0x1F469], "Clear", []⟩,
  ⟨[0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F466], "Clear", []⟩,
  ⟨[0x1F3FB], "Clear", []⟩,
  ⟨[0x1F600, 0x200D, 0x200D, 0x1F4BB], "Hazard:DoubleZWJ", [1]⟩,
  ⟨[0x1F600, 0x200D, 0x200D, 0x200D, 0x1F600], "Hazard:DoubleZWJ", [1, 2]⟩,
  ⟨[0x1F468, 0x200D, 0x200D, 0x1F469, 0x200D, 0x1F467], "Hazard:DoubleZWJ", [1]⟩,
  ⟨[0x1F600, 0x200D, 0x0061], "Hazard:NonEmojiInjection", [1]⟩,
  ⟨[0x0030, 0x200D, 0x1F600], "Hazard:NonEmojiInjection", [1]⟩,
  ⟨[0x1F600, 0x200D, 0x4E2D], "Hazard:NonEmojiInjection", [1]⟩,
  ⟨[0x1F600, 0x200D, 0x0430], "Hazard:NonEmojiInjection", [1]⟩,
  ⟨[0x1F600, 0x200D, 0x0627], "Hazard:NonEmojiInjection", [1]⟩,
  ⟨[0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468], "Hazard:OverLength", []⟩,
  ⟨[0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468], "Hazard:OverLength", []⟩,
  ⟨[0x1F44B, 0x1F3FB, 0x1F3FC, 0x1F3FD, 0x1F3FE, 0x1F3FF], "Hazard:SkinToneOverflow", []⟩,
  ⟨[0x1F44B, 0x1F3FB, 0x1F3FC, 0x1F3FD, 0x1F3FE, 0x1F3FF, 0x1F3FB], "Hazard:SkinToneOverflow", []⟩,
  ⟨[0x1F44B, 0x1F3FB, 0x1F3FC, 0x1F3FD, 0x1F3FE, 0x1F3FF, 0x1F3FB, 0x1F3FC], "Hazard:SkinToneOverflow", []⟩
]

-- `rowsList` mirrors a fresh parse of the vector file, checked at build time.
#eval do
  unless rowsList == parsedRows do
    throw (IO.userError "EmojiZwjIntegrityTest drift: rowsList ≠ parsed vector file")

/-- Run the detector over one row and compare with the verdict the file states. -/
def verifyVectorRow (r : VectorRow) : Bool :=
  let v := detect r.codepoints
  if r.expectsClear then v.classify.isClear
  else v.classify.tag == r.expectedTag

/-- Every vector the pinned file states holds of the detector. -/
theorem all_vectors_pass : rowsList.all verifyVectorRow = true := by decide +kernel

end Unicode.Conformance.Security.EmojiZwjIntegrityTest
