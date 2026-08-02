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

end Unicode.Conformance.Security.EmojiZwjIntegrityTest
