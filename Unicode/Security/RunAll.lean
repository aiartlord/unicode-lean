/-
  Unicode.Security.RunAll

  Aggregator over every Security Conformance Layer detector.  Folds
  the 26 per-family `detect` functions into a uniform
  `Array FamilyResult` shape so downstream consumers can call once
  and receive a structured per-family inventory of verdicts on a
  single input.

  Each per-family module retains its own `Verdict` type with its
  own metadata fields.  This module deliberately projects to a flat
  shape that exposes only the universal fields:

    * `family`         — the family's long name (e.g.
                         "VariationSelectorPayload").  Matches the
                         detector module name exactly.
    * `layer`          — the layer number (1..6).
    * `classification` — the shared `ClassificationKind` reduced to
                         `clear` or `hazard` for every family.
    * `subThreat`      — the firing sub-threat tag, or `none` if clear.
    * `positions`      — the input positions flagged by the family.

  Callers that need per-family metadata (decoded ByteArray payloads,
  expansion ratios, run lengths, etc.) should call the corresponding
  `<Family>.detect` directly.
-/

import Unicode.Security
import Unicode.Security.Crypto.Bip39Canonical
import Unicode.Security.Crypto.HashInputStability
import Unicode.Security.Crypto.AiWatermarkDetectability

namespace Unicode.Security.RunAll

open Unicode.Security.Calculus

/-- Flat per-family result.  See module header for field semantics.
    `family` carries the `Calculus.Family` enum value rather than a
    String tag — pattern-matching is exhaustive and there is no
    risk of a typo in the family name silently bypassing a
    rejection-set check. -/
structure FamilyResult where
  family         : Family
  classification : ClassificationKind
  subThreat      : Option String
  positions      : Array Nat
  deriving Repr, Inhabited

/-- Build a `FamilyResult` from a per-family classification's three
    projection helpers (`isClear`, `tag`, `positions`).  Every family
    in `Unicode/Security/` exposes those three by convention. -/
@[inline]
def mkResult (family : Family)
    (isClear : Bool) (tag : Option String) (positions : Array Nat) :
    FamilyResult :=
  { family         := family,
    classification := if isClear then .clear else .hazard,
    subThreat      := tag,
    positions      := positions }

/-- True iff every element of `input` fits in a single octet.
    Used to gate SurrogateReassembly in `runAll`: that detector's
    predicate is byte-stream-oriented, so feeding it a
    codepoint array containing any codepoint > 0xFF gives
    spurious `InvalidStartByte` hits.  Skipping SurrogateReassembly
    on non-byte-stream inputs makes `runAll` semantically clean
    on both byte-array and codepoint-array inputs without
    requiring callers to choose. -/
@[inline]
def looksLikeByteStream (input : Array Nat) : Bool :=
  input.all (fun cp => cp < 0x100)

/-- Run every Security Conformance Layer detector on `input` and
    return a `FamilyResult` per family.  The output array has exactly
    26 entries, one per family, in declaration order grouped by
    layer.

    SurrogateReassembly is only invoked when `input` looks
    like a byte stream (every codepoint ≤ 0xFF).  For
    codepoint-array inputs the entry reports clear, since the
    detector's predicate is meaningless on those.  Callers who
    specifically want SurrogateReassembly on a byte stream
    should either use `runAll` directly with a `[0..0xFF]`-
    bounded input or invoke
    `Unicode.Security.Covert.SurrogateReassembly.detect` on
    their byte input separately. -/
def runAll (input : Array Nat) : Array FamilyResult :=
  let c1 := Unicode.Security.Covert.TagBlockPayload.detect           input
  let c2 := Unicode.Security.Covert.VariationSelectorPayload.detect  input
  let c3 := Unicode.Security.Covert.ZeroWidthPayload.detect          input
  let c4 :=
    if looksLikeByteStream input then
      Unicode.Security.Covert.SurrogateReassembly.detect input
    else
      ({ input              := input,
         classify           := .clear,
         byteCount          := input.size,
         firstInvalidOffset := none }
        : Unicode.Security.Covert.SurrogateReassembly.Verdict)
  let c5 := Unicode.Security.Covert.BidiControlBalance.detect        input
  let i1 := Unicode.Security.Identity.HomoglyphConfusable.detect     input
  let i2 := Unicode.Security.Identity.MixedScriptAdmissibility.detect input
  let i3 := Unicode.Security.Identity.EmojiZwjIntegrity.detect       input
  let i4 := Unicode.Security.Identity.SkinToneVariationForgery.detect input
  let d1 := Unicode.Security.Display.SourceDisplayDivergence.detect  input
  let d2 := Unicode.Security.Display.FilenameDisguise.detect         input
  let d3 := Unicode.Security.Display.RtlInjection.detect             input
  let d4 := Unicode.Security.Display.RendererDivergence.detect       input
  let f1 := Unicode.Security.Form.NormalizationBomb.detect           input
  let f2 := Unicode.Security.Form.StreamSafeViolation.detect         input
  let f3 := Unicode.Security.Form.LocaleCaseInversion.detect         input
  let f4 := Unicode.Security.Form.CaseExpansionMismatch.detect       input
  let f5 := Unicode.Security.Form.WidthClassConfusion.detect         input
  let f6 := Unicode.Security.Form.NfcIdempotenceWitness.detect       input
  let x1 := Unicode.Security.Boundary.IdentifierFormDrift.detect     input
  let x2 := Unicode.Security.Boundary.CovertDisplayCompound.detect   input
  let x3 := Unicode.Security.Boundary.ConfusableBidiCompound.detect  input
  let x4 := Unicode.Security.Boundary.AdmissibilityFormDrift.detect  input
  let k1 := Unicode.Security.Crypto.Bip39Canonical.detect            input
  let k2 := Unicode.Security.Crypto.HashInputStability.detect        input
  let k3 := Unicode.Security.Crypto.AiWatermarkDetectability.detect  input
  #[ mkResult .tagBlockPayload          c1.classify.isClear c1.classify.tag c1.classify.positions,
     mkResult .variationSelectorPayload c2.classify.isClear c2.classify.tag c2.classify.positions,
     mkResult .zeroWidthPayload         c3.classify.isClear c3.classify.tag c3.classify.positions,
     mkResult .surrogateReassembly      c4.classify.isClear c4.classify.tag c4.classify.positions,
     mkResult .bidiControlBalance       c5.classify.isClear c5.classify.tag c5.classify.positions,
     mkResult .homoglyphConfusable      i1.classify.isClear i1.classify.tag i1.classify.positions,
     mkResult .mixedScriptAdmissibility i2.classify.isClear i2.classify.tag i2.classify.positions,
     mkResult .emojiZwjIntegrity        i3.classify.isClear i3.classify.tag i3.classify.positions,
     mkResult .skinToneVariationForgery i4.classify.isClear i4.classify.tag i4.classify.positions,
     mkResult .sourceDisplayDivergence  d1.classify.isClear d1.classify.tag d1.classify.positions,
     mkResult .filenameDisguise         d2.classify.isClear d2.classify.tag d2.classify.positions,
     mkResult .rtlInjection             d3.classify.isClear d3.classify.tag d3.classify.positions,
     mkResult .rendererDivergence       d4.classify.isClear d4.classify.tag d4.classify.positions,
     mkResult .normalizationBomb        f1.classify.isClear f1.classify.tag f1.classify.positions,
     mkResult .streamSafeViolation      f2.classify.isClear f2.classify.tag f2.classify.positions,
     mkResult .localeCaseInversion      f3.classify.isClear f3.classify.tag f3.classify.positions,
     mkResult .caseExpansionMismatch    f4.classify.isClear f4.classify.tag f4.classify.positions,
     mkResult .widthClassConfusion      f5.classify.isClear f5.classify.tag f5.classify.positions,
     mkResult .nfcIdempotenceWitness    f6.classify.isClear f6.classify.tag f6.classify.positions,
     mkResult .identifierFormDrift      x1.classify.isClear x1.classify.tag x1.classify.positions,
     mkResult .covertDisplayCompound    x2.classify.isClear x2.classify.tag x2.classify.positions,
     mkResult .confusableBidiCompound   x3.classify.isClear x3.classify.tag x3.classify.positions,
     mkResult .admissibilityFormDrift   x4.classify.isClear x4.classify.tag x4.classify.positions,
     mkResult .bip39Canonical           k1.classify.isClear k1.classify.tag k1.classify.positions,
     mkResult .hashInputStability       k2.classify.isClear k2.classify.tag k2.classify.positions,
     mkResult .aiWatermarkDetectability k3.classify.isClear k3.classify.tag k3.classify.positions ]

/-- Subset of `runAll` containing only the families whose verdict is
    `.hazard`.  Empty when the input passes every detector. -/
def hazardsOnly (input : Array Nat) : Array FamilyResult :=
  (runAll input).filter (fun r =>
    match r.classification with
    | .clear        => false
    | .hazard       => true
    | .compound     => true
    | .informational => false)

/-- True iff at least one family fires on `input`. -/
def anyHazard (input : Array Nat) : Bool :=
  (runAll input).any (fun r =>
    match r.classification with
    | .clear        => false
    | .hazard       => true
    | .compound     => true
    | .informational => false)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Shape invariants
-- ═══════════════════════════════════════════════════════════════════════════════

/-- `runAll` always returns exactly 26 entries, one per family. -/
theorem runAll_size (input : Array Nat) : (runAll input).size = 26 := by
  unfold runAll
  rfl

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Pure ASCII "Hello" fires no general-Unicode detector.  The
    cryptographic-stability detectors are filtered out of this
    baseline because they are context-dependent — Bip39Canonical
    fires on the capital H via its `mixedCase` sub-threat, which
    is correct behaviour for a BIP-39 mnemonic context but not a
    general-Unicode hazard. -/
theorem ascii_hello_no_unicode_hazards :
    ((runAll #[0x48, 0x65, 0x6C, 0x6C, 0x6F]).filter
      (fun r =>
        ¬ (r.family = .bip39Canonical
           ∨ r.family = .hashInputStability
           ∨ r.family = .aiWatermarkDetectability))).all
      (fun r =>
        match r.classification with
        | .clear         => true
        | .informational => true
        | .hazard        => false
        | .compound      => false) = true := by decide

/-- The Arabic ligature U+FDFA fires at least one detector
    (NormalizationBomb, at minimum). -/
theorem arabic_ligature_hazardous :
    anyHazard #[0xFDFA] = true := by decide

/-- The Math Italic identifier fires multiple detectors at once —
    at minimum HomoglyphConfusable, IdentifierFormDrift (per-cp
    identifier-status shift), and AdmissibilityFormDrift (whole-
    string admissibility drift). -/
theorem math_italic_admin_multiple_hazards :
    (hazardsOnly #[0x1D44E, 0x1D451, 0x1D45A, 0x1D456, 0x1D45B]).size ≥ 3 := by
  decide

end Unicode.Security.RunAll
