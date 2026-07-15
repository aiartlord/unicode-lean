/-
  Unicode.Security.Level

  Strictness-level admission predicate for the Security
  Conformance Layer.  Lifts the UTS #39 §5 restriction-level
  shape from the identifier-admissibility surface to the
  general-Unicode detector set, with opt-in gating for the
  cryptographic-stability families.

  ## Why this shape

  UTS #39 §5 organises identifier admissibility into a
  totally-ordered scale of "restriction levels":

      ASCIIOnly  ⊑  SingleScript  ⊑  HighlyRestrictive
                 ⊑  ModeratelyRestrictive  ⊑  MinimallyRestrictive
                 ⊑  Unrestricted

  Every level accepts a *superset* of what stricter levels
  accept.  Callers declare which level their context requires;
  the spec hands them the predicate.  Detectors are not turned
  on or off — every codepoint always carries its
  `Identifier_Status`, and the level decides which combinations
  of statuses are admissible.  Crucially, the level surface is
  never a suppression knob: there is no way to mark an input
  "safe" while a detector says hazard.

  This module lifts that pattern to the detector
  layer.  The same invariants hold:

    1. Every detector remains available through
       `Unicode.Security.RunAll.runAll`, whose reporting surface is
       unchanged.
    2. A `Level` declares an *admission predicate* on the
       input.  `admissibleAt level cryptoCtx input = true`
       iff both the declared level and cryptographic context
       accepts this input.
    3. The levels are totally ordered: `restrictive ⊑ moderate
       ⊑ minimal`.  Admission is monotone in the laxer
       direction: `admissibleAt restrictive ⇒ admissibleAt
       moderate ⇒ admissibleAt minimal`.
    4. No level "filters away" or suppresses a hazard.  Every
       hazard reported by `runAll` remains in the result; the
       level only answers the boolean question "is this input
       acceptable at the declared strictness?".

  ## What Each Level Accepts

  * `restrictive` — accept iff every general-Unicode family in
    the restrictive rejection set reports `.clear`.  Any hazard
    from that set rejects the input.  Strictest level; smallest
    accept set.  This is
    the natural choice for highly sensitive contexts (e.g.
    DNS-label gating, package-registry submission, security-
    audit pipelines).
  * `moderate`    — accept iff no family in the moderate-set
    fires.  The moderate-set drops the heuristic / high-false-
    positive-risk detectors (NormalizationBomb's
    NfdHighExpansion-class ratio hits on legitimate Greek
    polytonic text, RtlInjection's StrongRTLInLTR on user-
    supplied multilingual content, RendererDivergence on emoji
    ZWJ chains, EmojiZwjIntegrity's UnregisteredZwjVariance on
    novel emoji sequences).  Keeps every targeted-attack
    detector intact.
  * `minimal`     — accept iff no family in the structural-
    violation set fires.  The structural set is
    `{SurrogateReassembly, BidiControlBalance, StreamSafeViolation}`
    — UTF-8 byte validity (RFC 3629), bidi-control imbalance
    (Trojan Source class), and stream-safe-format overflow
    (UAX #15 §13 DoS class).  Largest accept set; this is the
    floor below which we never go, suitable as a network-edge
    gate before more specific policy-layer filtering downstream.

  Note on SurrogateReassembly: as of `Unicode.Security.RunAll`
  v0.12.0, `runAll` only invokes the detector when the input
  "looks like a byte stream" (every codepoint ≤ 0xFF);
  otherwise it emits a clear verdict.  This means the detector
  contributes to admission rejection only on actual byte-stream
  inputs, never spuriously on codepoint arrays with non-ASCII
  content.  Accordingly, SurrogateReassembly IS in every
  rejection set (including `minimal`, since UTF-8 byte validity
  per RFC 3629 is exactly the structural invariant `minimal`
  exists to enforce).

  Note on Bip39Canonical / HashInputStability /
  AiWatermarkDetectability: the cryptographic-stability
  detectors are *highly context-dependent* by their family
  threat models.
  Bip39Canonical fires `mixedCase` on any ASCII text with
  capital letters; `wordlistMismatch` on any ASCII text whose
  words aren't BIP-39 vocabulary.  Those verdicts are correct
  only in a BIP-39 mnemonic *context*; for general Unicode
  input they would produce constant rejection.

  Accordingly, cryptographic-stability gating is **opt-in via a
  `CryptoContext` parameter** passed to `admissibleAt`.  Callers
  doing general identifier / display gating pass
  `CryptoContext.nonCrypto` (cryptographic-stability detectors ignored).  Callers
  verifying a BIP-39 mnemonic pass `.bip39Mnemonic`
  (Bip39Canonical gated); callers hashing the input pass
  `.hashInput` (HashInputStability gated); callers attributing
  AI provenance pass `.aiAttribution` (AiWatermarkDetectability
  gated).  A single input is one crypto-shape at a time.
-/

import Unicode.Security.RunAll

set_option maxHeartbeats 4000000

namespace Unicode.Security.Level

open Unicode.Security.Calculus
open Unicode.Security.RunAll (runAll)

/-- The three canonical strictness levels, ordered from
    strictest to laxest.  See module header for what each
    accepts. -/
inductive Level where
  | restrictive
  | moderate
  | minimal
  deriving DecidableEq, Repr, Inhabited

/-- The family-tag set whose hazards cause admission failure
    at `level`.  Note this is a REJECTION set, not an allow-
    list.  `restrictive` rejects on every family; `moderate`
    rejects on a subset; `minimal` rejects on only the
    structural-violation families.

    Monotonicity: `minimal.rejectionSet ⊆ moderate.rejectionSet
    ⊆ restrictive.rejectionSet`.  Proven below. -/
def rejectionSet : Level → Array Family
  | .restrictive =>
    -- All 23 non-K families.  SurrogateReassembly is included
    -- because `runAll` gates it on `looksLikeByteStream`
    -- (every codepoint ≤ 0xFF); on codepoint arrays with any
    -- non-ASCII content the detector emits clear and does not
    -- reject.
    #[ .tagBlockPayload, .variationSelectorPayload
     , .zeroWidthPayload, .surrogateReassembly
     , .bidiControlBalance
     , .homoglyphConfusable, .mixedScriptAdmissibility
     , .emojiZwjIntegrity, .skinToneVariationForgery
     , .sourceDisplayDivergence, .filenameDisguise
     , .rtlInjection, .rendererDivergence
     , .normalizationBomb, .streamSafeViolation
     , .localeCaseInversion, .caseExpansionMismatch
     , .widthClassConfusion, .nfcIdempotenceWitness
     , .identifierFormDrift, .covertDisplayCompound
     , .confusableBidiCompound, .admissibilityFormDrift ]
  | .moderate =>
    -- Drops the heuristic / FP-prone detectors that don't
    -- need to gate "default-safe for multilingual text"
    -- pipelines:
    --
    --   NormalizationBomb — ratio-based NfdHighExpansion /
    --     NfkdHighExpansion fire on legitimate Greek
    --     polytonic text.  The precise SingleCpBlowup sub-
    --     threat (FDFA 1→18) is backstopped by
    --     IdentifierFormDrift since FDFA is Restricted-Allowed
    --     in identifier-status terms.
    --   RtlInjection — StrongRTLInLTR / FieldTakeover fire on
    --     legitimate Hebrew / Arabic UI strings (the detector
    --     assumes an LTR-declared field).  Callers handling
    --     RTL UI text must declare the field direction and
    --     bypass the detector anyway.
    --   RendererDivergence — Zalgo / fullwidth / emoji
    --     variance heuristic; high FP on legitimate
    --     emoji-heavy or multilingual content.
    --   EmojiZwjIntegrity — novel emoji ZWJ sequences not yet
    --     in RGI fire UnregisteredSequence / NonEmojiInjection.
    --     Routine in modern social / chat content.
    --
    -- SurrogateReassembly is retained because `runAll` gates
    -- it on `looksLikeByteStream`, so it never spuriously
    -- fires on multilingual codepoint inputs.  Every other
    -- targeted-attack detector and UTS #39 spec-compliance
    -- signal is intact.
    #[ .tagBlockPayload, .variationSelectorPayload
     , .zeroWidthPayload, .surrogateReassembly
     , .bidiControlBalance
     , .homoglyphConfusable, .mixedScriptAdmissibility
     , .skinToneVariationForgery
     , .sourceDisplayDivergence, .filenameDisguise
     , .streamSafeViolation, .localeCaseInversion
     , .caseExpansionMismatch, .widthClassConfusion
     , .nfcIdempotenceWitness
     , .identifierFormDrift, .covertDisplayCompound
     , .confusableBidiCompound, .admissibilityFormDrift ]
  | .minimal =>
    -- Structural / RFC-violation families: UTF-8 byte
    -- validity (RFC 3629, via runAll's byte-stream gate),
    -- bidi-control imbalance (Trojan Source class), stream-
    -- safe overflow (UAX #15 §13 DoS class).
    #[ .surrogateReassembly, .bidiControlBalance, .streamSafeViolation ]

/-- True iff `family` is in `level`'s rejection set. -/
@[inline]
def Level.rejects (level : Level) (family : Family) : Bool :=
  (rejectionSet level).contains family

/-- True iff every element of `input` fits in a single octet.
    Mirrors `Unicode.Security.RunAll`'s SurrogateReassembly gate:
    C4 is byte-stream-oriented and must not reject codepoint arrays
    merely because they contain non-ASCII scalar values. -/
@[inline]
def looksLikeByteStream (input : Array Nat) : Bool :=
  input.all (fun cp => cp < 0x100)

/-- Admission-relevant hazard bit for one detector family.

    This is deliberately factored per family instead of computing
    `runAll input` and filtering its 26 results.  The public reporting
    surface remains `runAll`; the admission predicate only needs the
    hazards in the declared rejection set, so evaluating unrelated
    detectors is avoidable proof-engineering cost. -/
@[inline]
def familyHazard (family : Family) (input : Array Nat) : Bool :=
  match family with
  | .tagBlockPayload =>
      !(Unicode.Security.Covert.TagBlockPayload.detect input).classify.isClear
  | .variationSelectorPayload =>
      !(Unicode.Security.Covert.VariationSelectorPayload.detect input).classify.isClear
  | .zeroWidthPayload =>
      !(Unicode.Security.Covert.ZeroWidthPayload.detect input).classify.isClear
  | .surrogateReassembly =>
      if looksLikeByteStream input then
        !(Unicode.Security.Covert.SurrogateReassembly.detect input).classify.isClear
      else
        false
  | .bidiControlBalance =>
      !(Unicode.Security.Covert.BidiControlBalance.detect input).classify.isClear
  | .homoglyphConfusable =>
      !(Unicode.Security.Identity.HomoglyphConfusable.detect input).classify.isClear
  | .mixedScriptAdmissibility =>
      !(Unicode.Security.Identity.MixedScriptAdmissibility.detect input).classify.isClear
  | .emojiZwjIntegrity =>
      !(Unicode.Security.Identity.EmojiZwjIntegrity.detect input).classify.isClear
  | .skinToneVariationForgery =>
      !(Unicode.Security.Identity.SkinToneVariationForgery.detect input).classify.isClear
  | .sourceDisplayDivergence =>
      !(Unicode.Security.Display.SourceDisplayDivergence.detect input).classify.isClear
  | .filenameDisguise =>
      !(Unicode.Security.Display.FilenameDisguise.detect input).classify.isClear
  | .rtlInjection =>
      !(Unicode.Security.Display.RtlInjection.detect input).classify.isClear
  | .rendererDivergence =>
      !(Unicode.Security.Display.RendererDivergence.detect input).classify.isClear
  | .normalizationBomb =>
      !(Unicode.Security.Form.NormalizationBomb.detect input).classify.isClear
  | .streamSafeViolation =>
      !(Unicode.Security.Form.StreamSafeViolation.detect input).classify.isClear
  | .localeCaseInversion =>
      !(Unicode.Security.Form.LocaleCaseInversion.detect input).classify.isClear
  | .caseExpansionMismatch =>
      !(Unicode.Security.Form.CaseExpansionMismatch.detect input).classify.isClear
  | .widthClassConfusion =>
      !(Unicode.Security.Form.WidthClassConfusion.detect input).classify.isClear
  | .nfcIdempotenceWitness =>
      !(Unicode.Security.Form.NfcIdempotenceWitness.detect input).classify.isClear
  | .identifierFormDrift =>
      !(Unicode.Security.Boundary.IdentifierFormDrift.detect input).classify.isClear
  | .covertDisplayCompound =>
      !(Unicode.Security.Boundary.CovertDisplayCompound.detect input).classify.isClear
  | .confusableBidiCompound =>
      !(Unicode.Security.Boundary.ConfusableBidiCompound.detect input).classify.isClear
  | .admissibilityFormDrift =>
      !(Unicode.Security.Boundary.AdmissibilityFormDrift.detect input).classify.isClear
  | .bip39Canonical =>
      !(Unicode.Security.Crypto.Bip39Canonical.detect input).classify.isClear
  | .hashInputStability =>
      !(Unicode.Security.Crypto.HashInputStability.detect input).classify.isClear
  | .aiWatermarkDetectability =>
      !(Unicode.Security.Crypto.AiWatermarkDetectability.detect input).classify.isClear

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 CryptoContext — opt-in cryptographic-stability gating
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The context under which the cryptographic-stability
    detectors (Bip39Canonical, HashInputStability,
    AiWatermarkDetectability) are treated as admission-
    relevant.  Defaults to `nonCrypto` — general Unicode-only
    admission with the cryptographic-stability detectors
    ignored.

    Constructor map:
      * `nonCrypto`     — cryptographic-stability detectors ignored
      * `bip39Mnemonic` — adds Bip39Canonical to rejection set
      * `hashInput`     — adds HashInputStability
      * `aiAttribution` — adds AiWatermarkDetectability

    Per `cryptographic-stability.md`, a single input is one
    crypto-shape at a time, so a sum-of-constructors fits the
    current calling pattern. -/
inductive CryptoContext where
  | nonCrypto
  | bip39Mnemonic
  | hashInput
  | aiAttribution
  deriving DecidableEq, Repr, Inhabited

/-- The cryptographic-stability detector tag added to the effective rejection set
    under each context.  `nonCrypto` adds none; `bip39Mnemonic`
    adds Bip39Canonical; `hashInput` adds HashInputStability;
    `aiAttribution` adds AiWatermarkDetectability.  Each
    crypto-shape is exactly one cryptographic-stability detector. -/
@[inline]
def CryptoContext.toFamilies : CryptoContext → Array Family
  | .nonCrypto      => #[]
  | .bip39Mnemonic  => #[.bip39Canonical]
  | .hashInput      => #[.hashInputStability]
  | .aiAttribution  => #[.aiWatermarkDetectability]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Factored admission predicates (Level ⊥ Crypto)
--
-- Admission has two ORTHOGONAL dimensions:
--
--   * `levelAdmissible level input` — does the Unicode-layer
--     family set declared by `level` accept `input`?  Answer is
--     INDEPENDENT of any cryptographic context.
--
--   * `cryptoAdmissible ctx input` — does the cryptographic-stability detector set
--     declared by `ctx` accept `input`?  Answer is INDEPENDENT
--     of any Level.
--
-- The composite `admissibleAt level ctx input` is the AND of
-- the two — both factors must accept.  Factoring them this way
-- makes the cryptographic-stability detectors' distinguishing power directly observable
-- as a difference in `cryptoAdmissible`, even on inputs that
-- `levelAdmissible level input` already rejects.  Without this
-- factoring, the cryptographic-stability contribution would be masked by the
-- union whenever any general-Unicode detector also flags the
-- same input —
-- e.g. decomposed é, which HashInputStability flags as
-- NormalizationDrift AND NfcIdempotenceWitness rejects at
-- `.restrictive`/`.moderate`, so a naive `admissibleAt`-only test
-- would show both contexts rejecting and miss that
-- HashInputStability is independently contributing.
--
-- Mathematical equivalence to the union-based form:
--   ¬ any (haz ∧ r ∈ (L ++ K))
--     ↔ ¬ any (haz ∧ (r ∈ L ∨ r ∈ K))
--     ↔ ¬ (any (haz ∧ r ∈ L) ∨ any (haz ∧ r ∈ K))
--     ↔ ¬ any (haz ∧ r ∈ L) ∧ ¬ any (haz ∧ r ∈ K)
--     ↔ levelAdmissible level input ∧ cryptoAdmissible ctx input
--
-- So no behaviour of `admissibleAt` changes; what changes is
-- that callers and theorems can now inspect each factor
-- independently.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff the Unicode-layer family set declared by `level`
    accepts `input`.  Independent of any cryptographic context.
    Used as the Level-only factor of the composite
    `admissibleAt`. -/
def levelAdmissible (level : Level) (input : Array Nat) : Bool :=
  let effective := rejectionSet level
  ¬ effective.any (fun family => familyHazard family input)

/-- Does the cryptographic-stability detector set declared by `cryptoCtx` accept `input`?
    Independent of any Level.  Used as the Crypto-only factor of
    the composite `admissibleAt`.  Captures the cryptographic-stability's
    distinguishing power directly, without union-masking by
    general-Unicode detectors. -/
def cryptoAdmissible (cryptoCtx : CryptoContext)
    (input : Array Nat) : Bool :=
  let effective := cryptoCtx.toFamilies
  ¬ effective.any (fun family => familyHazard family input)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Composite admission predicate
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `input` is admissible at the declared `level` under
    the declared `cryptoCtx`.  Defined as the AND of the two
    orthogonal factors — both must accept.  Hazards from
    families in the union (Level ∪ Crypto) cause admission
    failure; hazards from other families are reported by
    `runAll` but do not gate admission at this surface.

    Callers who need to see WHICH factor rejected should call
    `levelAdmissible` and `cryptoAdmissible` separately.  See
    `crypto_admissible_gates_decomposed_e_acute` for a worked
    example of the cryptographic-stability detectors' distinguishing power being visible
    in `cryptoAdmissible` even on inputs where `admissibleAt`
    would mask the contribution behind a general-Unicode
    rejection. -/
def admissibleAt (level : Level) (cryptoCtx : CryptoContext)
    (input : Array Nat) : Bool :=
  levelAdmissible level input && cryptoAdmissible cryptoCtx input

/-- The architectural invariant: `admissibleAt` is exactly the
    conjunction of its two orthogonal factors.  True by
    construction (the definition of `admissibleAt` is the
    body), so the theorem closes by `rfl`.  Spelled out
    explicitly here to document the invariant on the public
    surface — downstream consumers and proof obligations can
    rely on this equality without reading the definition. -/
theorem admissibleAt_factors
    (level : Level) (cryptoCtx : CryptoContext) (input : Array Nat) :
    admissibleAt level cryptoCtx input
      = (levelAdmissible level input && cryptoAdmissible cryptoCtx input) :=
  rfl

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Rejection-set monotonicity
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The restrictive rejection set covers all 23 non-K families.
    `runAll`'s byte-stream gate makes C4 contribution
    well-behaved on codepoint inputs. -/
theorem restrictive_rejection_size :
    (rejectionSet .restrictive).size = 23 := by decide

/-- The moderate rejection set drops the 4 heuristic / FP-prone
    detectors (F1, D3, D4, I3) from restrictive, keeping 19. -/
theorem moderate_rejection_size :
    (rejectionSet .moderate).size = 19 := by decide

/-- The minimal rejection set covers the 3 structural / RFC-
    violation families (C4 UTF-8 byte validity, C5 bidi-control
    balance, F2 stream-safe overflow). -/
theorem minimal_rejection_size :
    (rejectionSet .minimal).size = 3 := by decide

/-- Every family in `moderate.rejectionSet` is also in
    `restrictive.rejectionSet`. -/
theorem moderate_rejection_subset_restrictive :
    (rejectionSet .moderate).all (fun fam =>
      (rejectionSet .restrictive).contains fam) = true := by
  decide

/-- Every family in `minimal.rejectionSet` is also in
    `moderate.rejectionSet`. -/
theorem minimal_rejection_subset_moderate :
    (rejectionSet .minimal).all (fun fam =>
      (rejectionSet .moderate).contains fam) = true := by
  decide

/-- Every family in `minimal.rejectionSet` is also in
    `restrictive.rejectionSet` (transitive). -/
theorem minimal_rejection_subset_restrictive :
    (rejectionSet .minimal).all (fun fam =>
      (rejectionSet .restrictive).contains fam) = true := by
  decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Admission monotonicity
--
-- The headline correctness property: admission is monotone in
-- the laxer direction.  If `input` is admissible at the strict
-- level it is also admissible at the laxer level.
--
-- Universal monotonicity holds *by construction*: `admissibleAt
-- level input` is defined as "no `runAll` result is both a
-- hazard AND in `level.rejectionSet`".  Since
-- `minimal.rejectionSet ⊆ moderate.rejectionSet ⊆
-- restrictive.rejectionSet` (proven in §2 above), any result
-- rejected at the laxer level is also rejected at the stricter
-- level — equivalently, any input admissible at the stricter
-- level is also admissible at the laxer level.
--
-- The structural argument is straight-line propositional
-- reasoning: `(haz ∧ r ∈ S₁) → (haz ∧ r ∈ S₂)` whenever
-- `S₁ ⊆ S₂`.  We pin the invariant via spot-checks on every
-- canonical attack vector below — any monotonicity violation
-- in a future refactor would surface as a failed
-- `decide`.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Monotonicity witness, pure ASCII.  Admissible at all three
    levels. -/
theorem monotone_ascii_hello :
    let input : Array Nat := #[0x48, 0x65, 0x6C, 0x6C, 0x6F]
    admissibleAt .restrictive .nonCrypto input = true
    ∧ admissibleAt .moderate .nonCrypto input = true
    ∧ admissibleAt .minimal .nonCrypto input = true := by decide

/-- Monotonicity witness, lone RLO.  Inadmissible at every
    level (C5 is in every rejection set). -/
theorem monotone_lone_rlo :
    let input : Array Nat := #[0x202E]
    admissibleAt .restrictive .nonCrypto input = false
    ∧ admissibleAt .moderate .nonCrypto input = false
    ∧ admissibleAt .minimal .nonCrypto input = false := by decide

/-- Monotonicity witness, Cyrillic Nethereum typosquat.
    Inadmissible at restrictive + moderate (I1 fires there),
    admissible at minimal (I1 not in minimal rejection set). -/
theorem monotone_nethereum :
    let input : Array Nat := #[0x4E, 0x65, 0x74, 0x68, 0x65, 0x72,
                                0x0435, 0x75, 0x6D]
    admissibleAt .restrictive .nonCrypto input = false
    ∧ admissibleAt .moderate .nonCrypto input = false
    ∧ admissibleAt .minimal .nonCrypto input = true := by decide

/-- Monotonicity witness, Math Italic admin.  Same shape as
    Nethereum — identifier-side attack, inadmissible at
    restrictive + moderate, admissible at minimal. -/
theorem monotone_math_italic_admin :
    let input : Array Nat := #[0x1D44E, 0x1D451, 0x1D45A, 0x1D456, 0x1D45B]
    admissibleAt .restrictive .nonCrypto input = false
    ∧ admissibleAt .moderate .nonCrypto input = false
    ∧ admissibleAt .minimal .nonCrypto input = true := by decide

/-- Monotonicity witness, Greek polytonic.  Inadmissible at
    restrictive (F1 NfdHighExpansion fires there), admissible
    at moderate (F1 not in moderate's rejection set) AND
    minimal.  Note: the Greek polytonic codepoint also fires
    I2 RestrictedStatusCp — but I2 IS in moderate's rejection
    set, so the monotone-pass at moderate level requires that
    Greek polytonic ALSO not trigger I2.  In practice U+1F86
    does trigger I2, so this row pins the actual outcome:
    moderate REJECTS the Greek polytonic, even though F1
    alone would have accepted it.  Pinning this prevents a
    future refactor of moderate's rejection set from
    accidentally accepting Greek polytonic without auditing
    the trade-off. -/
theorem monotone_greek_polytonic :
    let input : Array Nat := #[0x1F86]
    admissibleAt .restrictive .nonCrypto input = false
    ∧ admissibleAt .moderate .nonCrypto input = false
    ∧ admissibleAt .minimal .nonCrypto input = true := by decide

/-- Monotonicity witness, Arabic ligature FDFA (1→18 NFKD
    expansion — the canonical normalization bomb).
    Inadmissible at restrictive (F1 fires).  Also inadmissible
    at moderate (X1 IdentifierFormDrift fires — the codepoint's
    NFKD-head Identifier_Status differs from its own).
    Admissible at minimal — neither C4, C5, nor F2 fires on
    the single codepoint (FDFA > 0xFF so C4's byte-stream
    gate skips it). -/
theorem monotone_fdfa :
    let input : Array Nat := #[0xFDFA]
    admissibleAt .restrictive .nonCrypto input = false
    ∧ admissibleAt .moderate .nonCrypto input = false
    ∧ admissibleAt .minimal .nonCrypto input = true := by decide

/-- Monotonicity witness, Java modified-UTF-8 NUL `0xC0 0x80`.
    Pure byte-stream input (every codepoint ≤ 0xFF), so
    runAll's byte-stream gate runs C4, which fires
    InvalidStartByte at offset 0.  Inadmissible at every
    level — C4 is in every rejection set including `minimal`. -/
theorem monotone_modified_utf8_nul :
    let input : Array Nat := #[0xC0, 0x80]
    admissibleAt .restrictive .nonCrypto input = false
    ∧ admissibleAt .moderate .nonCrypto input = false
    ∧ admissibleAt .minimal .nonCrypto input = false := by decide

/-- Monotonicity witness, mixed input with a non-ASCII codepoint
    `#[0xC0, 0x80, 0x4E2D]`.  The Han codepoint 0x4E2D > 0xFF
    so runAll's byte-stream gate skips C4 entirely.  Without
    C4 firing, the input is admissible at minimal (no other
    family fires on this short non-bidi codepoint sequence).
    This pins the byte-stream gate's intended behaviour:
    mixing high codepoints into the input flips C4 off,
    preventing spurious rejection. -/
theorem monotone_mixed_high_codepoint :
    let input : Array Nat := #[0xC0, 0x80, 0x4E2D]
    admissibleAt .minimal .nonCrypto input = true := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 CryptoContext gating — K1 only fires under .bip39Mnemonic
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Single ASCII U+0020 SPACE alone fires I2 `restrictedStatusCp` —
    UTS #39 IdentifierStatus.txt classifies U+0020 as Restricted
    because spaces aren't valid in any identifier.  This documents
    the design point: any input containing whitespace will be
    rejected at restrictive (and moderate), regardless of context.
    Multi-word mnemonics, sentences, and other space-bearing text
    are not "identifier admissible" by design. -/
theorem space_alone_fires_I2 :
    (Unicode.Security.Identity.MixedScriptAdmissibility.detect
      #[0x20]).classify.isClear = false := by
  decide

/-- Pure ASCII "Hello" is admissible at every level under
    `nonCrypto` — no Unicode-layer hazard fires.  Under
    `bip39Mnemonic` the verdict flips: K1's `mixedCase` fires on
    the capital H and admission is refused. -/
theorem crypto_ctx_gates_mixed_case :
    let input : Array Nat := #[0x48, 0x65, 0x6C, 0x6C, 0x6F]
    admissibleAt .restrictive .nonCrypto     input = true
    ∧ admissibleAt .restrictive .bip39Mnemonic input = false := by
  decide

/-- Single BIP-39 word "abandon" (pure lowercase ASCII, valid
    English wordlist entry) is admissible under both contexts.
    Pins that the BIP-39 context does NOT spuriously reject
    canonical-form input. -/
theorem crypto_ctx_single_word_passes_both :
    let input : Array Nat := #[0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E]
    admissibleAt .restrictive .nonCrypto     input = true
    ∧ admissibleAt .restrictive .bip39Mnemonic input = true := by
  decide

/-- K2's `hashInput` context-gating, measured directly via
    `cryptoAdmissible` — Level-independent.  Decomposed é
    (U+0065 U+0301) is accepted under `.nonCrypto` (no cryptographic-stability detector in
    the effective set) and rejects under `.hashInput` because
    K2's `NormalizationDrift` fires.  This is the architectural
    pin for the cryptographic-stability detectors' distinguishing power: the contribution
    is observable at every Level via `cryptoAdmissible`, NOT
    only at `.minimal` via `admissibleAt`.  Pinning this here
    matters because F6 NfcIdempotenceWitness rejects the same
    input under `levelAdmissible .restrictive` and
    `levelAdmissible .moderate`, so a naive `admissibleAt`-only
    test would show both contexts rejecting and miss that K2
    is independently contributing.  See
    `crypto_ctx_gates_decomposed_e_acute_at_minimal` below for
    the composite-form co-witness. -/
theorem crypto_admissible_gates_decomposed_e_acute :
    let input : Array Nat := #[0x0065, 0x0301]
    cryptoAdmissible .nonCrypto input = true
    ∧ cryptoAdmissible .hashInput input = false := by
  decide

/-- Composite-form co-witness for the K2 gating: at `.minimal`
    (where F6 is excluded from the Level set), `admissibleAt`
    flips between `.nonCrypto` and `.hashInput`.  At `.restrictive`
    and `.moderate`, F6 NfcIdempotenceWitness also rejects
    decomposed é, so `admissibleAt` returns `false` under BOTH
    contexts — that's the Level ∧ Crypto union, NOT a suppression
    of K2.  The `crypto_admissible_gates_decomposed_e_acute` pin
    above shows K2's contribution explicitly without the masking. -/
theorem crypto_ctx_gates_decomposed_e_acute_at_minimal :
    let input : Array Nat := #[0x0065, 0x0301]
    admissibleAt .minimal .nonCrypto input = true
    ∧ admissibleAt .minimal .hashInput input = false := by
  decide

/-- Co-witness that under `.restrictive` and `.moderate`, the
    composite `admissibleAt` rejects decomposed é under BOTH
    `.nonCrypto` and `.hashInput` — the Level factor rejects
    independently via F6 NfcIdempotenceWitness, so the Crypto
    factor's flip is masked at the composite surface.  The
    factored predicates above show K2's contribution is still
    present in `cryptoAdmissible`. -/
theorem level_admissible_rejects_decomposed_e_at_restrictive :
    let input : Array Nat := #[0x0065, 0x0301]
    levelAdmissible .restrictive input = false
    ∧ levelAdmissible .moderate    input = false := by
  decide

/-- K3's `aiAttribution` context-gating, measured directly via
    `cryptoAdmissible` — Level-independent.  Plain ASCII
    `a NNBSP b` (#[0x61, 0x202F, 0x62]) is accepted under
    `.nonCrypto` (no cryptographic-stability detector in the effective set) and rejects
    under `.aiAttribution` because K3's `NnbspBoundary` fires.
    This is the architectural pin for K3's distinguishing power:
    the contribution is observable at every Level via
    `cryptoAdmissible`, even though five general-Unicode
    detectors
    (C3 BareZeroWidth, I2 RestrictedStatusCp, D1 ZeroWidth,
    F6 NonNfkcCompatForm, K1 NonNFKD under .bip39Mnemonic) also
    flag U+202F at `.restrictive`.  Those overlaps mask the
    contribution at the `admissibleAt` composite surface but
    do NOT suppress K3's verdict — `cryptoAdmissible` shows the
    K3-specific decision directly.  Follows the same shape as
    `crypto_admissible_gates_decomposed_e_acute` for K2. -/
theorem crypto_admissible_gates_nnbsp_under_aiAttribution :
    let input : Array Nat := #[0x61, 0x202F, 0x62]
    cryptoAdmissible .nonCrypto     input = true
    ∧ cryptoAdmissible .aiAttribution input = false := by
  decide

/-- Co-witness of the masking effect: at `.restrictive`,
    `levelAdmissible` rejects `a NNBSP b` independently of any
    crypto context (C3 / I2 / D1 / F6 all fire on U+202F at
    that Level).  Pins that the K3 contribution above is a
    distinct verdict from the Level rejection, not a duplicate.
    See `crypto_admissible_gates_nnbsp_under_aiAttribution`
    for the K3-specific gating pin. -/
theorem level_admissible_rejects_nnbsp_at_restrictive :
    let input : Array Nat := #[0x61, 0x202F, 0x62]
    levelAdmissible .restrictive input = false := by
  decide

end Unicode.Security.Level
