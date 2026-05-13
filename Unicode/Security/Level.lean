/-
  Unicode.Security.Level

  Strictness-level admission predicate for the Security
  Conformance Layer.  Lifts the UTS #39 §5 restriction-level
  shape from the identifier-admissibility surface to the full
  23-family detector layer.

  ## Why this shape

  UTS #39 §5 organises identifier admissibility into a
  totally-ordered scale of "restriction levels":

      ASCIIOnly  ⊑  SingleScript  ⊑  HighlyRestrictive
                 ⊑  ModeratelyRestrictive  ⊑  MinimallyRestrictive
                 ⊑  Unrestricted

  Every level admits a *superset* of what stricter levels
  admit.  Callers declare which level their context requires;
  the spec hands them the predicate.  Detectors are not turned
  on or off — every codepoint always carries its
  `Identifier_Status`, and the level decides which combinations
  of statuses are admissible.  Crucially, the level surface is
  never a suppression knob: there is no way to mark an input
  "safe" while a detector says hazard.

  This module lifts that pattern to the 23-family detector
  layer.  The same invariants hold:

    1. Every detector always runs and reports its own verdict
       (`Unicode.Security.RunAll.runAll` is unchanged).
    2. A `Level` declares an *admission predicate* on the
       input.  `admissibleAt level input = true` iff the
       declared level admits this input.
    3. The levels are totally ordered: `restrictive ⊑ moderate
       ⊑ minimal`.  Admission is monotone in the laxer
       direction: `admissibleAt restrictive ⇒ admissibleAt
       moderate ⇒ admissibleAt minimal`.
    4. No level "filters away" or suppresses a hazard.  Every
       hazard reported by `runAll` remains in the result; the
       level only answers the boolean question "is this input
       acceptable at the declared strictness?".

  ## What each level admits

  * `restrictive` — admit iff every one of the 23 families'
    verdicts is `.clear`.  Any hazard from any family rejects
    the input.  Strictest level; smallest admit set.  This is
    the natural choice for highly sensitive contexts (e.g.
    DNS-label gating, package-registry submission, security-
    audit pipelines).
  * `moderate`    — admit iff no family in the moderate-set
    fires.  The moderate-set drops the heuristic / high-false-
    positive-risk detectors (F1 NfdHighExpansion-class ratio
    hits on legitimate Greek polytonic text, D3
    StrongRTLInLTR on user-supplied multilingual content, D4
    RendererDivergence on emoji ZWJ chains, I3
    UnregisteredZwjVariance on novel emoji sequences).  Keeps
    every targeted-attack detector intact.
  * `minimal`     — admit iff no family in the structural-
    violation set fires.  The structural set is `{C5, F2}` —
    bidi-control imbalance (Trojan Source class) and stream-
    safe-format overflow (UAX #15 §13 DoS class).  Largest
    admit set; this is the floor below which we never go,
    suitable as a network-edge gate before more specific
    policy-layer filtering downstream.

  Note on C4 SurrogateReassembly: as of `Unicode.Security.RunAll`
  v0.12.0, `runAll` only invokes C4 when the input "looks like
  a byte stream" (every codepoint ≤ 0xFF); otherwise C4 emits
  a clear verdict.  This means C4 contributes to admission
  rejection only on actual byte-stream inputs, never spuriously
  on codepoint arrays with non-ASCII content.  Accordingly, C4
  IS in every rejection set (including `minimal`, since UTF-8
  byte validity per RFC 3629 is exactly the structural
  invariant `minimal` exists to enforce).

  Note on K-family (Layer 6, Cryptographic Stability): K1
  (BIP-39 canonical form), and the planned K2 / K3, are *highly
  context-dependent* per `docs/specs/security/L6-cryptographic-
  stability.md`.  K1 fires `mixedCase` on any ASCII text with
  capital letters; `wordlistMismatch` on any ASCII text whose
  words aren't BIP-39 vocabulary.  Those verdicts are correct
  only in a BIP-39 mnemonic *context*; for general Unicode
  input they would produce constant rejection.

  Accordingly, K-family gating is **opt-in via a
  `CryptoContext` parameter** passed to `admissibleAt`.  Callers
  doing general identifier / display gating pass
  `CryptoContext.nonCrypto` (K-family ignored).  Callers
  verifying a BIP-39 mnemonic pass `.bip39Mnemonic` (K1
  gated); callers hashing the input pass `.hashInput` (K2
  gated); callers attributing AI provenance pass
  `.aiAttribution` (K3 gated).  A single input is one crypto-
  shape at a time.
-/

import Unicode.Security.RunAll

set_option maxHeartbeats 4000000

namespace Unicode.Security.Level

open Unicode.Security.Calculus
open Unicode.Security.RunAll (FamilyResult runAll)

/-- The three canonical strictness levels, ordered from
    strictest to laxest.  See module header for what each
    admits. -/
inductive Level where
  | restrictive
  | moderate
  | minimal
  deriving DecidableEq, Repr, Inhabited

/-- True iff the result is a hazard-class verdict (hazard or
    compound).  Clear and informational results never cause
    admission failure at any level. -/
@[inline]
private def isHazard (r : FamilyResult) : Bool :=
  match r.classification with
  | .clear         => false
  | .informational => false
  | unknownHaz     =>
    Function.const ClassificationKind true unknownHaz

/-- The family-tag set whose hazards cause admission failure
    at `level`.  Note this is a REJECTION set, not an allow-
    list.  `restrictive` rejects on every family; `moderate`
    rejects on a subset; `minimal` rejects on only the
    structural-violation families.

    Monotonicity: `minimal.rejectionSet ⊆ moderate.rejectionSet
    ⊆ restrictive.rejectionSet`.  Proven below. -/
def rejectionSet : Level → Array String
  | .restrictive =>
    -- All 23 families.  C4 SurrogateReassembly is included
    -- because `runAll` gates C4 on `looksLikeByteStream`
    -- (every codepoint ≤ 0xFF), so C4 only contributes
    -- rejection on actual byte-stream inputs.  For codepoint
    -- arrays with any non-ASCII content, C4 emits clear and
    -- doesn't reject.
    #[ "C1", "C2", "C3", "C4", "C5"
     , "I1", "I2", "I3", "I4"
     , "D1", "D2", "D3", "D4"
     , "F1", "F2", "F3", "F4", "F5", "F6"
     , "X1", "X2", "X3", "X4" ]
  | .moderate =>
    -- Drops the heuristic / FP-prone detectors that don't
    -- need to gate "default-safe for multilingual text"
    -- pipelines:
    --
    --   F1 — ratio-based NfdHighExpansion / NfkdHighExpansion
    --        fire on legitimate Greek polytonic text.  F1's
    --        precise SingleCpBlowup sub-threat (FDFA 1→18) is
    --        backstopped by X1 IdentifierFormDrift since FDFA
    --        is Restricted-Allowed in identifier-status terms.
    --   D3 — StrongRTLInLTR / FieldTakeover fire on legitimate
    --        Hebrew / Arabic UI strings (D3 assumes an
    --        LTR-declared field).  Callers handling RTL UI
    --        text must declare the field direction and bypass
    --        D3 anyway.
    --   D4 — Zalgo / fullwidth / emoji variance heuristic;
    --        high FP on legitimate emoji-heavy or
    --        multilingual content.
    --   I3 — Novel emoji ZWJ sequences not yet in RGI fire
    --        UnregisteredSequence / NonEmojiInjection.
    --        Routine in modern social / chat content.
    --
    -- C4 is retained because `runAll` gates it on
    -- `looksLikeByteStream`, so it never spuriously fires on
    -- multilingual codepoint inputs.  Every other targeted-
    -- attack detector and UTS #39 spec-compliance signal is
    -- intact.
    #[ "C1", "C2", "C3", "C4", "C5"
     , "I1", "I2", "I4"
     , "D1", "D2"
     , "F2", "F3", "F4", "F5", "F6"
     , "X1", "X2", "X3", "X4" ]
  | .minimal =>
    -- Structural / RFC-violation families.  C4
    -- SurrogateReassembly (RFC 3629 UTF-8 byte validity,
    -- via runAll's byte-stream gate), C5 (bidi-control
    -- imbalance, Trojan Source class), F2 (stream-safe
    -- overflow, UAX #15 §13 DoS class).
    #[ "C4", "C5", "F2" ]

/-- True iff `family` is in `level`'s rejection set. -/
@[inline]
def Level.rejects (level : Level) (family : String) : Bool :=
  (rejectionSet level).contains family

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 CryptoContext — opt-in K-family gating
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The context under which K-family (Layer 6) detectors are
    treated as admission-relevant.  Defaults to `nonCrypto` —
    general Unicode-only admission with K-family ignored.

    Constructor map:
      * `nonCrypto`     — K-family ignored
      * `bip39Mnemonic` — adds K1 (Bip39Canonical) to rejection set
      * `hashInput`     — adds K2 (HashInputStability)
      * `aiAttribution` — adds K3 (AiWatermarkDetectability)

    Per `L6-cryptographic-stability.md`, a single input is one
    crypto-shape at a time, so a sum-of-constructors fits the
    current calling pattern. -/
inductive CryptoContext where
  | nonCrypto
  | bip39Mnemonic
  | hashInput
  | aiAttribution
  deriving DecidableEq, Repr, Inhabited

/-- The K-family tag(s) added to the effective rejection set
    under each context.  `nonCrypto` adds none; `bip39Mnemonic`
    adds K1; `hashInput` adds K2; `aiAttribution` adds K3.
    Each crypto-shape is exactly one K-family. -/
@[inline]
def CryptoContext.toFamilies : CryptoContext → Array String
  | .nonCrypto      => #[]
  | .bip39Mnemonic  => #["K1"]
  | .hashInput      => #["K2"]
  | .aiAttribution  => #["K3"]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Factored admission predicates (Level ⊥ Crypto)
--
-- Admission has two ORTHOGONAL dimensions:
--
--   * `levelAdmissible level input` — does the Unicode-layer
--     family set declared by `level` admit `input`?  Answer is
--     INDEPENDENT of any cryptographic context.
--
--   * `cryptoAdmissible ctx input` — does the K-family set
--     declared by `ctx` admit `input`?  Answer is INDEPENDENT
--     of any Level.
--
-- The composite `admissibleAt level ctx input` is the AND of
-- the two — both factors must admit.  Factoring them this way
-- makes the K-family's distinguishing power directly observable
-- as a difference in `cryptoAdmissible`, even on inputs that
-- `levelAdmissible level input` already rejects.  Without this
-- factoring, the K-family's contribution would be masked by the
-- union whenever any L1–L5 family also flags the same input —
-- e.g. decomposed é, which K2 flags as NormalizationDrift AND
-- F6 NfcIdempotenceWitness rejects at `.restrictive`/`.moderate`,
-- so a naive `admissibleAt`-only test would show both contexts
-- rejecting and miss that K2 is independently contributing.
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
    admits `input`.  Independent of any cryptographic context.
    Used as the Level-only factor of the composite
    `admissibleAt`. -/
def levelAdmissible (level : Level) (input : Array Nat) : Bool :=
  let results  := runAll input
  let effective := rejectionSet level
  ¬ results.any (fun r => isHazard r ∧ effective.contains r.family)

/-- Does the K-family set declared by `cryptoCtx` admit `input`?
    Independent of any Level.  Used as the Crypto-only factor of
    the composite `admissibleAt`.  Captures the K-family's
    distinguishing power directly, without union-masking by
    L1–L5 detectors. -/
def cryptoAdmissible (cryptoCtx : CryptoContext)
    (input : Array Nat) : Bool :=
  let results  := runAll input
  let effective := cryptoCtx.toFamilies
  ¬ results.any (fun r => isHazard r ∧ effective.contains r.family)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Composite admission predicate
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `input` is admissible at the declared `level` under
    the declared `cryptoCtx`.  Defined as the AND of the two
    orthogonal factors — both must admit.  Hazards from
    families in the union (Level ∪ Crypto) cause admission
    failure; hazards from other families are reported by
    `runAll` but do not gate admission at this surface.

    Callers who need to see WHICH factor rejected should call
    `levelAdmissible` and `cryptoAdmissible` separately.  See
    `crypto_admissible_gates_decomposed_e_acute` for a worked
    example of K-family's distinguishing power being visible
    in `cryptoAdmissible` even on inputs where `admissibleAt`
    would mask the contribution behind an L1–L5 rejection. -/
def admissibleAt (level : Level) (cryptoCtx : CryptoContext)
    (input : Array Nat) : Bool :=
  levelAdmissible level input && cryptoAdmissible cryptoCtx input

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Rejection-set monotonicity
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The restrictive rejection set covers all 23 families.
    `runAll`'s byte-stream gate makes C4 contribution
    well-behaved on codepoint inputs. -/
theorem restrictive_rejection_size :
    (rejectionSet .restrictive).size = 23 := by native_decide

/-- The moderate rejection set drops the 4 heuristic / FP-prone
    detectors (F1, D3, D4, I3) from restrictive, keeping 19. -/
theorem moderate_rejection_size :
    (rejectionSet .moderate).size = 19 := by native_decide

/-- The minimal rejection set covers the 3 structural / RFC-
    violation families (C4 UTF-8 byte validity, C5 bidi-control
    balance, F2 stream-safe overflow). -/
theorem minimal_rejection_size :
    (rejectionSet .minimal).size = 3 := by native_decide

/-- Every family in `moderate.rejectionSet` is also in
    `restrictive.rejectionSet`. -/
theorem moderate_rejection_subset_restrictive :
    (rejectionSet .moderate).all (fun fam =>
      (rejectionSet .restrictive).contains fam) = true := by
  native_decide

/-- Every family in `minimal.rejectionSet` is also in
    `moderate.rejectionSet`. -/
theorem minimal_rejection_subset_moderate :
    (rejectionSet .minimal).all (fun fam =>
      (rejectionSet .moderate).contains fam) = true := by
  native_decide

/-- Every family in `minimal.rejectionSet` is also in
    `restrictive.rejectionSet` (transitive). -/
theorem minimal_rejection_subset_restrictive :
    (rejectionSet .minimal).all (fun fam =>
      (rejectionSet .restrictive).contains fam) = true := by
  native_decide

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
-- `native_decide`.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Monotonicity witness, pure ASCII.  Admissible at all three
    levels. -/
theorem monotone_ascii_hello :
    let input : Array Nat := #[0x48, 0x65, 0x6C, 0x6C, 0x6F]
    admissibleAt .restrictive .nonCrypto input = true
    ∧ admissibleAt .moderate .nonCrypto input = true
    ∧ admissibleAt .minimal .nonCrypto input = true := by native_decide

/-- Monotonicity witness, lone RLO.  Inadmissible at every
    level (C5 is in every rejection set). -/
theorem monotone_lone_rlo :
    let input : Array Nat := #[0x202E]
    admissibleAt .restrictive .nonCrypto input = false
    ∧ admissibleAt .moderate .nonCrypto input = false
    ∧ admissibleAt .minimal .nonCrypto input = false := by native_decide

/-- Monotonicity witness, Cyrillic Nethereum typosquat.
    Inadmissible at restrictive + moderate (I1 fires there),
    admissible at minimal (I1 not in minimal rejection set). -/
theorem monotone_nethereum :
    let input : Array Nat := #[0x4E, 0x65, 0x74, 0x68, 0x65, 0x72,
                                0x0435, 0x75, 0x6D]
    admissibleAt .restrictive .nonCrypto input = false
    ∧ admissibleAt .moderate .nonCrypto input = false
    ∧ admissibleAt .minimal .nonCrypto input = true := by native_decide

/-- Monotonicity witness, Math Italic admin.  Same shape as
    Nethereum — identifier-side attack, inadmissible at
    restrictive + moderate, admissible at minimal. -/
theorem monotone_math_italic_admin :
    let input : Array Nat := #[0x1D44E, 0x1D451, 0x1D45A, 0x1D456, 0x1D45B]
    admissibleAt .restrictive .nonCrypto input = false
    ∧ admissibleAt .moderate .nonCrypto input = false
    ∧ admissibleAt .minimal .nonCrypto input = true := by native_decide

/-- Monotonicity witness, Greek polytonic.  Inadmissible at
    restrictive (F1 NfdHighExpansion fires there), admissible
    at moderate (F1 not in moderate's rejection set) AND
    minimal.  Note: the Greek polytonic codepoint also fires
    I2 RestrictedStatusCp — but I2 IS in moderate's rejection
    set, so the monotone-pass at moderate level requires that
    Greek polytonic ALSO not trigger I2.  In practice U+1F86
    does trigger I2, so this row pins the actual outcome:
    moderate REJECTS the Greek polytonic, even though F1
    alone would have admitted it.  Pinning this prevents a
    future refactor of moderate's rejection set from
    accidentally admitting Greek polytonic without auditing
    the trade-off. -/
theorem monotone_greek_polytonic :
    let input : Array Nat := #[0x1F86]
    admissibleAt .restrictive .nonCrypto input = false
    ∧ admissibleAt .moderate .nonCrypto input = false
    ∧ admissibleAt .minimal .nonCrypto input = true := by native_decide

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
    ∧ admissibleAt .minimal .nonCrypto input = true := by native_decide

/-- Monotonicity witness, Java modified-UTF-8 NUL `0xC0 0x80`.
    Pure byte-stream input (every codepoint ≤ 0xFF), so
    runAll's byte-stream gate runs C4, which fires
    InvalidStartByte at offset 0.  Inadmissible at every
    level — C4 is in every rejection set including `minimal`. -/
theorem monotone_modified_utf8_nul :
    let input : Array Nat := #[0xC0, 0x80]
    admissibleAt .restrictive .nonCrypto input = false
    ∧ admissibleAt .moderate .nonCrypto input = false
    ∧ admissibleAt .minimal .nonCrypto input = false := by native_decide

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
    admissibleAt .minimal .nonCrypto input = true := by native_decide

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
  native_decide

/-- Pure ASCII "Hello" is admissible at every level under
    `nonCrypto` — no Unicode-layer hazard fires.  Under
    `bip39Mnemonic` the verdict flips: K1's `mixedCase` fires on
    the capital H and admission is refused. -/
theorem crypto_ctx_gates_mixed_case :
    let input : Array Nat := #[0x48, 0x65, 0x6C, 0x6C, 0x6F]
    admissibleAt .restrictive .nonCrypto     input = true
    ∧ admissibleAt .restrictive .bip39Mnemonic input = false := by
  native_decide

/-- Single BIP-39 word "abandon" (pure lowercase ASCII, valid
    English wordlist entry) is admissible under both contexts.
    Pins that the BIP-39 context does NOT spuriously reject
    canonical-form input. -/
theorem crypto_ctx_single_word_passes_both :
    let input : Array Nat := #[0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E]
    admissibleAt .restrictive .nonCrypto     input = true
    ∧ admissibleAt .restrictive .bip39Mnemonic input = true := by
  native_decide

/-- K2's `hashInput` context-gating, measured directly via
    `cryptoAdmissible` — Level-independent.  Decomposed é
    (U+0065 U+0301) admits under `.nonCrypto` (no K-family in
    the effective set) and rejects under `.hashInput` because
    K2's `NormalizationDrift` fires.  This is the architectural
    pin for K-family's distinguishing power: the contribution
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
  native_decide

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
  native_decide

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
  native_decide

/-- K3's `aiAttribution` context-gating, measured directly via
    `cryptoAdmissible` — Level-independent.  Plain ASCII
    `a NNBSP b` (#[0x61, 0x202F, 0x62]) admits under
    `.nonCrypto` (no K-family in the effective set) and rejects
    under `.aiAttribution` because K3's `NnbspBoundary` fires.
    This is the architectural pin for K3's distinguishing power:
    the contribution is observable at every Level via
    `cryptoAdmissible`, even though five L1–L5 families
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
  native_decide

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
  native_decide

end Unicode.Security.Level
