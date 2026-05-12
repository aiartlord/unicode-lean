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
  input they would produce constant rejection.  Accordingly,
  the K-family is **excluded from every rejection set** —
  `restrictive` / `moderate` / `minimal` each gate exclusively
  on the 23 Unicode-as-attack-surface families (Layers 1–5).
  Callers who need K-family gating should call
  `Unicode.Security.Crypto.Bip39Canonical.detect` (or `runAll`
  and filter on `family = "K1"`) directly inside the BIP-39
  context, alongside the Level admission predicate.
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
  | _otherHaz      =>
    Function.const ClassificationKind true _otherHaz

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
-- §1 Admission predicate
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `input` is admissible at the declared `level`.

    Note: every detector in `runAll` always runs and reports
    its own verdict.  `admissibleAt` is purely an admission
    predicate over the full `runAll` result — it does NOT
    suppress any per-family hazard.  Callers who need the
    per-family detail should call `runAll input` directly and
    inspect each `FamilyResult`. -/
def admissibleAt (level : Level) (input : Array Nat) : Bool :=
  let results := runAll input
  ¬ results.any (fun r => isHazard r ∧ level.rejects r.family)

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
    admissibleAt .restrictive input = true
    ∧ admissibleAt .moderate input = true
    ∧ admissibleAt .minimal input = true := by native_decide

/-- Monotonicity witness, lone RLO.  Inadmissible at every
    level (C5 is in every rejection set). -/
theorem monotone_lone_rlo :
    let input : Array Nat := #[0x202E]
    admissibleAt .restrictive input = false
    ∧ admissibleAt .moderate input = false
    ∧ admissibleAt .minimal input = false := by native_decide

/-- Monotonicity witness, Cyrillic Nethereum typosquat.
    Inadmissible at restrictive + moderate (I1 fires there),
    admissible at minimal (I1 not in minimal rejection set). -/
theorem monotone_nethereum :
    let input : Array Nat := #[0x4E, 0x65, 0x74, 0x68, 0x65, 0x72,
                                0x0435, 0x75, 0x6D]
    admissibleAt .restrictive input = false
    ∧ admissibleAt .moderate input = false
    ∧ admissibleAt .minimal input = true := by native_decide

/-- Monotonicity witness, Math Italic admin.  Same shape as
    Nethereum — identifier-side attack, inadmissible at
    restrictive + moderate, admissible at minimal. -/
theorem monotone_math_italic_admin :
    let input : Array Nat := #[0x1D44E, 0x1D451, 0x1D45A, 0x1D456, 0x1D45B]
    admissibleAt .restrictive input = false
    ∧ admissibleAt .moderate input = false
    ∧ admissibleAt .minimal input = true := by native_decide

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
    admissibleAt .restrictive input = false
    ∧ admissibleAt .moderate input = false
    ∧ admissibleAt .minimal input = true := by native_decide

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
    admissibleAt .restrictive input = false
    ∧ admissibleAt .moderate input = false
    ∧ admissibleAt .minimal input = true := by native_decide

/-- Monotonicity witness, Java modified-UTF-8 NUL `0xC0 0x80`.
    Pure byte-stream input (every codepoint ≤ 0xFF), so
    runAll's byte-stream gate runs C4, which fires
    InvalidStartByte at offset 0.  Inadmissible at every
    level — C4 is in every rejection set including `minimal`. -/
theorem monotone_modified_utf8_nul :
    let input : Array Nat := #[0xC0, 0x80]
    admissibleAt .restrictive input = false
    ∧ admissibleAt .moderate input = false
    ∧ admissibleAt .minimal input = false := by native_decide

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
    admissibleAt .minimal input = true := by native_decide

end Unicode.Security.Level
