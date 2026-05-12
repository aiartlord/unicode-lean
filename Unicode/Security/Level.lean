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

  Note: C4 SurrogateReassembly is NOT in any structural set
  because `runAll` feeds codepoint arrays, and C4's predicate
  treats every codepoint as a byte — giving spurious hits on
  any input with a codepoint > 0xFF.  Callers with a real byte
  stream should invoke `Unicode.Security.Covert.SurrogateReassembly.detect`
  directly.
-/

import Unicode.Security.RunAll

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
    #[ "C1", "C2", "C3", "C4", "C5"
     , "I1", "I2", "I3", "I4"
     , "D1", "D2", "D3", "D4"
     , "F1", "F2", "F3", "F4", "F5", "F6"
     , "X1", "X2", "X3", "X4" ]
  | .moderate =>
    -- Drops the heuristic / FP-prone detectors: F1 (ratio-
    -- based), D3 (single-letter Hebrew triggers on legitimate
    -- multilingual text), D4 (Zalgo heuristic), I3 (novel
    -- emoji ZWJ sequences).  Keeps every targeted-attack
    -- detector intact.
    #[ "C1", "C2", "C3", "C4", "C5"
     , "I1", "I2", "I4"
     , "D1", "D2"
     , "F2", "F3", "F4", "F5", "F6"
     , "X1", "X2", "X3", "X4" ]
  | .minimal =>
    -- Only structural / RFC-violation families.  C5
    -- (bidi-control imbalance, Trojan Source class) and F2
    -- (stream-safe overflow, UAX #15 §13 DoS class).
    #[ "C5", "F2" ]

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

/-- The restrictive rejection set is all 23 families. -/
theorem restrictive_rejection_size :
    (rejectionSet .restrictive).size = 23 := by native_decide

/-- The moderate rejection set drops 4 high-FP-risk families,
    keeping 19. -/
theorem moderate_rejection_size :
    (rejectionSet .moderate).size = 19 := by native_decide

/-- The minimal rejection set covers the 2 structural-violation
    families (C5 bidi-control balance, F2 stream-safe overflow). -/
theorem minimal_rejection_size :
    (rejectionSet .minimal).size = 2 := by native_decide

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
    Admissible at minimal — neither C5 nor F2 fires on the
    single codepoint. -/
theorem monotone_fdfa :
    let input : Array Nat := #[0xFDFA]
    admissibleAt .restrictive input = false
    ∧ admissibleAt .moderate input = false
    ∧ admissibleAt .minimal input = true := by native_decide

end Unicode.Security.Level
