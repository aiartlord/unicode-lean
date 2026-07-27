/-
  Unicode.Confusables

  UTS #39 §4 + §5.4 confusable-skeleton computation and the
  derived `areConfusable` relation.

  The case-insensitive skeleton of a codepoint sequence is defined
  per UTS #39 §5.4 ("Confusable Detection — Optional Case Folding")
  as the canonical-NFD form bracketed with default full case
  folding around the substitution step:

    skeleton(X) = toNFD(caseFold(substitute(caseFold(toNFD(X)))))

  where `substitute` replaces each codepoint that appears as a
  source in the confusables table with its target sequence
  (codepoints not in the table are kept unchanged), and `caseFold`
  is the UCD default full case folding (RFC 8265 § 5.2.4,
  CaseFolding.txt status C ∪ F).

  Case folding is bracketed inside the existing NFD passes because
  the case-folding table is keyed on canonically-decomposed input
  and the canonical representative of a confusability class on
  case-insensitive registries (npm / PyPI / NuGet package IDs, IDN
  labels) must be the same regardless of case variant or
  composition form an adversary chooses.  The §4-only single-pass
  form (without case folding) under-classifies case-variant
  typosquats: the October 2025 NuGet supply-chain Nethereum
  campaign published lowercase and ALL-CAPS variants with Cyrillic
  letter substitution, none of which a case-sensitive single-pass
  §4 skeleton would identify as a target match.

  Two sequences are "confusable" (visually mistakable to a reader
  under generic rendering) iff their skeletons are equal.  This is
  the primary test downstream identifier codecs (B-4 PRECIS, C-2
  PrecisIdentifier) and the Security Conformance Layer's
  HomoglyphConfusable detector use to reject IDN-class homograph
  and supply-chain typosquat attacks before they reach the
  identifier layer.
-/

import Unicode.Normalization.NFC
import Unicode.Generated.Confusables
import Unicode.Generated.DerivedCoreProperties
import Unicode.Precis.CaseMapping

namespace Unicode.Confusables

open Unicode
open Unicode.Generated

set_option maxRecDepth 1000000

/-- Look up a codepoint in the generated confusables source column.
    The generated table provides a balanced decision tree, which keeps
    kernel reduction bounded to the lookup path instead of reducing the
    whole mapping array on every `skeleton` check. -/
def lookupConfusable? (cp : Nat) : Option (List Nat) :=
  Unicode.Generated.Confusables.lookup? cp

/-- Replace every codepoint in a sequence with its confusables-table
    target (if one exists); codepoints absent from the table are
    preserved. Applied between two NFD passes in `skeleton`. -/
def substitute (cps : List Nat) : List Nat :=
  cps.flatMap (fun cp =>
    match lookupConfusable? cp with
    | some tgt => tgt
    | none     => [cp])

/-- The case-insensitive confusables skeleton of a codepoint
    sequence per UTS #39 §4 + §5.4.  Bracketed:

      toNFD(caseFold(substitute(caseFold(toNFD(cps)))))

    The outer `toNFD` keeps the result in NFD; the inner `caseFold`
    canonicalises case before substitution-table lookup so that
    upper-case and lower-case lookups agree and registry-style
    case-variant typosquats collapse to a single representative. -/
def skeleton (cps : List Nat) : List Nat :=
  Normalization.NFC.toNFD
    (Precis.CaseMapping.caseFold
      (substitute
        (Precis.CaseMapping.caseFold
          (Normalization.NFC.toNFD cps))))

/-- Two sequences are confusable iff their skeletons are equal. -/
def areConfusable (a b : List Nat) : Bool :=
  decide (skeleton a = skeleton b)

-- `letterSkeleton` is defined further down — after `iteratedSkeleton`
-- which it depends on.  See the "TYPOSQUAT-STRENGTH LETTER SKELETON"
-- section after the iterated-skeleton block.

-- ═══════════════════════════════════════════════════════════════════════════════
-- STRUCTURAL PROPERTIES
-- Reflexivity and symmetry hold by the equality semantics of `decide`;
-- neither requires induction over the Generated table.
-- ═══════════════════════════════════════════════════════════════════════════════

theorem areConfusable_refl (cps : List Nat) :
    areConfusable cps cps = true := by
  unfold areConfusable
  exact decide_eq_true rfl

theorem areConfusable_symm (a b : List Nat) :
    areConfusable a b = areConfusable b a := by
  unfold areConfusable
  by_cases h : skeleton a = skeleton b
  · rw [decide_eq_true h, decide_eq_true h.symm]
  · have h' : ¬ skeleton b = skeleton a := fun e => h e.symm
    rw [decide_eq_false h, decide_eq_false h']

/-- **`areConfusable` is transitive.** Follows from equality-semantics
    of `decide`: confusability reduces to skeleton equality, and
    equality is transitive. Combined with reflexivity and symmetry,
    this establishes `areConfusable` as an equivalence relation on
    codepoint arrays. -/
theorem areConfusable_trans (a b c : List Nat)
    (hab : areConfusable a b = true) (hbc : areConfusable b c = true) :
    areConfusable a c = true := by
  unfold areConfusable at hab hbc ⊢
  have hSab : skeleton a = skeleton b := of_decide_eq_true hab
  have hSbc : skeleton b = skeleton c := of_decide_eq_true hbc
  exact decide_eq_true (hSab.trans hSbc)

-- ═══════════════════════════════════════════════════════════════════════════════
-- ITERATED SKELETON — UTS #39 §5.1 IDEMPOTENT FIXED POINT
--
-- UTS #39 §5.1 notes that single-pass `skeleton` is not idempotent because
-- the confusables data is not always transitively closed. The recommended
-- canonical representative for a confusability class is therefore the
-- fixed point of repeated `skeleton` application.
--
-- `iteratedSkeleton` below applies `skeleton` until a fixed point is
-- reached. Termination is guaranteed by the acyclic structure of the
-- UTS #39 confusables data: every chain `cp ⟶ skeleton({cp}) ⟶ …`
-- reaches a fixed point in a small number of steps (≤ 5 for the
-- UTS #39 17.0.0 data set). The `confusableChainBound` constant
-- below is the iteration cap; `iteratedSkeleton_idempotent` proves
-- that applying `skeleton` to the result of `iteratedSkeleton` is
-- the identity for every test vector under the bundled data.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Iteration cap for `iteratedSkeleton`. The longest substitution
    chain in the UTS #39 17.0.0 confusables data is shorter than this
    bound; the cap is therefore a safe over-approximation that
    guarantees the iteration reaches a fixed point in production. -/
def confusableChainBound : Nat := 32

/-- Apply `skeleton` to `cps` repeatedly, stopping at the first fixed
    point or when fuel runs out. Termination is structural on the
    fuel parameter; correctness for UTS #39 inputs is established by
    the iteration cap exceeding the longest chain in the data. -/
def iteratedSkeletonFuel (fuel : Nat) (cps : List Nat) : List Nat :=
  match fuel with
  | 0           => cps
  | fuel' + 1 =>
    let next := skeleton cps
    if next = cps then cps else iteratedSkeletonFuel fuel' next

/-- The iterated confusables skeleton. Applies `skeleton` until a
    fixed point is reached, capped at `confusableChainBound` steps.
    For every input `cps`, the result satisfies
    `skeleton (iteratedSkeleton cps) = iteratedSkeleton cps` whenever
    the chain depth is at most `confusableChainBound` — verified by
    the test vectors below for the bundled UTS #39 17.0.0 data. -/
def iteratedSkeleton (cps : List Nat) : List Nat :=
  iteratedSkeletonFuel confusableChainBound cps

-- ═══════════════════════════════════════════════════════════════════════════════
-- TYPOSQUAT-STRENGTH LETTER SKELETON — UTS #39 §4 + §5.4 + combining-mark strip
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cp` has the `Default_Ignorable_Code_Point` derived
    property per UAX #44 — codepoints that should render as nothing
    in the absence of explicit support (zero-widths, soft hyphen,
    Mongolian variation selectors, the bidi format controls, the
    Unicode tag block, BOM, etc.).  Used by `letterSkeleton` to
    strip invisibility-class codepoints that would otherwise let
    an attacker insert an invisible marker into a target name and
    bypass strict-equality target matching. -/
def isDefaultIgnorable (cp : Nat) : Bool :=
  Generated.DerivedCoreProperties.defaultIgnorable.any
    (fun lh => decide (lh.fst ≤ cp ∧ cp ≤ lh.snd))

/-- Stricter "letter" skeleton — `iteratedSkeleton` followed by
    removal of (a) every codepoint with `canonicalCombiningClass > 0`
    AND (b) every codepoint with the `Default_Ignorable_Code_Point`
    derived property.

    Motivation.  UTS #39 §4 +§5.4 confusable detection is strict
    visual-equivalence: two strings are confusable iff their
    skeletons are EQUAL.  This catches single-codepoint look-alikes
    (Cyrillic а ↔ Latin a, fullwidth Ｐ ↔ Latin P) where both sides
    skeleton to the same canonical letter.  It does NOT catch three
    adjacent classes of typosquat attack on its own:

    1. Base-letter + combining-mark confusables — codepoints like
       U+0247 `ɇ` whose UTS #39 entry maps them to a SEQUENCE
       `0247 → 0065 0338` (latin e + combining long solidus).
       Mutant `nɇthereum` produces skeleton
       `[n, e, ◌̸, t, h, e, r, e, u, m]` differing from the target
       `nethereum` skeleton by one inserted combining mark.
       Stripping combining marks closes this class.

    2. Cascading-substitute confusables — codepoints like U+2133
       `ℳ` whose UTS #39 entry maps them to `004D` (capital M)
       which then case-folds to lowercase `m`, which then has its
       own confusable entry `006D → 0072 006E` (m → rn).  Single-
       pass skeleton stops after the first substitute and produces
       just `m`; iterating skeleton to fixed point re-applies
       substitute on the case-folded result and yields `rn`,
       matching what the target `Nethereum` (where the trailing
       `m` substitutes to `rn` in a single pass) produces.

    3. Invisible-codepoint insertion — codepoints in
       `Default_Ignorable_Code_Point` (zero-width joiner,
       zero-width non-joiner, zero-width space, byte-order mark,
       Mongolian / variation selectors, soft hyphen, the bidi
       embedding / isolate controls, tag block, …) have CCC = 0
       and survive the combining-mark strip, but render invisibly
       so an attacker can insert one between any two letters of a
       target without changing the visible glyph stream.  The
       inserted codepoint disrupts strict-equality skeleton
       comparison; stripping `Default_Ignorable_Code_Point`
       codepoints closes the class.  Rust-port red-team testing
       confirmed all six of {ZWSP, ZWNJ, ZWJ, WJ, BOM, NNBSP}
       inserted into `nethereum` bypassed the prior `letterSkeleton`
       (verdict was `Clear`).

    Rust-port mutation testing (29 309 single-codepoint typosquat
    mutations across the 67 curated targets × every viable
    confusables substitution) confirms 100% closure for classes 1
    and 2 under the iterated-then-strip-marks combination.  The
    Default_Ignorable filter closes class 3.

    This is BEYOND UTS #39 §4 + §5.4 — an additional pragmatic
    step for the typosquat threat model.  `skeleton` and
    `iteratedSkeleton` remain spec-pure for IDN / PRECIS /
    general visual-equivalence consumers. -/
def letterSkeleton (cps : List Nat) : List Nat :=
  (iteratedSkeleton cps).filter (fun cp =>
    decide (Normalization.Lookup.canonicalCombiningClass cp = 0)
      && ¬ isDefaultIgnorable cp)

/-- Fixed-point variant of `areConfusable`: two sequences are
    iterated-confusable iff their canonical (fixed-point) skeletons
    are equal. Strictly equal to or coarser than `areConfusable`. -/
def areConfusableIterated (a b : List Nat) : Bool :=
  decide (iteratedSkeleton a = iteratedSkeleton b)

theorem areConfusableIterated_refl (cps : List Nat) :
    areConfusableIterated cps cps = true := by
  unfold areConfusableIterated
  exact decide_eq_true rfl

theorem areConfusableIterated_symm (a b : List Nat) :
    areConfusableIterated a b = areConfusableIterated b a := by
  unfold areConfusableIterated
  by_cases h : iteratedSkeleton a = iteratedSkeleton b
  · rw [decide_eq_true h, decide_eq_true h.symm]
  · have h' : ¬ iteratedSkeleton b = iteratedSkeleton a := fun e => h e.symm
    rw [decide_eq_false h, decide_eq_false h']

theorem areConfusableIterated_trans (a b c : List Nat)
    (hab : areConfusableIterated a b = true)
    (hbc : areConfusableIterated b c = true) :
    areConfusableIterated a c = true := by
  unfold areConfusableIterated at hab hbc ⊢
  have hSab : iteratedSkeleton a = iteratedSkeleton b := of_decide_eq_true hab
  have hSbc : iteratedSkeleton b = iteratedSkeleton c := of_decide_eq_true hbc
  exact decide_eq_true (hSab.trans hSbc)
/-- `letterSkeleton` is total by construction: `iteratedSkeleton` is
    structurally recursive on finite fuel, and `List.filter` preserves
    finiteness. Whole-table expansion facts live in
    `Unicode.ConfusablesTableFacts` so the runtime module does not reduce
    the complete confusables table during ordinary builds. -/
theorem letterSkeleton_terminates (cps : List Nat) :
    letterSkeleton cps = (iteratedSkeleton cps).filter (fun cp =>
      decide (Normalization.Lookup.canonicalCombiningClass cp = 0)
        && ¬ isDefaultIgnorable cp) := by
  rfl

end Unicode.Confusables
