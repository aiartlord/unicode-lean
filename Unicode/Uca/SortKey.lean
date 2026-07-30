/-
  Unicode.Uca.SortKey

  UTS #10 §4 — main UCA algorithm: produce a sort key from a
  Unicode codepoint sequence under a chosen variable-weighting
  policy. The pipeline is:

      input → NFD → collation-element walk → variable handling
            → multi-level weight extraction → sort key

  Two variable-weighting policies are exposed:

    * NonIgnorable — variable elements keep their weights
                     (the simplest policy, used by the
                     `CollationTest_NON_IGNORABLE_SHORT.txt`
                     conformance file).

    * Shifted      — variable elements have their L1 zeroed and
                     are tracked at L4 instead (used by the
                     `CollationTest_SHIFTED_SHORT.txt` file).

  The output is a `List Nat` of weights interleaved with the
  separator `0` between levels. Comparing two sort keys
  lexicographically yields the same ordering as the UCA
  `compare` function.
-/

import Unicode.Uca.Lookup
import Unicode.Normalization.NFC

namespace Unicode.Uca.SortKey

open Unicode.Generated.Allkeys
open Unicode.Uca.Lookup

/-- Variable-weighting policy from UTS #10 §4.4. The four policies
    differ in how variable collation elements (most punctuation
    and whitespace) are treated:

      * `nonIgnorable` — variable elements keep their full weights
                         and participate in primary-level comparison.
      * `blanked`      — variable elements are zeroed out at every
                         level (no L4 emitted); ignorable-after-
                         variable elements are also zeroed.
      * `shifted`      — variable elements have L1/L2/L3 zeroed
                         and their primary demoted to L4; the sort
                         key includes L4.
      * `shiftTrimmed` — same as `shifted`, but trailing 0xFFFF
                         L4 weights (from non-variable trailing
                         elements) are trimmed from the L4 sequence.
                         Standard for Unicode-collation key
                         generation in CLDR. -/
inductive VariableHandling where
  | nonIgnorable
  | blanked
  | shifted
  | shiftTrimmed
  deriving Repr, DecidableEq, Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 COLLATION-ELEMENT WALK
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Walk `cps` from index `i`, performing one (possibly discontiguous)
    DUCET match per unconsumed position. The `consumed` list tracks
    which input positions a previous match has already absorbed via
    discontiguous contraction; those positions are skipped on
    subsequent visits. The fuel parameter bounds recursion at
    `cps.length + 1`, which suffices because every iteration either
    advances `i` by one or terminates. -/
def collateGo : Nat → List Nat → List Bool → Nat → List CollationElement →
    List CollationElement
  | 0,      cps, consumed, i, acc =>
    Function.const (List Nat) (Function.const (List Bool)
      (Function.const Nat acc i) consumed) cps
  | fuel+1, cps, consumed, i, acc =>
    if i ≥ cps.length then acc
    else if (consumed[i]?.getD true) then
      collateGo fuel cps consumed (i + 1) acc
    else
      let step := matchAtList cps consumed i
      let consumed' := step.consumed.foldl
        (fun c k => if k < c.length then c.set k true else c)
        consumed
      collateGo fuel cps consumed' (i + 1) (acc ++ step.ces)

/-- Compute the collation-element list for an NFD-normalised input.
    Initialises the `consumed` tracker to all `false` (no positions
    yet absorbed by a contraction). -/
def collationElementsOf (cps : List Nat) : List CollationElement :=
  let consumed : List Bool := List.replicate cps.length false
  collateGo (cps.length + 1) cps consumed 0 []

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 VARIABLE HANDLING  (UTS #10 §4.4)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Adjust collation elements per the chosen variable-handling
    policy (UTS #10 §4.4). Under `NonIgnorable` every element keeps
    its weights with L4 = 0xFFFF. Under `Shifted`:

      * a variable element becomes ⟨0,0,0⟩ at L1/L2/L3 with its
        original L1 demoted to L4, and the "shifted carry" flag
        is set;
      * a completely-ignorable element (L1 = L2 = L3 = 0) is
        suppressed at every level including L4 = 0, regardless of
        carry — these contribute nothing to the sort key;
      * a primary-ignorable but not completely-ignorable element
        (`primary = 0`, secondary or tertiary ≠ 0) inherits the
        carry: under carry it is fully suppressed (L4 = 0), else
        it is kept unchanged with L4 = 0xFFFF;
      * a non-variable element with `primary ≠ 0` is kept unchanged
        with L4 = 0xFFFF and clears the carry. -/
def applyVariable (handling : VariableHandling)
    (ces : List CollationElement) : List (CollationElement × Nat) :=
  (ces.foldl
    (fun (st : List (CollationElement × Nat) × Bool) ce =>
      let acc := st.fst
      let shiftedCarry := st.snd
      match handling with
      | .nonIgnorable =>
        (acc ++ [(ce, 0xFFFF)], shiftedCarry)
      | .blanked =>
        -- Variable elements zeroed completely; ignorable-after-variable
        -- elements also zeroed. No L4 emitted (every entry's quaternary
        -- weight is 0 so `quaternaries` filters them all out).
        if ce.isVariable then
          let zeroed : CollationElement := ⟨0, 0, 0, false⟩
          (acc ++ [(zeroed, 0)], true)
        else if ce.primary = 0 ∧ ce.secondary = 0 ∧ ce.tertiary = 0 then
          let zeroed : CollationElement := ⟨0, 0, 0, false⟩
          (acc ++ [(zeroed, 0)], shiftedCarry)
        else if ce.primary = 0 then
          if shiftedCarry then
            let zeroed : CollationElement := ⟨0, 0, 0, false⟩
            (acc ++ [(zeroed, 0)], shiftedCarry)
          else
            (acc ++ [(ce, 0)], shiftedCarry)
        else
          (acc ++ [(ce, 0)], false)
      | .shifted | .shiftTrimmed =>
        if ce.isVariable then
          let zeroed : CollationElement := ⟨0, 0, 0, true⟩
          (acc ++ [(zeroed, ce.primary)], true)
        else if ce.primary = 0 ∧ ce.secondary = 0 ∧ ce.tertiary = 0 then
          let zeroed : CollationElement := ⟨0, 0, 0, false⟩
          (acc ++ [(zeroed, 0)], shiftedCarry)
        else if ce.primary = 0 then
          if shiftedCarry then
            let zeroed : CollationElement := ⟨0, 0, 0, false⟩
            (acc ++ [(zeroed, 0)], shiftedCarry)
          else
            (acc ++ [(ce, 0xFFFF)], shiftedCarry)
        else
          -- A non-variable CE with primary ≠ 0 normally gets L4 = FFFF.
          -- The exception: a "primary-only trail" (S = T = 0) — the
          -- second CE of an implicit-weight pair (UTS #10 §10.1.3) or
          -- of an explicit DUCET expansion like U+3358's third CE
          -- `[F0B9.0000.0000]`. Such CEs are suppressed at L4 (=0) so
          -- the L4 sequence carries one weight per "real" CE rather
          -- than one per element of the expansion.
          let l4 := if ce.secondary = 0 ∧ ce.tertiary = 0 then 0 else 0xFFFF
          (acc ++ [(ce, l4)], false))
    ([], false)).fst

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 SORT-KEY ASSEMBLY  (UTS #10 §4.5)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Build the L1 (primary) sequence — every non-zero primary weight
    in element order. -/
def primaries (xs : List (CollationElement × Nat)) : List Nat :=
  xs.foldl (fun a (cew : CollationElement × Nat) =>
    let ce := cew.fst
    if ce.primary = 0 then a else a ++ [ce.primary]) []

/-- Build the L2 (secondary) sequence. -/
def secondaries (xs : List (CollationElement × Nat)) : List Nat :=
  xs.foldl (fun a (cew : CollationElement × Nat) =>
    let ce := cew.fst
    if ce.secondary = 0 then a else a ++ [ce.secondary]) []

/-- Build the L3 (tertiary) sequence. -/
def tertiaries (xs : List (CollationElement × Nat)) : List Nat :=
  xs.foldl (fun a (cew : CollationElement × Nat) =>
    let ce := cew.fst
    if ce.tertiary = 0 then a else a ++ [ce.tertiary]) []

/-- Build the L4 (quaternary) sequence. Entries with L4 = 0 are
    skipped — those mark either completely-ignorable elements or
    ignorable-after-variable elements, both of which UCA omits from
    the sort key at L4. -/
def quaternaries (xs : List (CollationElement × Nat)) : List Nat :=
  xs.foldl (fun a (cew : CollationElement × Nat) =>
    if cew.snd = 0 then a else a ++ [cew.snd]) []

/-- The level separator between L1, L2, L3, (L4) sections. -/
def sep : Nat := 0

/-- Drop trailing 0xFFFF entries from the L4 sequence per the
    Shift-Trimmed policy (UTS #10 §4.4.4). -/
def trimTrailingFFFF (xs : List Nat) : List Nat :=
  (xs.reverse.dropWhile (· = 0xFFFF)).reverse

/-- Assemble the full sort key from a codepoint sequence under the
    given variable-handling policy. The pipeline normalises to NFD
    first, walks the DUCET, applies variable handling, then
    concatenates `L1 ‖ 0 ‖ L2 ‖ 0 ‖ L3 [‖ 0 ‖ L4]`. -/
def sortKey (handling : VariableHandling) (cps : List Nat) : List Nat :=
  let nfd := Unicode.Normalization.NFC.toNFD cps
  let ces := collationElementsOf nfd
  let xs  := applyVariable handling ces
  let l1  := primaries xs
  let l2  := secondaries xs
  let l3  := tertiaries xs
  match handling with
  | .nonIgnorable | .blanked =>
    l1 ++ [sep] ++ l2 ++ [sep] ++ l3
  | .shifted =>
    let l4 := quaternaries xs
    l1 ++ [sep] ++ l2 ++ [sep] ++ l3 ++ [sep] ++ l4
  | .shiftTrimmed =>
    let l4 := trimTrailingFFFF (quaternaries xs)
    l1 ++ [sep] ++ l2 ++ [sep] ++ l3 ++ [sep] ++ l4

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 LEXICOGRAPHIC COMPARISON
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Lexicographic comparison of two `List Nat` keys. Shorter is
    less than longer when one is a prefix of the other. -/
def compareLexAux : Nat → List Nat → List Nat → Nat → Ordering
  | 0,      xs, ys, i =>
    Function.const (List Nat)
      (Function.const (List Nat)
        (Function.const Nat (.eq : Ordering) i) ys) xs
  | fuel+1, xs, ys, i =>
    match xs[i]?, ys[i]? with
    | none,   none   => .eq
    | none,   some y => Function.const Nat (.lt : Ordering) y
    | some x, none   => Function.const Nat (.gt : Ordering) x
    | some x, some y =>
      if x < y then .lt
      else if x > y then .gt
      else compareLexAux fuel xs ys (i + 1)

/-- Lexicographic comparison of two sort keys. -/
def compareLex (xs ys : List Nat) : Ordering :=
  compareLexAux (max xs.length ys.length + 1) xs ys 0

/-- `compareLexAux` reports equality when both operands are the same key. -/
private theorem compareLexAux_refl (fuel : Nat) (xs : List Nat) (i : Nat) :
    compareLexAux fuel xs xs i = .eq := by
  induction fuel generalizing i with
  | zero => rfl
  | succ f ih =>
    unfold compareLexAux
    cases hx : xs[i]? with
    | none => rfl
    | some x =>
      simp only [Nat.lt_irrefl, if_false, gt_iff_lt]
      exact ih (i + 1)

/-- **Reflexivity (all inputs).** The lexicographic key comparator ranks any key equal
    to itself. -/
theorem compareLex_refl (xs : List Nat) : compareLex xs xs = .eq := by
  unfold compareLex
  exact compareLexAux_refl (max xs.length xs.length + 1) xs 0

/-- UCA comparison under the chosen variable-handling policy. -/
def ucaCompare (handling : VariableHandling) (a b : List Nat) : Ordering :=
  compareLex (sortKey handling a) (sortKey handling b)

/-- **Reflexivity of the collation order (all inputs).** Every string compares equal to
    itself under UCA — the reflexivity axiom of the total preorder the algorithm defines. -/
theorem ucaCompare_refl (handling : VariableHandling) (a : List Nat) :
    ucaCompare handling a a = .eq :=
  compareLex_refl (sortKey handling a)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 SPOT CHECKS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- "a" < "b" under either policy. -/
theorem ucaCompare_a_b_nonIgnorable :
    ucaCompare .nonIgnorable [0x0061] [0x0062] = .lt := by decide +kernel

theorem ucaCompare_a_b_shifted :
    ucaCompare .shifted [0x0061] [0x0062] = .lt := by decide +kernel

/-- "a" = "A" at primary level, but "a" < "A" lexicographically because
    of the L3 (case) tiebreak: 'a' has tertiary 0x0002, 'A' has 0x0008,
    so "a" sorts before "A". -/
theorem ucaCompare_a_A :
    ucaCompare .nonIgnorable [0x0061] [0x0041] = .lt := by decide +kernel

/-- "à" (U+00E0) and "à" (U+0061 U+0300) produce equal sort keys
    after NFD normalisation — that is the canonical-equivalence
    invariant promised by UCA §1.4. -/
theorem ucaCompare_canonical_equivalence :
    ucaCompare .nonIgnorable [0x00E0] [0x0061, 0x0300] = .eq := by decide +kernel

/-- "a" < "b" under blanked policy too. -/
theorem ucaCompare_a_b_blanked :
    ucaCompare .blanked [0x0061] [0x0062] = .lt := by decide +kernel

/-- "a" < "b" under shift-trimmed policy. -/
theorem ucaCompare_a_b_shiftTrimmed :
    ucaCompare .shiftTrimmed [0x0061] [0x0062] = .lt := by decide +kernel

/-- Under `blanked`, `"a-b"` and `"ab"` collate equally because the
    hyphen is a variable element zeroed at every level. Under
    `nonIgnorable`, the hyphen contributes a primary weight that
    makes the two strings unequal. -/
theorem blanked_collapses_punctuation :
    ucaCompare .blanked [0x0061, 0x002D, 0x0062] [0x0061, 0x0062]
      = .eq := by decide +kernel

theorem nonIgnorable_distinguishes_punctuation :
    ucaCompare .nonIgnorable [0x0061, 0x002D, 0x0062] [0x0061, 0x0062]
      ≠ .eq := by decide +kernel

/-- `trimTrailingFFFF` drops the trailing run; `shiftTrimmed`
    differs from `shifted` only in producing the trimmed L4. -/
theorem trimTrailingFFFF_drops_trailing :
    trimTrailingFFFF [0x10, 0x20, 0xFFFF, 0xFFFF] = [0x10, 0x20] := by
  decide

theorem trimTrailingFFFF_keeps_internal :
    trimTrailingFFFF [0x10, 0xFFFF, 0x20] = [0x10, 0xFFFF, 0x20] := by
  decide

theorem trimTrailingFFFF_empty :
    trimTrailingFFFF [] = [] := by decide

theorem trimTrailingFFFF_all_FFFF :
    trimTrailingFFFF [0xFFFF, 0xFFFF, 0xFFFF] = [] := by decide

end Unicode.Uca.SortKey
