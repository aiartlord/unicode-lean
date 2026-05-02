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

  The output is an `Array Nat` of weights interleaved with the
  separator `0` between levels. Comparing two sort keys
  lexicographically yields the same ordering as the UCA
  `compare` function.
-/

import Unicode.Uca.Lookup
import Unicode.Normalization.NFC

namespace Unicode.Uca.SortKey

open Unicode.Generated.Allkeys
open Unicode.Uca.Lookup

/-- Variable-weighting policy from UTS #10 §4.4. -/
inductive VariableHandling where
  | nonIgnorable
  | shifted
  deriving Repr, DecidableEq, Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 COLLATION-ELEMENT WALK
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Greedily walk `cps` from index `i`, looking up each prefix
    against DUCET (with implicit-weight fallback) and accumulating
    every emitted collation element. -/
def collateGo : Nat → Array Nat → Nat → Array CollationElement → Array CollationElement
  | 0,      cps, i, acc =>
    Function.const (Array Nat) (Function.const Nat acc i) cps
  | fuel+1, cps, i, acc =>
    if i ≥ cps.size then acc
    else
      let (entry, consumed) := resolveAt cps i
      let step              := if consumed = 0 then 1 else consumed
      collateGo fuel cps (i + step) (acc ++ entry.ces)

/-- Compute the collation-element array for an NFD-normalised input. -/
def collationElementsOf (cps : Array Nat) : Array CollationElement :=
  collateGo (cps.size + 1) cps 0 #[]

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
    (ces : Array CollationElement) : Array (CollationElement × Nat) := Id.run do
  let mut acc : Array (CollationElement × Nat) := #[]
  let mut shiftedCarry : Bool := false
  for ce in ces do
    match handling with
    | .nonIgnorable =>
      acc := acc.push (ce, 0xFFFF)
    | .shifted =>
      if ce.isVariable then
        let zeroed : CollationElement := ⟨0, 0, 0, true⟩
        acc := acc.push (zeroed, ce.primary)
        shiftedCarry := true
      else if ce.primary = 0 ∧ ce.secondary = 0 ∧ ce.tertiary = 0 then
        let zeroed : CollationElement := ⟨0, 0, 0, false⟩
        acc := acc.push (zeroed, 0)
      else if ce.primary = 0 then
        if shiftedCarry then
          let zeroed : CollationElement := ⟨0, 0, 0, false⟩
          acc := acc.push (zeroed, 0)
        else
          acc := acc.push (ce, 0xFFFF)
      else
        acc := acc.push (ce, 0xFFFF)
        shiftedCarry := false
  return acc

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 SORT-KEY ASSEMBLY  (UTS #10 §4.5)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Build the L1 (primary) sequence — every non-zero primary weight
    in element order. -/
def primaries (xs : Array (CollationElement × Nat)) : Array Nat :=
  xs.foldl (fun a (cew : CollationElement × Nat) =>
    let ce := cew.fst
    if ce.primary = 0 then a else a.push ce.primary) #[]

/-- Build the L2 (secondary) sequence. -/
def secondaries (xs : Array (CollationElement × Nat)) : Array Nat :=
  xs.foldl (fun a (cew : CollationElement × Nat) =>
    let ce := cew.fst
    if ce.secondary = 0 then a else a.push ce.secondary) #[]

/-- Build the L3 (tertiary) sequence. -/
def tertiaries (xs : Array (CollationElement × Nat)) : Array Nat :=
  xs.foldl (fun a (cew : CollationElement × Nat) =>
    let ce := cew.fst
    if ce.tertiary = 0 then a else a.push ce.tertiary) #[]

/-- Build the L4 (quaternary) sequence. Entries with L4 = 0 are
    skipped — those mark either completely-ignorable elements or
    ignorable-after-variable elements, both of which UCA omits from
    the sort key at L4. -/
def quaternaries (xs : Array (CollationElement × Nat)) : Array Nat :=
  xs.foldl (fun a (cew : CollationElement × Nat) =>
    if cew.snd = 0 then a else a.push cew.snd) #[]

/-- The level separator between L1, L2, L3, (L4) sections. -/
def sep : Nat := 0

/-- Assemble the full sort key from a codepoint sequence under the
    given variable-handling policy. The pipeline normalises to NFD
    first, walks the DUCET, applies variable handling, then
    concatenates `L1 ‖ 0 ‖ L2 ‖ 0 ‖ L3 [‖ 0 ‖ L4]`. -/
def sortKey (handling : VariableHandling) (cps : Array Nat) : Array Nat :=
  let nfd := Unicode.Normalization.NFC.toNFD cps
  let ces := collationElementsOf nfd
  let xs  := applyVariable handling ces
  let l1  := primaries xs
  let l2  := secondaries xs
  let l3  := tertiaries xs
  match handling with
  | .nonIgnorable => l1.push sep ++ l2.push sep ++ l3
  | .shifted      =>
    let l4 := quaternaries xs
    l1.push sep ++ l2.push sep ++ l3.push sep ++ l4

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 LEXICOGRAPHIC COMPARISON
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Lexicographic comparison of two `Array Nat` keys. Shorter is
    less than longer when one is a prefix of the other. -/
def compareLexAux : Nat → Array Nat → Array Nat → Nat → Ordering
  | 0,      xs, ys, i =>
    Function.const (Array Nat)
      (Function.const (Array Nat)
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
def compareLex (xs ys : Array Nat) : Ordering :=
  compareLexAux (max xs.size ys.size + 1) xs ys 0

/-- UCA comparison under the chosen variable-handling policy. -/
def ucaCompare (handling : VariableHandling) (a b : Array Nat) : Ordering :=
  compareLex (sortKey handling a) (sortKey handling b)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 SPOT CHECKS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- "a" < "b" under either policy. -/
theorem ucaCompare_a_b_nonIgnorable :
    ucaCompare .nonIgnorable #[0x0061] #[0x0062] = .lt := by native_decide

theorem ucaCompare_a_b_shifted :
    ucaCompare .shifted #[0x0061] #[0x0062] = .lt := by native_decide

/-- "a" = "A" at primary level, but "a" < "A" lexicographically because
    of the L3 (case) tiebreak: 'a' has tertiary 0x0002, 'A' has 0x0008,
    so "a" sorts before "A". -/
theorem ucaCompare_a_A :
    ucaCompare .nonIgnorable #[0x0061] #[0x0041] = .lt := by native_decide

/-- "à" (U+00E0) and "à" (U+0061 U+0300) produce equal sort keys
    after NFD normalisation — that is the canonical-equivalence
    invariant promised by UCA §1.4. -/
theorem ucaCompare_canonical_equivalence :
    ucaCompare .nonIgnorable #[0x00E0] #[0x0061, 0x0300] = .eq := by native_decide

end Unicode.Uca.SortKey
