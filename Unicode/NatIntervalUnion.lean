/-
  Unicode.NatIntervalUnion

  Membership and — crucially — non-membership for a natural number in a
  union of closed intervals `⋃ᵢ [loᵢ, hiᵢ]`, given as a `List (Nat × Nat)`.

  This is the substrate every range-table classifier sits on: a codepoint
  property table expressed as `List (Nat × Nat)` discharges
  `memUnion cp table = false` through `OutsideAll`, which reflects union
  non-membership to a finite conjunction of per-interval order facts
  (`cp < loᵢ ∨ hiᵢ < cp`) — each closed by `omega`, with no decision
  procedure run over the codepoint space. It is the same survivor/obstruction
  shape as a residue sieve (`survives ⟺ avoids every obstruction`), here
  instantiated for closed `Nat` intervals.

  A table entry `(lo, hi)` denotes the closed interval `lo ≤ x ≤ hi`; a
  malformed entry with `lo > hi` simply contains nothing, the correct
  semantics for a range table, so no `lo ≤ hi` field is required.

  Lean 4 core only — no Mathlib. Sibling of `Unicode.NatListBounds`.
-/

namespace Unicode.NatIntervalUnion

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1  MEMBERSHIP — ONE INTERVAL, THE UNION
-- ═══════════════════════════════════════════════════════════════════════════════

/-- `x` is in the closed interval `[iv.1, iv.2]`. -/
def memInterval (x : Nat) (iv : Nat × Nat) : Bool :=
  decide (iv.1 ≤ x ∧ x ≤ iv.2)

/-- `x` is in the union of the intervals in `ivs`. -/
def memUnion (x : Nat) (ivs : List (Nat × Nat)) : Bool :=
  ivs.any (memInterval x)

@[simp] theorem memUnion_nil (x : Nat) :
    memUnion x [] = false := rfl

@[simp] theorem memUnion_cons
    (x : Nat) (iv : Nat × Nat) (rest : List (Nat × Nat)) :
    memUnion x (iv :: rest) = (memInterval x iv || memUnion x rest) := by
  simp [memUnion, List.any_cons]

theorem memInterval_eq_true_iff (x : Nat) (iv : Nat × Nat) :
    memInterval x iv = true ↔ (iv.1 ≤ x ∧ x ≤ iv.2) := by
  unfold memInterval
  rw [decide_eq_true_eq]

/-- Outside one interval ⟺ below its low end or above its high end. The
    `omega` step is the whole point: De Morgan over `Nat` order. -/
theorem memInterval_eq_false_iff (x : Nat) (iv : Nat × Nat) :
    memInterval x iv = false ↔ (x < iv.1 ∨ iv.2 < x) := by
  unfold memInterval
  rw [decide_eq_false_iff_not]
  omega

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2  OUTSIDE-EVERY-INTERVAL PREDICATE
-- ═══════════════════════════════════════════════════════════════════════════════

/-- `x` lies outside every interval in the list: for each `(lo, hi)`,
    either `x < lo` or `hi < x` — a finite conjunction of `Nat` order
    facts, each dischargeable by `omega`. -/
def OutsideAll (x : Nat) : List (Nat × Nat) → Prop
  | []         => True
  | iv :: rest => (x < iv.1 ∨ iv.2 < x) ∧ OutsideAll x rest

@[simp] theorem OutsideAll_nil (x : Nat) :
    OutsideAll x ([] : List (Nat × Nat)) = True := rfl

@[simp] theorem OutsideAll_cons
    (x : Nat) (iv : Nat × Nat) (rest : List (Nat × Nat)) :
    OutsideAll x (iv :: rest)
      = ((x < iv.1 ∨ iv.2 < x) ∧ OutsideAll x rest) := rfl

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3  UNION NON-MEMBERSHIP, TABLELESS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A `Nat` lies outside the union of a list of closed intervals iff it
    lies outside every interval. Structural induction on the list: the
    cons step splits the Bool `or` and rewrites the head with
    `memInterval_eq_false_iff` (an `omega` fact) and the tail with the
    inductive hypothesis.

    A consumer proving `isSource cp = false` (with `isSource` defined via
    `memUnion cp sourceRanges`) rewrites by this lemma and is left with one
    `cp < loᵢ ∨ hiᵢ < cp` per range — `omega` or `decide` closes each, with
    no decision table over the codepoint space. -/
theorem memUnion_eq_false_iff (x : Nat) (ivs : List (Nat × Nat)) :
    memUnion x ivs = false ↔ OutsideAll x ivs := by
  induction ivs with
  | nil => simp
  | cons iv rest ih =>
      rw [memUnion_cons, OutsideAll_cons, Bool.or_eq_false_iff,
          memInterval_eq_false_iff, ih]

/-- Positive membership: `x` is in the union iff some listed interval
    contains it. -/
theorem memUnion_eq_true_iff (x : Nat) (ivs : List (Nat × Nat)) :
    memUnion x ivs = true ↔ ∃ iv ∈ ivs, iv.1 ≤ x ∧ x ≤ iv.2 := by
  unfold memUnion
  rw [List.any_eq_true]
  constructor
  · rintro ⟨iv, hmem, hiv⟩
    exact ⟨iv, hmem, (memInterval_eq_true_iff x iv).mp hiv⟩
  · rintro ⟨iv, hmem, hiv⟩
    exact ⟨iv, hmem, (memInterval_eq_true_iff x iv).mpr hiv⟩

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4  CONSUMER ENTRY POINTS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- To prove a `Nat` is outside the union, prove it is outside every
    interval. The direct discharge path for `… = false` goals. -/
theorem memUnion_eq_false_of_outsideAll
    (x : Nat) (ivs : List (Nat × Nat)) (h : OutsideAll x ivs) :
    memUnion x ivs = false :=
  (memUnion_eq_false_iff x ivs).mpr h

/-- A single containing interval witnesses union membership. -/
theorem memUnion_eq_true_of_mem
    (x : Nat) (ivs : List (Nat × Nat)) (iv : Nat × Nat)
    (hmem : iv ∈ ivs) (hlo : iv.1 ≤ x) (hhi : x ≤ iv.2) :
    memUnion x ivs = true :=
  (memUnion_eq_true_iff x ivs).mpr ⟨iv, hmem, hlo, hhi⟩

end Unicode.NatIntervalUnion

-- ═══════════════════════════════════════════════════════════════════════════════
-- SORTED-DISJOINT REFINEMENT — one boundary fact settles the whole table
-- ═══════════════════════════════════════════════════════════════════════════════

namespace Unicode.NatIntervalUnionSorted

open Unicode.NatIntervalUnion

/-- An ascending, gap-disjoint range table: each interval's high end is
    strictly below the next interval's low end. -/
def Ascending (ivs : List (Nat × Nat)) : Prop :=
  ivs.Pairwise (fun a b => a.2 < b.1)

/-- If `x` is below the low end of every interval, it is outside the
    union. The direct path for "below the whole table" non-membership. -/
theorem outsideAll_of_forall_lt_lo (x : Nat) (ivs : List (Nat × Nat))
    (h : ∀ iv ∈ ivs, x < iv.1) : OutsideAll x ivs := by
  induction ivs with
  | nil => exact True.intro
  | cons iv rest ih =>
      exact ⟨Or.inl (h iv List.mem_cons_self),
             ih (fun j hj => h j (List.mem_cons_of_mem iv hj))⟩

/-- If `x` is above the high end of every interval, it is outside the
    union. The direct path for "above the whole table" non-membership. -/
theorem outsideAll_of_forall_gt_hi (x : Nat) (ivs : List (Nat × Nat))
    (h : ∀ iv ∈ ivs, iv.2 < x) : OutsideAll x ivs := by
  induction ivs with
  | nil => exact True.intro
  | cons iv rest ih =>
      exact ⟨Or.inr (h iv List.mem_cons_self),
             ih (fun j hj => h j (List.mem_cons_of_mem iv hj))⟩

/-- For an ascending table whose first interval is well-formed
    (`lo ≤ hi`), being below the FIRST low end places `x` outside the
    entire union: the head gap `x < lo₀ ≤ hi₀ < lo₁ ≤ hi₁ < …` propagates,
    so `x` is below every low end. One boundary comparison, not one per
    interval. -/
theorem outsideAll_of_lt_head
    (x : Nat) (iv0 : Nat × Nat) (rest : List (Nat × Nat))
    (hWF : iv0.1 ≤ iv0.2)
    (hAsc : Ascending (iv0 :: rest))
    (hx : x < iv0.1) :
    OutsideAll x (iv0 :: rest) := by
  apply outsideAll_of_forall_lt_lo
  intro iv hiv
  rcases List.mem_cons.mp hiv with hEq | hIn
  · rw [hEq]; exact hx
  · have hHead : ∀ r ∈ rest, iv0.2 < r.1 := (List.pairwise_cons.mp hAsc).1
    have hGap : iv0.2 < iv.1 := hHead iv hIn
    omega

/-- Below the first low end of an ascending, well-headed table ⟹ not in
    the union. -/
theorem memUnion_eq_false_of_lt_head
    (x : Nat) (iv0 : Nat × Nat) (rest : List (Nat × Nat))
    (hWF : iv0.1 ≤ iv0.2)
    (hAsc : Ascending (iv0 :: rest))
    (hx : x < iv0.1) :
    memUnion x (iv0 :: rest) = false :=
  memUnion_eq_false_of_outsideAll x (iv0 :: rest)
    (outsideAll_of_lt_head x iv0 rest hWF hAsc hx)

end Unicode.NatIntervalUnionSorted
