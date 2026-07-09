/-
  Unicode.NatListBounds

  Reusable `Nat`-list sum bound — average ≤ max.

  A `foldr`-summed list whose per-element values are uniformly
  bounded by `M` is itself bounded by `length · M`.

    AllElementsBoundedBy f M xs
      → xs.foldr (fun x acc => f x + acc) 0 ≤ xs.length · M

  Used by `Unicode.Confusables` to prove the universal output-size
  bound on `substitute` / `skeleton` / `iteratedSkeleton` /
  `letterSkeleton` without `decide`.

  Substrate copied locally (rather than imported from a sibling
  repository) to keep the unicode repo self-contained and the
  TCB transparent.  Original substrate: `jpyxal/lemma/proofs/
  Lemma/Math/NatListBounds.lean`.

  Established by structural induction over `List`, with `omega` for the
  linear-arithmetic step.
-/

namespace Unicode.NatListBounds

-- ═══════════════════════════════════════════════════════════════════════════════
-- UNIFORM PER-ELEMENT BOUND PREDICATE
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Every element `x` in the list satisfies `f x ≤ M` under the
    consumer-supplied evaluator `f`. The hypothesis predicate the
    `foldr`-bound theorem below consumes. -/
def AllElementsBoundedBy
    {α : Type} (f : α → Nat) (M : Nat) : List α → Prop
  | []         => True
  | x :: rest  => f x ≤ M ∧ AllElementsBoundedBy f M rest

@[simp] theorem AllElementsBoundedBy_nil
    {α : Type} (f : α → Nat) (M : Nat) :
    AllElementsBoundedBy f M ([] : List α) = True := rfl

@[simp] theorem AllElementsBoundedBy_cons
    {α : Type} (f : α → Nat) (M : Nat) (x : α) (rest : List α) :
    AllElementsBoundedBy f M (x :: rest)
      = (f x ≤ M ∧ AllElementsBoundedBy f M rest) := rfl

-- ═══════════════════════════════════════════════════════════════════════════════
-- THE HEADLINE: foldr-sum ≤ length · max
-- ═══════════════════════════════════════════════════════════════════════════════

/-- For a `Nat`-valued function `f : α → Nat` uniformly bounded by
    `M` on every element of `xs`, the `foldr`-sum
    over elements of `xs` is bounded by `xs.length · M`. -/
theorem foldrAdd_le_length_mul_bound
    {α : Type} (f : α → Nat) (M : Nat) (xs : List α)
    (hBound : AllElementsBoundedBy f M xs) :
    xs.foldr (fun x accumulator => f x + accumulator) 0
      ≤ xs.length * M := by
  induction xs with
  | nil =>
      show (0 : Nat) ≤ 0 * M
      omega
  | cons headX restXs ih =>
      have hHeadBound : f headX ≤ M := hBound.1
      have hRestBound : AllElementsBoundedBy f M restXs := hBound.2
      have hRestSum : restXs.foldr (fun x accumulator => f x + accumulator) 0
                        ≤ restXs.length * M :=
        ih hRestBound
      show f headX + restXs.foldr (fun x accumulator => f x + accumulator) 0
            ≤ (headX :: restXs).length * M
      rw [List.length_cons]
      have hExpand : (restXs.length + 1) * M
                      = restXs.length * M + M := by
        rw [Nat.add_mul, Nat.one_mul]
      rw [hExpand]
      omega

-- ═══════════════════════════════════════════════════════════════════════════════
-- COROLLARY: existence of per-element bound from a foldl-max definition
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Helper: `foldl max acc xs ≥ acc`.  Used to chain the
    head-element bound through the rest of the fold. -/
theorem foldl_max_ge : ∀ (xs : List Nat) (acc : Nat), acc ≤ xs.foldl max acc
  | [],         acc => Nat.le_refl acc
  | y :: ys, acc =>
      have h1 : acc ≤ max acc y := Nat.le_max_left acc y
      have h2 : max acc y ≤ ys.foldl max (max acc y) :=
        foldl_max_ge ys (max acc y)
      Nat.le_trans h1 h2

/-- For a `List Nat` whose maximum is computed as `foldl max 0`,
    every element is ≤ the maximum.  Connects "max is the spec
    bound" to "every element satisfies the bound" — the converse
    direction needed when the bound is itself defined as the max
    of the data. -/
theorem each_le_foldlMax (xs : List Nat) :
    ∀ x, x ∈ xs → x ≤ xs.foldl max 0 := by
  -- Generalize the accumulator so the induction goes through.
  suffices h : ∀ (acc : Nat), ∀ x, x ∈ xs → x ≤ xs.foldl max acc by
    intro x hx
    exact h 0 x hx
  induction xs with
  | nil =>
      intro acc x hx
      cases hx
  | cons headX restXs ih =>
      intro acc x hx
      have hxCases : x = headX ∨ x ∈ restXs := List.mem_cons.mp hx
      cases hxCases with
      | inl hEq =>
          rw [hEq]
          show headX ≤ (headX :: restXs).foldl max acc
          rw [List.foldl_cons]
          have hMaxAccHead : headX ≤ max acc headX := Nat.le_max_right acc headX
          have hFoldGe : max acc headX ≤ restXs.foldl max (max acc headX) :=
            foldl_max_ge restXs (max acc headX)
          exact Nat.le_trans hMaxAccHead hFoldGe
      | inr hxRest =>
          show x ≤ (headX :: restXs).foldl max acc
          rw [List.foldl_cons]
          exact ih (max acc headX) x hxRest

end Unicode.NatListBounds
