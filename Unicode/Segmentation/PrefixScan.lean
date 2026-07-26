/-
  Unicode.Segmentation.PrefixScan

  A *push-carry scan* is a fold that threads a carry `c : β` through a list,
  pushing the carry onto an output array at each step before updating it from the
  current input. Its output array is therefore the sequence of *prefix carries*:
  the entry at index `i` is the carry reached after consuming the first `i`
  inputs, `(l.take i).foldl upd c`.

  This is the shape of every precompute pass in the UAX #29 segmentation
  algorithms — the Regional_Indicator run, the effective previous/next class —
  each an instance for a particular carry type and update `upd`. The results here
  characterise such a scan independently of the update: `foldl_toList` gives the
  whole output as the prefix-carry list, and `build_getElem!` reads off a single
  index. A concrete pass is an instance once its step is shown to push-then-update
  (its `_fst` / `_snd` lemmas).
-/

namespace Unicode.Segmentation.PrefixScan

variable {α : Type} {β : Type}

/-- The carries a push-carry fold accumulates: entry `i` is the carry after the
    first `i` inputs, `(l.take i).foldl upd c`. -/
def carries (upd : β → α → β) : β → List α → List β
  | _seed, []     => []
  | c, (x :: xs)  => c :: carries upd (upd c x) xs

/-- `carries` has one entry per input. -/
theorem carries_length (upd : β → α → β) (c : β) (l : List α) :
    (carries upd c l).length = l.length := by
  induction l generalizing c with
  | nil => rfl
  | cons x xs ih => rw [carries, List.length_cons, List.length_cons, ih]

/-- A push-carry fold — a step `s` whose first component pushes the carry and
    whose second updates it by `upd` — leaves the seed array `bs` extended by
    exactly the prefix carries of the input. -/
theorem foldl_toList (s : List β × β → α → List β × β) (upd : β → α → β)
    (hfst : ∀ acc x, (s acc x).1 = acc.1 ++ [acc.2])
    (hsnd : ∀ acc x, (s acc x).2 = upd acc.2 x)
    (l : List α) (bs : List β) (c : β) :
    (l.foldl s (bs, c)).1 = bs ++ carries upd c l := by
  induction l generalizing bs c with
  | nil => simp [carries]
  | cons x xs ih =>
    rw [List.foldl_cons]
    have hstep : s (bs, c) x = (bs ++ [c], upd c x) := by
      have h1 := hfst (bs, c) x
      have h2 := hsnd (bs, c) x
      simp only at h1 h2
      exact Prod.ext h1 h2
    rw [hstep, ih, carries]
    simp

/-- A conditional whose branches share a first component is a pair over a
    conditional second component — the reshaping that turns a fold body which
    interleaves its output-push with the branch into a push-then-update step. -/
theorem ite_prod {γ : Type} {δ : Type} (C : Prop) [Decidable C] (a : γ) (x y : δ) :
    (if C then (a, x) else (a, y)) = (a, if C then x else y) := by
  split <;> rfl

/-- Two folds with pointwise-equal steps produce the same result — the bridge
    from an inline fold body to a named step it agrees with on every input. -/
theorem foldl_congr (f g : β → α → β) (h : ∀ (b : β) (a : α), f b a = g b a)
    (l : List α) (init : β) :
    l.foldl f init = l.foldl g init := by
  induction l generalizing init with
  | nil => rfl
  | cons x xs ih => rw [List.foldl_cons, List.foldl_cons, h init x, ih]

/-- A fold ignores every input its update leaves the carry fixed on: it depends
    only on the sublist of inputs that can change the carry (`filter p`, given
    `upd c x = c` whenever `p x` is `false`). This is the skip-invariance the
    WB4 "ignore Extend/Format/ZWJ" mechanism relies on. -/
theorem foldl_filter (upd : β → α → β) (p : α → Bool)
    (hfix : ∀ (c : β) (x : α), p x = false → upd c x = c)
    (l : List α) (c : β) :
    l.foldl upd c = (l.filter p).foldl upd c := by
  induction l generalizing c with
  | nil => rfl
  | cons x xs ih =>
    rw [List.filter_cons]
    by_cases hpx : p x
    · simp only [hpx, if_pos, List.foldl_cons]
      exact ih (upd c x)
    · have hpf : p x = false := by simpa using hpx
      rw [if_neg (by simp [hpf]), List.foldl_cons, hfix c x hpf]
      exact ih c

/-- Entry `i` of the carries list is the carry after folding `upd` over the first
    `i` inputs. -/
theorem carries_getElem? (upd : β → α → β) (c : β) (l : List α) (i : Nat) :
    (carries upd c l)[i]? =
      if i < l.length then some ((l.take i).foldl upd c) else none := by
  induction l generalizing c i with
  | nil => simp [carries]
  | cons x xs ih =>
    cases i with
    | zero => simp [carries]
    | succ j =>
      simp only [carries, List.getElem?_cons_succ, ih, List.length_cons,
        List.take_succ_cons, List.foldl_cons, Nat.succ_lt_succ_iff]

/-- For a push-carry fold from the empty seed, the entry at any in-range index
    `i` is the carry over the first `i` inputs, `(arr.take i).foldl upd c0`. -/
theorem build_getElem! [Inhabited β]
    (s : List β × β → α → List β × β) (upd : β → α → β)
    (hfst : ∀ acc x, (s acc x).1 = acc.1 ++ [acc.2])
    (hsnd : ∀ acc x, (s acc x).2 = upd acc.2 x)
    (c0 : β) (arr : List α) (build : List β)
    (hbuild : build = (arr.foldl s ([], c0)).1)
    (i : Nat) (h : i < arr.length) :
    build[i]! = (arr.take i).foldl upd c0 := by
  have hbl : build = carries upd c0 arr := by
    rw [hbuild, foldl_toList s upd hfst hsnd]
    simp
  have hsize : i < build.length := by
    rw [hbl, carries_length]
    exact h
  have hq : build[i]? = some ((arr.take i).foldl upd c0) := by
    rw [hbl]
    have hqi := carries_getElem? upd c0 arr i
    simp only [h, if_pos] at hqi
    exact hqi
  rw [getElem!_pos build i hsize]
  have hsome : build[i]? = some build[i] := List.getElem?_eq_getElem hsize
  rw [hsome] at hq
  exact Option.some_inj.mp hq

/-- Induction that peels the last element (Lean 4.30 core has no reverse
    recursor): reduce to forward induction on the reversed list. -/
theorem list_snoc_induction {motive : List α → Prop} (hnil : motive [])
    (hsnoc : ∀ (m : List α) (c : α), motive m → motive (m ++ [c])) :
    ∀ l, motive l := by
  intro l
  have key : ∀ (r : List α), motive r.reverse := by
    intro r
    induction r with
    | nil => exact hnil
    | cons a as ih => rw [List.reverse_cons]; exact hsnoc as.reverse a ih
  have h := key l.reverse
  rwa [List.reverse_reverse] at h

/-- **Fold preserves an invariant.** If a predicate holds at the seed and every
    step preserves it, it holds of the whole fold — the tool for characterising a
    bundled-state field redundant with another (a relation the fold keeps). -/
theorem foldl_inv (P : β → Prop) (f : β → α → β)
    (hstep : ∀ (s : β) (x : α), P s → P (f s x))
    (l : List α) (init : β) (hinit : P init) : P (l.foldl f init) := by
  induction l generalizing init with
  | nil => exact hinit
  | cons x xs ih => exact ih (f init x) (hstep init x hinit)

/-- **Field projection through a fold.** If a projection `π` of the step `f`
    depends only on the projected carry — `π (f s x) = g (π s) x` — then `π` of the
    whole fold is the fold of `g` from the projected seed. This isolates one field
    of a bundled state carry (e.g. one `EffSnapshot` component) as its own scan. -/
theorem foldl_proj {γ : Type} (π : β → γ) (f : β → α → β) (g : γ → α → γ)
    (hproj : ∀ (s : β) (x : α), π (f s x) = g (π s) x) (l : List α) (init : β) :
    π (l.foldl f init) = l.foldl g (π init) := by
  induction l generalizing init with
  | nil => rfl
  | cons x xs ih => rw [List.foldl_cons, List.foldl_cons, ← hproj]; exact ih (f init x)

/-- A left fold that pushes a function of each element appends exactly that map
    to the seed array. This is the per-position decision fold of a segmentation
    algorithm: `breaks[i] = decide i` collected over `0 .. n-1`. -/
theorem foldl_push_map_toList (l : List α) (hmap : α → β) (bs0 : List β) :
    (l.foldl (fun bs x => bs ++ [hmap x]) bs0) = bs0 ++ l.map hmap := by
  induction l generalizing bs0 with
  | nil => simp
  | cons x xs ih =>
    rw [List.foldl_cons, ih, List.map_cons]
    simp

end Unicode.Segmentation.PrefixScan
