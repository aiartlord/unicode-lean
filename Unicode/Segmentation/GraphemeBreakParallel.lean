/-
  Unicode.Segmentation.GraphemeBreakParallel

  The grapheme-break scan is a monoid homomorphism, hence computable by a
  parallel-prefix (Blelloch) scan rather than strictly left-to-right.

  `graphemeBreaks` decides each boundary from the running `State`, which is the
  left fold of `advance` over the prefix. `advanceRun l` is that fold packaged as
  a single state transition `State → State`. The key theorem
  `advanceRun_append_comp` shows this packaging is a homomorphism from
  `(List, ++)` to `(State → State, ∘)`:

      advanceRun (l₁ ++ l₂) = advanceRun l₂ ∘ advanceRun l₁

  Function composition is associative, so the prefix states can be computed by
  any balanced bracketing of the per-chunk transitions — an O(log n)-depth
  parallel-prefix scan over chunks, then the boundary decisions within each
  chunk in parallel — instead of the O(n) sequential threading. The transition
  domain that matters for the decision is finite (previous class × GB11 state ×
  GB9c state × Regional_Indicator parity), so the transitions form a finite
  monoid and the scan is realizable in SIMD / GPU hardware in the ports.

  Correctness is inherited: `scanState` (used by `GraphemeBreakSpec`) equals
  `advanceRun · State.initial`, so any implementation that composes chunk
  transitions computes the same boundary states, hence — via
  `graphemeBreaks_eq_spec` — the same UAX #29 result. A parallel engine earns
  its correctness by matching this transition algebra, not by re-testing.
-/

import Unicode.Segmentation.GraphemeBreakSpec

namespace Unicode.Segmentation.GraphemeBreak

/-- The composed state transition of a run of code points: the left fold of
    `advance` over `l`, packaged as one `State → State` map. -/
def advanceRun (l : List Nat) (s : State) : State :=
  l.foldl (fun st cp => advance cp st) s

/-- The empty run is the identity transition. -/
theorem advanceRun_nil (s : State) : advanceRun [] s = s := rfl

/-- **Splittability.** The transition of a concatenated run is the second run's
    transition applied after the first — the property a divide-and-conquer scan
    needs to combine chunk results. -/
theorem advanceRun_append (l₁ l₂ : List Nat) (s : State) :
    advanceRun (l₁ ++ l₂) s = advanceRun l₂ (advanceRun l₁ s) := by
  unfold advanceRun
  rw [List.foldl_append]

/-- **Monoid homomorphism.** `advanceRun` maps concatenation to composition:
    `advanceRun (l₁ ++ l₂) = advanceRun l₂ ∘ advanceRun l₁`. Composition is
    associative, so the prefix transitions may be reduced by any balanced tree —
    an O(log n)-depth parallel-prefix scan — with the same result. -/
theorem advanceRun_append_comp (l₁ l₂ : List Nat) :
    advanceRun (l₁ ++ l₂) = advanceRun l₂ ∘ advanceRun l₁ := by
  funext s
  exact advanceRun_append l₁ l₂ s

/-- The state component of the break-scan fold ignores the accumulated break
    array and equals `advanceRun`. -/
theorem step_snd (l : List Nat) (bs : List Bool) (s : State) :
    (l.foldl step (bs, s)).snd = advanceRun l s := by
  induction l generalizing bs s with
  | nil => rfl
  | cons x xs ih =>
    rw [List.foldl_cons]
    show (xs.foldl step (bs ++ [shouldBreakBefore x s], advance x s)).snd = advanceRun (x :: xs) s
    rw [ih]
    unfold advanceRun
    rw [List.foldl_cons]

/-- The scanned prefix state is `advanceRun` from the initial state, so the
    boundary states of `GraphemeBreakSpec` are exactly this monoid scan. Any
    engine that computes them by composing chunk transitions — sequentially,
    or by a parallel-prefix tree — computes the same UAX #29 boundaries via
    `graphemeBreaks_eq_spec`. -/
theorem scanState_eq_advanceRun (pre : List Nat) :
    scanState pre = advanceRun pre State.initial :=
  step_snd pre [] State.initial

/-- **Chunk composition.** The boundary state after two runs is the second run's
    transition applied to the boundary state after the first — chunks compose,
    so per-chunk transitions computed in parallel combine to the global scan. -/
theorem scanState_append (l₁ l₂ : List Nat) :
    scanState (l₁ ++ l₂) = advanceRun l₂ (scanState l₁) := by
  rw [scanState_eq_advanceRun, scanState_eq_advanceRun, advanceRun_append]

/-- `advanceRun` peels its first element as one `advance`. -/
theorem advanceRun_cons (x : Nat) (xs : List Nat) (s : State) :
    advanceRun (x :: xs) s = advanceRun xs (advance x s) := by
  unfold advanceRun
  rw [List.foldl_cons]

/-- **Divide-and-conquer correctness.** The break decisions over a concatenated
    run are the decisions over the first chunk (from the incoming state) followed
    by the decisions over the second chunk (from the first chunk's boundary
    state). With `advanceRun_append_comp` supplying the boundary states by
    parallel prefix, this is the full correctness of a chunked parallel engine:
    split the input, compute each chunk's transition and local breaks
    independently, then concatenate. -/
theorem breaksOf_append (s : State) (l₁ l₂ : List Nat) :
    breaksOf s (l₁ ++ l₂) = breaksOf s l₁ ++ breaksOf (advanceRun l₁ s) l₂ := by
  induction l₁ generalizing s with
  | nil => rw [List.nil_append, advanceRun_nil, breaksOf, List.nil_append]
  | cons x xs ih =>
    rw [List.cons_append, breaksOf, breaksOf, ih, advanceRun_cons, List.cons_append]

/-- The scan output over a concatenation, decomposed into the first chunk's
    breaks and the second chunk's breaks from the boundary state — the form a
    parallel-prefix engine materializes, still ending in the GB2 break. -/
theorem graphemeBreaks_append (l₁ l₂ : List Nat) :
    breaksOf State.initial (l₁ ++ l₂) ++ [true]
      = breaksOf State.initial l₁ ++ breaksOf (scanState l₁) l₂ ++ [true] := by
  rw [breaksOf_append, ← scanState_eq_advanceRun]

end Unicode.Segmentation.GraphemeBreak
