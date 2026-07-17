/-
  Unicode.Machine

  A Mealy stream transducer `AbstractMachine I O` and its behavioural theory,
  ported (core-only, no import) from the Continuity machine arrow. A machine
  consumes inputs one at a time, threading hidden state and emitting a list of
  outputs per input; its observable behaviour is the stream function
  `outputs : List I → List O`.

  The point for this repo: a scanning detector or normalization pass is a fold
  over the input, i.e. an `accumulate` machine. `feedThrough_append` lets a
  property of the final state be lifted over the input's `++` structure by
  induction, proving a detector correct for *every* input as a state-machine
  invariant.

  Composition (`⋙`) is a homomorphism on the stream function
  (`outputs_compose`), so the Category/Arrow laws are theorems; a compound
  detector assembled from verified parts inherits their soundness.
-/

namespace Unicode.Machine

/-- A Mealy stream transducer `I → O` with hidden state.
    `step s i = (s', os)` : consume one input, advance state, emit outputs. -/
structure AbstractMachine (I O : Type) where
  State : Type
  initial : State
  step : State → I → State × List O
  done : State → Bool := fun _s => false

namespace AbstractMachine

variable {I J O P : Type}

-- Feed-through / run --------------------------------------------------------

/-- Drive `n` over `inputs` from `s`, threading state and concatenating the
    per-input output lists. -/
def feedThrough (n : AbstractMachine I O) : n.State → List I → n.State × List O
  | s, []      => (s, [])
  | s, i :: is =>
    let r  := n.step s i
    let r' := feedThrough n r.1 is
    (r'.1, r.2 ++ r'.2)

/-- Run from the initial state. -/
def run (m : AbstractMachine I O) (inputs : List I) : m.State × List O :=
  feedThrough m m.initial inputs

/-- The observable behaviour: the output stream produced for an input stream. -/
def outputs (m : AbstractMachine I O) (inputs : List I) : List O :=
  (run m inputs).2

/-- The final state after driving the whole input from `initial`. -/
def finalState (m : AbstractMachine I O) (inputs : List I) : m.State :=
  (run m inputs).1

/-- Behavioural equivalence: same outputs for every input stream. -/
def behEquiv (m n : AbstractMachine I O) : Prop := ∀ inputs, outputs m inputs = outputs n inputs

@[inherit_doc] scoped infix:50 " ≋ " => behEquiv

theorem behEquiv_refl (m : AbstractMachine I O) : m ≋ m := fun _inputs => rfl
theorem behEquiv_symm {m n : AbstractMachine I O} (h : m ≋ n) : n ≋ m := fun i => (h i).symm
theorem behEquiv_trans {m n p : AbstractMachine I O} (h₁ : m ≋ n) (h₂ : n ≋ p) : m ≋ p :=
  fun i => (h₁ i).trans (h₂ i)

-- Combinators ---------------------------------------------------------------

/-- Identity: pass each input straight through. -/
def idMachine : AbstractMachine I I where
  State := Unit
  initial := ()
  step := fun _s i => ((), [i])

/-- Lift a pure function to a stateless machine. -/
def arr (f : I → O) : AbstractMachine I O where
  State := Unit
  initial := ()
  step := fun _s i => ((), [f i])

/-- Sequential composition: feed `m`'s outputs through `n`. -/
def compose (m : AbstractMachine I J) (n : AbstractMachine J O) : AbstractMachine I O where
  State := m.State × n.State
  initial := (m.initial, n.initial)
  step := fun s i =>
    let rm := m.step s.1 i
    let rn := feedThrough n s.2 rm.2
    ((rm.1, rn.1), rn.2)
  done := fun s => m.done s.1 && n.done s.2

@[inherit_doc] scoped infixr:80 " ⋙ " => compose

/-- Stateful fold: emit the running accumulator after each input. A detector or
    normalization pass over the input is an `accumulate` machine. -/
def accumulate {S : Type} (f : S → I → S) (init : S) : AbstractMachine I S where
  State := S
  initial := init
  step := fun s i => let s' := f s i; (s', [s'])

-- Reduction lemmas ----------------------------------------------------------

@[simp] theorem feedThrough_nil (n : AbstractMachine I O) (s : n.State) :
    feedThrough n s [] = (s, []) := rfl

@[simp] theorem feedThrough_cons (n : AbstractMachine I O) (s : n.State) (i : I) (is : List I) :
    feedThrough n s (i :: is)
      = ((feedThrough n (n.step s i).1 is).1, (n.step s i).2 ++ (feedThrough n (n.step s i).1 is).2) :=
  rfl

@[simp] theorem idMachine_step (s : Unit) (i : I) :
    (idMachine : AbstractMachine I I).step s i = ((), [i]) := rfl
@[simp] theorem arr_step (f : I → O) (s : Unit) (i : I) : (arr f).step s i = ((), [f i]) := rfl
@[simp] theorem compose_initial (m : AbstractMachine I J) (n : AbstractMachine J O) :
    (m ⋙ n).initial = (m.initial, n.initial) := rfl
@[simp] theorem compose_step (m : AbstractMachine I J) (n : AbstractMachine J O)
    (s : m.State × n.State) (i : I) :
    (m ⋙ n).step s i
      = (((m.step s.1 i).1, (feedThrough n s.2 (m.step s.1 i).2).1),
         (feedThrough n s.2 (m.step s.1 i).2).2) := rfl

-- The key lemmas ------------------------------------------------------------

/-- `feedThrough` distributes over `++`: drive `a`, then drive `b` from the
    resulting state, concatenating outputs. The induction workhorse. -/
theorem feedThrough_append (n : AbstractMachine I O) (s : n.State) (a b : List I) :
    feedThrough n s (a ++ b)
      = ((feedThrough n (feedThrough n s a).1 b).1,
         (feedThrough n s a).2 ++ (feedThrough n (feedThrough n s a).1 b).2) := by
  induction a generalizing s with
  | nil => simp
  | cons i is ih => simp [ih, List.append_assoc]

/-- The final state after `a ++ b` is `b` driven from the final state after `a`. -/
theorem finalState_append (n : AbstractMachine I O) (s : n.State) (a b : List I) :
    (feedThrough n s (a ++ b)).1 = (feedThrough n (feedThrough n s a).1 b).1 := by
  simp [feedThrough_append]

/-- Driving an `accumulate` machine's state from an arbitrary start is the left
    fold from that start. -/
theorem feedThrough_accumulate_fst {S : Type} (f : S → I → S) (init : S)
    (s : S) (inputs : List I) :
    (feedThrough (accumulate f init) s inputs).1 = inputs.foldl f s := by
  induction inputs generalizing s with
  | nil => rfl
  | cons i is ih => simpa [feedThrough_cons, accumulate] using ih (f s i)

/-- The final state of an `accumulate` machine is exactly the left fold. This is
    the bridge: any fold-based detector (`input.foldl step init`) is an
    `accumulate` machine, so it inherits `finalState_append` and the whole
    machine theory for free. -/
theorem accumulate_finalState {S : Type} (f : S → I → S) (init : S) (inputs : List I) :
    finalState (accumulate f init) inputs = inputs.foldl f init := by
  simp only [finalState, run]
  exact feedThrough_accumulate_fst f init init inputs

/-- Step-preservation lifts to the whole fold: if `P` survives one step from any
    state, it survives folding an arbitrary suffix from any state satisfying it. -/
theorem foldl_invariant {S : Type} (f : S → I → S) (P : S → Prop)
    (hstep : ∀ (s : S) (i : I), P s → P (f s i)) :
    ∀ (s : S), P s → ∀ (inputs : List I), P (inputs.foldl f s) := by
  intro s hs inputs
  induction inputs generalizing s with
  | nil => exact hs
  | cons i is ih => exact ih (f s i) (hstep s i hs)

/-- The universal state-machine invariant principle. If a hazard/safety property
    `P` holds initially and is preserved by every step, then it holds on the
    final state for *every* input. This turns a detector's per-step reasoning
    into a proof over all inputs. -/
theorem accumulate_invariant {S : Type} (f : S → I → S) (init : S) (P : S → Prop)
    (h0 : P init) (hstep : ∀ (s : S) (i : I), P s → P (f s i)) (inputs : List I) :
    P (finalState (accumulate f init) inputs) := by
  rw [accumulate_finalState]
  exact foldl_invariant f P hstep init h0 inputs

/-- A counting fold (`+1` on match, unchanged otherwise) is bounded by the number
    of steps: from `n` over `l` it is at most `n + l.length`. Any detector that
    tallies matching codepoints inherits `count ≤ length`, so its count
    arithmetic cannot run past the input size. -/
theorem foldl_count_le {α : Type} (p : α → Bool) :
    ∀ (n : Nat) (l : List α),
      l.foldl (fun m x => if p x then m + 1 else m) n ≤ n + l.length := by
  intro n l
  induction l generalizing n with
  | nil => simp
  | cons x xs ih =>
    simp only [List.foldl_cons, List.length_cons]
    split
    · have h := ih (n + 1); omega
    · have h := ih n; omega

/-- Outputs of `arr f` = `map f`. -/
theorem outputs_arr (f : I → O) (inputs : List I) :
    outputs (arr f) inputs = inputs.map f := by
  simp only [outputs, run]
  generalize (arr f).initial = s
  induction inputs generalizing s with
  | nil => rfl
  | cons i is ih => simp [ih]

/-- Outputs of `idMachine` = the inputs unchanged. -/
theorem outputs_id (inputs : List I) :
    outputs (idMachine : AbstractMachine I I) inputs = inputs := by
  simp only [outputs, run]
  generalize (idMachine : AbstractMachine I I).initial = s
  induction inputs generalizing s with
  | nil => rfl
  | cons i is ih => simp [ih]

/-- Generalized over states: a composite's output is `n` driven over `m`'s output. -/
private theorem feedThrough_compose_snd (m : AbstractMachine I J) (n : AbstractMachine J O)
    (sm : m.State) (sn : n.State) (inputs : List I) :
    (feedThrough (m ⋙ n) (sm, sn) inputs).2
      = (feedThrough n sn (feedThrough m sm inputs).2).2 := by
  induction inputs generalizing sm sn with
  | nil => rfl
  | cons i is ih => simp [feedThrough_append, ih]

/-- The homomorphism: composing machines composes their stream functions. -/
theorem outputs_compose (m : AbstractMachine I J) (n : AbstractMachine J O) (inputs : List I) :
    outputs (m ⋙ n) inputs = outputs n (outputs m inputs) := by
  simp only [outputs, run, compose_initial]
  exact feedThrough_compose_snd m n m.initial n.initial inputs

-- The laws — proven once; every composed machine inherits them ---------------

/-- Category — left identity. -/
theorem id_compose (m : AbstractMachine I O) : idMachine ⋙ m ≋ m := by
  intro inputs; rw [outputs_compose, outputs_id]

/-- Category — right identity. -/
theorem compose_id (m : AbstractMachine I O) : m ⋙ idMachine ≋ m := by
  intro inputs; rw [outputs_compose, outputs_id]

/-- Category — associativity. -/
theorem compose_assoc (m : AbstractMachine I J) (n : AbstractMachine J P) (p : AbstractMachine P O) :
    (m ⋙ n) ⋙ p ≋ m ⋙ (n ⋙ p) := by
  intro inputs; simp only [outputs_compose]

/-- Arrow — `arr id` is the identity machine. -/
theorem arr_id : arr (fun i : I => i) ≋ (idMachine : AbstractMachine I I) := by
  intro inputs; simp [outputs_arr, outputs_id]

/-- Arrow — `arr` is a functor: `arr (g ∘ f) = arr f ⋙ arr g`. -/
theorem arr_compose (f : I → J) (g : J → O) : arr (g ∘ f) ≋ arr f ⋙ arr g := by
  intro inputs; simp [outputs_compose, outputs_arr, List.map_map]

end AbstractMachine
end Unicode.Machine
