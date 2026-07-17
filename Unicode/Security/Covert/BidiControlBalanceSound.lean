/-
  Unicode.Security.Covert.BidiControlBalanceSound

  Universal soundness for the BidiControlBalance walk.

  This module proves a depth-accounting invariant that holds for *every* input,
  using the ported state-machine invariant principle
  `Unicode.Machine.accumulate_invariant`: the walk's fold is an `accumulate`
  machine, so a property preserved by each `WalkState.step` holds on the final
  state for all inputs.
-/

import Unicode.Security.Covert.BidiControlBalance
import Unicode.Machine

namespace Unicode.Security.Covert.BidiControlBalance

open Unicode.Machine.AbstractMachine

/-- The depth-accounting property: the recorded peak `maxDepth` is at least the
    current combined embedding-plus-isolate stack height. -/
def depthAccounted (st : WalkState) : Prop :=
  st.maxDepth ≥ st.embStack + st.isoStack

/-- `depthAccounted` holds of the initial state. -/
theorem depthAccounted_initial : depthAccounted WalkState.initial := by
  simp [depthAccounted, WalkState.initial]

/-- Every `WalkState.step` preserves `depthAccounted`, whichever branch it takes:
    openers raise `maxDepth` to at least the new depth, poppers only lower the
    live depth, and non-controls leave both sides fixed. -/
theorem step_preserves_depthAccounted (st : WalkState) (cp : Nat) :
    depthAccounted st → depthAccounted (WalkState.step st cp) := by
  intro h
  unfold depthAccounted at h
  unfold WalkState.step
  repeat' split
  all_goals (unfold depthAccounted; dsimp only)
  -- Opener branches raise `maxDepth` to `max _ newDepth ≥ newDepth`; the rest
  -- (poppers lower the live depth, non-controls fix it) close by omega from `h`.
  all_goals first
    | omega
    | apply Nat.le_max_right

/-- Universal depth soundness: for EVERY input, the walk's recorded peak depth is
    at least the final live stack height. -/
theorem runWalk_depthAccounted (input : Array Nat) :
    (runWalk input).maxDepth ≥ (runWalk input).embStack + (runWalk input).isoStack := by
  have key : depthAccounted (finalState (accumulate WalkState.step WalkState.initial) input.toList) :=
    accumulate_invariant WalkState.step WalkState.initial depthAccounted
      depthAccounted_initial step_preserves_depthAccounted input.toList
  rw [accumulate_finalState] at key
  simpa [runWalk, depthAccounted, Array.foldl_toList] using key

end Unicode.Security.Covert.BidiControlBalance
