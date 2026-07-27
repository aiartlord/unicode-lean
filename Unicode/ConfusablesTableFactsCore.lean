/-
  Unicode.ConfusablesTableFactsCore

  Shared predicates and structural lemmas for proof-heavy facts over the
  generated UTS #39 confusables table.

  The table-wide chain certificate is intentionally stated over the raw
  UTS #39 substitution graph.  The runtime `skeleton` function additionally
  brackets substitution with NFD and case folding; those stages have their own
  theorem surfaces.  Reducing the full product pipeline for every confusables
  row makes cold builds operationally unusable and does not measure the graph
  bound that `confusableChainBound` is meant to pin.
-/

import Unicode.Confusables

namespace Unicode.Confusables

open Unicode
open Unicode.Generated

set_option maxRecDepth 1000000

/-- One raw UTS #39 substitution step for a single codepoint. -/
def graphSubstituteCodepoint (cp : Nat) : List Nat :=
  match Unicode.Generated.Confusables.lookup? cp with
  | some target => target
  | none => [cp]

/-- Raw UTS #39 substitution over a codepoint sequence, without the runtime
    normalization/case-fold wrappers from `skeleton`. -/
def graphSubstitute (cps : List Nat) : List Nat :=
  cps.foldl (fun acc cp => acc ++ graphSubstituteCodepoint cp) []

/-- Iterate raw UTS #39 substitution to a fixed point or until fuel runs out. -/
def iteratedGraphSubstituteFuel (fuel : Nat) (cps : List Nat) : List Nat :=
  match fuel with
  | 0 => cps
  | fuel' + 1 =>
      let next := graphSubstitute cps
      if next = cps then cps else iteratedGraphSubstituteFuel fuel' next

/-- Per-entry certificate predicate for the raw confusables substitution graph.
    A generated table row already carries the first edge `source ↦ target`, so
    this checks that the row target reaches a fixed point within the remaining
    fuel. -/
def chainConvergesEntry (entry : Nat × List Nat) : Bool :=
  graphSubstitute
      (iteratedGraphSubstituteFuel (confusableChainBound - 1) entry.2) ==
    iteratedGraphSubstituteFuel (confusableChainBound - 1) entry.2

def expansionEntryUnderBound (bound : Nat) (entry : Nat × List Nat) : Bool :=
  decide (entry.2.length ≤ bound)

theorem foldl_max_size_le_of_all
    (bound : Nat) (l : List (Nat × List Nat)) (acc : Nat)
    (hAcc : acc ≤ bound)
    (hAll : l.all (expansionEntryUnderBound bound) = true) :
    l.foldl (fun m e => max m e.2.length) acc ≤ bound := by
  induction l generalizing acc with
  | nil =>
      simpa using hAcc
  | cons hd tl ih =>
      simp only [List.all_cons, Bool.and_eq_true] at hAll
      have hHd : hd.2.length ≤ bound := of_decide_eq_true hAll.1
      exact ih (max acc hd.2.length) (Nat.max_le.mpr ⟨hAcc, hHd⟩) hAll.2

end Unicode.Confusables
