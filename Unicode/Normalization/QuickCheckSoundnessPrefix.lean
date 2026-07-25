/-
  Unicode.Normalization.QuickCheckSoundnessPrefix

  Prefix-preservation support for the `isNFCQuickCheck` soundness snoc
  induction.  This module contains only the structural list plumbing
  needed to strip the trailing element from `xs ++ [cp]`; singleton NFC
  cases live in separate theorem modules.
-/

import Unicode.Normalization.NFC

namespace Unicode.Normalization.QuickCheckSoundnessPrefix

open Unicode.Normalization
open Unicode.Normalization.NFC
  (isNFCQuickCheck hasSortedRunsBool nfcQCValue)

universe u

/-- `hasSortedRunsBool` on a `cons-cons` head pair decomposes through
    the cons-cons unfolding equation and Boolean conjunction. -/
theorem hasSortedRunsBool_cons_tail
    (x y : Nat) (t : List Nat)
    (h : hasSortedRunsBool (x :: y :: t) = true) :
    hasSortedRunsBool (y :: t) = true := by
  have eq : hasSortedRunsBool (x :: y :: t) =
      ((decide (Lookup.canonicalCombiningClass y = 0) ||
        decide (Lookup.canonicalCombiningClass x
                  ≤ Lookup.canonicalCombiningClass y))
        && hasSortedRunsBool (y :: t)) := by
    unfold hasSortedRunsBool
    simp [List.tail_cons, List.zip_cons_cons]
  rw [eq] at h
  rw [Bool.and_eq_true] at h
  exact h.2

/-- A `hasSortedRunsBool` truth on `x :: rest` carries to `rest`. -/
theorem hasSortedRunsBool_tail
    (x : Nat) (rest : List Nat)
    (h : hasSortedRunsBool (x :: rest) = true) :
    hasSortedRunsBool rest = true := by
  cases rest with
  | nil => unfold hasSortedRunsBool; rfl
  | cons y t => exact hasSortedRunsBool_cons_tail x y t h

/-- `List.all` membership: every element of a `List.all = true`
    list satisfies the predicate. -/
theorem list_all_of_mem (l : List Nat) (p : Nat → Bool)
    (h : l.all p = true) : ∀ x ∈ l, p x = true :=
  List.all_eq_true.mp h

/-- `List.all` on an `xs ++ [cp]` truth carries to the prefix `xs`. -/
theorem all_append_singleton_of_all
    (xs : List Nat) (cp : Nat) (p : Nat → Bool)
    (h : (xs ++ [cp]).all p = true) :
    xs.all p = true := by
  rw [List.all_append, Bool.and_eq_true] at h
  exact h.1

/-- Every pair in the zip-with-tail of `l` is also in the zip-with-tail
    of `l ++ [x]`. -/
theorem zipTail_pair_mem_append_singleton {α : Type u}
    (l : List α) (x : α) (pair : α × α)
    (h : pair ∈ l.zip l.tail) :
    pair ∈ (l ++ [x]).zip (l ++ [x]).tail := by
  induction l with
  | nil =>
    simp at h
  | cons head tail ih =>
    cases tail with
    | nil =>
      simp at h
    | cons hd2 tl2 =>
      simp only [List.tail_cons, List.zip_cons_cons, List.mem_cons] at h
      simp only [List.cons_append, List.tail_cons, List.zip_cons_cons,
                 List.mem_cons]
      rcases h with hHead | hTail
      · exact Or.inl hHead
      · exact Or.inr (ih hTail)

/-- `hasSortedRunsBool` on `xs ++ [cp]` carries to `xs`. -/
theorem hasSortedRunsBool_dropLast
    (xs : List Nat) (cp : Nat)
    (h : hasSortedRunsBool (xs ++ [cp]) = true) :
    hasSortedRunsBool xs = true := by
  unfold hasSortedRunsBool at h ⊢
  rw [List.all_eq_true] at h ⊢
  intro pair hPair
  exact h pair (zipTail_pair_mem_append_singleton xs cp pair hPair)

/-- `isNFCQuickCheck` truth on `xs ++ [cp]` carries to `xs`. -/
theorem isNFCQuickCheck_dropLast
    (xs : List Nat) (cp : Nat)
    (h : isNFCQuickCheck (xs ++ [cp]) = true) :
    isNFCQuickCheck xs = true := by
  unfold isNFCQuickCheck at h ⊢
  rw [Bool.and_eq_true] at h ⊢
  obtain ⟨hAll, hHSR⟩ := h
  refine ⟨?prefixAllQcY, ?prefixHsr⟩
  · exact all_append_singleton_of_all xs cp
      (fun cp => decide (nfcQCValue cp = .Y)) hAll
  · exact hasSortedRunsBool_dropLast xs cp hHSR

end Unicode.Normalization.QuickCheckSoundnessPrefix
