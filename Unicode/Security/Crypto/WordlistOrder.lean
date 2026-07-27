/-
  Unicode.Security.Crypto.WordlistOrder

  Bounded non-membership for the BIP-39 codepoint wordlists. Non-membership is
  discharged by one linear `List.all` pass over the codepoint lists (O(n)) proving
  every entry differs from the target, which the runtime `List.any` membership
  check then inherits.
-/

namespace Unicode.Security.Crypto.WordlistOrder

/-- `arr.any (· == x) = false` from a single linear `List.all` pass proving every
    entry's codepoint list differs from `x`. -/
theorem any_beq_false_of_allNe (arr : List (List Nat)) (x : List Nat)
    (h : arr.all (fun w => !(w == x)) = true) :
    arr.any (fun e => e == x) = false := by
  by_contra hc
  have hc' : arr.any (fun e => e == x) = true := by
    cases hb : arr.any (fun e => e == x) with
    | false => exact absurd hb hc
    | true  => rfl
  obtain ⟨e, he, hb⟩ := List.any_eq_true.1 hc'
  have hne := (List.all_eq_true.1 h) e he
  rw [eq_of_beq hb, beq_self_eq_true] at hne
  simp at hne

end Unicode.Security.Crypto.WordlistOrder
