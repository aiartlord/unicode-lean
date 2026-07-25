/-
  Unicode.Security.Crypto.WordlistOrder

  Bounded non-membership for the BIP-39 codepoint wordlists. `Array.any` reduces
  by index (O(i) per element on the list-backed array, O(n²) overall), so a direct
  `isInWordlist … = false` blows up. Instead discharge non-membership by one linear
  `List.all` pass over the codepoint lists (O(n)) and bridge it to the `Array.any`
  form the runtime uses.
-/

namespace Unicode.Security.Crypto.WordlistOrder

/-- `arr.any (· == x) = false` from a single linear `List.all` pass proving every
    entry's codepoint list differs from `x`'s. The `List.all` traverses once
    (O(n)); the `Array.any` form would index each element (O(n²)). -/
theorem any_beq_false_of_allNe (arr : Array (Array Nat)) (x : Array Nat)
    (h : (arr.toList.map (·.toList)).all (fun w => !(w == x.toList)) = true) :
    arr.any (fun e => e == x) = false := by
  rw [Array.any_eq_false]
  intro i hi hb2
  have hmem : (arr[i]'hi).toList ∈ arr.toList.map (·.toList) :=
    List.mem_map.2 ⟨arr[i]'hi, Array.getElem_mem_toList hi, rfl⟩
  have hne := (List.all_eq_true.1 h) ((arr[i]'hi).toList) hmem
  have heq : arr[i]'hi = x := eq_of_beq hb2
  rw [heq, beq_self_eq_true] at hne
  simp at hne

end Unicode.Security.Crypto.WordlistOrder
