/-
  Unicode.Generated.CaseFoldingTargetFacts

  Target-column facts for default full case folding: no codepoint
  emitted by a fold is itself a fold source. This is the table-level
  ground for case-folding idempotence — re-folding any fold output
  finds no applicable mapping.

  One kernel-checked fact over `foldingsList` carries the load. A
  `lookupRaw?` hit is a `find?` hit on the same list, so the matched
  entry is a list member and the per-lookup corollaries follow from
  that membership without per-entry case analysis.
-/

import Unicode.Generated.CaseFolding

namespace Unicode.Generated.CaseFolding

set_option maxRecDepth 100000

/-- Every target codepoint in the case-folding table lies outside the
    table's source column. -/
theorem foldingsList_targets_non_source :
    foldingsList.all (fun e => e.2.all (fun t => !isSource t)) = true := by
  decide +kernel

/-- Any table entry's targets lie outside the source column, phrased
    for the runtime view of the table. -/
theorem target_non_source_of_entry (source cp : Nat) (target : List Nat)
    (hEntry : (source, target) ∈ foldings) (hMem : cp ∈ target) :
    isSource cp = false := by
  have hList : (source, target) ∈ foldingsList := by
    unfold foldings at hEntry
    exact hEntry
  have hAll := foldingsList_targets_non_source
  rw [List.all_eq_true] at hAll
  have hEntryAll := hAll (source, target) hList
  rw [List.all_eq_true] at hEntryAll
  have hBool := hEntryAll cp hMem
  simpa using hBool

/-- An unguarded lookup hit yields only targets outside the source
    column: the hit's `find?` witness is a table entry. -/
theorem lookupRaw_target_non_source (source cp : Nat) (target : List Nat)
    (hLookup : lookupRaw? source = some target) (hMem : cp ∈ target) :
    isSource cp = false := by
  unfold lookupRaw? at hLookup
  cases hFind : foldingsList.find? (fun e => e.1 == source) with
  | none =>
      rw [hFind] at hLookup
      cases hLookup
  | some entry =>
      rw [hFind] at hLookup
      injection hLookup with hTarget
      have hKey := List.find?_some hFind
      have hSourceEq : entry.1 = source := eq_of_beq hKey
      have hMemList : entry ∈ foldingsList := List.mem_of_find?_eq_some hFind
      have hEntryPair : (source, target) ∈ foldingsList := by
        rw [← hSourceEq, ← hTarget]
        exact hMemList
      have hAll := foldingsList_targets_non_source
      rw [List.all_eq_true] at hAll
      have hEntryAll := hAll (source, target) hEntryPair
      rw [List.all_eq_true] at hEntryAll
      have hBool := hEntryAll cp hMem
      simpa using hBool

/-- A raw lookup hit is exactly a member of the generated folding list. -/
theorem lookupRaw_mem_foldingsList (source : Nat) (target : List Nat)
    (hLookup : lookupRaw? source = some target) :
    (source, target) ∈ foldingsList := by
  unfold lookupRaw? at hLookup
  cases hFind : foldingsList.find? (fun e => e.1 == source) with
  | none =>
      rw [hFind] at hLookup
      cases hLookup
  | some entry =>
      rw [hFind] at hLookup
      injection hLookup with hTarget
      have hKey := List.find?_some hFind
      have hSourceEq : entry.1 = source := eq_of_beq hKey
      have hMemList : entry ∈ foldingsList := List.mem_of_find?_eq_some hFind
      rw [← hSourceEq, ← hTarget]
      exact hMemList

/-- A guarded lookup hit yields only targets outside the source column. -/
theorem lookup_target_non_source (source cp : Nat) (target : List Nat)
    (hLookup : lookup? source = some target) (hMem : cp ∈ target) :
    isSource cp = false := by
  unfold lookup? at hLookup
  split at hLookup
  · cases hRaw : lookupRaw? source with
    | some targetFound =>
        rw [hRaw] at hLookup
        cases hLookup
        exact lookupRaw_target_non_source source cp target hRaw hMem
    | none =>
        rw [hRaw] at hLookup
        cases hLookup
  · cases hLookup

-- ═══════════════════════════════════════════════════════════════════════════════
-- TEST VECTORS
-- Anchor lookups at both ends of the table plus known non-sources.
-- ═══════════════════════════════════════════════════════════════════════════════

theorem lookup_u0041 : lookup? 0x0041 = some [0x0061] := by decide
theorem lookup_u0042 : lookup? 0x0042 = some [0x0062] := by decide
theorem lookup_u0043 : lookup? 0x0043 = some [0x0063] := by decide
theorem lookup_u005A : lookup? 0x005A = some [0x007A] := by decide
theorem lookup_u00DF : lookup? 0x00DF = some [0x0073, 0x0073] := by decide
theorem lookup_u0049 : lookup? 0x0049 = some [0x0069] := by decide
theorem lookup_u0130 : lookup? 0x0130 = some [0x0069, 0x0307] := by decide
theorem lookup_u0061 : lookup? 0x0061 = none := by decide
theorem lookup_u0062 : lookup? 0x0062 = none := by decide
theorem lookup_u0063 : lookup? 0x0063 = none := by decide
theorem lookup_u0030 : lookup? 0x0030 = none := by decide
theorem lookup_u0073 : lookup? 0x0073 = none := by decide

end Unicode.Generated.CaseFolding
