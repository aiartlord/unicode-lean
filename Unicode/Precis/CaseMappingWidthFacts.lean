/-
  Unicode.Precis.CaseMappingWidthFacts

  Width-preservation fact for default full case folding: a fold source
  that is not a width-compatibility source folds only to codepoints
  that are not width-compatibility sources either. `Preparation`
  consumes this to carry width non-interference through the case-fold
  step of the PRECIS pipeline.

  One kernel-checked fact over `foldingsList` carries the load; the
  per-lookup form follows from the membership witness of a `find?`
  hit, exactly as in `CaseFoldingTargetFacts`.
-/

import Unicode.Generated.CaseFolding
import Unicode.Precis.WidthMapping

namespace Unicode.Generated.CaseFolding

set_option maxRecDepth 100000

/-- Table-level width preservation: every case-folding entry either
    has a width-compatibility source in its source column, or carries
    only non-width-compatibility targets. -/
theorem foldingsList_targets_non_width_of_source_non_width :
    foldingsList.all (fun e =>
      Unicode.Precis.WidthMapping.isWidthCompatSource e.1 ||
      e.2.all (fun t =>
        !Unicode.Precis.WidthMapping.isWidthCompatSource t)) = true := by
  decide +kernel

/-- An unguarded lookup hit from a non-width-compatibility source
    yields only non-width-compatibility targets: the hit's `find?`
    witness is a table entry, and the source hypothesis discharges the
    entry's width-source arm. -/
theorem lookupRaw_target_non_width_of_source_non_width
    (source cp : Nat) (target : List Nat)
    (hSourceNonWidth :
      Unicode.Precis.WidthMapping.isWidthCompatSource source = false)
    (hLookup : lookupRaw? source = some target) (hMem : cp ∈ target) :
    Unicode.Precis.WidthMapping.isWidthCompatSource cp = false := by
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
      have hAll := foldingsList_targets_non_width_of_source_non_width
      rw [List.all_eq_true] at hAll
      have hEntryAll := hAll (source, target) hEntryPair
      rw [Bool.or_eq_true] at hEntryAll
      rcases hEntryAll with hWidthSource | hTargets
      · exfalso
        rw [hSourceNonWidth] at hWidthSource
        exact Bool.noConfusion hWidthSource
      · rw [List.all_eq_true] at hTargets
        rcases List.getElem_of_mem hMem with ⟨i, hi, hIEq⟩
        have hBool := hTargets i hi
        rw [hIEq] at hBool
        simpa using hBool

/-- A guarded lookup hit from a non-width-compatibility source yields
    only non-width-compatibility targets. -/
theorem lookup_target_non_width_of_source_non_width
    (source cp : Nat) (target : List Nat)
    (hSourceNonWidth :
      Unicode.Precis.WidthMapping.isWidthCompatSource source = false)
    (hLookup : lookup? source = some target) (hMem : cp ∈ target) :
    Unicode.Precis.WidthMapping.isWidthCompatSource cp = false := by
  unfold lookup? at hLookup
  split at hLookup
  · cases hRaw : lookupRaw? source with
    | some targetFound =>
        rw [hRaw] at hLookup
        cases hLookup
        exact lookupRaw_target_non_width_of_source_non_width
          source cp target hSourceNonWidth hRaw hMem
    | none =>
        rw [hRaw] at hLookup
        cases hLookup
  · cases hLookup

end Unicode.Generated.CaseFolding
