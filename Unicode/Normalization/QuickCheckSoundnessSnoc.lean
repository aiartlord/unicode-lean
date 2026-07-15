/-
  Unicode.Normalization.QuickCheckSoundnessSnoc

  Compatibility surface for the older snoc-support module names.  The live
  QuickCheck proof path is split across smaller modules:

    * `QuickCheckSoundnessPrefix`
    * `QuickCheckSoundnessSingletonAtomic`
    * `QuickCheckSoundnessSingletonPair`
    * `QuickCheckSoundnessHangul`

  This file keeps the public namespace/theorem entry points available without
  carrying the stale local reducer proofs that were replaced by those modules.
-/

import Unicode.Normalization.QuickCheckSoundnessPrefix
import Unicode.Normalization.QuickCheckSoundnessSingletonAtomic
import Unicode.Normalization.QuickCheckSoundnessSingletonPair
import Unicode.Normalization.QuickCheckSoundnessHangul

namespace Unicode.Normalization.QuickCheckSoundnessSnoc

open Unicode.Normalization
open Unicode.Normalization.NFC
  (toNFC isNFCQuickCheck hasSortedRunsBool nfcQCValue)

universe u

/-- Compatibility wrapper for the prefix module. -/
theorem hasSortedRunsBool_cons_tail
    (x y : Nat) (t : List Nat)
    (h : hasSortedRunsBool (x :: y :: t) = true) :
    hasSortedRunsBool (y :: t) = true :=
  Unicode.Normalization.QuickCheckSoundnessPrefix.hasSortedRunsBool_cons_tail
    x y t h

/-- Compatibility wrapper for the prefix module. -/
theorem hasSortedRunsBool_tail
    (x : Nat) (rest : List Nat)
    (h : hasSortedRunsBool (x :: rest) = true) :
    hasSortedRunsBool rest = true :=
  Unicode.Normalization.QuickCheckSoundnessPrefix.hasSortedRunsBool_tail
    x rest h

/-- Compatibility wrapper for the prefix module. -/
theorem array_all_of_mem (arr : Array Nat) (p : Nat → Bool)
    (h : arr.all p = true) : ∀ x ∈ arr, p x = true :=
  Unicode.Normalization.QuickCheckSoundnessPrefix.array_all_of_mem arr p h

/-- Compatibility wrapper for the prefix module. -/
theorem all_append_singleton_of_all
    (xs : Array Nat) (cp : Nat) (p : Nat → Bool)
    (h : (xs ++ #[cp]).all p = true) :
    xs.all p = true :=
  Unicode.Normalization.QuickCheckSoundnessPrefix.all_append_singleton_of_all
    xs cp p h

/-- Compatibility wrapper for the prefix module. -/
theorem zipTail_pair_mem_append_singleton {α : Type u}
    (l : List α) (x : α) (pair : α × α)
    (h : pair ∈ l.zip l.tail) :
    pair ∈ (l ++ [x]).zip (l ++ [x]).tail :=
  Unicode.Normalization.QuickCheckSoundnessPrefix.zipTail_pair_mem_append_singleton
    l x pair h

/-- Compatibility wrapper for the prefix module. -/
theorem hasSortedRunsBool_dropLast
    (xs : Array Nat) (cp : Nat)
    (h : hasSortedRunsBool (xs ++ #[cp]).toList = true) :
    hasSortedRunsBool xs.toList = true :=
  Unicode.Normalization.QuickCheckSoundnessPrefix.hasSortedRunsBool_dropLast
    xs cp h

/-- Compatibility wrapper for the prefix module. -/
theorem isNFCQuickCheck_dropLast
    (xs : Array Nat) (cp : Nat)
    (h : isNFCQuickCheck (xs ++ #[cp]) = true) :
    isNFCQuickCheck xs = true :=
  Unicode.Normalization.QuickCheckSoundnessPrefix.isNFCQuickCheck_dropLast
    xs cp h

/-- Compatibility wrapper for the atomic singleton module. -/
theorem singleton_sound_atomic
    (cp : Nat)
    (hCcc : Lookup.canonicalCombiningClass cp = 0)
    (hDecomp : Lookup.canonicalDecomposition cp = #[])
    (hNotHangul : Hangul.isHangulSyllable cp = false) :
    toNFC #[cp] = #[cp] :=
  Unicode.Normalization.QuickCheckSoundnessSingletonAtomic.singleton_sound_atomic
    cp hCcc hDecomp hNotHangul

/-- Compatibility wrapper for the singleton-pair module. -/
theorem singleton_sound_pair
    (cp d e : Nat)
    (hQC : nfcQCValue cp = .Y)
    (hCcc : Lookup.canonicalCombiningClass cp = 0)
    (hDecomp : Lookup.canonicalDecomposition cp = #[d, e]) :
    Compose.primaryComposite? d e = some cp :=
  Unicode.Normalization.QuickCheckSoundnessSingletonPair.singleton_sound_pair
    cp d e hQC hCcc hDecomp

/-- Compatibility wrapper for the structural Hangul singleton proof. -/
theorem hangul_singleton_nfc_id_table :
    (List.range Hangul.SCount).all
      (fun i => decide (toNFC #[Hangul.SBase + i] = #[Hangul.SBase + i])) = true := by
  rw [List.all_eq_true]
  intro i hi
  apply decide_eq_true
  have hiLt : i < Hangul.SCount := List.mem_range.mp hi
  exact
    Unicode.Normalization.QuickCheckSoundnessHangul.singleton_sound_hangul
      (Hangul.SBase + i)
      (by
        unfold Hangul.isHangulSyllable Hangul.SBase Hangul.SCount
          Hangul.LCount Hangul.NCount Hangul.VCount Hangul.TCount
        exact decide_eq_true (by omega))

/-- Compatibility wrapper for the structural Hangul singleton proof. -/
theorem singleton_sound_hangul (cp : Nat)
    (hHangul : Hangul.isHangulSyllable cp = true) :
    toNFC #[cp] = #[cp] :=
  Unicode.Normalization.QuickCheckSoundnessHangul.singleton_sound_hangul
    cp hHangul

/-- Compatibility wrapper for the singleton-pair module. -/
theorem singleton_sound_pair_full
    (cp d e : Nat)
    (hQC : nfcQCValue cp = .Y)
    (hCcc : Lookup.canonicalCombiningClass cp = 0)
    (hDecomp : Lookup.canonicalDecomposition cp = #[d, e])
    (hDStarter : Lookup.canonicalCombiningClass d = 0)
    (hENonStarter : 0 < Lookup.canonicalCombiningClass e)
    (hNotHangul : Hangul.isHangulSyllable cp = false)
    (hDDecompEmpty : Lookup.canonicalDecomposition d = #[])
    (hEDecompEmpty : Lookup.canonicalDecomposition e = #[])
    (hDNotHangul : Hangul.isHangulSyllable d = false)
    (hENotHangul : Hangul.isHangulSyllable e = false) :
    toNFC #[cp] = #[cp] :=
  Unicode.Normalization.QuickCheckSoundnessSingletonPair.singleton_sound_pair_full
    cp d e hQC hCcc hDecomp hDStarter hENonStarter hNotHangul
    hDDecompEmpty hEDecompEmpty hDNotHangul hENotHangul

end Unicode.Normalization.QuickCheckSoundnessSnoc
