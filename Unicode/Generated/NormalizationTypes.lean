/-
  Unicode.Generated.NormalizationTypes

  Shared generated certificate row types and search helpers.
-/

import Unicode.Generated.WidthCompatMappings

namespace Unicode.Generated.NormalizationLookups

set_option maxRecDepth 100000

structure CertifiedDecomposition where
  codepoint : Nat
  target : List Nat
  targetNonSource : target.all (fun cp => !WidthCompatMappings.isSource cp) = true

instance : Inhabited CertifiedDecomposition where
  default := {
    codepoint := 0,
    target := [],
    targetNonSource := by simp [WidthCompatMappings.isSource]
  }

def lookupCertifiedDecompositionIn (rows : List CertifiedDecomposition)
    (cp : Nat) (left right fuel : Nat) : Option CertifiedDecomposition :=
  match fuel with
  | 0 => none
  | fuelNext + 1 =>
    if left < right then
      let mid := (left + right) / 2
      let row := rows[mid]!
      if cp < row.codepoint then
        lookupCertifiedDecompositionIn rows cp left mid fuelNext
      else if row.codepoint < cp then
        lookupCertifiedDecompositionIn rows cp (mid + 1) right fuelNext
      else
        some row
    else
      none

def lookupCertifiedDecompositionChunk (rows : List CertifiedDecomposition)
    (cp : Nat) : Option CertifiedDecomposition :=
  lookupCertifiedDecompositionIn rows cp 0 rows.length (rows.length + 1)

theorem certifiedDecomposition_target_non_source
    (cert : CertifiedDecomposition) (cp : Nat) (hMem : cp ∈ cert.target) :
    WidthCompatMappings.isSource cp = false := by
  have hAll := cert.targetNonSource
  rw [List.all_eq_true] at hAll
  have hBool := hAll cp hMem
  simpa using hBool

theorem getElemBang_eq_getElem_of_lt
    {α : Type} [Inhabited α] (rows : List α) (idx : Nat) (hIdx : idx < rows.length) :
    rows[idx]! = rows[idx] := by
  simp [hIdx]

theorem lookupCertifiedDecompositionIn_mem
    (rows : List CertifiedDecomposition) (cp left right fuel : Nat)
    (hRight : right <= rows.length) (cert : CertifiedDecomposition)
    (hLookup :
      lookupCertifiedDecompositionIn rows cp left right fuel = some cert) :
    cert ∈ rows ∧ cert.codepoint = cp := by
  induction fuel generalizing left right with
  | zero =>
      simp [lookupCertifiedDecompositionIn] at hLookup
  | succ fuel ih =>
      unfold lookupCertifiedDecompositionIn at hLookup
      split at hLookup
      · next hLt =>
        let mid := (left + right) / 2
        have hMid : mid < rows.length := by
          have hTwo : 0 < 2 := by decide
          have hMidLtRight : (left + right) / 2 < right := by
            apply (Nat.div_lt_iff_lt_mul hTwo).2
            omega
          omega
        have hBang : rows[mid]! = rows[mid] :=
          getElemBang_eq_getElem_of_lt rows mid hMid
        dsimp only at hLookup
        rw [hBang] at hLookup
        by_cases hCpLt : cp < rows[mid].codepoint
        · rw [if_pos hCpLt] at hLookup
          have hMidLe : mid <= rows.length := by omega
          exact ih left mid hMidLe hLookup
        · rw [if_neg hCpLt] at hLookup
          by_cases hRowLt : rows[mid].codepoint < cp
          · rw [if_pos hRowLt] at hLookup
            exact ih (mid + 1) right hRight hLookup
          · rw [if_neg hRowLt] at hLookup
            cases hLookup
            constructor
            · exact List.mem_of_getElem rfl
            · omega
      · next hNotLt =>
        simp at hLookup

theorem lookupCertifiedDecompositionChunk_mem
    (rows : List CertifiedDecomposition) (cp : Nat) (cert : CertifiedDecomposition)
    (hLookup : lookupCertifiedDecompositionChunk rows cp = some cert) :
    cert ∈ rows ∧ cert.codepoint = cp := by
  unfold lookupCertifiedDecompositionChunk at hLookup
  exact lookupCertifiedDecompositionIn_mem rows cp 0 rows.length (rows.length + 1)
    (Nat.le_refl rows.length) cert hLookup

structure CertifiedPrimaryComposite where
  starter : Nat
  combining : Nat
  composite : Nat
  compositeNonSource : WidthCompatMappings.isSource composite = false

instance : Inhabited CertifiedPrimaryComposite where
  default := {
    starter := 0,
    combining := 0,
    composite := 0,
    compositeNonSource := by simp [WidthCompatMappings.isSource]
  }

def primaryCompositeKey (starter combining : Nat) : Nat :=
  starter * 0x110000 + combining

def primaryCompositeRowKey (row : CertifiedPrimaryComposite) : Nat :=
  primaryCompositeKey row.starter row.combining

def primaryCompositePairLt
    (starter combining rowStarter rowCombining : Nat) : Bool :=
  decide (starter < rowStarter ∨
          (starter = rowStarter ∧ combining < rowCombining))

def lookupCertifiedPrimaryCompositeIn (rows : List CertifiedPrimaryComposite)
    (starter combining : Nat) (left right fuel : Nat) : Option CertifiedPrimaryComposite :=
  match fuel with
  | 0 => none
  | fuelNext + 1 =>
    if left < right then
      let mid := (left + right) / 2
      let row := rows[mid]!
      if primaryCompositePairLt starter combining row.starter row.combining then
        lookupCertifiedPrimaryCompositeIn rows starter combining left mid fuelNext
      else if primaryCompositePairLt row.starter row.combining starter combining then
        lookupCertifiedPrimaryCompositeIn rows starter combining (mid + 1) right fuelNext
      else
        some row
    else
      none

def lookupCertifiedPrimaryCompositeChunk (rows : List CertifiedPrimaryComposite)
    (starter combining : Nat) : Option CertifiedPrimaryComposite :=
  lookupCertifiedPrimaryCompositeIn rows starter combining 0 rows.length (rows.length + 1)

theorem lookupCertifiedPrimaryCompositeIn_mem
    (rows : List CertifiedPrimaryComposite)
    (starter combining left right fuel : Nat)
    (hRight : right <= rows.length) (cert : CertifiedPrimaryComposite)
    (hLookup :
      lookupCertifiedPrimaryCompositeIn rows starter combining left right fuel = some cert) :
    cert ∈ rows ∧ cert.starter = starter ∧ cert.combining = combining := by
  induction fuel generalizing left right with
  | zero =>
      simp [lookupCertifiedPrimaryCompositeIn] at hLookup
  | succ fuel ih =>
      unfold lookupCertifiedPrimaryCompositeIn at hLookup
      split at hLookup
      · next hLt =>
        let mid := (left + right) / 2
        have hMid : mid < rows.length := by
          have hTwo : 0 < 2 := by decide
          have hMidLtRight : (left + right) / 2 < right := by
            apply (Nat.div_lt_iff_lt_mul hTwo).2
            omega
          omega
        have hBang : rows[mid]! = rows[mid] :=
          getElemBang_eq_getElem_of_lt rows mid hMid
        dsimp only at hLookup
        rw [hBang] at hLookup
        by_cases hTargetLt :
            rows[mid].starter > starter ∨
              (starter = rows[mid].starter ∧ combining < rows[mid].combining)
        · have hTargetBool :
              primaryCompositePairLt starter combining
                rows[mid].starter rows[mid].combining = true :=
            decide_eq_true hTargetLt
          rw [hTargetBool] at hLookup
          have hMidLe : mid <= rows.length := by omega
          exact ih left mid hMidLe hLookup
        · have hTargetBool :
              primaryCompositePairLt starter combining
                rows[mid].starter rows[mid].combining = false :=
            decide_eq_false hTargetLt
          rw [hTargetBool] at hLookup
          by_cases hRowLt :
              rows[mid].starter < starter ∨
                (rows[mid].starter = starter ∧ rows[mid].combining < combining)
          · have hRowBool :
                primaryCompositePairLt rows[mid].starter rows[mid].combining
                  starter combining = true :=
              decide_eq_true hRowLt
            rw [hRowBool] at hLookup
            exact ih (mid + 1) right hRight hLookup
          · have hRowBool :
                primaryCompositePairLt rows[mid].starter rows[mid].combining
                  starter combining = false :=
              decide_eq_false hRowLt
            rw [hRowBool] at hLookup
            cases hLookup
            have hNotStarterLt : ¬ starter < rows[mid].starter := by
              intro h
              exact hTargetLt (Or.inl h)
            have hNotRowStarterLt : ¬ rows[mid].starter < starter := by
              intro h
              exact hRowLt (Or.inl h)
            have hStarterEq : rows[mid].starter = starter := by omega
            have hNotCombiningLt : ¬ combining < rows[mid].combining := by
              intro h
              exact hTargetLt (Or.inr ⟨hStarterEq.symm, h⟩)
            have hNotRowCombiningLt : ¬ rows[mid].combining < combining := by
              intro h
              exact hRowLt (Or.inr ⟨hStarterEq, h⟩)
            have hCombiningEq : rows[mid].combining = combining := by omega
            exact ⟨List.mem_of_getElem rfl, hStarterEq, hCombiningEq⟩
      · next hNotLt =>
        simp at hLookup

theorem lookupCertifiedPrimaryCompositeChunk_mem
    (rows : List CertifiedPrimaryComposite)
    (starter combining : Nat) (cert : CertifiedPrimaryComposite)
    (hLookup :
      lookupCertifiedPrimaryCompositeChunk rows starter combining = some cert) :
    cert ∈ rows ∧ cert.starter = starter ∧ cert.combining = combining := by
  unfold lookupCertifiedPrimaryCompositeChunk at hLookup
  exact lookupCertifiedPrimaryCompositeIn_mem rows starter combining 0 rows.length
    (rows.length + 1) (Nat.le_refl rows.length) cert hLookup

end Unicode.Generated.NormalizationLookups
