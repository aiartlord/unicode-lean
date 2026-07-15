/-
  Unicode.Normalization.Invertibility

  Structural groundwork for `decompose_compose_inversion` (NFC idempotence
  pillar 2). Establishes the primary-composite / canonical-decomposition
  correspondence: whenever `primaryComposite? d c = some p` (via the
  UnicodeData lookup path), the canonical decomposition column of `p` is
  exactly `#[d, c]`. This reflects the one-to-one relationship between
  primary composites and their canonical decompositions that UCD defines.

  Requires `UnicodeData.rows` to have distinct codepoints — established by
  a strict-monotone adjacent-pair `decide` + transitive induction
  on the index difference. The inductive step is parametrized over an
  abstract array `rows` to avoid triggering Lean's reducer on the 3045-row
  pinned UCD table (which exhausts `maxRecDepth`).
-/

import Unicode.Normalization.Lookup
import Unicode.Normalization.Compose

namespace Unicode.Normalization.Invertibility

open Unicode.Normalization
open Unicode.Generated

/-- Abstract strict-monotonicity lemma: over any array of `UnicodeDataRow`s
    whose codepoints are adjacent-strictly-increasing, the codepoint column
    is strictly monotone across any index gap. Parametric in the array so
    Lean does not try to reduce `UnicodeData.rows.size = 3045` during the
    induction. -/
theorem array_codepoints_StrictMono_of_adjacent
    (rows : Array UnicodeData.UnicodeDataRow)
    (hAdj : ∀ i (hi : i + 1 < rows.size),
              rows[i].codepoint < rows[i + 1].codepoint) :
    ∀ d (i : Nat) (hd : i + d + 1 < rows.size),
      rows[i].codepoint < rows[i + d + 1].codepoint := by
  intro d
  induction d with
  | zero =>
    intro i hd
    have hi1 : i + 1 < rows.size := by simpa using hd
    simpa using hAdj i hi1
  | succ d ih =>
    intro i hd
    have hMid : i + d + 1 < rows.size := by omega
    have hPrev := ih i hMid
    have hSucc : (i + d + 1) + 1 < rows.size := by omega
    have hStep := hAdj (i + d + 1) hSucc
    have hLt : rows[i].codepoint < rows[(i + d + 1) + 1].codepoint :=
      Nat.lt_trans hPrev hStep
    have hReshapeBnd : i + (d + 1) + 1 < rows.size := by omega
    have hRowEq : rows[i + (d + 1) + 1]'hReshapeBnd = rows[(i + d + 1) + 1]'hSucc := by
      congr 1
    rw [hRowEq]
    exact hLt

/-- Abstract no-dup lemma: strict monotonicity implies NoDup on codepoints.
    Parametric for the same reason as the mono lemma. -/
theorem array_codepoint_NoDup_of_StrictMono
    (rows : Array UnicodeData.UnicodeDataRow)
    (hMono : ∀ i j (hi : i < rows.size) (hj : j < rows.size), i < j →
              rows[i].codepoint < rows[j].codepoint)
    (i j : Nat) (hi : i < rows.size) (hj : j < rows.size)
    (hEq : rows[i].codepoint = rows[j].codepoint) : i = j := by
  rcases Nat.lt_trichotomy i j with hLt | hEqIJ | hLt
  · have := hMono i j hi hj hLt
    rw [hEq] at this
    exact absurd this (Nat.lt_irrefl rows[j].codepoint)
  · exact hEqIJ
  · have := hMono j i hj hi hLt
    rw [hEq] at this
    exact absurd this (Nat.lt_irrefl rows[j].codepoint)

/-- Bridge from the abstract offset form to the general
    `i < j → rows[i] < rows[j]` form. Parametric. -/
theorem array_codepoints_StrictMono_gap
    (rows : Array UnicodeData.UnicodeDataRow)
    (hOffset : ∀ d (i : Nat) (hd : i + d + 1 < rows.size),
                rows[i].codepoint < rows[i + d + 1].codepoint)
    (i j : Nat) (hi : i < rows.size) (hj : j < rows.size) (hLt : i < j) :
    rows[i].codepoint < rows[j].codepoint := by
  have hBound : i + (j - i - 1) + 1 < rows.size := by omega
  have hMono := hOffset (j - i - 1) i hBound
  have hIdxEq : i + (j - i - 1) + 1 = j := by omega
  have hRowEq : rows[i + (j - i - 1) + 1]'hBound = rows[j]'hj := by
    congr 1
  rw [hRowEq] at hMono
  exact hMono

/-- The adjacent-pair view of the strict-monotonicity fact: one linear
    kernel pass over the zip of the row list with its own tail. -/
theorem rowsList_adjacent_lt :
    (UnicodeData.rowsList.zip UnicodeData.rowsList.tail).all
      (fun p => decide (p.1.codepoint < p.2.codepoint)) = true := by
  decide +kernel

/-- The codepoints of `UnicodeData.rows` are strictly increasing between
    adjacent entries. The index-driven form, transported from the
    zip-with-tail pass — the indexed enumeration itself is never
    reduced. -/
theorem UnicodeData_rows_adjacent_StrictMono :
    (List.range (UnicodeData.rows.size - 1)).all (fun i =>
      if h : i + 1 < UnicodeData.rows.size then
        decide (UnicodeData.rows[i].codepoint < UnicodeData.rows[i + 1].codepoint)
      else true) = true := by
  rw [List.all_eq_true]
  intro i hiMem
  have hiLt : i < UnicodeData.rows.size - 1 := List.mem_range.mp hiMem
  have hi1 : i + 1 < UnicodeData.rows.size := by omega
  have hLen : UnicodeData.rows.size = UnicodeData.rowsList.length := by
    simp [UnicodeData.rows]
  have hiZip : i < (UnicodeData.rowsList.zip UnicodeData.rowsList.tail).length := by
    rw [List.length_zip, List.length_tail]
    omega
  have hPair := of_decide_eq_true
    (List.all_eq_true.mp rowsList_adjacent_lt
      ((UnicodeData.rowsList.zip UnicodeData.rowsList.tail)[i]'hiZip)
      (List.getElem_mem hiZip))
  rw [List.getElem_zip, List.getElem_tail] at hPair
  rw [dif_pos hi1]
  simp only [UnicodeData.rows, List.getElem_toArray]
  exact decide_eq_true hPair

/-- Pointwise: the immediate successor index has strictly greater codepoint. -/
theorem UnicodeData_rows_codepoint_lt_succ
    (i : Nat) (hi : i + 1 < UnicodeData.rows.size) :
    UnicodeData.rows[i].codepoint < UnicodeData.rows[i + 1].codepoint := by
  have hTable := UnicodeData_rows_adjacent_StrictMono
  rw [List.all_eq_true] at hTable
  have hIRange : i ∈ List.range (UnicodeData.rows.size - 1) := by
    apply List.mem_range.mpr
    omega
  have hAt := hTable i hIRange
  simp [hi] at hAt
  exact hAt

/-- `UnicodeData.rows` has distinct codepoints: if two rows have the same
    codepoint, they are at the same index. -/
theorem UnicodeData_rows_codepoint_NoDup
    (i j : Nat) (hi : i < UnicodeData.rows.size) (hj : j < UnicodeData.rows.size)
    (hEq : UnicodeData.rows[i].codepoint = UnicodeData.rows[j].codepoint) :
    i = j := by
  apply array_codepoint_NoDup_of_StrictMono UnicodeData.rows
    (fun a b ha hb hLt =>
      array_codepoints_StrictMono_gap UnicodeData.rows
        (array_codepoints_StrictMono_of_adjacent UnicodeData.rows
          UnicodeData_rows_codepoint_lt_succ) a b ha hb hLt)
    i j hi hj hEq

set_option maxRecDepth 8192 in
/-- **Primary-composite / canonical-decomposition correspondence**
    (non-Hangul path). When `primaryComposite? d c = some p` via the
    UnicodeData linear scan (i.e., `Hangul.composePair? d c = none`), the
    canonical decomposition column of `p` is exactly `#[d, c]`. The proof
    uses `UnicodeData_rows_codepoint_NoDup` to conclude that the row
    produced by `findSome?` in `primaryComposite?` is the same row
    produced by `find?` in `lookupRow`. Uses a per-theorem `maxRecDepth`
    bump (per the canon's `Continuity.Codec.Varint` precedent) because the
    `Array.find?_eq_some_iff_getElem` unification triggers Lean's
    reducer on the 3045-row UCD table. -/
theorem primaryComposite_canonicalDecomposition_nonHangul
    (d c p : Nat) (hHangul : Hangul.composePair? d c = none)
    (h : Compose.primaryComposite? d c = some p) :
    Lookup.canonicalDecomposition p = #[d, c] := by
  unfold Compose.primaryComposite? at h
  rw [hHangul] at h
  simp only at h
  obtain ⟨row, hRowMem, hFEq⟩ := Array.exists_of_findSome?_eq_some h
  split at hFEq
  · next hCond =>
    obtain ⟨hDec, hNotExc⟩ := hCond
    simp only [Option.some.injEq] at hFEq
    rcases Array.getElem_of_mem hRowMem with ⟨idx, hIdx, hRowEq⟩
    unfold Lookup.canonicalDecomposition
    cases hLookup : Lookup.lookupRow p with
    | none =>
      exfalso
      have hRowList : row ∈ UnicodeData.rowsList := by
        simpa [UnicodeData.rows] using hRowMem
      exact Unicode.Generated.UnicodeDataIndex.lookupRow?_none_no_rowsList_codepoint
        hLookup hRowList hFEq
    | some found =>
      simp
      obtain ⟨src, hSrcMem, hSrcCp, _hSrcCcc, hSrcDecomp⟩ :=
        Unicode.Generated.UnicodeDataIndex.lookupRow?_supported_rowsList hLookup
      have hFoundCp : found.codepoint = p :=
        Unicode.Generated.UnicodeDataIndex.lookupRow?_codepoint hLookup
      have hSrcArray : src ∈ UnicodeData.rows := by
        simpa [UnicodeData.rows] using hSrcMem
      rcases Array.getElem_of_mem hSrcArray with ⟨srcIdx, hSrcIdx, hSrcEq⟩
      have hSrcAtIdxCp : UnicodeData.rows[srcIdx].codepoint = p := by
        rw [hSrcEq]
        exact hSrcCp.trans hFoundCp
      have hRowAtIdxCp : UnicodeData.rows[idx].codepoint = p := by
        rw [hRowEq]
        exact hFEq
      have hIdxEq := UnicodeData_rows_codepoint_NoDup srcIdx idx hSrcIdx hIdx
        (hSrcAtIdxCp.trans hRowAtIdxCp.symm)
      have hSrcEqRow : src = row := by
        subst srcIdx
        exact hSrcEq.symm.trans hRowEq
      have hSrcDec : src.canonicalDecomposition = #[d, c] := by
        rw [hSrcEqRow]
        exact hDec
      exact hSrcDecomp.symm.trans hSrcDec
  · cases hFEq

end Unicode.Normalization.Invertibility
