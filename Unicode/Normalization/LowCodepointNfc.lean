/-
  Unicode.Normalization.LowCodepointNfc

  Canonical composition (NFC) is the identity on any sequence whose code points
  all lie below U+00C0 — the least code point carrying a non-trivial canonical
  decomposition. Every such code point is a starter with no decomposition, and no
  two of them primary-compose (every composition's combining component is ≥ U+0300),
  so all three NFC stages act as the identity:

      toNFC cps = compose (reorder (decomposeSequence cps)) = cps.

  Proven structurally, without reducing the normalization tables. The two table
  facts — `rows_ge_0xC0` (every UnicodeData row's code point is ≥ U+00C0) and
  `comp_snd_ge_0x300` (every canonical-composition combining component is ≥ U+0300)
  — are each one linear pass, the row table distributed through its chunk `++`-chain
  so the concatenation is never materialized. Every per-code-point lookup then
  discharges in O(1) against those facts.

  `toNFC_id_all_lt` makes any all-ASCII / low-Latin string's NFC form a one-line
  corollary, in place of a table of per-string kernel reductions.
-/

import Unicode.Normalization.NFC
import Unicode.Normalization.NFD
import Unicode.Normalization.Reorder
import Unicode.Invariants

namespace Unicode.Normalization.LowCodepointNfc

open Unicode.Normalization Unicode.Normalization.NFC Unicode.Generated

set_option maxRecDepth 1000000

/-- Every `UnicodeData` row's code point is at least U+00C0. One linear pass,
    distributed through the chunk `++`-chain so the concatenation is not
    materialized. -/
theorem rows_ge_0xC0 :
    UnicodeData.rowsList.all (fun r => decide (0xC0 ≤ r.codepoint)) = true := by
  unfold UnicodeData.rowsList
  simp only [List.all_append]
  decide +kernel

/-- Every canonical-composition combining component is at least U+0300. -/
theorem comp_snd_ge_0x300 :
    CanonicalComposition.compositionPairs.all (fun t => decide (0x300 ≤ t.2.1)) = true := by
  decide +kernel

/-- A code point below the row-table minimum has no `UnicodeData` row. -/
theorem lookupRow_none_lt (cp : Nat) (h : cp < 0xC0) : Lookup.lookupRow cp = none :=
  Lookup.lookupRow_none_of_all_ne cp (by
    rw [List.all_eq_true]
    intro r hr
    have hge := of_decide_eq_true (List.all_eq_true.mp rows_ge_0xC0 r hr)
    exact decide_eq_true (by omega))

/-- Below U+00C0: combining class is zero (a starter). -/
theorem cccz (cp : Nat) (h : cp < 0xC0) : Lookup.canonicalCombiningClass cp = 0 := by
  unfold Lookup.canonicalCombiningClass
  rw [lookupRow_none_lt cp h]

/-- Below U+00C0: no canonical decomposition. -/
theorem dec_lt (cp : Nat) (h : cp < 0xC0) : Lookup.canonicalDecomposition cp = [] := by
  unfold Lookup.canonicalDecomposition
  rw [lookupRow_none_lt cp h]

/-- A pair whose combining component is below U+0300 has no primary composite:
    no Hangul composite, and no composition-pair key carries it. -/
theorem nc_lt (d c : Nat) (h : c < 0x300) (hH : Hangul.composePair? d c = none) :
    Compose.primaryComposite? d c = none :=
  Compose.primaryComposite?_none_of_all_ne d c hH (by
    rw [List.all_eq_true]
    intro t ht
    have hge := of_decide_eq_true (List.all_eq_true.mp comp_snd_ge_0x300 t ht)
    apply decide_eq_true
    rintro ⟨hd, hc⟩
    omega)

/-- Below U+00C0 there is no Hangul composition: the L-jamo and syllable ranges
    both start well above U+00C0. -/
theorem hang_none_lt (d c : Nat) (hd : d < 0xC0) : Hangul.composePair? d c = none := by
  have hL : Hangul.isLJamo d = false := by
    unfold Hangul.isLJamo
    exact decide_eq_false (by simp only [Hangul.LBase, Hangul.LCount]; omega)
  have hS : Hangul.isHangulSyllable d = false := by
    unfold Hangul.isHangulSyllable
    exact decide_eq_false (by simp only [Hangul.SBase, Hangul.SCount]; omega)
  unfold Hangul.composePair?
  simp [hL, hS]

theorem hsyl_false_lt (cp : Nat) (h : cp < 0xC0) : Hangul.isHangulSyllable cp = false := by
  unfold Hangul.isHangulSyllable
  exact decide_eq_false (by simp only [Hangul.SBase, Hangul.SCount]; omega)

/-- No adjacent pair of below-U+00C0 code points primary-composes. -/
theorem noAdj_all_lt : ∀ (l : List Nat), (∀ cp ∈ l, cp < 0xC0) → Compose.noAdjCompose l
  | [], _hnil => trivial
  | [_x], _hsingle => trivial
  | a :: b :: r, h =>
    ⟨nc_lt a b (by have hb := h b (by simp); omega) (hang_none_lt a b (h a (by simp))),
     noAdj_all_lt (b :: r) (fun cp hcp => h cp (by simp [hcp]))⟩

/-- All-starter sequences of below-U+00C0 code points are canonically ordered
    (every ordering constraint is vacuous, its non-starter antecedent false). -/
theorem hsr_all_lt : ∀ (l : List Nat), (∀ cp ∈ l, cp < 0xC0) → Reorder.HasSortedRuns l
  | [], _hnil => trivial
  | [_x], _hsingle => trivial
  | x :: y :: t, h =>
    ⟨fun hy => by rw [cccz y (h y (by simp))] at hy; omega,
     hsr_all_lt (y :: t) (fun cp hcp => h cp (by simp [hcp]))⟩

/-- Below U+00C0 every code point is already fully decomposed (no decomposition,
    not a Hangul syllable). -/
theorem ifd_all_lt (cps : List Nat) (h : ∀ cp ∈ cps, cp < 0xC0) :
    Unicode.Invariants.IsFullyDecomposed cps := fun cp hMem =>
  ⟨dec_lt cp (h cp hMem), hsyl_false_lt cp (h cp hMem)⟩

/-- **NFC is the identity on any sequence of code points below U+00C0.** Each NFC
    stage — decompose, reorder, compose — acts as the identity, established
    structurally against the two table facts, never reducing the tables. -/
theorem toNFC_id_all_lt (cps : List Nat) (h : ∀ cp ∈ cps, cp < 0xC0) :
    toNFC cps = cps := by
  have hHSR : Reorder.HasSortedRuns cps :=
    hsr_all_lt cps (fun cp hcp => h cp hcp)
  unfold toNFC toNFD
  rw [NFD.decomposeSequence_id_on_FullyDecomposed cps (ifd_all_lt cps h),
      Reorder.reorder_id_on_HasSortedRuns cps hHSR,
      Compose.compose_id_of_shift cps
        (fun cp hcp => cccz cp (h cp hcp))
        (noAdj_all_lt cps (fun cp hcp => h cp hcp))]

/-- An all-starter list is canonically ordered: every ordering constraint's
    non-starter antecedent (`0 < ccc y`) is false. -/
theorem hsr_of_all_ccc0 : ∀ (l : List Nat),
    (∀ cp ∈ l, Lookup.canonicalCombiningClass cp = 0) → Reorder.HasSortedRuns l
  | [], _hnil => trivial
  | [_x], _hsingle => trivial
  | x :: y :: t, h =>
    ⟨fun hy => by rw [h y (by simp)] at hy; omega,
     hsr_of_all_ccc0 (y :: t) (fun cp hcp => h cp (by simp [hcp]))⟩

/-- **NFC is the identity on any all-starter, non-decomposing, non-composing
    sequence.** The three per-code-point structural conditions are supplied
    directly, generalising `toNFC_id_all_lt` past the U+00C0 sufficient bound to
    format characters and any other starter with no canonical decomposition. -/
theorem toNFC_id_of_starters (cps : List Nat)
    (hFD : Unicode.Invariants.IsFullyDecomposed cps)
    (hCCC : ∀ cp ∈ cps, Lookup.canonicalCombiningClass cp = 0)
    (hNoAdj : Compose.noAdjCompose cps) :
    toNFC cps = cps := by
  unfold toNFC toNFD
  rw [NFD.decomposeSequence_id_on_FullyDecomposed cps hFD,
      Reorder.reorder_id_on_HasSortedRuns cps (hsr_of_all_ccc0 cps hCCC),
      Compose.compose_id_of_shift cps hCCC hNoAdj]

end Unicode.Normalization.LowCodepointNfc
