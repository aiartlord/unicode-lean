/-
  Unicode.Normalization.Compose

  Canonical composition per UAX #15 §1.3 / D117. Walks a reordered
  sequence left-to-right, maintaining the "active starter" and its
  buffered trailing non-starters. For each new non-starter C:

    * If C is not blocked from the starter (no buffered non-starter
      has CCC ≥ CCC(C)), and the pair `(starter, C)` primary-composes
      to some `P` that is NOT in Full_Composition_Exclusion, then
      the starter is replaced by `P` and `C` is consumed.
    * Otherwise `C` joins the buffer.

  "Primary composite" lookup is the reverse of the canonical-
  decomposition table: find the codepoint whose decomposition is
  exactly `[starter, C]`. Hangul L+V / LV+T pairs short-circuit via
  the algorithmic path in `Hangul.composePair?`.
-/

import Unicode.Normalization.Lookup
import Unicode.Normalization.Hangul
import Unicode.Generated.NormalizationLookups
import Unicode.Generated.CanonicalComposition
import Unicode.Precis.WidthMapping

namespace Unicode.Normalization.Compose

open Unicode.Normalization
open Unicode.Generated

set_option maxRecDepth 100000

/-- Primary-composite lookup: return `P` when `(d, c)` is the canonical
    decomposition of exactly one non-excluded codepoint `P`, else
    `none`. Hangul L+V and LV+T pairs handled algorithmically; all
    other pairs go through a linear scan of the UnicodeData table,
    skipping codepoints flagged Full_Composition_Exclusion. -/
def primaryComposite? (d c : Nat) : Option Nat :=
  match Hangul.composePair? d c with
  | some p => some p
  | none =>
    UnicodeData.rowsList.findSome? (fun r =>
      if r.canonicalDecomposition = [d, c]
         ∧ ¬ Lookup.isFullCompositionExclusion r.codepoint then
        some r.codepoint
      else
        none)

-- ─────────────────────────────────────────────────────────────────────────────
--                                          // compose // pairs-table-agreement
-- ─────────────────────────────────────────────────────────────────────────────

-- The row scan inside `primaryComposite?` re-walks the entire UnicodeData
-- table per query — a cost no reduction engine can pay when the query
-- itself sits inside a table-scale enumeration. The generated
-- `CanonicalComposition.compositionPairs` list is the checked indexed view
-- used by table-scale proofs: entries appear in UnicodeData row order, so a
-- `find?` over the pairs selects the same match the row scan did. The
-- agreement is proven once by a structural induction relating the two
-- traversals, fed by one kernel-checked data certificate; concrete
-- composition facts then transport through the pairs list.

/-- The pair-extraction view of one UnicodeData row: `some (d, c, p)`
    exactly when the row records a non-excluded two-element canonical
    decomposition `[d, c]` for codepoint `p` — precisely the rows the
    scan inside `primaryComposite?` can select. -/
def pairOfRow (r : UnicodeData.UnicodeDataRow) : Option (Nat × Nat × Nat) :=
  if Lookup.isFullCompositionExclusion r.codepoint then
    none
  else
    match r.canonicalDecomposition with
    | [] => none
    | [_only] => none
    | [d, c] => some (d, c, r.codepoint)
    | _first :: _second :: _third :: _rest => none

/-- Data certificate: the generated pairs table is exactly the
    pair-extraction view of the pinned rows, in row order. One linear
    kernel pass over the row list. -/
theorem compositionPairs_eq_filterMap :
    CanonicalComposition.compositionPairs
      = UnicodeData.rowsList.filterMap pairOfRow := by
  decide +kernel

/-- The row scan inside `primaryComposite?` agrees with a `find?` over
    the pair-extraction view, for every list of rows: excluded and
    non-two-element rows are invisible to both sides, and a live row
    matches the scan exactly when its extracted key matches the query. -/
theorem findSome?_matcher_eq_find?_pairs (d c : Nat)
    (l : List UnicodeData.UnicodeDataRow) :
    l.findSome? (fun r =>
      if r.canonicalDecomposition = [d, c]
         ∧ ¬ Lookup.isFullCompositionExclusion r.codepoint then
        some r.codepoint
      else
        none)
    = ((l.filterMap pairOfRow).find?
        (fun t => decide (t.1 = d) && decide (t.2.1 = c))).map
        (fun t => t.2.2) := by
  induction l with
  | nil => rfl
  | cons r rest ih =>
    rw [List.findSome?_cons, List.filterMap_cons]
    by_cases hExcl : Lookup.isFullCompositionExclusion r.codepoint
    · have hMatch : (if r.canonicalDecomposition = [d, c]
             ∧ ¬ Lookup.isFullCompositionExclusion r.codepoint then
            some r.codepoint else none) = none := by
        rw [if_neg]
        intro hCon
        exact hCon.2 hExcl
      have hPair : pairOfRow r = none := by
        unfold pairOfRow
        rw [if_pos hExcl]
      simp only [hMatch, hPair]
      exact ih
    · cases hDT : r.canonicalDecomposition with
      | nil =>
        have hMatch : (if r.canonicalDecomposition = [d, c]
               ∧ ¬ Lookup.isFullCompositionExclusion r.codepoint then
              some r.codepoint else none) = none := by
          rw [if_neg]
          intro hCon
          have hTL := hCon.1
          rw [hDT] at hTL
          simp at hTL
        have hPair : pairOfRow r = none := by
          unfold pairOfRow
          rw [if_neg hExcl, hDT]
        simp only [hMatch, hPair]
        exact ih
      | cons a tail1 =>
        cases hDT2 : tail1 with
        | nil =>
          have hMatch : (if r.canonicalDecomposition = [d, c]
                 ∧ ¬ Lookup.isFullCompositionExclusion r.codepoint then
                some r.codepoint else none) = none := by
            rw [if_neg]
            intro hCon
            have hTL := hCon.1
            rw [hDT, hDT2] at hTL
            simp at hTL
          have hPair : pairOfRow r = none := by
            unfold pairOfRow
            rw [if_neg hExcl, hDT, hDT2]
          simp only [hMatch, hPair]
          exact ih
        | cons b tail2 =>
          cases hDT3 : tail2 with
          | cons e tail3 =>
            have hMatch : (if r.canonicalDecomposition = [d, c]
                   ∧ ¬ Lookup.isFullCompositionExclusion r.codepoint then
                  some r.codepoint else none) = none := by
              rw [if_neg]
              intro hCon
              have hTL := hCon.1
              rw [hDT, hDT2, hDT3] at hTL
              simp at hTL
            have hPair : pairOfRow r = none := by
              unfold pairOfRow
              rw [if_neg hExcl, hDT, hDT2, hDT3]
            simp only [hMatch, hPair]
            exact ih
          | nil =>
            have hPair : pairOfRow r = some (a, b, r.codepoint) := by
              unfold pairOfRow
              rw [if_neg hExcl, hDT, hDT2, hDT3]
            by_cases hKey : a = d ∧ b = c
            · obtain ⟨hA, hB⟩ := hKey
              have hMatch : (if r.canonicalDecomposition = [d, c]
                     ∧ ¬ Lookup.isFullCompositionExclusion r.codepoint then
                    some r.codepoint else none) = some r.codepoint := by
                rw [if_pos]
                refine ⟨?arrEq, hExcl⟩
                rw [hDT, hDT2, hDT3, hA, hB]
              have hCond : (decide ((a, b, r.codepoint).1 = d)
                  && decide ((a, b, r.codepoint).2.1 = c)) = true := by
                simp [hA, hB]
              have hFind : ((a, b, r.codepoint) :: rest.filterMap pairOfRow).find?
                    (fun t => decide (t.1 = d) && decide (t.2.1 = c))
                  = some (a, b, r.codepoint) :=
                List.find?_cons_of_pos hCond
              simp only [hMatch, hPair, hFind, Option.map_some]
            · have hMatch : (if r.canonicalDecomposition = [d, c]
                     ∧ ¬ Lookup.isFullCompositionExclusion r.codepoint then
                    some r.codepoint else none) = none := by
                rw [if_neg]
                intro hCon
                have hTL := hCon.1
                rw [hDT, hDT2, hDT3] at hTL
                simp at hTL
                exact hKey hTL
              have hFind : ((a, b, r.codepoint) :: rest.filterMap pairOfRow).find?
                    (fun t => decide (t.1 = d) && decide (t.2.1 = c))
                  = (rest.filterMap pairOfRow).find?
                      (fun t => decide (t.1 = d) && decide (t.2.1 = c)) := by
                rw [List.find?_cons_of_neg]
                simp only [Bool.and_eq_true, decide_eq_true_eq]
                intro hCon
                exact hKey hCon
              simp only [hMatch, hPair, hFind]
              exact ih

/-- `primaryComposite?` computed against the generated pairs table: the
    Hangul algorithmic branch unchanged, the row scan replaced by a
    linear `find?` keyed on `(starter, combiner)`. -/
def primaryCompositePairs? (d c : Nat) : Option Nat :=
  match Hangul.composePair? d c with
  | some p => some p
  | none =>
    (CanonicalComposition.compositionPairs.find?
      (fun t => decide (t.1 = d) && decide (t.2.1 = c))).map
      (fun t => t.2.2)

/-- The two lookups agree everywhere. Composes the data certificate with
    the traversal agreement. -/
theorem primaryComposite?_eq_pairs (d c : Nat) :
    primaryComposite? d c = primaryCompositePairs? d c := by
  unfold primaryComposite? primaryCompositePairs?
  cases hHangul : Hangul.composePair? d c with
  | some p => rfl
  | none =>
    rw [compositionPairs_eq_filterMap]
    exact findSome?_matcher_eq_find?_pairs d c UnicodeData.rowsList

/-- A non-composing pair, without reducing either scan: the Hangul
    branch misses by arithmetic, and a linear `List.all` pass witnesses
    that no pairs-table entry carries the key. -/
theorem primaryComposite?_none_of_all_ne (d c : Nat)
    (hHangul : Hangul.composePair? d c = none)
    (hAll : CanonicalComposition.compositionPairs.all
      (fun t => decide (¬ (t.1 = d ∧ t.2.1 = c))) = true) :
    primaryComposite? d c = none := by
  rw [primaryComposite?_eq_pairs]
  unfold primaryCompositePairs?
  have hNone : CanonicalComposition.compositionPairs.find?
      (fun t => decide (t.1 = d) && decide (t.2.1 = c)) = none := by
    rw [List.find?_eq_none]
    intro t ht
    have hNe := of_decide_eq_true (List.all_eq_true.mp hAll t ht)
    intro hKey
    rw [Bool.and_eq_true, decide_eq_true_eq, decide_eq_true_eq] at hKey
    exact hNe hKey
  rw [hHangul, hNone]
  rfl

/-- A composing pair, without reducing either scan: `hAny` witnesses a
    pairs-table entry carrying the key, `hAll` pins the composite of
    every entry carrying it. -/
theorem primaryComposite?_some_of_pair (d c p : Nat)
    (hHangul : Hangul.composePair? d c = none)
    (hAny : CanonicalComposition.compositionPairs.any
      (fun t => decide (t.1 = d) && decide (t.2.1 = c)) = true)
    (hAll : CanonicalComposition.compositionPairs.all
      (fun t => decide ((t.1 = d ∧ t.2.1 = c) → t.2.2 = p)) = true) :
    primaryComposite? d c = some p := by
  rw [primaryComposite?_eq_pairs]
  unfold primaryCompositePairs?
  cases hF : CanonicalComposition.compositionPairs.find?
      (fun t => decide (t.1 = d) && decide (t.2.1 = c)) with
  | none =>
    exfalso
    rw [List.find?_eq_none] at hF
    rw [List.any_eq_true] at hAny
    obtain ⟨t, htMem, htKey⟩ := hAny
    exact (hF t htMem) htKey
  | some t =>
    have hMem : t ∈ CanonicalComposition.compositionPairs :=
      List.mem_of_find?_eq_some hF
    have hKey := List.find?_some
      (p := fun (t : Nat × Nat × Nat) =>
        decide (t.1 = d) && decide (t.2.1 = c)) hF
    rw [Bool.and_eq_true, decide_eq_true_eq, decide_eq_true_eq] at hKey
    have hPin : (t.1 = d ∧ t.2.1 = c) → t.2.2 = p :=
      of_decide_eq_true (List.all_eq_true.mp hAll t hMem)
    rw [hHangul]
    simp [hPin hKey]

/-- Fold state for the composition pass.

    * `emitted`  — the sequence finalized behind the current active
                   starter (finished runs).
    * `starter`  — the active starter codepoint, possibly the result
                   of one or more primary-composite absorptions.
    * `buffer`   — non-starters seen after `starter` that did not
                   compose with it, in REVERSE scan order.
    * `maxCCC`   — maximum CCC among buffered non-starters, used to
                   detect blocking per UAX #15. -/
structure ComposeState where
  emitted : List Nat
  starter : Option Nat
  buffer  : List Nat
  maxCCC  : Nat
  deriving Inhabited

def initialState : ComposeState :=
  { emitted := [], starter := none, buffer := [], maxCCC := 0 }

/-- Emit the accumulated starter + buffer as a suffix appended to
    `emitted`, producing the final output list. -/
def flushCompose (s : ComposeState) : List Nat :=
  let bufferList := s.buffer.reverse
  match s.starter with
  | some st => s.emitted ++ [st] ++ bufferList
  | none    => s.emitted ++ bufferList

/-- Step: process one codepoint.

    Handles both starter-with-non-starter composition (the common case)
    and starter-with-starter composition (Hangul L+V → LV, LV+T → LVT).
    UAX #15 D115/D117: when the current codepoint `cp` is itself a
    starter (CCC = 0), it is blocked from the active starter iff any
    non-starter is buffered between them (equivalently, `buffer` is
    non-empty). -/
def stepCompose (s : ComposeState) (cp : Nat) : ComposeState :=
  let ccc := Lookup.canonicalCombiningClass cp
  match s.starter with
  | none =>
    if ccc = 0 then
      -- First starter of the sequence; no flush needed.
      { s with starter := some cp }
    else
      -- Leading non-starter with no active starter to absorb into.
      { s with emitted := s.emitted ++ [cp] }
  | some st =>
    if ccc = 0 then
      -- New starter. Compose with active starter only if no buffered
      -- non-starters stand between them.
      if s.buffer.isEmpty then
        match primaryComposite? st cp with
        | some p => { s with starter := some p }
        | none =>
          { emitted := s.emitted ++ [st]
            starter := some cp
            buffer  := []
            maxCCC  := 0 }
      else
        { emitted := s.emitted ++ [st] ++ s.buffer.reverse
          starter := some cp
          buffer  := []
          maxCCC  := 0 }
    else
      -- Non-starter. Blocked iff any buffered non-starter has CCC ≥
      -- this codepoint's CCC.
      if ccc ≤ s.maxCCC then
        { s with buffer := cp :: s.buffer, maxCCC := Nat.max s.maxCCC ccc }
      else
        match primaryComposite? st cp with
        | some p => { s with starter := some p }
        | none   => { s with buffer := cp :: s.buffer, maxCCC := Nat.max s.maxCCC ccc }

/-- Canonical composition of a codepoint sequence per UAX #15 §1.3. -/
def compose (cps : List Nat) : List Nat :=
  flushCompose (cps.foldl stepCompose initialState)

-- ═══════════════════════════════════════════════════════════════════════════════
-- TEST VECTORS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Primary-composite sanity: `A` + combining grave composes to `À`. -/
theorem primary_A_grave :
    primaryComposite? 0x0041 0x0300 = some 0x00C0 := by decide

/-- Primary-composite sanity: `A` + combining ring above composes to `Å`. -/
theorem primary_A_ring :
    primaryComposite? 0x0041 0x030A = some 0x00C5 := by decide

/-- Hangul primary composition: L + V composes to LV syllable. -/
theorem primary_hangul_LV :
    primaryComposite? 0x1100 0x1161 = some 0xAC00 := by decide

/-- Empty sequence composes to empty. -/
theorem compose_empty : compose [] = [] := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- WIDTH-COMPAT NON-INTERFERENCE
--
-- Canonical composition preserves non-width-compat-source input codepoints.
-- Two routes produce output codepoints: direct passthrough of input cps
-- (preserved by hypothesis) and primary-composite lookup. For the latter,
-- the composed codepoint is either
--   * a Hangul syllable in 0xAC00..0xD7A4 (bounded by the Hangul composition
--     arithmetic); the entire inclusive range is enumerated non-width-compat-
--     source by `decide`, or
--   * the codepoint of a UnicodeData row whose canonical decomposition equals
--     `[d, c]`; rows with any canonical decomposition are non-width-compat-
--     source by `decide` on the pinned UnicodeData table (Unicode
--     invariant: a codepoint has either a canonical decomposition or a
--     compatibility decomposition, not both).
--
-- Both `decide` table facts combine with a structural state-invariant
-- induction on `stepCompose` to yield `compose_preserves_non_widthCompatSource`.
-- ═══════════════════════════════════════════════════════════════════════════════

section WidthCompatPreservation

open Unicode.Precis.WidthMapping (isWidthCompatSource lookupWidthMapping?)

theorem isWidthCompatSource_false_of_generated_non_source
    (cp : Nat) (h : WidthCompatMappings.isSource cp = false) :
    isWidthCompatSource cp = false := by
  unfold isWidthCompatSource lookupWidthMapping?
  rw [WidthCompatMappings.lookup_none_of_non_source cp h]
  rfl

/-- Every codepoint in the inclusive Hangul syllable range
    `[0xAC00, 0xD7A4]` is a non-width-compat-source. The upper inclusive
    bound covers the off-by-one edge that `Hangul.composePair?` may
    produce when the T-jamo offset saturates its maximum (`TCount = 28`).
    Closed by `decide` over 11173 cases. -/
theorem hangulFull_range_non_widthCompatSource :
    (List.range 11173).all
      (fun i => !isWidthCompatSource (0xAC00 + i)) = true := by
  rw [List.all_eq_true]
  intro i hI
  have hILt : i < 11173 := List.mem_range.mp hI
  have hGenerated : WidthCompatMappings.isSource (0xAC00 + i) = false := by
    simp [WidthCompatMappings.isSource]
    omega
  have hWidth :
      isWidthCompatSource (0xAC00 + i) = false :=
    isWidthCompatSource_false_of_generated_non_source (0xAC00 + i) hGenerated
  simp [hWidth]

/-- `Hangul.composePair?` output, when `some`, lies in the inclusive
    range `[0xAC00, 0xD7A4]`. The LV branch produces
    `SBase + (lIndex * VCount + vIndex) * TCount` with
    `lIndex * VCount + vIndex < LCount * VCount = NCount`, hence strictly
    less than `SBase + SCount`. The LVT branch produces
    `first + (second - TBase)` with `first ∈ [SBase, SBase + SCount)`
    and `second ∈ (TBase, TBase + TCount]`, hence the sum is at most
    `SBase + SCount = 0xD7A4`. -/
theorem composePair_output_range
    (a b p : Nat) (h : Hangul.composePair? a b = some p) :
    0xAC00 ≤ p ∧ p ≤ 0xD7A4 := by
  unfold Hangul.composePair? at h
  split at h
  · next hLV =>
    obtain ⟨hL, hV⟩ := hLV
    simp only [Hangul.isLJamo, Hangul.LBase, Hangul.LCount] at hL
    simp only [Hangul.isVJamo, Hangul.VBase, Hangul.VCount] at hV
    have hLR := of_decide_eq_true hL
    have hVR := of_decide_eq_true hV
    simp only [Option.some.injEq] at h
    subst h
    simp only [Hangul.SBase, Hangul.VCount, Hangul.TCount, Hangul.LBase, Hangul.VBase]
    refine ⟨by omega, ?upperBound⟩
    omega
  · split at h
    · next hLVT =>
      obtain ⟨hS, hT⟩ := hLVT
      simp only [Hangul.isHangulSyllable, Hangul.SBase, Hangul.SCount,
                 Hangul.LCount, Hangul.NCount, Hangul.VCount, Hangul.TCount] at hS
      simp only [Hangul.isTJamo, Hangul.TBase, Hangul.TCount] at hT
      have hSR := of_decide_eq_true hS
      have hTR := of_decide_eq_true hT
      change (if (a - Hangul.SBase) % Hangul.TCount = 0
                then some (a + (b - Hangul.TBase)) else none) = some p at h
      split at h
      · simp only [Option.some.injEq] at h
        subst h
        simp only [Hangul.TBase, Hangul.SBase, Hangul.TCount] at *
        refine ⟨by omega, by omega⟩
      · simp at h
    · simp at h

/-- `Hangul.composePair?` output, when `some`, is a non-width-compat-source. -/
theorem composePair_output_non_widthCompatSource
    (a b p : Nat) (h : Hangul.composePair? a b = some p) :
    isWidthCompatSource p = false := by
  obtain ⟨hLo, hHi⟩ := composePair_output_range a b p h
  have hiLt : p - 0xAC00 < 11173 := by omega
  have hCpEq : 0xAC00 + (p - 0xAC00) = p := by omega
  have hTable := hangulFull_range_non_widthCompatSource
  rw [List.all_eq_true] at hTable
  have hI : p - 0xAC00 ∈ List.range 11173 := List.mem_range.mpr hiLt
  have hAt := hTable (p - 0xAC00) hI
  rw [hCpEq] at hAt
  simpa using hAt

/-- Primary-composite output is always a non-width-compat-source. Case
    on `Hangul.composePair?`: the Hangul branch is discharged by
    `composePair_output_non_widthCompatSource`; the generated non-Hangul
    lookup carries a certificate that its output is not a width source. -/
theorem primaryComposite_non_widthCompatSource
    (d c p : Nat) (h : primaryComposite? d c = some p) :
    isWidthCompatSource p = false := by
  unfold primaryComposite? at h
  split at h
  · next q hq =>
    simp only [Option.some.injEq] at h
    subst h
    exact composePair_output_non_widthCompatSource d c q hq
  · have hGenerated :
        WidthCompatMappings.isSource p = false :=
      NormalizationLookups.primaryComposite_target_non_source d c p h
    exact isWidthCompatSource_false_of_generated_non_source p hGenerated

/-- State invariant for `compose`: all codepoints reachable through
    emitted/starter/buffer satisfy the predicate `P`. -/
def AllSatisfiesP (P : Nat → Bool) (s : ComposeState) : Prop :=
  (∀ x ∈ s.emitted, P x = true)
    ∧ (∀ x, s.starter = some x → P x = true)
    ∧ (∀ x ∈ s.buffer, P x = true)

theorem initial_state_AllSatisfiesP (P : Nat → Bool) :
    AllSatisfiesP P initialState := by
  refine ⟨?emitInv, ?starterInv, ?bufInv⟩
  · intro x hx; simp [initialState] at hx
  · intro x hx; simp [initialState] at hx
  · intro x hx; simp [initialState] at hx

/-- Specialized step preservation for the non-width-compat-source
    predicate. The primary-composite branches supply their preservation
    witness through `primaryComposite_non_widthCompatSource`. -/
theorem stepCompose_preserves_non_widthCompatSource
    (s : ComposeState) (cp : Nat) (hCp : isWidthCompatSource cp = false)
    (hInv : AllSatisfiesP (fun x => !isWidthCompatSource x) s) :
    AllSatisfiesP (fun x => !isWidthCompatSource x) (stepCompose s cp) := by
  obtain ⟨hE, hStar, hBuf⟩ := hInv
  have hCpP : (fun x => !isWidthCompatSource x) cp = true := by simp [hCp]
  unfold stepCompose
  cases hS : s.starter with
  | none =>
    by_cases hCCC : Lookup.canonicalCombiningClass cp = 0
    · simp only [hCCC, if_true]
      refine ⟨hE, ?starterInvA, hBuf⟩
      intro x hx
      rw [← Option.some.inj hx]
      exact hCpP
    · simp only [hCCC, if_false]
      refine ⟨?emitInvB, ?starterInvB, hBuf⟩
      · intro x hx
        rcases List.mem_append.mp hx with h1 | h2
        · exact hE x h1
        · simp at h2; rw [h2]; exact hCpP
      · intro x hx
        simp at hx
  | some st =>
    by_cases hCCC : Lookup.canonicalCombiningClass cp = 0
    · simp only [hCCC, if_true]
      by_cases hBufEm : s.buffer.isEmpty = true
      · simp only [hBufEm, if_true]
        cases hPrim : primaryComposite? st cp with
        | some p =>
          refine ⟨hE, ?starterInvC, hBuf⟩
          intro x hx
          rw [← Option.some.inj hx]
          have hP : isWidthCompatSource p = false :=
            primaryComposite_non_widthCompatSource st cp p hPrim
          simp [hP]
        | none =>
          refine ⟨?emitInvD, ?starterInvD, ?bufInvD⟩
          · intro x hx
            rcases List.mem_append.mp hx with h1 | h2
            · exact hE x h1
            · simp at h2; rw [h2]; exact hStar st hS
          · intro x hx
            rw [← Option.some.inj hx]; exact hCpP
          · intro x hx; simp at hx
      · simp only [hBufEm]
        refine ⟨?emitInvE, ?starterInvE, ?bufInvE⟩
        · intro x hx
          rcases List.mem_append.mp hx with h1 | h2
          · rcases List.mem_append.mp h1 with h1a | h1b
            · exact hE x h1a
            · simp at h1b; rw [h1b]; exact hStar st hS
          · rw [List.mem_reverse] at h2
            exact hBuf x h2
        · intro x hx
          rw [← Option.some.inj hx]; exact hCpP
        · intro x hx; simp at hx
    · simp only [hCCC, if_false]
      by_cases hBlock : Lookup.canonicalCombiningClass cp ≤ s.maxCCC
      · simp only [hBlock, if_true]
        refine ⟨hE, ?starterInvF, ?bufInvF⟩
        · intro x hx
          rw [← Option.some.inj hx]
          exact hStar st hS
        · intro x hx
          rcases List.mem_cons.mp hx with h1 | h2
          · rw [h1]; exact hCpP
          · exact hBuf x h2
      · simp only [hBlock, if_false]
        cases hPrim : primaryComposite? st cp with
        | some p =>
          refine ⟨hE, ?starterInvG, hBuf⟩
          intro x hx
          rw [← Option.some.inj hx]
          have hP : isWidthCompatSource p = false :=
            primaryComposite_non_widthCompatSource st cp p hPrim
          simp [hP]
        | none =>
          refine ⟨hE, ?starterInvH, ?bufInvH⟩
          · intro x hx
            rw [← Option.some.inj hx]
            exact hStar st hS
          · intro x hx
            rcases List.mem_cons.mp hx with h1 | h2
            · rw [h1]; exact hCpP
            · exact hBuf x h2

/-- `flushCompose` preserves the predicate: every output codepoint
    comes from `emitted`, `starter`, or the (reversed) buffer. -/
theorem flushCompose_preserves_non_widthCompatSource
    (s : ComposeState)
    (hInv : AllSatisfiesP (fun x => !isWidthCompatSource x) s) :
    ∀ j ∈ flushCompose s, isWidthCompatSource j = false := by
  obtain ⟨hE, hStar, hBuf⟩ := hInv
  intro j hj
  unfold flushCompose at hj
  split at hj
  · next st hSt =>
    rcases List.mem_append.mp hj with h1 | h2
    · rcases List.mem_append.mp h1 with h1a | h1b
      · have := hE j h1a; simpa using this
      · simp at h1b
        rw [h1b]
        have := hStar st hSt
        simpa using this
    · rw [List.mem_reverse] at h2
      have := hBuf j h2
      simpa using this
  · next hSt =>
    rcases List.mem_append.mp hj with h1 | h2
    · have := hE j h1; simpa using this
    · rw [List.mem_reverse] at h2
      have := hBuf j h2
      simpa using this

/-- **Sequence-level preservation.** If every input codepoint is a
    non-width-compat-source, every output codepoint of `compose` is
    also a non-width-compat-source. -/
theorem compose_preserves_non_widthCompatSource
    (cps : List Nat) (h : ∀ cp ∈ cps, isWidthCompatSource cp = false) :
    ∀ j ∈ compose cps, isWidthCompatSource j = false := by
  unfold compose
  have hFold : AllSatisfiesP (fun x => !isWidthCompatSource x)
                  (cps.foldl stepCompose initialState) := by
    have key : ∀ (l : List Nat) (s : ComposeState),
        (∀ x ∈ l, isWidthCompatSource x = false) →
        AllSatisfiesP (fun x => !isWidthCompatSource x) s →
        AllSatisfiesP (fun x => !isWidthCompatSource x) (l.foldl stepCompose s) := by
      intro l
      induction l with
      | nil => intro s hL hS; simpa using hS
      | cons hd tl ih =>
        intro s hL hS
        simp only [List.foldl_cons]
        apply ih (stepCompose s hd) (fun y hy => hL y (by simp [hy]))
        exact stepCompose_preserves_non_widthCompatSource s hd
          (hL hd (by simp)) hS
    exact key cps initialState
      (fun x hx => h x hx)
      (initial_state_AllSatisfiesP (fun x => !isWidthCompatSource x))
  intro j hj
  exact flushCompose_preserves_non_widthCompatSource
    (cps.foldl stepCompose initialState) hFold j (by simpa using hj)

end WidthCompatPreservation

-- ═══════════════════════════════════════════════════════════════════════════════
-- COMPOSE IS THE IDENTITY ON UNCOMPOSABLE STARTER SEQUENCES
--
-- The final NFC stage `compose` leaves a sequence untouched when every codepoint
-- is a starter (CCC 0) and no adjacent pair has a precomposed form. Proven
-- structurally as a shift-register fold invariant, so a caller establishing NFC
-- form on such input (e.g. pure ASCII) never reduces the composition tables in the
-- kernel. `decompose` and `reorder` already have their identity lemmas
-- (`decomposeSequence_id_on_FullyDecomposed`, `reorder_id_on_HasSortedRuns`); this
-- supplies the third for `toNFC = compose ∘ reorder ∘ decompose`.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- No adjacent pair in the sequence has a primary composite. -/
def noAdjCompose : List Nat → Prop
  | []          => True
  | [_a]        => True
  | a :: b :: r => primaryComposite? a b = none ∧ noAdjCompose (b :: r)

/-- **The compose fold is a shift register on uncomposable starters.** Folding
    `stepCompose` over an all-starter, no-adjacent-compose list from a clean
    single-starter state emits each held starter in turn: the flushed output is the
    emitted prefix, the held starter, then the list verbatim. -/
theorem foldl_stepCompose_shift : ∀ (l : List Nat) (em : List Nat) (st : Nat),
    (∀ cp ∈ l, Lookup.canonicalCombiningClass cp = 0) →
    noAdjCompose (st :: l) →
    flushCompose (l.foldl stepCompose
        { emitted := em, starter := some st, buffer := [], maxCCC := 0 })
      = em ++ [st] ++ l := by
  intro l
  induction l with
  | nil => intro em st hSn hNn; simp [flushCompose]
  | cons c cs ih =>
    intro em st hS hN
    have hcc : Lookup.canonicalCombiningClass c = 0 := hS c (by simp)
    have hpc : primaryComposite? st c = none := hN.1
    have hstep : stepCompose { emitted := em, starter := some st, buffer := [], maxCCC := 0 } c
        = { emitted := em ++ [st], starter := some c, buffer := [], maxCCC := 0 } := by
      unfold stepCompose; simp only [hcc, hpc, List.isEmpty_nil, if_true]
    rw [List.foldl_cons, hstep,
        ih (em ++ [st]) c (fun cp h => hS cp (by simp [h])) hN.2]
    simp

/-- **`compose` is the identity on all-starter, no-adjacent-compose input.** -/
theorem compose_id_of_shift (l : List Nat)
    (hS : ∀ cp ∈ l, Lookup.canonicalCombiningClass cp = 0)
    (hN : noAdjCompose l) :
    compose l = l := by
  cases l with
  | nil => simp [compose, flushCompose, initialState]
  | cons c cs =>
    have hcc : Lookup.canonicalCombiningClass c = 0 := hS c (by simp)
    have hfirst : stepCompose initialState c
        = { emitted := [], starter := some c, buffer := [], maxCCC := 0 } := by
      unfold stepCompose initialState; simp only [hcc, reduceIte]
    unfold compose
    rw [List.foldl_cons, hfirst,
        foldl_stepCompose_shift cs [] c (fun cp h => hS cp (by simp [h])) hN]
    simp

end Unicode.Normalization.Compose
