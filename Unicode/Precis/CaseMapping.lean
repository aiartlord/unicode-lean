/-
  Unicode.Precis.CaseMapping

  Unicode default full case
  folding per UAX #21 and RFC 8265 §5.2.4 as consumed by the
  UsernameCaseMapped profile built on PRECIS IdentifierClass.

  Source of truth: the pinned `CaseFolding.txt` entries with status
  `C` (common, simple=full) and `F` (full-only, length-changing) —
  the union RFC 8265 calls "default full case folding". Entries with
  status `S` (simple, length-preserving) are redundant with `C` or
  paired with `F` and are not in the pinned table. Entries with
  status `T` (Turkic-locale-specific) are excluded from the default
  path.

  Codepoints with no CaseFolding entry fold to themselves; callers
  receive the original codepoint as a singleton sequence.
-/

import Unicode.Generated.CaseFoldingTargetFacts
import Unicode.Precis.WidthMapping
import Unicode.Precis.CaseMappingWidthFacts

namespace Unicode.Precis.CaseMapping

open Unicode.Generated

set_option maxRecDepth 100000

/-- Look up a codepoint's default-full case-folded target. Returns
    `some target` when the codepoint has a status-C or status-F
    entry in CaseFolding.txt, otherwise `none`. -/
def lookupCaseFolding? (cp : Nat) : Option (Array Nat) :=
  CaseFolding.lookup? cp

/-- Apply default full case folding to a single codepoint,
    substituting with the fold target if one exists, otherwise
    returning the codepoint unchanged (as a singleton sequence). -/
def caseFoldCodepoint (cp : Nat) : Array Nat :=
  match lookupCaseFolding? cp with
  | some target => target
  | none        => #[cp]

/-- Apply default full case folding to a codepoint sequence,
    flattening each per-codepoint result back into a single
    sequence. -/
def caseFold (cps : Array Nat) : Array Nat :=
  cps.foldl (fun acc cp => acc ++ caseFoldCodepoint cp) #[]

-- ═══════════════════════════════════════════════════════════════════════════════
-- TEST VECTORS
-- Anchored on canonical case-folding examples: ASCII uppercase →
-- ASCII lowercase (status C), SHARP S → "ss" (status F, the
-- classic length-growing case), DOTLESS I and DOTTED CAPITAL I
-- (edge cases omitted from Turkic fold — their `C` / `F`
-- mappings here match the default non-locale-specific path).
-- ═══════════════════════════════════════════════════════════════════════════════

/-- LATIN CAPITAL LETTER A folds to LATIN SMALL LETTER A. -/
theorem caseFold_latin_A : caseFoldCodepoint 0x0041 = #[0x0061] := by
  unfold caseFoldCodepoint lookupCaseFolding?
  rw [CaseFolding.lookup_u0041]

/-- LATIN CAPITAL LETTER Z folds to LATIN SMALL LETTER Z. -/
theorem caseFold_latin_Z : caseFoldCodepoint 0x005A = #[0x007A] := by
  unfold caseFoldCodepoint lookupCaseFolding?
  rw [CaseFolding.lookup_u005A]

/-- LATIN SMALL LETTER SHARP S (ß) folds to "ss" — the length-growing
    status-F case RFC 8265 requires. -/
theorem caseFold_sharp_s :
    caseFoldCodepoint 0x00DF = #[0x0073, 0x0073] := by
  unfold caseFoldCodepoint lookupCaseFolding?
  rw [CaseFolding.lookup_u00DF]

/-- LATIN CAPITAL LETTER I folds to LATIN SMALL LETTER I (non-Turkic
    default path — status C). -/
theorem caseFold_capital_I : caseFoldCodepoint 0x0049 = #[0x0069] := by
  unfold caseFoldCodepoint lookupCaseFolding?
  rw [CaseFolding.lookup_u0049]

/-- LATIN CAPITAL LETTER I WITH DOT ABOVE folds to LATIN SMALL
    LETTER I + COMBINING DOT ABOVE per the status-F entry. -/
theorem caseFold_I_with_dot_above :
    caseFoldCodepoint 0x0130 = #[0x0069, 0x0307] := by
  unfold caseFoldCodepoint lookupCaseFolding?
  rw [CaseFolding.lookup_u0130]

/-- Already-lowercase ASCII is unchanged. -/
theorem caseFold_lowercase_a : caseFoldCodepoint 0x0061 = #[0x0061] := by
  unfold caseFoldCodepoint lookupCaseFolding?
  rw [CaseFolding.lookup_u0061]

/-- Digit has no case mapping. -/
theorem caseFold_digit : caseFoldCodepoint 0x0030 = #[0x0030] := by
  unfold caseFoldCodepoint lookupCaseFolding?
  rw [CaseFolding.lookup_u0030]

/-- Sequence-level fold lowercases each ASCII letter. -/
theorem caseFold_ascii_word :
    caseFold #[0x0041, 0x0042, 0x0043] = #[0x0061, 0x0062, 0x0063] := by
  have hB : caseFoldCodepoint 0x0042 = #[0x0062] := by
    unfold caseFoldCodepoint lookupCaseFolding?
    rw [CaseFolding.lookup_u0042]
  have hC : caseFoldCodepoint 0x0043 = #[0x0063] := by
    unfold caseFoldCodepoint lookupCaseFolding?
    rw [CaseFolding.lookup_u0043]
  simp [caseFold, caseFold_latin_A, hB, hC]

/-- The sharp-s substitution grows a 1-codepoint input into a 2-codepoint output. -/
theorem caseFold_straße_style :
    caseFold #[0x0073, 0x00DF] = #[0x0073, 0x0073, 0x0073] := by
  have hS : caseFoldCodepoint 0x0073 = #[0x0073] := by
    unfold caseFoldCodepoint lookupCaseFolding?
    rw [CaseFolding.lookup_u0073]
  simp [caseFold, hS, caseFold_sharp_s]

-- ═══════════════════════════════════════════════════════════════════════════════
-- IDEMPOTENCE
--
-- `caseFold` is idempotent on every input. The structural reason:
-- every target codepoint of a CaseFolding entry (in the retained
-- full-fold subset — status C + F) is itself absent from the
-- source column of `foldings`, so the output of `caseFold` is a
-- sequence of codepoints on which `lookupCaseFolding?` returns
-- `none`, and `caseFold` of such a sequence is the identity.
--
-- The "targets absent from source" fact is closed by `decide`
-- over the pinned table below. The concrete-vector idempotence
-- theorems that follow anchor the testable surface.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Predicate: `cp` is a source codepoint of some default-full case
    folding entry, i.e. `lookupCaseFolding?` would return a `Some`
    value on it. -/
def isCaseFoldSource (cp : Nat) : Bool :=
  (lookupCaseFolding? cp).isSome

/-- Every target codepoint of a successful case-fold lookup is itself
    absent from the source column — the table is a one-step
    substitution that produces a fixed point. -/
theorem caseFoldTargets_not_in_source (source cp : Nat) (target : Array Nat)
    (hLookup : lookupCaseFolding? source = some target) (hMem : cp ∈ target) :
    isCaseFoldSource cp = false := by
  unfold lookupCaseFolding? at hLookup
  have hGenerated : CaseFolding.isSource cp = false :=
    CaseFolding.lookup_target_non_source source cp target hLookup hMem
  unfold isCaseFoldSource lookupCaseFolding?
  rw [CaseFolding.lookup_none_of_non_source cp hGenerated]
  rfl

/-- A codepoint that is not a case-fold source has no
    `lookupCaseFolding?` result. -/
theorem lookupCaseFolding_none_of_non_source (cp : Nat)
    (h : isCaseFoldSource cp = false) :
    lookupCaseFolding? cp = none := by
  unfold isCaseFoldSource at h
  cases hLookup : lookupCaseFolding? cp with
  | none => rfl
  | some target =>
      rw [hLookup] at h
      simp at h

/-- A codepoint that is not a case-fold source maps to its own
    singleton under `caseFoldCodepoint`. -/
theorem caseFoldCodepoint_id_of_non_source (cp : Nat)
    (h : isCaseFoldSource cp = false) :
    caseFoldCodepoint cp = #[cp] := by
  unfold caseFoldCodepoint
  rw [lookupCaseFolding_none_of_non_source cp h]

/-- Generic lift: on any `Array Nat` whose codepoints each satisfy
    `f cp = #[cp]`, the foldl-with-append pipeline is the identity. -/
theorem arr_foldl_map_id_of_all_identity (cps : Array Nat)
    (f : Nat → Array Nat) (hAll : ∀ cp ∈ cps, f cp = #[cp]) :
    cps.foldl (fun acc cp => acc ++ f cp) #[] = cps := by
  rw [← Array.foldl_toList]
  have hAllList : ∀ cp ∈ cps.toList, f cp = #[cp] :=
    fun cp hMem => hAll cp (by simpa using hMem)
  have key : ∀ (l : List Nat) (init : Array Nat),
      (∀ cp ∈ l, f cp = #[cp]) →
      l.foldl (fun acc cp => acc ++ f cp) init = init ++ l.toArray := by
    intro l
    induction l with
    | nil => intro init hH; simp
    | cons hd tl ih =>
      intro init hH
      have hHd : f hd = #[hd] := hH hd (by simp)
      have hTl : ∀ cp ∈ tl, f cp = #[cp] := fun cp hMem => hH cp (by simp [hMem])
      simp only [List.foldl_cons, hHd]
      rw [ih (init ++ #[hd]) hTl]
      simp
  rw [key cps.toList #[] hAllList]
  simp

/-- `caseFold` is the identity on any sequence whose codepoints are
    all non-sources. -/
theorem caseFold_id_of_all_non_source (cps : Array Nat)
    (h : ∀ cp ∈ cps, isCaseFoldSource cp = false) :
    caseFold cps = cps := by
  unfold caseFold
  apply arr_foldl_map_id_of_all_identity cps caseFoldCodepoint
  intro cp hMem
  exact caseFoldCodepoint_id_of_non_source cp (h cp hMem)

/-- Converse of `lookupCaseFolding_none_of_non_source`: a codepoint
    with no `lookupCaseFolding?` result is not a source. -/
theorem non_source_of_lookupCaseFolding_none (cp : Nat)
    (h : lookupCaseFolding? cp = none) :
    isCaseFoldSource cp = false := by
  unfold isCaseFoldSource
  rw [h]
  rfl

/-- Membership decomposition: a codepoint in `caseFold cps` comes
    from `caseFoldCodepoint x` for some `x ∈ cps`. -/
theorem mem_caseFold_iff (cps : Array Nat) (cp : Nat)
    (hMem : cp ∈ caseFold cps) :
    ∃ x ∈ cps, cp ∈ caseFoldCodepoint x := by
  unfold caseFold at hMem
  rw [← Array.foldl_toList] at hMem
  have key : ∀ (l : List Nat) (init : Array Nat),
      cp ∈ l.foldl (fun acc x => acc ++ caseFoldCodepoint x) init →
      cp ∈ init ∨ ∃ x ∈ l, cp ∈ caseFoldCodepoint x := by
    intro l
    induction l with
    | nil => intro init hM; left; simpa using hM
    | cons hd tl ih =>
      intro init hM
      simp [List.foldl_cons] at hM
      rcases ih (init ++ caseFoldCodepoint hd) hM with hInit | ⟨x, hxM, hxF⟩
      · rcases Array.mem_append.mp hInit with h1 | h2
        · left; exact h1
        · right; exact ⟨hd, by simp, h2⟩
      · right; exact ⟨x, by simp [hxM], hxF⟩
  rcases key cps.toList #[] hMem with hEmpty | ⟨x, hxM, hxF⟩
  · simp at hEmpty
  · exact ⟨x, by simpa using hxM, hxF⟩

/-- Every codepoint in the output of `caseFold` is a non-source. -/
theorem caseFold_output_all_non_source (cps : Array Nat) :
    ∀ cp ∈ caseFold cps, isCaseFoldSource cp = false := by
  intro cp hMem
  obtain ⟨x, hxInCps, hxF⟩ := mem_caseFold_iff cps cp hMem
  clear hxInCps
  unfold caseFoldCodepoint at hxF
  cases hLook : lookupCaseFolding? x with
  | none =>
    rw [hLook] at hxF
    simp at hxF
    have hCpEqX : cp = x := hxF
    rw [hCpEqX]
    exact non_source_of_lookupCaseFolding_none x hLook
  | some tgt =>
    rw [hLook] at hxF
    exact caseFoldTargets_not_in_source x cp tgt hLook hxF

/-- **`caseFold` is idempotent.** For every codepoint sequence,
    applying RFC 8265 §5.2.4 default full case folding twice
    produces the same result as applying it once. -/
theorem caseFold_idempotent (cps : Array Nat) :
    caseFold (caseFold cps) = caseFold cps :=
  caseFold_id_of_all_non_source (caseFold cps) (caseFold_output_all_non_source cps)

-- ═══════════════════════════════════════════════════════════════════════════════
-- CROSS-TABLE NON-INTERFERENCE WITH WidthMapping
-- The PRECIS pipeline applies width-mapping BEFORE case-folding. For
-- the composition to preserve the "no width-compat sources" invariant
-- established by widthMap, case-folding must not reintroduce any
-- width-compat source. The check below witnesses this:
-- on any input whose codepoints are all non-width-compat-sources, the
-- case-folded output is still all non-width-compat-sources.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A successful case-fold lookup from a non-width-compat source
    cannot produce a width-compat source. -/
theorem caseFold_preserves_non_widthCompatSource
    (source cp : Nat) (target : Array Nat)
    (hSourceNonWidth : WidthMapping.isWidthCompatSource source = false)
    (hLookup : lookupCaseFolding? source = some target) (hMem : cp ∈ target) :
    WidthMapping.isWidthCompatSource cp = false := by
  unfold lookupCaseFolding? at hLookup
  exact CaseFolding.lookup_target_non_width_of_source_non_width
    source cp target hSourceNonWidth hLookup hMem

/-- Structural lift: on any sequence whose codepoints are all
    non-width-compat-sources, the case-folded output is still all
    non-width-compat-sources. -/
theorem caseFold_output_non_widthCompatSource (cps : Array Nat)
    (hIn : ∀ cp ∈ cps, WidthMapping.isWidthCompatSource cp = false) :
    ∀ cp ∈ caseFold cps, WidthMapping.isWidthCompatSource cp = false := by
  intro cp hMem
  obtain ⟨x, hxInCps, hxF⟩ := mem_caseFold_iff cps cp hMem
  have hxNonWidth : WidthMapping.isWidthCompatSource x = false := hIn x hxInCps
  unfold caseFoldCodepoint at hxF
  cases hLook : lookupCaseFolding? x with
  | none =>
    -- caseFoldCodepoint x = #[x]; cp = x; x is already a non-width-source by hIn.
    rw [hLook] at hxF
    simp at hxF
    have hCpEqX : cp = x := hxF
    rw [hCpEqX]
    exact hxNonWidth
  | some tgt =>
    -- caseFoldCodepoint x = tgt. Since x is not a width source, the
    -- generated cross-table certificate says tgt has no width sources.
    rw [hLook] at hxF
    exact caseFold_preserves_non_widthCompatSource x cp tgt hxNonWidth hLook hxF


/-- Double case-fold on capital A equals single case-fold. -/
theorem caseFold_idempotent_A :
    caseFold (caseFold #[0x0041]) = caseFold #[0x0041] := by decide

/-- Double case-fold on sharp-s equals single case-fold. -/
theorem caseFold_idempotent_sharp_s :
    caseFold (caseFold #[0x00DF]) = caseFold #[0x00DF] := by decide

/-- Double case-fold on a mixed ASCII word equals single case-fold. -/
theorem caseFold_idempotent_ascii_word :
    caseFold (caseFold #[0x0041, 0x0062, 0x0043])
      = caseFold #[0x0041, 0x0062, 0x0043] := by decide

end Unicode.Precis.CaseMapping
