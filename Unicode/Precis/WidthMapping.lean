/-
  Unicode.Precis.WidthMapping

  The "Width Mapping Rule" of RFC
  8265 §5.2.3 for the UsernameCaseMapped / UsernameCasePreserved
  profiles built on PRECIS IdentifierClass.

  Per RFC 8265:

      Fullwidth and halfwidth characters MUST be mapped to their
      decomposition equivalents.

  The source of truth for that mapping is the Decomposition_Mapping
  field of UnicodeData.txt whenever the decomposition is tagged
  `<wide>` (a fullwidth codepoint mapping to its narrow equivalent)
  or `<narrow>` (a halfwidth codepoint mapping to its non-halfwidth
  equivalent). Those 226 mappings are pinned in
  `Unicode.Generated.WidthCompatMappings` by the UcdGen
  preprocessor; this module consumes them through the `widthMap`
  function below.

  Codepoints that do not carry a `<wide>` or `<narrow>` compatibility
  decomposition are not affected.
-/

import Unicode.Generated.WidthCompatMappings

namespace Unicode.Precis.WidthMapping

open Unicode.Generated

set_option maxRecDepth 100000

/-- Look up a codepoint's width-compat mapping target. Returns `some
    target` if the codepoint carries a `<wide>` or `<narrow>`
    compatibility decomposition per the pinned UCD tables, otherwise
    `none`. -/
def lookupWidthMapping? (cp : Nat) : Option (List Nat) :=
  WidthCompatMappings.lookup? cp

/-- Apply the width mapping to a single codepoint, substituting with
    its compat target if one exists, otherwise returning the
    codepoint unchanged (as a singleton sequence). -/
def widthMapCodepoint (cp : Nat) : List Nat :=
  match lookupWidthMapping? cp with
  | some target => target
  | none        => [cp]

/-- Apply the width mapping to a codepoint sequence, flattening each
    per-codepoint result back into a single sequence. -/
def widthMap (cps : List Nat) : List Nat :=
  cps.flatMap widthMapCodepoint

-- ═══════════════════════════════════════════════════════════════════════════════
-- TEST VECTORS
-- Anchored on RFC 8265 canonical examples plus ASCII identity to
-- exercise the no-match path. FULLWIDTH LATIN CAPITAL A (U+FF21)
-- maps to LATIN CAPITAL A (U+0041). IDEOGRAPHIC SPACE (U+3000) maps
-- to ASCII SPACE (U+0020). ASCII letters carry no `<wide>`/`<narrow>`
-- decomposition and are preserved.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- FULLWIDTH LATIN CAPITAL LETTER A maps to LATIN CAPITAL LETTER A. -/
theorem widthMap_fullwidth_A :
    widthMapCodepoint 0xFF21 = [0x0041] := by decide

/-- IDEOGRAPHIC SPACE maps to ASCII SPACE. -/
theorem widthMap_ideographic_space :
    widthMapCodepoint 0x3000 = [0x0020] := by decide

/-- HALFWIDTH KATAKANA LETTER A (U+FF71) maps to KATAKANA LETTER A (U+30A2). -/
theorem widthMap_halfwidth_katakana_a :
    widthMapCodepoint 0xFF71 = [0x30A2] := by decide

/-- ASCII letter has no width mapping. -/
theorem widthMap_ascii_a : widthMapCodepoint 0x0061 = [0x0061] := by decide

/-- The sequence-level mapping preserves pure-ASCII input. -/
theorem widthMap_ascii_identity :
    widthMap [0x0041, 0x0042, 0x0043] = [0x0041, 0x0042, 0x0043] := by decide

/-- Mixed input: a fullwidth A followed by ASCII B maps fullwidth A
    to plain A while leaving B unchanged. -/
theorem widthMap_mixed :
    widthMap [0xFF21, 0x0042] = [0x0041, 0x0042] := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- IDEMPOTENCE
--
-- `widthMap` is idempotent on every input. The structural reason:
-- every `<wide>`/`<narrow>` compat target in UCD 17.0 is itself absent
-- from the source column of `widthCompatMappings`, so the output of
-- `widthMap` is a sequence of codepoints on which
-- `lookupWidthMapping?` returns `none`, and `widthMap` of such a
-- sequence is the identity.
--
-- The generated lookup carries a certificate that every replacement
-- target is absent from the source set. The identity-on-miss half
-- lifts to `List` level via `widthMap_id_on_non_sources` by structural
-- induction on the input sequence.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Predicate: `cp` is a source codepoint of some `<wide>`/`<narrow>`
    compat decomposition, i.e. `lookupWidthMapping?` would return a
    `Some` value on it. -/
def isWidthCompatSource (cp : Nat) : Bool :=
  (lookupWidthMapping? cp).isSome

/-- A codepoint that is not a width-compat source has no
    `lookupWidthMapping?` result. -/
theorem lookupWidthMapping_none_of_non_source (cp : Nat)
    (h : isWidthCompatSource cp = false) :
    lookupWidthMapping? cp = none := by
  unfold isWidthCompatSource at h
  cases hLook : lookupWidthMapping? cp with
  | none => rfl
  | some target =>
      rw [hLook] at h
      exact Bool.noConfusion h

/-- A codepoint that is not a width-compat source maps to its own
    singleton under `widthMapCodepoint`. -/
theorem widthMapCodepoint_id_of_non_source (cp : Nat)
    (h : isWidthCompatSource cp = false) :
    widthMapCodepoint cp = [cp] := by
  unfold widthMapCodepoint
  rw [lookupWidthMapping_none_of_non_source cp h]

/-- Generic lift: on any `List Nat` whose codepoints each satisfy
    `f cp = [cp]`, the foldl-with-append pipeline is the identity. -/
theorem arr_foldl_map_id_of_all_identity (cps : List Nat)
    (f : Nat → List Nat) (hAll : ∀ cp ∈ cps, f cp = [cp]) :
    cps.foldl (fun acc cp => acc ++ f cp) [] = cps := by
  have key : ∀ (l : List Nat) (init : List Nat),
      (∀ cp ∈ l, f cp = [cp]) →
      l.foldl (fun acc cp => acc ++ f cp) init = init ++ l := by
    intro l
    induction l with
    | nil => intro init hH; simp
    | cons hd tl ih =>
      intro init hH
      have hHd : f hd = [hd] := hH hd (by simp)
      have hTl : ∀ cp ∈ tl, f cp = [cp] := fun cp hMem => hH cp (by simp [hMem])
      simp only [List.foldl_cons, hHd]
      rw [ih (init ++ [hd]) hTl]
      simp
  rw [key cps [] hAll]
  simp

/-- `widthMap` is the identity on any sequence whose codepoints are
    all non-sources. -/
theorem widthMap_id_of_all_non_source (cps : List Nat)
    (h : ∀ cp ∈ cps, isWidthCompatSource cp = false) :
    widthMap cps = cps := by
  unfold widthMap
  have key : ∀ (l : List Nat), (∀ cp ∈ l, widthMapCodepoint cp = [cp]) →
      l.flatMap widthMapCodepoint = l := by
    intro l
    induction l with
    | nil => intro _hH; simp
    | cons hd tl ih =>
      intro hH
      have hHd : widthMapCodepoint hd = [hd] := hH hd (by simp)
      have hTl : ∀ cp ∈ tl, widthMapCodepoint cp = [cp] :=
        fun cp hMem => hH cp (by simp [hMem])
      simp [hHd, ih hTl]
  rw [key cps (fun cp hMem =>
        widthMapCodepoint_id_of_non_source cp (h cp hMem))]

/-- Converse of `lookupWidthMapping_none_of_non_source`: a codepoint
    with no `lookupWidthMapping?` result is not a source. -/
theorem non_source_of_lookupWidthMapping_none (cp : Nat)
    (h : lookupWidthMapping? cp = none) :
    isWidthCompatSource cp = false := by
  unfold isWidthCompatSource
  rw [h]
  rfl

/-- Membership decomposition: a codepoint in `widthMap cps` comes
    from `widthMapCodepoint x` for some `x ∈ cps`. -/
theorem mem_widthMap_iff (cps : List Nat) (cp : Nat)
    (hMem : cp ∈ widthMap cps) :
    ∃ x ∈ cps, cp ∈ widthMapCodepoint x := by
  unfold widthMap at hMem
  simp only [List.mem_flatMap] at hMem
  obtain ⟨x, hxM, hxF⟩ := hMem
  exact ⟨x, hxM, by simpa using hxF⟩

/-- Every codepoint in the output of `widthMap` is a non-source:
    - sources in the input are replaced by certified non-source targets;
    - non-sources in the input are preserved as themselves.
-/
theorem widthMap_output_all_non_source (cps : List Nat) :
    ∀ cp ∈ widthMap cps, isWidthCompatSource cp = false := by
  intro cp hMem
  obtain ⟨x, hxInCps, hxF⟩ := mem_widthMap_iff cps cp hMem
  clear hxInCps
  unfold widthMapCodepoint at hxF
  -- Split on whether `x` has a lookup or not.
  cases hLook : lookupWidthMapping? x with
  | none =>
    -- widthMapCodepoint x reduces to [x]; cp ∈ [x] forces cp = x, which is a non-source.
    rw [hLook] at hxF
    simp at hxF
    have hCpEqX : cp = x := hxF
    rw [hCpEqX]
    exact non_source_of_lookupWidthMapping_none x hLook
  | some tgt =>
    -- widthMapCodepoint x reduces to tgt; cp ∈ tgt; lookup certificates
    -- prove every target codepoint is a non-source.
    rw [hLook] at hxF
    unfold lookupWidthMapping? at hLook
    have hGeneratedSource :
        WidthCompatMappings.isSource cp = false :=
      WidthCompatMappings.lookup_target_non_source x tgt cp hLook hxF
    have hTargetLookup :
        lookupWidthMapping? cp = none := by
      unfold lookupWidthMapping?
      exact WidthCompatMappings.lookup_none_of_non_source cp hGeneratedSource
    exact non_source_of_lookupWidthMapping_none cp hTargetLookup

/-- **`widthMap` is idempotent.** For every codepoint sequence,
    applying the RFC 8265 §5.2.3 width mapping twice produces the
    same result as applying it once. The proof chains:

    - `widthMap cps` produces codepoints all absent from the source
      column of `widthCompatMappings` by generated lookup certificates;
    - `widthMap` is the identity on such a sequence (by
      `widthMap_id_of_all_non_source`).
-/
theorem widthMap_idempotent (cps : List Nat) :
    widthMap (widthMap cps) = widthMap cps :=
  widthMap_id_of_all_non_source (widthMap cps) (widthMap_output_all_non_source cps)

/-- Double width-map on fullwidth A equals single width-map. -/
theorem widthMap_idempotent_fullwidth_A :
    widthMap (widthMap [0xFF21]) = widthMap [0xFF21] := by decide

/-- Double width-map on halfwidth katakana equals single width-map. -/
theorem widthMap_idempotent_halfwidth_katakana_a :
    widthMap (widthMap [0xFF71]) = widthMap [0xFF71] := by decide

/-- Double width-map on ASCII equals single width-map (trivially). -/
theorem widthMap_idempotent_ascii :
    widthMap (widthMap [0x0041, 0x0042]) = widthMap [0x0041, 0x0042] := by decide

end Unicode.Precis.WidthMapping
