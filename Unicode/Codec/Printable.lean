/-
  Unicode.Codec.Printable

  Tier-2 text predicate for human-readable content. Every byte
  passes four checks in order:

    1. Structural UTF-8 validity (rejects overlong, surrogate,
       beyond-max, truncated, and bare-continuation sequences).
    2. No C0 control byte except HT (U+0009) and LF (U+000A), and
       no DEL (U+007F). CR (U+000D) is rejected; callers ingesting
       Windows-origin content normalise CRLF upstream.
    3. No forbidden codepoint. Two tiers:
         * Narrow CVE-flagged blocklist — bidi overrides
           (U+202A..U+202E), bidi isolates (U+2066..U+2069),
           zero-widths (U+200B..U+200F), BOM (U+FEFF), tag
           characters (U+E0000..U+E007F), variation selectors
           (U+FE00..U+FE0F and U+E0100..U+E01EF), Hangul fillers
           (U+FFA0, U+3164), soft hyphen (U+00AD), interlinear
           annotation controls (U+FFF9..U+FFFB), Mongolian vowel
           separator (U+180E).
         * Default_Ignorable_Code_Point residual — every codepoint
           flagged `Default_Ignorable_Code_Point` by UCD 17.0 that
           is not already covered by the narrow tier.
    4. Content is in Unicode Normalization Form C. Non-NFC input
       is rejected, never silently normalised — silent normalisation
       would mask the fact that the source was malformed.

  Three layers exposed:

    * `isPrintableUtf8Bytes` — Boolean validity predicate.
    * `PrintableUtf8 maxBytes` — refinement type.
    * `PrintableUtf8.ofBytes?` — smart constructor.

  Strict-cohesion (StrictBox + RejectReason) and any wire-format
  framing are downstream concerns; this module owns only the
  specification predicate, the categorical classification, the
  refinement type, and the constructor.
-/

import Unicode.Codec.Strict
import Unicode.Codec.Utf8
import Unicode.Generated.DerivedCoreProperties
import Unicode.Normalization.Utf8Bridge
import Unicode.Normalization.LowCodepointNfc

namespace Unicode.Codec.Printable

open Unicode.Codec.Strict (ForbiddenCategory)
open Unicode.Codec.Utf8 (firstInvalidUtf8Offset foldCodepointsWithOffset)
open Unicode.Generated
open Unicode.Normalization

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 CONTROL-BYTE PREDICATE
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A byte is "forbidden control" if it is a C0 control other than
    HT (U+0009) and LF (U+000A), or if it is DEL (U+007F). CR
    (U+000D) falls under C0 and is rejected; callers should
    normalise CRLF upstream when ingesting Windows-origin content. -/
def isForbiddenControlByte (b : UInt8) : Bool :=
  decide ((b.toNat < 0x20 ∧ b.toNat ≠ 0x09 ∧ b.toNat ≠ 0x0A) ∨ b.toNat = 0x7F)

theorem isForbiddenControlByte_NUL : isForbiddenControlByte 0x00 = true := by decide
theorem isForbiddenControlByte_HT  : isForbiddenControlByte 0x09 = false := by decide
theorem isForbiddenControlByte_LF  : isForbiddenControlByte 0x0A = false := by decide
theorem isForbiddenControlByte_CR  : isForbiddenControlByte 0x0D = true := by decide
theorem isForbiddenControlByte_DEL : isForbiddenControlByte 0x7F = true := by decide
theorem isForbiddenControlByte_A   : isForbiddenControlByte 0x41 = false := by decide
theorem isForbiddenControlByte_hi  : isForbiddenControlByte 0xFF = false := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 FORBIDDEN-CONTROL WALKER
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Byte offset + offending byte of the first forbidden control byte
    in `bs`, or `none` if none is present. -/
def firstForbiddenControlFrom (bs : List UInt8) (i : Nat) : Option (Nat × UInt8) :=
  if hi : i < bs.length then
    let b := bs[i]'hi
    if isForbiddenControlByte b then some (i, b)
    else firstForbiddenControlFrom bs (i + 1)
  else none
termination_by bs.length - i

def firstForbiddenControl (bs : List UInt8) : Option (Nat × UInt8) :=
  firstForbiddenControlFrom bs 0

/-- The forbidden-control walker returns `none` exactly when no byte is a forbidden
    control. Proven by well-founded recursion mirroring `firstForbiddenControlFrom`;
    that recursion does not reduce definitionally, so the fact is established
    structurally rather than by evaluation. -/
theorem firstForbiddenControlFrom_none (bs : List UInt8) (i : Nat)
    (h : ∀ (j : Nat) (hj : j < bs.length), isForbiddenControlByte (bs[j]'hj) = false) :
    firstForbiddenControlFrom bs i = none := by
  unfold firstForbiddenControlFrom
  split
  · next hi =>
    rw [if_neg (by rw [h i hi]; simp)]
    exact firstForbiddenControlFrom_none bs (i + 1) h
  · rfl
termination_by bs.length - i

theorem firstForbiddenControl_none (bs : List UInt8)
    (h : ∀ (j : Nat) (hj : j < bs.length), isForbiddenControlByte (bs[j]'hj) = false) :
    firstForbiddenControl bs = none :=
  firstForbiddenControlFrom_none bs 0 h

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 FORBIDDEN-CODEPOINT CLASSIFICATION
-- ═══════════════════════════════════════════════════════════════════════════════

-- The categorical label for the curated CVE-flagged blocklist is
-- `Unicode.Codec.Strict.ForbiddenCategory`. It is shared with every
-- strict text codec under `Unicode.Codec.*` so reject paths agree on a
-- single vocabulary; the `open Unicode.Codec.Strict (ForbiddenCategory)`
-- above pulls it into the local namespace.

/-- Outcome of classifying a codepoint against the printable-text
    rejection rules. Two tiers: `narrow` for the curated CVE-flagged
    list (carries the specific category), `defaultIgnorable` for the
    UCD 17.0 `Default_Ignorable_Code_Point` residual. -/
inductive ForbiddenClassification where
  | narrow (category : ForbiddenCategory)
  | defaultIgnorable
  deriving Repr, DecidableEq, Inhabited

/-- `Default_Ignorable_Code_Point` membership per UCD 17.0. The
    narrow categories below are all DICP-subsets; this predicate is
    consulted AFTER the narrow list so the narrow tier always wins
    on overlapping codepoints. -/
def isDefaultIgnorableCodepoint (cp : Nat) : Bool :=
  DerivedCoreProperties.defaultIgnorable.any
    (fun lh => decide (lh.fst ≤ cp ∧ cp ≤ lh.snd))

/-- Classify a codepoint against the printable-text rejection rules.
    Returns `some (.narrow cat)` for a CVE-flagged class,
    `some .defaultIgnorable` for a DICP residual, `none` otherwise.

    Order is load-bearing: the narrow categories are checked first
    so the most specific category wins; DICP catches everything else
    flagged `Default_Ignorable_Code_Point`. -/
def classifyCodepointIfForbidden (cp : Nat) : Option ForbiddenClassification :=
  if 0x202A ≤ cp ∧ cp ≤ 0x202E then some (.narrow .bidiOverride)
  else if 0x2066 ≤ cp ∧ cp ≤ 0x2069 then some (.narrow .bidiIsolate)
  else if 0x200B ≤ cp ∧ cp ≤ 0x200F then some (.narrow .zeroWidth)
  else if cp = 0xFEFF then some (.narrow .bom)
  else if 0xE0000 ≤ cp ∧ cp ≤ 0xE007F then some (.narrow .tagCharacter)
  else if (0xFE00 ≤ cp ∧ cp ≤ 0xFE0F) ∨ (0xE0100 ≤ cp ∧ cp ≤ 0xE01EF)
    then some (.narrow .variationSelector)
  else if cp = 0xFFA0 ∨ cp = 0x3164 then some (.narrow .hangulFiller)
  else if cp = 0x00AD then some (.narrow .softHyphen)
  else if 0xFFF9 ≤ cp ∧ cp ≤ 0xFFFB then some (.narrow .interlinearAnnotation)
  else if cp = 0x180E then some (.narrow .mongolianVowelSeparator)
  else if isDefaultIgnorableCodepoint cp then some .defaultIgnorable
  else none

/-- Predicate form derived from `classifyCodepointIfForbidden`. -/
def isForbiddenCodepoint (cp : Nat) : Bool :=
  (classifyCodepointIfForbidden cp).isSome

theorem classify_U202E :
    classifyCodepointIfForbidden 0x202E = some (.narrow .bidiOverride) := by decide
theorem classify_U2067 :
    classifyCodepointIfForbidden 0x2067 = some (.narrow .bidiIsolate) := by decide
theorem classify_U200B :
    classifyCodepointIfForbidden 0x200B = some (.narrow .zeroWidth) := by decide
theorem classify_UFEFF :
    classifyCodepointIfForbidden 0xFEFF = some (.narrow .bom) := by decide
theorem classify_UE0041 :
    classifyCodepointIfForbidden 0xE0041 = some (.narrow .tagCharacter) := by decide
theorem classify_UFE00 :
    classifyCodepointIfForbidden 0xFE00 = some (.narrow .variationSelector) := by decide
theorem classify_U3164 :
    classifyCodepointIfForbidden 0x3164 = some (.narrow .hangulFiller) := by decide
theorem classify_U00AD :
    classifyCodepointIfForbidden 0x00AD = some (.narrow .softHyphen) := by decide
theorem classify_UFFF9 :
    classifyCodepointIfForbidden 0xFFF9 = some (.narrow .interlinearAnnotation) := by
  decide
theorem classify_U180E :
    classifyCodepointIfForbidden 0x180E = some (.narrow .mongolianVowelSeparator) := by
  decide

/-- COMBINING GRAPHEME JOINER U+034F is DICP but not in any narrow
    category — exercises the `defaultIgnorable` residual tier. -/
theorem classify_U034F_dicp :
    classifyCodepointIfForbidden 0x034F = some .defaultIgnorable := by decide

/-- WORD JOINER U+2060 is DICP but not in any narrow category. -/
theorem classify_U2060_dicp :
    classifyCodepointIfForbidden 0x2060 = some .defaultIgnorable := by decide

theorem classify_hello_letter_none :
    classifyCodepointIfForbidden 0x68 = none := by decide
theorem classify_digit_none :
    classifyCodepointIfForbidden 0x30 = none := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 CLASSIFIED-FORBIDDEN WALKER
-- Returns offset + codepoint + classification together so a strict
-- variant never needs a second-pass classification lookup.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- First forbidden codepoint in `bs`, bundled with its
    `ForbiddenClassification`. Returns `some (offset, cp, class)`
    at the first forbidden codepoint encountered, or `none` when
    the content has no forbidden codepoints. -/
def firstForbiddenCodepointClassified (bs : List UInt8) :
    Option (Nat × Nat × ForbiddenClassification) :=
  foldCodepointsWithOffset bs (Option.none : Option (Nat × Nat × ForbiddenClassification))
    (fun acc off cp =>
      match acc with
      | some r => some r
      | none   => match classifyCodepointIfForbidden cp with
                  | some kind => some (off, cp, kind)
                  | none      => none)

/-- The UTF-8 bytes of "hello" contain no forbidden codepoint. -/
theorem firstForbidden_hello_none :
    firstForbiddenCodepointClassified ([0x68, 0x65, 0x6C, 0x6C, 0x6F] : List UInt8)
      = none := by decide

theorem firstForbidden_bidi :
    firstForbiddenCodepointClassified ([0x61, 0xE2, 0x80, 0xAE, 0x62])
      = some (1, 0x202E, .narrow .bidiOverride) := by decide

theorem firstForbidden_bom :
    firstForbiddenCodepointClassified ([0xEF, 0xBB, 0xBF])
      = some (0, 0xFEFF, .narrow .bom) := by decide

theorem firstForbidden_cgj :
    firstForbiddenCodepointClassified ([0xCD, 0x8F])
      = some (0, 0x034F, .defaultIgnorable) := by decide

theorem firstForbidden_word_joiner :
    firstForbiddenCodepointClassified ([0xE2, 0x81, 0xA0])
      = some (0, 0x2060, .defaultIgnorable) := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 AGGREGATE PRINTABLE PREDICATE
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The full printable-text predicate: four checks ANDed.

    Defined via the structural walkers' `.isNone` plus `isNFCBytes`
    rather than `bs.all`-style traversals, so any downstream
    offset-tracking variant remains by-definition consistent.

    The NFC stage runs last because only it depends on the holistic
    sequence rather than a per-byte or per-codepoint signal; the
    three earlier stages' cheaper rejections short-circuit its
    evaluation on invalid or forbidden inputs. -/
def isPrintableUtf8Bytes (bs : List UInt8) : Bool :=
  (firstInvalidUtf8Offset bs).isNone
    && (firstForbiddenControl bs).isNone
    && (firstForbiddenCodepointClassified bs).isNone
    && Utf8Bridge.isNFCBytes bs

/-- Byte-level NFC holds whenever the content decodes to code points that are all
    below U+00C0 and re-encodes to itself: those code points are NFC-fixed by
    `LowCodepointNfc.toNFC_id_all_lt`, so the pipeline is the identity. -/
theorem isNFCBytes_of_lt (bs : List UInt8) (cps : List Nat)
    (hv : Unicode.Codec.Utf8.isValidUtf8 bs = true)
    (hd : Unicode.Normalization.Utf8Bridge.decodeToCodepoints bs = cps)
    (he : Unicode.Normalization.Utf8Bridge.encodeCodepoints cps = bs)
    (hlt : ∀ cp ∈ cps, cp < 0xC0) :
    Unicode.Normalization.Utf8Bridge.isNFCBytes bs = true := by
  unfold Unicode.Normalization.Utf8Bridge.isNFCBytes Unicode.Normalization.Utf8Bridge.toNFCBytes
  simp [hv, hd, he, Unicode.Normalization.LowCodepointNfc.toNFC_id_all_lt cps hlt]

/-- Acceptance from the four stages: valid UTF-8, no forbidden control, no forbidden
    code point, and NFC form. -/
theorem printable_true_of (bs : List UInt8)
    (hv : (firstInvalidUtf8Offset bs).isNone = true)
    (hc : firstForbiddenControl bs = none)
    (hf : (firstForbiddenCodepointClassified bs).isNone = true)
    (hn : Unicode.Normalization.Utf8Bridge.isNFCBytes bs = true) :
    isPrintableUtf8Bytes bs = true := by
  unfold isPrintableUtf8Bytes
  rw [hc]
  simp [hv, hf, hn]

-- ═══════════════════════════════════════════════════════════════════════════════
-- The precomposed "é" composition, for the two vectors that exercise it. `é`
-- (U+00E9) decomposes to `e` + combining acute (U+0301) and recomposes; this is the
-- one canonical composition the printable vectors touch, established structurally
-- via the composition-pairs table rather than by reducing it whole.
-- ═══════════════════════════════════════════════════════════════════════════════

theorem primaryComposite_e_acute : Compose.primaryComposite? 0x65 0x301 = some 0xE9 :=
  Compose.primaryComposite?_some_of_pair 0x65 0x301 0xE9 (by decide)
    (by unfold CanonicalComposition.compositionPairs; decide +kernel)
    (by unfold CanonicalComposition.compositionPairs; decide +kernel)

theorem stepCompose_init_e : Compose.stepCompose Compose.initialState 0x65
    = { emitted := [], starter := some 0x65, buffer := [], maxCCC := 0 } := by
  rw [Compose.stepCompose.eq_def]
  simp [Compose.initialState, LowCodepointNfc.cccz 0x65 (by decide)]

theorem stepCompose_e_acute : Compose.stepCompose
    { emitted := [], starter := some 0x65, buffer := [], maxCCC := 0 } 0x301
    = { emitted := [], starter := some 0xE9, buffer := [], maxCCC := 0 } := by
  rw [Compose.stepCompose.eq_def]
  simp [Reorder.ccc_combining_acute, primaryComposite_e_acute]

theorem compose_e_acute : Compose.compose [0x65, 0x301] = [0xE9] := by
  rewrite [Compose.compose.eq_def,
           List.foldl_cons, List.foldl_cons, List.foldl_nil, stepCompose_init_e,
           stepCompose_e_acute]
  rfl

theorem canonicalDecomposition_acute : Lookup.canonicalDecomposition 0x301 = [] :=
  Lookup.canonicalDecomposition_of_hit 0x301 []
    (by unfold UnicodeData.rowsList; simp only [List.any_append]; decide +kernel)
    (by unfold UnicodeData.rowsList; simp only [List.all_append]; decide +kernel)

theorem isFullyDecomposed_e_acute :
    Unicode.Invariants.IsFullyDecomposed [0x65, 0x301] := by
  intro cp hMem; simp at hMem
  rcases hMem with rfl | rfl
  · exact ⟨LowCodepointNfc.dec_lt 0x65 (by decide), by decide⟩
  · exact ⟨canonicalDecomposition_acute, by decide⟩

theorem hasSortedRuns_e_acute : Reorder.HasSortedRuns [0x65, 0x301] := by
  simp [Reorder.HasSortedRuns, LowCodepointNfc.cccz 0x65 (by decide),
        Reorder.ccc_combining_acute]

theorem toNFC_e_acute : NFC.toNFC [0x65, 0x301] = [0xE9] := by
  unfold NFC.toNFC NFC.toNFD
  rw [NFD.decomposeSequence_id_on_FullyDecomposed [0x65, 0x301] isFullyDecomposed_e_acute,
      Reorder.reorder_id_on_HasSortedRuns [0x65, 0x301] hasSortedRuns_e_acute,
      compose_e_acute]

-- ═══════════════════════════════════════════════════════════════════════════════
-- "héllo" round-trips through NFC: the precomposed é (U+00E9) decomposes to
-- e + combining acute, reorders (identity — already canonically ordered), then
-- recomposes to é. The compose stage is a six-step shift/compose fold; the
-- decompose stage expands é and leaves h/l/o terminal.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A compose step on a starter that does not compose with the active starter:
    emit the active starter, hold the new one. -/
theorem stepCompose_shift (em : List Nat) (s c : Nat)
    (hc : Lookup.canonicalCombiningClass c = 0)
    (hpc : Compose.primaryComposite? s c = none) :
    Compose.stepCompose { emitted := em, starter := some s, buffer := [], maxCCC := 0 } c
      = { emitted := em ++ [s], starter := some c, buffer := [], maxCCC := 0 } := by
  rw [Compose.stepCompose.eq_def]
  simp [hc, hpc]

/-- The e + combining acute compose step, from any emitted prefix. -/
theorem stepCompose_e_acute_gen (em : List Nat) :
    Compose.stepCompose { emitted := em, starter := some 0x65, buffer := [], maxCCC := 0 } 0x301
      = { emitted := em, starter := some 0xE9, buffer := [], maxCCC := 0 } := by
  rw [Compose.stepCompose.eq_def]
  simp [Reorder.ccc_combining_acute, primaryComposite_e_acute]

theorem stepCompose_init_h : Compose.stepCompose Compose.initialState 0x68
    = { emitted := [], starter := some 0x68, buffer := [], maxCCC := 0 } := by
  rw [Compose.stepCompose.eq_def]
  simp [Compose.initialState, LowCodepointNfc.cccz 0x68 (by decide)]

theorem compose_héllo :
    Compose.compose [0x68, 0x65, 0x301, 0x6C, 0x6C, 0x6F] = [0x68, 0xE9, 0x6C, 0x6C, 0x6F] := by
  rewrite [Compose.compose.eq_def,
           List.foldl_cons, List.foldl_cons, List.foldl_cons, List.foldl_cons,
           List.foldl_cons, List.foldl_cons, List.foldl_nil, stepCompose_init_h,
           stepCompose_shift [] 0x68 0x65 (LowCodepointNfc.cccz 0x65 (by decide))
             (LowCodepointNfc.nc_lt 0x68 0x65 (by decide)
               (LowCodepointNfc.hang_none_lt 0x68 0x65 (by decide))),
           stepCompose_e_acute_gen ([] ++ [0x68]),
           stepCompose_shift ([] ++ [0x68]) 0xE9 0x6C (LowCodepointNfc.cccz 0x6C (by decide))
             (LowCodepointNfc.nc_lt 0xE9 0x6C (by decide) (by decide)),
           stepCompose_shift (([] ++ [0x68]) ++ [0xE9]) 0x6C 0x6C
             (LowCodepointNfc.cccz 0x6C (by decide))
             (LowCodepointNfc.nc_lt 0x6C 0x6C (by decide)
               (LowCodepointNfc.hang_none_lt 0x6C 0x6C (by decide))),
           stepCompose_shift ((([] ++ [0x68]) ++ [0xE9]) ++ [0x6C]) 0x6C 0x6F
             (LowCodepointNfc.cccz 0x6F (by decide))
             (LowCodepointNfc.nc_lt 0x6C 0x6F (by decide)
               (LowCodepointNfc.hang_none_lt 0x6C 0x6F (by decide)))]
  rfl

theorem canonicalDecomposition_eacute : Lookup.canonicalDecomposition 0xE9 = [0x65, 0x301] :=
  Lookup.canonicalDecomposition_of_hit 0xE9 [0x65, 0x301]
    (by unfold UnicodeData.rowsList; simp only [List.any_append]; decide +kernel)
    (by unfold UnicodeData.rowsList; simp only [List.all_append]; decide +kernel)

theorem fcdf_acute (fuel : Nat) :
    Decompose.fullCanonicalDecomposeFuel (fuel + 1) 0x0301 = [0x0301] := by
  rw [Decompose.fullCanonicalDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_acute]

theorem fcdf_eacute (fuel : Nat) :
    Decompose.fullCanonicalDecomposeFuel (fuel + 2) 0x00E9 = [0x0065, 0x0301] := by
  rw [Decompose.fullCanonicalDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_eacute, Decompose.fcdf_latin_e, fcdf_acute]

theorem decomposeSequence_héllo :
    Decompose.decomposeSequence [0x68, 0xE9, 0x6C, 0x6C, 0x6F]
      = [0x68, 0x65, 0x301, 0x6C, 0x6C, 0x6F] := by
  simp [Decompose.decomposeSequence, Decompose.fullCanonicalDecompose, Decompose.maxDepth,
        Decompose.fcdf_latin_h 31, fcdf_eacute 30, Decompose.fcdf_latin_l 31,
        Decompose.fcdf_latin_o 31]

theorem hasSortedRuns_decomposed_héllo :
    Reorder.HasSortedRuns [0x68, 0x65, 0x301, 0x6C, 0x6C, 0x6F] := by
  simp [Reorder.HasSortedRuns, LowCodepointNfc.cccz 0x68 (by decide),
        LowCodepointNfc.cccz 0x65 (by decide), Reorder.ccc_combining_acute,
        LowCodepointNfc.cccz 0x6C (by decide), LowCodepointNfc.cccz 0x6F (by decide)]

theorem toNFC_héllo :
    NFC.toNFC [0x68, 0xE9, 0x6C, 0x6C, 0x6F] = [0x68, 0xE9, 0x6C, 0x6C, 0x6F] := by
  unfold NFC.toNFC NFC.toNFD
  rw [decomposeSequence_héllo,
      Reorder.reorder_id_on_HasSortedRuns [0x68, 0x65, 0x301, 0x6C, 0x6C, 0x6F]
        hasSortedRuns_decomposed_héllo,
      compose_héllo]

theorem empty_is_printable :
    isPrintableUtf8Bytes ([] : List UInt8) = true :=
  printable_true_of ([] : List UInt8) (by decide)
    (firstForbiddenControl_none ([] : List UInt8) (by decide)) (by decide)
    (isNFCBytes_of_lt ([] : List UInt8) [] (by decide) (by decide) (by decide)
      (by intro cp hMem; simp at hMem))

/-- The UTF-8 bytes of "hello" are printable. -/
theorem hello_is_printable :
    isPrintableUtf8Bytes ([0x68, 0x65, 0x6C, 0x6C, 0x6F] : List UInt8) = true :=
  printable_true_of ([0x68, 0x65, 0x6C, 0x6C, 0x6F] : List UInt8) (by decide)
    (firstForbiddenControl_none ([0x68, 0x65, 0x6C, 0x6C, 0x6F] : List UInt8) (by decide))
    (by decide)
    (isNFCBytes_of_lt ([0x68, 0x65, 0x6C, 0x6C, 0x6F] : List UInt8) [0x68, 0x65, 0x6C, 0x6C, 0x6F]
      (by decide) (by decide) (by decide)
      (by intro cp hMem; simp at hMem; rcases hMem with rfl|rfl|rfl|rfl|rfl <;> decide))

/-- The UTF-8 bytes of "hello\nworld" are printable: newline is a permitted
    control, not a forbidden one. -/
theorem hello_nl_is_printable :
    isPrintableUtf8Bytes
        ([0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x0A, 0x77, 0x6F, 0x72, 0x6C, 0x64] : List UInt8)
      = true :=
  printable_true_of
    ([0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x0A, 0x77, 0x6F, 0x72, 0x6C, 0x64] : List UInt8) (by decide)
    (firstForbiddenControl_none
      ([0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x0A, 0x77, 0x6F, 0x72, 0x6C, 0x64] : List UInt8) (by decide))
    (by decide)
    (isNFCBytes_of_lt
      ([0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x0A, 0x77, 0x6F, 0x72, 0x6C, 0x64] : List UInt8)
      [0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x0A, 0x77, 0x6F, 0x72, 0x6C, 0x64]
      (by decide) (by decide) (by decide)
      (by intro cp hMem; simp at hMem
          rcases hMem with rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl <;> decide))

/-- The UTF-8 bytes of "héllo" (é = U+00E9 → 0xC3 0xA9) are printable: the
    accented form is already in NFC, so the NFC-stability gate passes. -/
theorem accented_is_printable :
    isPrintableUtf8Bytes ([0x68, 0xC3, 0xA9, 0x6C, 0x6C, 0x6F] : List UInt8) = true := by
  have hn : Unicode.Normalization.Utf8Bridge.isNFCBytes
      ([0x68, 0xC3, 0xA9, 0x6C, 0x6C, 0x6F] : List UInt8) = true := by
    have hv : Unicode.Codec.Utf8.isValidUtf8
        ([0x68, 0xC3, 0xA9, 0x6C, 0x6C, 0x6F] : List UInt8) = true := by decide
    have hd : Unicode.Normalization.Utf8Bridge.decodeToCodepoints
        ([0x68, 0xC3, 0xA9, 0x6C, 0x6C, 0x6F] : List UInt8)
        = [0x68, 0xE9, 0x6C, 0x6C, 0x6F] := by decide
    have he : Unicode.Normalization.Utf8Bridge.encodeCodepoints [0x68, 0xE9, 0x6C, 0x6C, 0x6F]
        = ([0x68, 0xC3, 0xA9, 0x6C, 0x6C, 0x6F] : List UInt8) := by decide
    unfold Unicode.Normalization.Utf8Bridge.isNFCBytes Unicode.Normalization.Utf8Bridge.toNFCBytes
    simp [hv, hd, toNFC_héllo, he]
  exact printable_true_of ([0x68, 0xC3, 0xA9, 0x6C, 0x6C, 0x6F] : List UInt8) (by decide)
    (firstForbiddenControl_none ([0x68, 0xC3, 0xA9, 0x6C, 0x6C, 0x6F] : List UInt8) (by decide))
    (by decide) hn

theorem control_NUL_not_printable :
    isPrintableUtf8Bytes ([0x00]) = false := by
  unfold isPrintableUtf8Bytes
  rw [show firstForbiddenControl ([0x00]) = some (0, 0) from by
        unfold firstForbiddenControl firstForbiddenControlFrom; decide]
  simp

theorem control_CR_not_printable :
    isPrintableUtf8Bytes ([0x0D]) = false := by
  unfold isPrintableUtf8Bytes
  rw [show firstForbiddenControl ([0x0D]) = some (0, 0x0D) from by
        unfold firstForbiddenControl firstForbiddenControlFrom; decide]
  simp

theorem bidi_override_not_printable :
    isPrintableUtf8Bytes ([0xE2, 0x80, 0xAE]) = false := by
  unfold isPrintableUtf8Bytes
  rw [firstForbiddenControl_none ([0xE2, 0x80, 0xAE]) (by decide)]
  simp only [Option.isNone_none]
  decide

theorem bom_not_printable :
    isPrintableUtf8Bytes ([0xEF, 0xBB, 0xBF]) = false := by
  unfold isPrintableUtf8Bytes
  rw [firstForbiddenControl_none ([0xEF, 0xBB, 0xBF]) (by decide)]
  simp only [Option.isNone_none]
  decide

theorem dicp_cgj_not_printable :
    isPrintableUtf8Bytes ([0xCD, 0x8F]) = false := by
  unfold isPrintableUtf8Bytes
  rw [firstForbiddenControl_none ([0xCD, 0x8F]) (by decide)]
  simp only [Option.isNone_none]
  decide

/-- Decomposed "e + combining acute" is valid UTF-8 with no forbidden
    codepoints, but it is not in NFC — the precomposed "é" is the NFC
    form. The aggregate predicate rejects. -/
theorem non_nfc_decomposed_e_not_printable :
    isPrintableUtf8Bytes ([0x65, 0xCC, 0x81]) = false := by
  have hn : Unicode.Normalization.Utf8Bridge.isNFCBytes ([0x65, 0xCC, 0x81]) = false := by
    unfold Unicode.Normalization.Utf8Bridge.isNFCBytes Unicode.Normalization.Utf8Bridge.toNFCBytes
    rw [show Unicode.Codec.Utf8.isValidUtf8 ([0x65, 0xCC, 0x81]) = true from by decide,
        show Unicode.Normalization.Utf8Bridge.decodeToCodepoints ([0x65, 0xCC, 0x81])
               = [0x65, 0x301] from by decide,
        toNFC_e_acute,
        show Unicode.Normalization.Utf8Bridge.encodeCodepoints [0xE9]
               = [0xC3, 0xA9] from by decide]
    decide
  unfold isPrintableUtf8Bytes
  rw [firstForbiddenControl_none ([0x65, 0xCC, 0x81]) (by decide), hn]
  simp

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 REFINEMENT TYPE
-- ═══════════════════════════════════════════════════════════════════════════════

structure PrintableUtf8 (maxBytes : Nat) where
  bytes     : List UInt8
  sizeOk    : bytes.length ≤ maxBytes
  printable : isPrintableUtf8Bytes bytes = true

instance (maxBytes : Nat) : DecidableEq (PrintableUtf8 maxBytes) := fun a b =>
  if h : a.bytes = b.bytes then
    isTrue (by cases a; cases b; simp only [PrintableUtf8.mk.injEq]; exact h)
  else
    isFalse (fun heq => h (by rw [heq]))

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 CONSTRUCTION
-- ═══════════════════════════════════════════════════════════════════════════════

def PrintableUtf8.ofBytes? (maxBytes : Nat) (bs : List UInt8) :
    Option (PrintableUtf8 maxBytes) :=
  if hSize : bs.length ≤ maxBytes then
    if hPrint : isPrintableUtf8Bytes bs = true then
      some ⟨bs, hSize, hPrint⟩
    else none
  else none

theorem PrintableUtf8.ofBytes?_self {maxBytes : Nat} (r : PrintableUtf8 maxBytes) :
    PrintableUtf8.ofBytes? maxBytes r.bytes = some r := by
  cases r with
  | mk bytes sizeOk printable =>
    unfold ofBytes?
    simp [sizeOk, printable]

end Unicode.Codec.Printable
