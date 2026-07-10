/-
  Unicode.Normalization.CompatDecompose

  Recursive compatibility decomposition per UAX #15 §1.3 (NFKD). For
  each codepoint, applies BOTH canonical and compatibility mappings
  recursively until a fixed point:

    * Hangul precomposed syllables decompose algorithmically to their
      L/V(/T) jamo.
    * If the codepoint has a canonical decomposition (UnicodeData
      column 5, no `<tag>` prefix), recurse on each target.
    * Else if the codepoint has a compatibility decomposition
      (UnicodeData column 5, with a `<tag>` prefix), recurse on each
      target.
    * Else the codepoint is its own decomposition.

  Parallel to `Unicode.Normalization.Decompose` but consults both
  decomposition tables. The `compatDecomposition` lookup goes
  through `Unicode.Generated.CompatDecomp`, which holds the rows whose
  source UnicodeData entry was tagged.

  Recursion is fuel-bounded for trivial termination. UAX #15 guarantees
  no decomposition cycles and bounded chain depth (in practice ≤ 4 for
  every Unicode release to date); the fuel constant leaves a wide margin.
-/

import Unicode.Normalization.Lookup
import Unicode.Normalization.Hangul
import Unicode.Normalization.Decompose
import Unicode.Generated.CompatDecomp

namespace Unicode.Normalization.CompatDecompose

open Unicode.Normalization
open Unicode.Generated

set_option maxRecDepth 100000

/-- Find the `CompatDecompRow` for a codepoint, if one is present in the
    pinned compat-decomp subset. Returns `none` for codepoints that have
    no compatibility decomposition (the vast majority). -/
def compatRow? (cp : Nat) : Option CompatDecomp.CompatDecompRow :=
  CompatDecomp.lookup? cp

/-- Compatibility decomposition target sequence, or `#[]` when the
    codepoint has no compatibility decomposition. -/
def compatDecomposition (cp : Nat) : Array Nat :=
  match compatRow? cp with
  | some r => r.mapping
  | none   => #[]

/-- The decomposition tag (if any) of a codepoint with compatibility
    decomposition. Returns `none` for canonical or non-decomposing
    codepoints. -/
def compatTag? (cp : Nat) : Option CompatDecomp.CompatTag :=
  match compatRow? cp with
  | some r => some r.tag
  | none   => none

/-- Maximum recursion depth for compatibility decomposition. UAX #15
    bounds the longest decomposition chain at a small integer; 32
    leaves a comfortable safety margin over every published UCD. -/
def maxDepth : Nat := 32

/-- Fully decompose a single codepoint per UAX #15 NFKD, recursively
    applying canonical mappings first and compatibility mappings second,
    until a fixed point. Returns `#[cp]` when the codepoint has no
    decomposition.

    `fuel` bounds recursion depth; if exhausted the function returns the
    partial expansion, but this is unreachable under the `maxDepth`
    default on any real UCD release. -/
def fullCompatDecomposeFuel : Nat → Nat → Array Nat
  | 0,        cp => #[cp]
  | fuel + 1, cp =>
    match Hangul.decomposeSyllable? cp with
    | some jamo => jamo
    | none =>
      let canon := Lookup.canonicalDecomposition cp
      if canon.isEmpty then
        let compat := compatDecomposition cp
        if compat.isEmpty then
          #[cp]
        else
          compat.foldl
            (fun acc cp' => acc ++ fullCompatDecomposeFuel fuel cp') #[]
      else
        canon.foldl
          (fun acc cp' => acc ++ fullCompatDecomposeFuel fuel cp') #[]

/-- Fully compatibility-decompose a single codepoint. Thin wrapper that
    fixes `fuel = maxDepth`. -/
def fullCompatDecompose (cp : Nat) : Array Nat :=
  fullCompatDecomposeFuel maxDepth cp

/-- Fully compatibility-decompose a codepoint sequence. Applies
    `fullCompatDecompose` to each input codepoint and concatenates the
    results in order. -/
def compatDecomposeSequence (cps : Array Nat) : Array Nat :=
  cps.foldl (fun acc cp => acc ++ fullCompatDecompose cp) #[]

-- ═══════════════════════════════════════════════════════════════════════════════
-- TEST VECTORS
--
-- The canonical-decomposition branch consults the UnicodeData row scan,
-- which is never reduced (see the fact-transport section of
-- `Unicode.Normalization.Lookup`); each involved codepoint's canonical
-- fact is witnessed by a linear pass or reused from `Decompose`. The
-- compatibility branch reduces directly — `CompatDecomp.lookup?` is a
-- binary search, a handful of probes per query. The fuel recursion is
-- exposed one level at a time via `rw [eq_def]`.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- NO-BREAK SPACE has no UnicodeData row: `CCC = 0` and only a
    compatibility decomposition. -/
theorem rows_omit_nbsp :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint ≠ 0x00A0)) = true := by
  decide +kernel

/-- U+00A0 has no canonical decomposition. -/
theorem canonicalDecomposition_nbsp :
    Lookup.canonicalDecomposition 0x00A0 = #[] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0x00A0
    (Lookup.lookupRow_none_of_all_ne 0x00A0 rows_omit_nbsp)

/-- SUPERSCRIPT TWO is likewise outside the pinned subset. -/
theorem rows_omit_super_2 :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint ≠ 0x00B2)) = true := by
  decide +kernel

/-- U+00B2 has no canonical decomposition. -/
theorem canonicalDecomposition_super_2 :
    Lookup.canonicalDecomposition 0x00B2 = #[] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0x00B2
    (Lookup.lookupRow_none_of_all_ne 0x00B2 rows_omit_super_2)

/-- DIGIT TWO is likewise outside the pinned subset. -/
theorem rows_omit_digit_2 :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint ≠ 0x0032)) = true := by
  decide +kernel

/-- U+0032 has no canonical decomposition. -/
theorem canonicalDecomposition_digit_2 :
    Lookup.canonicalDecomposition 0x0032 = #[] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0x0032
    (Lookup.lookupRow_none_of_all_ne 0x0032 rows_omit_digit_2)

/-- SPACE is likewise outside the pinned subset. -/
theorem rows_omit_space :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint ≠ 0x0020)) = true := by
  decide +kernel

/-- U+0020 has no canonical decomposition. -/
theorem canonicalDecomposition_space :
    Lookup.canonicalDecomposition 0x0020 = #[] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0x0020
    (Lookup.lookupRow_none_of_all_ne 0x0020 rows_omit_space)

/-- DIAERESIS (the spacing character) is likewise outside the pinned
    subset — only its compatibility decomposition exists. -/
theorem rows_omit_diaeresis :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint ≠ 0x00A8)) = true := by
  decide +kernel

/-- U+00A8 has no canonical decomposition. -/
theorem canonicalDecomposition_diaeresis :
    Lookup.canonicalDecomposition 0x00A8 = #[] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0x00A8
    (Lookup.lookupRow_none_of_all_ne 0x00A8 rows_omit_diaeresis)

/-- MICRO SIGN is likewise outside the pinned subset. -/
theorem rows_omit_micro :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint ≠ 0x00B5)) = true := by
  decide +kernel

/-- U+00B5 has no canonical decomposition. -/
theorem canonicalDecomposition_micro :
    Lookup.canonicalDecomposition 0x00B5 = #[] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0x00B5
    (Lookup.lookupRow_none_of_all_ne 0x00B5 rows_omit_micro)

/-- GREEK SMALL LETTER MU is likewise outside the pinned subset. -/
theorem rows_omit_mu :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint ≠ 0x03BC)) = true := by
  decide +kernel

/-- U+03BC has no canonical decomposition. -/
theorem canonicalDecomposition_mu :
    Lookup.canonicalDecomposition 0x03BC = #[] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0x03BC
    (Lookup.lookupRow_none_of_all_ne 0x03BC rows_omit_mu)

/-- The pinned table carries a row for COMBINING DIAERESIS (for its
    non-zero CCC). -/
theorem rows_hit_combining_diaeresis :
    UnicodeData.rowsList.any (fun r => decide (r.codepoint = 0x0308)) = true := by
  decide +kernel

/-- Every row carrying U+0308 records an empty canonical decomposition. -/
theorem rows_decomp_combining_diaeresis :
    UnicodeData.rowsList.all (fun r =>
      decide (r.codepoint = 0x0308 →
        r.canonicalDecomposition = #[])) = true := by
  decide +kernel

/-- U+0308 has no canonical decomposition. -/
theorem canonicalDecomposition_combining_diaeresis :
    Lookup.canonicalDecomposition 0x0308 = #[] :=
  Lookup.canonicalDecomposition_of_hit 0x0308 #[]
    rows_hit_combining_diaeresis rows_decomp_combining_diaeresis

/-- One fuel step on `A`: no decomposition on either branch. -/
theorem fcd_latin_A (fuel : Nat) :
    fullCompatDecomposeFuel (fuel + 1) 0x0041 = #[0x0041] := by
  rw [fullCompatDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        Decompose.canonicalDecomposition_latin_A,
        show compatDecomposition 0x0041 = #[] from by decide]

/-- One fuel step on SPACE: terminal on both branches. -/
theorem fcd_space (fuel : Nat) :
    fullCompatDecomposeFuel (fuel + 1) 0x0020 = #[0x0020] := by
  rw [fullCompatDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_space,
        show compatDecomposition 0x0020 = #[] from by decide]

/-- One fuel step on DIGIT TWO: terminal on both branches. -/
theorem fcd_digit_2 (fuel : Nat) :
    fullCompatDecomposeFuel (fuel + 1) 0x0032 = #[0x0032] := by
  rw [fullCompatDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_digit_2,
        show compatDecomposition 0x0032 = #[] from by decide]

/-- One fuel step on GREEK SMALL LETTER MU: terminal on both branches. -/
theorem fcd_mu (fuel : Nat) :
    fullCompatDecomposeFuel (fuel + 1) 0x03BC = #[0x03BC] := by
  rw [fullCompatDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_mu,
        show compatDecomposition 0x03BC = #[] from by decide]

/-- One fuel step on COMBINING GRAVE ACCENT: terminal on both branches. -/
theorem fcd_grave (fuel : Nat) :
    fullCompatDecomposeFuel (fuel + 1) 0x0300 = #[0x0300] := by
  rw [fullCompatDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        Decompose.canonicalDecomposition_grave,
        show compatDecomposition 0x0300 = #[] from by decide]

/-- One fuel step on COMBINING DIAERESIS: terminal on both branches. -/
theorem fcd_combining_diaeresis (fuel : Nat) :
    fullCompatDecomposeFuel (fuel + 1) 0x0308 = #[0x0308] := by
  rw [fullCompatDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_combining_diaeresis,
        show compatDecomposition 0x0308 = #[] from by decide]

/-- Two fuel steps on U+00C0: the canonical branch expands to `A` +
    grave, both terminal. -/
theorem fcd_A_grave (fuel : Nat) :
    fullCompatDecomposeFuel (fuel + 2) 0x00C0 = #[0x0041, 0x0300] := by
  rw [fullCompatDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        Decompose.canonicalDecomposition_A_grave, fcd_latin_A, fcd_grave]

/-- Two fuel steps on NO-BREAK SPACE: the compatibility branch expands
    to SPACE, which is terminal. -/
theorem fcd_nbsp (fuel : Nat) :
    fullCompatDecomposeFuel (fuel + 2) 0x00A0 = #[0x0020] := by
  rw [fullCompatDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_nbsp,
        show compatDecomposition 0x00A0 = #[0x0020] from by decide,
        fcd_space]

/-- Two fuel steps on SUPERSCRIPT TWO: the compatibility branch expands
    to DIGIT TWO, which is terminal. -/
theorem fcd_super_2 (fuel : Nat) :
    fullCompatDecomposeFuel (fuel + 2) 0x00B2 = #[0x0032] := by
  rw [fullCompatDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_super_2,
        show compatDecomposition 0x00B2 = #[0x0032] from by decide,
        fcd_digit_2]

/-- Two fuel steps on DIAERESIS: the compatibility branch expands to
    SPACE + COMBINING DIAERESIS, both terminal. -/
theorem fcd_diaeresis (fuel : Nat) :
    fullCompatDecomposeFuel (fuel + 2) 0x00A8 = #[0x0020, 0x0308] := by
  rw [fullCompatDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_diaeresis,
        show compatDecomposition 0x00A8 = #[0x0020, 0x0308] from by decide,
        fcd_space, fcd_combining_diaeresis]

/-- Two fuel steps on MICRO SIGN: the compatibility branch expands to
    GREEK SMALL LETTER MU, which is terminal. -/
theorem fcd_micro (fuel : Nat) :
    fullCompatDecomposeFuel (fuel + 2) 0x00B5 = #[0x03BC] := by
  rw [fullCompatDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_micro,
        show compatDecomposition 0x00B5 = #[0x03BC] from by decide,
        fcd_mu]

/-- LATIN CAPITAL LETTER H is outside the pinned subset. -/
theorem rows_omit_latin_H :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint ≠ 0x0048)) = true := by
  decide +kernel

/-- U+0048 has no canonical decomposition. -/
theorem canonicalDecomposition_latin_H :
    Lookup.canonicalDecomposition 0x0048 = #[] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0x0048
    (Lookup.lookupRow_none_of_all_ne 0x0048 rows_omit_latin_H)

/-- One fuel step on `H`: terminal on both branches. -/
theorem fcd_latin_H (fuel : Nat) :
    fullCompatDecomposeFuel (fuel + 1) 0x0048 = #[0x0048] := by
  rw [fullCompatDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_latin_H,
        show compatDecomposition 0x0048 = #[] from by decide]

/-- LATIN SMALL LETTER I is outside the pinned subset. -/
theorem rows_omit_latin_i :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint ≠ 0x0069)) = true := by
  decide +kernel

/-- U+0069 has no canonical decomposition. -/
theorem canonicalDecomposition_latin_i :
    Lookup.canonicalDecomposition 0x0069 = #[] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0x0069
    (Lookup.lookupRow_none_of_all_ne 0x0069 rows_omit_latin_i)

/-- One fuel step on `i`: terminal on both branches. -/
theorem fcd_latin_i (fuel : Nat) :
    fullCompatDecomposeFuel (fuel + 1) 0x0069 = #[0x0069] := by
  rw [fullCompatDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_latin_i,
        show compatDecomposition 0x0069 = #[] from by decide]

/-- LATIN SMALL LETTER F is outside the pinned subset. -/
theorem rows_omit_latin_f :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint ≠ 0x0066)) = true := by
  decide +kernel

/-- U+0066 has no canonical decomposition. -/
theorem canonicalDecomposition_latin_f :
    Lookup.canonicalDecomposition 0x0066 = #[] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0x0066
    (Lookup.lookupRow_none_of_all_ne 0x0066 rows_omit_latin_f)

/-- One fuel step on `f`: terminal on both branches. -/
theorem fcd_latin_f (fuel : Nat) :
    fullCompatDecomposeFuel (fuel + 1) 0x0066 = #[0x0066] := by
  rw [fullCompatDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        canonicalDecomposition_latin_f,
        show compatDecomposition 0x0066 = #[] from by decide]

/-- LATIN SMALL LIGATURE FF is outside the pinned subset (no canonical
    decomposition — only a compatibility one). -/
theorem rows_omit_ligature_ff :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint ≠ 0xFB00)) = true := by
  decide +kernel

/-- U+FB00 has no canonical decomposition. -/
theorem canonicalDecomposition_ligature_ff :
    Lookup.canonicalDecomposition 0xFB00 = #[] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0xFB00
    (Lookup.lookupRow_none_of_all_ne 0xFB00 rows_omit_ligature_ff)

/-- Two fuel steps on LATIN SMALL LIGATURE FF: the compatibility branch
    expands to two `f`s, both terminal. -/
theorem fcd_ligature_ff (fuel : Nat) :
    fullCompatDecomposeFuel (fuel + 2) 0xFB00 = #[0x0066, 0x0066] := by
  rw [fullCompatDecomposeFuel.eq_def]
  simp [show Hangul.decomposeSyllable? 0xFB00 = none from by decide,
        canonicalDecomposition_ligature_ff,
        show compatDecomposition 0xFB00 = #[0x0066, 0x0066] from by decide,
        fcd_latin_f]

/-- One fuel step on HANGUL SYLLABLE GA: the algorithmic Hangul branch
    short-circuits to the L + V jamo pair; no table lookup. -/
theorem fcd_hangul_GA (fuel : Nat) :
    fullCompatDecomposeFuel (fuel + 1) 0xAC00 = #[0x1100, 0x1161] := by
  rw [fullCompatDecomposeFuel.eq_def]
  simp [Hangul.decomposeSyllable?, Hangul.isHangulSyllable,
        Hangul.SBase, Hangul.SCount, Hangul.NCount, Hangul.TCount,
        Hangul.LBase, Hangul.VBase, Hangul.LCount, Hangul.VCount]

/-- `A` (no decomposition) round-trips as its own singleton. -/
theorem compat_decompose_latin_A :
    fullCompatDecompose 0x0041 = #[0x0041] :=
  fcd_latin_A 31

/-- COMBINING GRAVE ACCENT round-trips as its own singleton. -/
theorem compat_decompose_grave :
    fullCompatDecompose 0x0300 = #[0x0300] :=
  fcd_grave 31

/-- `H` round-trips as its own singleton. -/
theorem compat_decompose_latin_H :
    fullCompatDecompose 0x0048 = #[0x0048] :=
  fcd_latin_H 31

/-- `i` round-trips as its own singleton. -/
theorem compat_decompose_latin_i :
    fullCompatDecompose 0x0069 = #[0x0069] :=
  fcd_latin_i 31

/-- LATIN SMALL LIGATURE FF (U+FB00) decomposes via compatibility to two
    lowercase f's. -/
theorem compat_decompose_ligature_ff :
    fullCompatDecompose 0xFB00 = #[0x0066, 0x0066] :=
  fcd_ligature_ff 30

/-- HANGUL SYLLABLE GA (U+AC00) decomposes algorithmically to L + V. -/
theorem compat_decompose_hangul_GA :
    fullCompatDecompose 0xAC00 = #[0x1100, 0x1161] :=
  fcd_hangul_GA 31

/-- HANGUL CHOSEONG KIYEOK is outside the pinned subset. -/
theorem rows_omit_choseong_kiyeok :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint ≠ 0x1100)) = true := by
  decide +kernel

/-- U+1100 has no canonical decomposition. -/
theorem canonicalDecomposition_choseong_kiyeok :
    Lookup.canonicalDecomposition 0x1100 = #[] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0x1100
    (Lookup.lookupRow_none_of_all_ne 0x1100 rows_omit_choseong_kiyeok)

/-- One fuel step on HANGUL CHOSEONG KIYEOK: terminal (a leading jamo is
    a starter with no canonical or compatibility decomposition). -/
theorem fcd_choseong_kiyeok (fuel : Nat) :
    fullCompatDecomposeFuel (fuel + 1) 0x1100 = #[0x1100] := by
  rw [fullCompatDecomposeFuel.eq_def]
  simp [show Hangul.decomposeSyllable? 0x1100 = none from by decide,
        canonicalDecomposition_choseong_kiyeok,
        show compatDecomposition 0x1100 = #[] from by decide]

/-- HANGUL CHOSEONG KIYEOK round-trips as its own singleton. -/
theorem compat_decompose_choseong_kiyeok :
    fullCompatDecompose 0x1100 = #[0x1100] :=
  fcd_choseong_kiyeok 31

/-- HANGUL JUNGSEONG A is outside the pinned subset. -/
theorem rows_omit_jungseong_a :
    UnicodeData.rowsList.all (fun r => decide (r.codepoint ≠ 0x1161)) = true := by
  decide +kernel

/-- U+1161 has no canonical decomposition. -/
theorem canonicalDecomposition_jungseong_a :
    Lookup.canonicalDecomposition 0x1161 = #[] :=
  Lookup.canonicalDecomposition_of_lookupRow_none 0x1161
    (Lookup.lookupRow_none_of_all_ne 0x1161 rows_omit_jungseong_a)

/-- One fuel step on HANGUL JUNGSEONG A: terminal. -/
theorem fcd_jungseong_a (fuel : Nat) :
    fullCompatDecomposeFuel (fuel + 1) 0x1161 = #[0x1161] := by
  rw [fullCompatDecomposeFuel.eq_def]
  simp [show Hangul.decomposeSyllable? 0x1161 = none from by decide,
        canonicalDecomposition_jungseong_a,
        show compatDecomposition 0x1161 = #[] from by decide]

/-- HANGUL JUNGSEONG A round-trips as its own singleton. -/
theorem compat_decompose_jungseong_a :
    fullCompatDecompose 0x1161 = #[0x1161] :=
  fcd_jungseong_a 31

/-- LATIN CAPITAL LETTER A WITH GRAVE has a canonical decomposition;
    NFKD reaches it through the canonical branch. -/
theorem compat_decompose_A_grave :
    fullCompatDecompose 0x00C0 = #[0x0041, 0x0300] :=
  fcd_A_grave 30

/-- NO-BREAK SPACE U+00A0 has compatibility decomposition `<noBreak> 0020`. -/
theorem compat_decompose_nbsp :
    fullCompatDecompose 0x00A0 = #[0x0020] :=
  fcd_nbsp 30

/-- SUPERSCRIPT TWO U+00B2 has compatibility decomposition `<super> 0032`. -/
theorem compat_decompose_super_2 :
    fullCompatDecompose 0x00B2 = #[0x0032] :=
  fcd_super_2 30

/-- DIAERESIS U+00A8 has compatibility decomposition `<compat> 0020 0308`. -/
theorem compat_decompose_diaeresis :
    fullCompatDecompose 0x00A8 = #[0x0020, 0x0308] :=
  fcd_diaeresis 30

/-- MICRO SIGN U+00B5 has compatibility decomposition `<compat> 03BC`
    (Greek small letter mu); 0x03BC has no further decomposition. -/
theorem compat_decompose_micro :
    fullCompatDecompose 0x00B5 = #[0x03BC] :=
  fcd_micro 30

/-- HANGUL SYLLABLE GAG decomposes algorithmically to L + V + T. -/
theorem compat_decompose_GAG :
    fullCompatDecompose 0xAC01 = #[0x1100, 0x1161, 0x11A8] := by decide

/-- Sequence decomposition concatenates per-codepoint decompositions. -/
theorem compat_decompose_sequence_mixed :
    compatDecomposeSequence #[0x00A0, 0x00B2, 0x0041]
      = #[0x0020, 0x0032, 0x0041] := by
  simp only [compatDecomposeSequence, fullCompatDecompose, maxDepth]
  simp [fcd_nbsp 30, fcd_super_2 30, fcd_latin_A 31]

/-- Decomposition of an empty sequence is empty. -/
theorem compat_decompose_empty :
    compatDecomposeSequence #[] = #[] := by decide

end Unicode.Normalization.CompatDecompose
