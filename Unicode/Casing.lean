/-
  Unicode.Casing

  UAX #21 / UAX #44 full case mappings — locale- and
  context-aware uppercase / lowercase / titlecase. Combines:

    * `UnicodeData.txt` simple case mappings (one-to-one,
      unconditional; via `Generated.SimpleCaseMappings`);
    * `SpecialCasing.txt` full case mappings (one-to-many,
      unconditional; via `Generated.SpecialCasing`);
    * `SpecialCasing.txt` conditional mappings (locale and
      context-dependent — Turkish dotted/dotless I, Lithuanian
      dot above, Greek final sigma).

  Pipeline at each codepoint position:

    1. Lookup all SpecialCasing rows for the codepoint.
    2. Pick the first row whose locale + context conditions hold
       under the chosen `Locale`.
    3. If a row matches, emit its `lower` / `upper` / `title`
       sequence; otherwise fall through to the simple
       UnicodeData mapping.
-/

import Unicode.Generated.SpecialCasing
import Unicode.Generated.SimpleCaseMappings
import Unicode.Normalization.Lookup
import Unicode.Generated.DerivedCoreProperties

namespace Unicode.Casing

set_option maxRecDepth 100000

open Unicode.Generated.SpecialCasing (Row Condition)

/-- The locales that SpecialCasing.txt distinguishes. `default`
    covers everything not explicitly tagged Turkish / Azeri /
    Lithuanian. -/
inductive Locale where
  | default
  | turkish
  | azeri
  | lithuanian
  deriving DecidableEq, Repr, Inhabited

/-- Match a SpecialCasing locale-condition list against the
    chosen `Locale`. A row with no locale conditions matches every
    locale; a row with a locale condition matches only that
    locale. -/
def localeMatches (loc : Locale) (conds : Array Condition) : Bool :=
  let hasLocaleCondition := conds.any (fun c =>
    match c with
    | .LangTr | .LangAz | .LangLt => true
    | .FinalSigma | .NotFinalSigma | .AfterSoftDotted | .MoreAbove |
      .NotBeforeDot | .AfterI => false
    | .Other token => Function.const String false token)
  if ! hasLocaleCondition then true
  else
    conds.any (fun c =>
      match c with
      | .LangTr => loc == .turkish
      | .LangAz => loc == .azeri
      | .LangLt => loc == .lithuanian
      | .FinalSigma | .NotFinalSigma | .AfterSoftDotted | .MoreAbove |
        .NotBeforeDot | .AfterI => false
      | .Other token => Function.const String false token)

/-- Get the canonical combining class of `cp`. Wraps the
    `Normalization.Lookup` helper so callers don't import its
    namespace directly. -/
@[inline]
def ccc (cp : Nat) : Nat :=
  Unicode.Normalization.Lookup.canonicalCombiningClass cp

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 CONTEXT PREDICATES
--
-- The four context conditions defined by UAX #21:
--   * Final_Sigma         — preceded by a cased character, not
--                            followed by a cased character before
--                            the next word break.
--   * After_Soft_Dotted   — last preceding base character has
--                            DerivedCoreProperties Soft_Dotted.
--   * More_Above          — followed (before next ccc=0 character)
--                            by a ccc=230 (above) combining mark.
--   * Not_Before_Dot      — NOT followed by U+0307 before next
--                            ccc=0 character.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Walk the forward suffix looking for a ccc=230 codepoint
    before the next ccc=0 codepoint.  Structural recursion on the
    codepoints following the current position. -/
def moreAboveAfterGo : List Nat → Bool
  | [] => false
  | cp :: rest =>
    let c := ccc cp
    if c = 230 then true
    else if c = 0 then false
    else moreAboveAfterGo rest

/-- More_Above: some ccc=230 mark follows before the next ccc=0
    break.  `suffix` is the codepoints strictly after the current
    position. -/
def moreAboveAfter (suffix : List Nat) : Bool :=
  moreAboveAfterGo suffix

/-- Walk the reversed prefix (nearest-first) looking for a
    Soft_Dotted base before the next ccc=0 or ccc=230 break. -/
def afterSoftDottedGo : List Nat → Bool
  | [] => false
  | cp :: rest =>
    let isSD := Unicode.Generated.DerivedCoreProperties.softDotted.any
      (fun lh => lh.fst ≤ cp ∧ cp ≤ lh.snd)
    if isSD then true
    else
      let c := ccc cp
      if c = 230 ∨ c = 0 then false
      else afterSoftDottedGo rest

/-- After_Soft_Dotted: the last preceding base is Soft_Dotted.
    `revPrefix` is the codepoints before the current position in
    nearest-first (reversed) order. -/
def afterSoftDotted (revPrefix : List Nat) : Bool :=
  afterSoftDottedGo revPrefix

/-- Walk the reversed prefix (nearest-first) looking for U+0049 'I'
    before the next ccc=0 or ccc=230 break. -/
def afterIGo : List Nat → Bool
  | [] => false
  | cp :: rest =>
    if cp = 0x0049 then true
    else
      let c := ccc cp
      if c = 230 ∨ c = 0 then false
      else afterIGo rest

/-- After_I: an uppercase 'I' precedes before the next above/base
    break.  `revPrefix` is the nearest-first preceding codepoints. -/
def afterI (revPrefix : List Nat) : Bool :=
  afterIGo revPrefix

/-- Walk the forward suffix looking for U+0307 before the next
    ccc=0 break. -/
def beforeDotGo : List Nat → Bool
  | [] => false
  | cp :: rest =>
    if cp = 0x0307 then true
    else
      let c := ccc cp
      if c = 0 then false
      else beforeDotGo rest

/-- Before_Dot: a U+0307 follows before the next ccc=0 break.
    `suffix` is the codepoints strictly after the current position. -/
def beforeDot (suffix : List Nat) : Bool :=
  beforeDotGo suffix

/-- True iff `cp` is Cased per `DerivedCoreProperties.txt`. -/
def isCased (cp : Nat) : Bool :=
  Unicode.Generated.DerivedCoreProperties.cased.any
    (fun lh => lh.fst ≤ cp ∧ cp ≤ lh.snd)

/-- Walk the reversed prefix (nearest-first) looking for the most-
    recent Cased character, skipping over combining marks. -/
def hasCasedBeforeGo : List Nat → Bool
  | [] => false
  | cp :: rest =>
    if isCased cp then true
    else
      let c := ccc cp
      if c = 0 then false
      else hasCasedBeforeGo rest

/-- Walk the forward suffix looking for the next non-combining
    character; returns `true` if it is Cased. -/
def hasCasedAfterGo : List Nat → Bool
  | [] => false
  | cp :: rest =>
    if isCased cp then true
    else
      let c := ccc cp
      if c = 0 then false
      else hasCasedAfterGo rest

/-- Final_Sigma: the position is between a Cased prefix and a
    no-Cased suffix (UAX #21).  `revPrefix` is the nearest-first
    preceding codepoints; `suffix` the strictly-following ones. -/
def finalSigma (revPrefix suffix : List Nat) : Bool :=
  hasCasedBeforeGo revPrefix && ! hasCasedAfterGo suffix

/-- Evaluate one row's condition list against the locale + context.
    `revPrefix` is the nearest-first preceding codepoints; `suffix`
    the strictly-following ones. -/
def conditionsHold (loc : Locale) (revPrefix suffix : List Nat)
    (conds : Array Condition) : Bool :=
  localeMatches loc conds
    && conds.all (fun c =>
      match c with
      | .LangTr | .LangAz | .LangLt => true
      | .FinalSigma         => finalSigma revPrefix suffix
      | .NotFinalSigma      => ! finalSigma revPrefix suffix
      | .AfterSoftDotted    => afterSoftDotted revPrefix
      | .MoreAbove          => moreAboveAfter suffix
      | .NotBeforeDot       => ! beforeDot suffix
      | .AfterI             => afterI revPrefix
      | .Other token        => Function.const String false token)

/-- Find the most-specific applicable SpecialCasing row for `cp`
    in the given context. UAX #21 semantics: a conditional row whose
    conditions hold takes precedence over an unconditional row
    for the same codepoint. We do this by searching conditional
    rows first and falling back to unconditional rows. -/
def findSpecialRow (loc : Locale) (revPrefix suffix : List Nat)
    (cp : Nat) : Option Row :=
  let matchConditional :=
    Unicode.Generated.SpecialCasing.parsedRows.findSome? (fun r =>
      if r.code = cp ∧ ! r.conditions.isEmpty
          ∧ conditionsHold loc revPrefix suffix r.conditions
        then some r else none)
  match matchConditional with
  | some r => some r
  | none =>
    Unicode.Generated.SpecialCasing.parsedRows.findSome? (fun r =>
      if r.code = cp ∧ r.conditions.isEmpty then some r else none)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 PER-CODEPOINT MAPPING
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Lowercase a single codepoint, falling back to simple lowercase
    when no SpecialCasing row applies. -/
def lowerCodepoint (loc : Locale) (revPrefix suffix : List Nat)
    (cp : Nat) : Array Nat :=
  match findSpecialRow loc revPrefix suffix cp with
  | some r => r.lower
  | none   => #[Unicode.Generated.SimpleCaseMappings.simpleLowercase cp]

/-- Uppercase a single codepoint. -/
def upperCodepoint (loc : Locale) (revPrefix suffix : List Nat)
    (cp : Nat) : Array Nat :=
  match findSpecialRow loc revPrefix suffix cp with
  | some r => r.upper
  | none   => #[Unicode.Generated.SimpleCaseMappings.simpleUppercase cp]

/-- Titlecase a single codepoint. -/
def titleCodepoint (loc : Locale) (revPrefix suffix : List Nat)
    (cp : Nat) : Array Nat :=
  match findSpecialRow loc revPrefix suffix cp with
  | some r => r.title
  | none   => #[Unicode.Generated.SimpleCaseMappings.simpleTitlecase cp]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 STRING-LEVEL OPERATIONS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Lowercase the codepoints in `suffix`, concatenating each
    codepoint's (possibly multi-element) mapping.  `revPrefix`
    carries the already-processed codepoints in nearest-first order
    so each position's context conditions read their neighbours. -/
def toLowerGo (loc : Locale) (revPrefix : List Nat) : List Nat → List Nat
  | [] => []
  | cp :: suffix =>
    (lowerCodepoint loc revPrefix suffix cp).toList
      ++ toLowerGo loc (cp :: revPrefix) suffix

/-- Lowercase a codepoint sequence under the given locale. -/
def toLower (loc : Locale) (cps : List Nat) : List Nat :=
  toLowerGo loc [] cps

/-- Uppercase the codepoints in `suffix`; see `toLowerGo`. -/
def toUpperGo (loc : Locale) (revPrefix : List Nat) : List Nat → List Nat
  | [] => []
  | cp :: suffix =>
    (upperCodepoint loc revPrefix suffix cp).toList
      ++ toUpperGo loc (cp :: revPrefix) suffix

/-- Uppercase a codepoint sequence under the given locale. -/
def toUpper (loc : Locale) (cps : List Nat) : List Nat :=
  toUpperGo loc [] cps

/-- The per-position context inventory of `cps`:
    `(index, revPrefix, cp, suffix)` for every position, where
    `revPrefix` is the nearest-first preceding codepoints and
    `suffix` the strictly-following ones.  Callers that need the
    context-aware per-codepoint mappings at a specific position
    read the tuple without any index arithmetic. -/
def contextSplitsGo (idx : Nat) (revPrefix : List Nat) :
    List Nat → List (Nat × List Nat × Nat × List Nat)
  | [] => []
  | cp :: suffix =>
    (idx, revPrefix, cp, suffix)
      :: contextSplitsGo (idx + 1) (cp :: revPrefix) suffix

def contextSplits (cps : List Nat) : List (Nat × List Nat × Nat × List Nat) :=
  contextSplitsGo 0 [] cps

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 SAMPLE STRINGS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- "Hello" lowercases to "hello" under the default locale. -/
theorem toLower_hello :
    toLower .default [0x48, 0x65, 0x6C, 0x6C, 0x6F] =
      [0x68, 0x65, 0x6C, 0x6C, 0x6F] := by decide +kernel

/-- "hello" uppercases to "HELLO". -/
theorem toUpper_hello :
    toUpper .default [0x68, 0x65, 0x6C, 0x6C, 0x6F] =
      [0x48, 0x45, 0x4C, 0x4C, 0x4F] := by decide +kernel

/-- ß (U+00DF) uppercases to "SS" (full case mapping). -/
theorem toUpper_sharp_s :
    toUpper .default [0x00DF] = [0x0053, 0x0053] := by decide +kernel

/-- Turkish I (U+0049) lowercases to dotless ı (U+0131) under tr/az,
    but to dotted i (U+0069) under default. -/
theorem toLower_I_default :
    toLower .default [0x0049] = [0x0069] := by decide +kernel

theorem toLower_I_turkish :
    toLower .turkish [0x0049] = [0x0131] := by decide +kernel

theorem toLower_I_azeri :
    toLower .azeri [0x0049] = [0x0131] := by decide +kernel

/-- Turkish dotted İ (U+0130) lowercases to plain `i` under tr/az;
    under default it lowercases to `i + COMBINING DOT ABOVE`. -/
theorem toLower_dotted_I_turkish :
    toLower .turkish [0x0130] = [0x0069] := by decide +kernel

theorem toLower_dotted_I_default :
    toLower .default [0x0130] = [0x0069, 0x0307] := by decide +kernel

end Unicode.Casing
