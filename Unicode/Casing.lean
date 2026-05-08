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
    | _ => false)
  if ! hasLocaleCondition then true
  else
    conds.any (fun c =>
      match loc, c with
      | .turkish,    .LangTr => true
      | .azeri,      .LangAz => true
      | .lithuanian, .LangLt => true
      | _, _ => false)

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

/-- Walk forward from `start` looking for a ccc=230 codepoint
    before the next ccc=0 codepoint. Fuel-bounded for
    `native_decide` evaluability. -/
def moreAboveGo : Nat → Array Nat → Nat → Bool
  | 0, _, _ => false
  | fuel + 1, cps, i =>
    if h : i < cps.size then
      let c := ccc cps[i]
      if c = 230 then true
      else if c = 0 then false
      else moreAboveGo fuel cps (i + 1)
    else false

def moreAboveAfter (cps : Array Nat) (idx : Nat) : Bool :=
  moreAboveGo cps.size cps (idx + 1)

/-- Walk backward from `start` looking for a Soft_Dotted base
    before the next ccc=0 or ccc=230 break. -/
def afterSoftDottedGo : Nat → Array Nat → Nat → Bool
  | 0, _, _ => false
  | fuel + 1, cps, i =>
    if i = 0 then false
    else
      let j := i - 1
      let cp := cps[j]!
      let isSD := Unicode.Generated.DerivedCoreProperties.softDotted.any
        (fun lh => lh.fst ≤ cp ∧ cp ≤ lh.snd)
      if isSD then true
      else
        let c := ccc cp
        if c = 230 ∨ c = 0 then false
        else afterSoftDottedGo fuel cps j

def afterSoftDotted (cps : Array Nat) (idx : Nat) : Bool :=
  afterSoftDottedGo cps.size cps idx

/-- Walk backward looking for U+0049 'I' before the next ccc=0
    or ccc=230 break. -/
def afterIGo : Nat → Array Nat → Nat → Bool
  | 0, _, _ => false
  | fuel + 1, cps, i =>
    if i = 0 then false
    else
      let j := i - 1
      let cp := cps[j]!
      if cp = 0x0049 then true
      else
        let c := ccc cp
        if c = 230 ∨ c = 0 then false
        else afterIGo fuel cps j

def afterI (cps : Array Nat) (idx : Nat) : Bool :=
  afterIGo cps.size cps idx

/-- Walk forward looking for U+0307 before the next ccc=0 break. -/
def beforeDotGo : Nat → Array Nat → Nat → Bool
  | 0, _, _ => false
  | fuel + 1, cps, i =>
    if h : i < cps.size then
      let cp := cps[i]
      if cp = 0x0307 then true
      else
        let c := ccc cp
        if c = 0 then false
        else beforeDotGo fuel cps (i + 1)
    else false

def beforeDot (cps : Array Nat) (idx : Nat) : Bool :=
  beforeDotGo cps.size cps (idx + 1)

/-- True iff `cp` is Cased per `DerivedCoreProperties.txt`. -/
def isCased (cp : Nat) : Bool :=
  Unicode.Generated.DerivedCoreProperties.cased.any
    (fun lh => lh.fst ≤ cp ∧ cp ≤ lh.snd)

/-- Walk backward looking for the most-recent Cased character
    before the current position, skipping over combining marks. -/
def hasCasedBeforeGo : Nat → Array Nat → Nat → Bool
  | 0, _, _ => false
  | fuel + 1, cps, i =>
    if i = 0 then false
    else
      let j := i - 1
      let cp := cps[j]!
      if isCased cp then true
      else
        let c := ccc cp
        if c = 0 then false
        else hasCasedBeforeGo fuel cps j

/-- Walk forward looking for the next non-combining character;
    returns `true` if it's Cased. -/
def hasCasedAfterGo : Nat → Array Nat → Nat → Bool
  | 0, _, _ => false
  | fuel + 1, cps, i =>
    if h : i < cps.size then
      let cp := cps[i]
      if isCased cp then true
      else
        let c := ccc cp
        if c = 0 then false
        else hasCasedAfterGo fuel cps (i + 1)
    else false

/-- Final_Sigma: the position is between a Cased prefix and a
    no-Cased suffix (UAX #21). -/
def finalSigma (cps : Array Nat) (idx : Nat) : Bool :=
  hasCasedBeforeGo cps.size cps idx
    && ! hasCasedAfterGo cps.size cps (idx + 1)

/-- Evaluate one row's condition list against the locale + context. -/
def conditionsHold (loc : Locale) (cps : Array Nat) (idx : Nat)
    (conds : Array Condition) : Bool :=
  localeMatches loc conds
    && conds.all (fun c =>
      match c with
      | .LangTr | .LangAz | .LangLt => true
      | .FinalSigma         => finalSigma cps idx
      | .NotFinalSigma      => ! finalSigma cps idx
      | .AfterSoftDotted    => afterSoftDotted cps idx
      | .MoreAbove          => moreAboveAfter cps idx
      | .NotBeforeDot       => ! beforeDot cps idx
      | .AfterI             => afterI cps idx
      | .Other _            => false)

/-- Find the most-specific applicable SpecialCasing row for `cp`
    at position `idx`. UAX #21 semantics: a conditional row whose
    conditions hold takes precedence over an unconditional row
    for the same codepoint. We do this by searching conditional
    rows first and falling back to unconditional rows. -/
def findSpecialRow (loc : Locale) (cps : Array Nat) (idx : Nat)
    (cp : Nat) : Option Row :=
  let matchConditional :=
    Unicode.Generated.SpecialCasing.parsedRows.findSome? (fun r =>
      if r.code = cp ∧ ! r.conditions.isEmpty
          ∧ conditionsHold loc cps idx r.conditions
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
def lowerCodepoint (loc : Locale) (cps : Array Nat) (idx : Nat)
    (cp : Nat) : Array Nat :=
  match findSpecialRow loc cps idx cp with
  | some r => r.lower
  | none   => #[Unicode.Generated.SimpleCaseMappings.simpleLowercase cp]

/-- Uppercase a single codepoint. -/
def upperCodepoint (loc : Locale) (cps : Array Nat) (idx : Nat)
    (cp : Nat) : Array Nat :=
  match findSpecialRow loc cps idx cp with
  | some r => r.upper
  | none   => #[Unicode.Generated.SimpleCaseMappings.simpleUppercase cp]

/-- Titlecase a single codepoint. -/
def titleCodepoint (loc : Locale) (cps : Array Nat) (idx : Nat)
    (cp : Nat) : Array Nat :=
  match findSpecialRow loc cps idx cp with
  | some r => r.title
  | none   => #[Unicode.Generated.SimpleCaseMappings.simpleTitlecase cp]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 STRING-LEVEL OPERATIONS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Lowercase a codepoint sequence under the given locale. -/
def toLower (loc : Locale) (cps : Array Nat) : Array Nat := Id.run do
  let mut acc : Array Nat := #[]
  for h : i in [0:cps.size] do
    acc := acc ++ lowerCodepoint loc cps i cps[i]
  return acc

/-- Uppercase a codepoint sequence under the given locale. -/
def toUpper (loc : Locale) (cps : Array Nat) : Array Nat := Id.run do
  let mut acc : Array Nat := #[]
  for h : i in [0:cps.size] do
    acc := acc ++ upperCodepoint loc cps i cps[i]
  return acc

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 SAMPLE STRINGS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- "Hello" lowercases to "hello" under the default locale. -/
theorem toLower_hello :
    toLower .default #[0x48, 0x65, 0x6C, 0x6C, 0x6F] =
      #[0x68, 0x65, 0x6C, 0x6C, 0x6F] := by native_decide

/-- "hello" uppercases to "HELLO". -/
theorem toUpper_hello :
    toUpper .default #[0x68, 0x65, 0x6C, 0x6C, 0x6F] =
      #[0x48, 0x45, 0x4C, 0x4C, 0x4F] := by native_decide

/-- ß (U+00DF) uppercases to "SS" (full case mapping). -/
theorem toUpper_sharp_s :
    toUpper .default #[0x00DF] = #[0x0053, 0x0053] := by native_decide

/-- Turkish I (U+0049) lowercases to dotless ı (U+0131) under tr/az,
    but to dotted i (U+0069) under default. -/
theorem toLower_I_default :
    toLower .default #[0x0049] = #[0x0069] := by native_decide

theorem toLower_I_turkish :
    toLower .turkish #[0x0049] = #[0x0131] := by native_decide

theorem toLower_I_azeri :
    toLower .azeri #[0x0049] = #[0x0131] := by native_decide

/-- Turkish dotted İ (U+0130) lowercases to plain `i` under tr/az;
    under default it lowercases to `i + COMBINING DOT ABOVE`. -/
theorem toLower_dotted_I_turkish :
    toLower .turkish #[0x0130] = #[0x0069] := by native_decide

theorem toLower_dotted_I_default :
    toLower .default #[0x0130] = #[0x0069, 0x0307] := by native_decide

end Unicode.Casing
