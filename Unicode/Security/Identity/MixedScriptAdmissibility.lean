/-
  Unicode.Security.Identity.MixedScriptAdmissibility

  Detection of mixed-script identifier admissibility hazards
  per UTS #39 §5 (Restriction Levels) + UTS #39 General Security
  Profile (Identifier_Status).

  Threat model.  Tier A₁..A₃.  Adversary registers an identifier
  whose script composition is technically admissible under
  permissive identifier rules (e.g. UAX #31 default) but violates
  the stricter UTS #39 General Security Profile — typically a
  Latin/Cyrillic or Latin/Greek mix where the visible glyph
  collapses to a popular Latin target.

  Distinction from HomoglyphConfusable.

    * HomoglyphConfusable answers "does this LOOK like a known
      canonical target?" via skeleton-equivalence to a curated
      brand list.
    * This detector answers "is this identifier admissible
      under the Standard's restriction-level rules?" — no
      target list, just script-composition rules.

    The two compose: an admissibility-clear identifier may
    still be a confusable hazard (and vice versa).
    SourceDisplayDivergence already aggregates both.

  Algorithm shape (one pass over `input`).

    Phase 1 — scan for any codepoint with
              `Identifier_Status = Restricted` per UTS #39
              `IdentifierStatus.txt`.
    Phase 2 — resolve the script composition via
              `Unicode.Restriction.stringResolvedScripts`.
    Phase 3 — classify by script combination:
                * `Latn` ∩ `Cyrl` ≠ ∅  → `.latinCyrillic`
                * `Latn` ∩ `Grek` ≠ ∅  → `.latinGreek`
                * scripts.size ≥ 2 and outside an allowed CJK
                  profile → `.cjkMix` or `.scriptMixOther`
    Phase 4 — surface the input's `RestrictionLevel` for audit.
              `.Unrestricted` always fires `.unrestrictedLevel`
              regardless of any specific pair-rule.
-/

import Unicode.Security.Calculus
import Unicode.Identifier
import Unicode.Restriction
import Unicode.ResolvedScripts
import Unicode.Generated.ScriptExtensions

namespace Unicode.Security.Identity.MixedScriptAdmissibility

open Unicode.Security.Calculus
open Unicode.Restriction (RestrictionLevel)
open Unicode.Generated.ScriptExtensions (ScriptAbbrev)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Sub-threat enumeration for MixedScriptAdmissibility.

    Priority order (highest first):
      1. `restrictedStatusCp` Identifier_Status = Restricted found
      2. `latinCyrillic`      Latn + Cyrl mix
      3. `latinGreek`         Latn + Grek mix
      4. `cjkMix`             multi-script that exceeds allowed
                              CJK profiles (Japanese / Chinese /
                              Korean)
      5. `scriptMixOther`     ≥ 2 distinct non-Common,
                              non-Inherited scripts not covered
                              above
      6. `unrestrictedLevel`  catch-all when `restrictionLevel`
                              resolves to `.Unrestricted`
-/
inductive SubThreat where
  | restrictedStatusCp  (firstPos : Nat) (firstCp : Nat)
  | latinCyrillic       (cyrillicPositions : Array Nat)
  | latinGreek          (greekPositions : Array Nat)
  | cjkMix              (scriptCount : Nat)
  | scriptMixOther      (scriptCount : Nat)
  | unrestrictedLevel
  deriving DecidableEq, Repr, Inhabited

/-- Top-level classification for MixedScriptAdmissibility.
    The clear case is just `.clear`; the input's restriction
    level is reported via the `Verdict.level` field for
    downstream audit. -/
inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : Array Nat) (decoded : ByteArray)
  deriving Inhabited

/-- Verdict — the structured output of `detect`. -/
structure Verdict where
  input            : Array Nat
  classify         : Classification
  scripts          : Array ScriptAbbrev
  level            : RestrictionLevel
  restrictedCps    : Array Nat
  hasLatin         : Bool
  hasCyrillic      : Bool
  hasGreek         : Bool
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Sub-detectors
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cp` has `Identifier_Status = Restricted`. -/
@[inline]
def isRestrictedStatus (cp : Nat) : Bool :=
  ¬ Unicode.Identifier.isAllowedStatus cp

/-- Collect positions of every Restricted-status codepoint. -/
def restrictedStatusPositions (input : Array Nat) : Array Nat :=
  (Array.range input.size).filterMap (fun i =>
    if h : i < input.size then
      if isRestrictedStatus input[i] then some i else none
    else none)

/-- Codepoints at the restricted positions. -/
def restrictedStatusCps (input : Array Nat) : Array Nat :=
  (restrictedStatusPositions input).filterMap (fun p =>
    if h : p < input.size then some input[p] else none)

/-- Collect positions of every codepoint whose resolved script
    set contains `target`. -/
def positionsForScript
    (input : Array Nat) (target : ScriptAbbrev) : Array Nat :=
  (Array.range input.size).filterMap (fun i =>
    if h : i < input.size then
      let scripts := Unicode.ResolvedScripts.resolveScripts input[i]
      if scripts.contains target then some i else none
    else none)

/-- True iff `input` contains at least one codepoint whose
    resolved script set contains `target`.  Re-export of
    `Unicode.Restriction.hasScript` (the union-side question,
    distinct from the intersection-based
    `stringResolvedScripts`). -/
@[inline]
def hasScript (input : Array Nat) (target : ScriptAbbrev) : Bool :=
  Unicode.Restriction.hasScript input target

/-- Union of resolved scripts over all non-ignored codepoints in
    `input`.  Re-export of `Unicode.Restriction.stringScriptUnion`. -/
@[inline]
def unionOfScripts (input : Array Nat) : Array ScriptAbbrev :=
  Unicode.Restriction.stringScriptUnion input

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The MixedScriptAdmissibility detection function. -/
def detect (input : Array Nat) : Verdict :=
  let scriptsIntersect := Unicode.Restriction.stringResolvedScripts input
  let scriptsUnion := unionOfScripts input
  let level := Unicode.Restriction.restrictionLevel input
  let restrictedPositions := restrictedStatusPositions input
  let restrictedCps := restrictedStatusCps input
  let hasLatn := hasScript input .Latn
  let hasCyrl := hasScript input .Cyrl
  let hasGrek := hasScript input .Grek
  let classification : Classification :=
    if h : restrictedPositions.size > 0 then
      let p0 := restrictedPositions[0]'h
      let cp0 := if hp : p0 < input.size then input[p0]'hp else 0
      .hazard (.restrictedStatusCp p0 cp0)
        restrictedPositions ByteArray.empty
    else if hasLatn ∧ hasCyrl then
      .hazard (.latinCyrillic (positionsForScript input .Cyrl))
        (positionsForScript input .Cyrl) ByteArray.empty
    else if hasLatn ∧ hasGrek then
      .hazard (.latinGreek (positionsForScript input .Grek))
        (positionsForScript input .Grek) ByteArray.empty
    else if scriptsUnion.size ≥ 2 ∧
            ¬ Unicode.Restriction.isHighlyRestrictive input then
      -- Multi-script outside CJK profile.  Distinguish from the
      -- CJK-shaped-but-not-Highly-Restrictive case.
      let inAnyCJK :=
        Unicode.Restriction.allWithinCoveredSet input
          Unicode.Restriction.coveredJapanese ||
        Unicode.Restriction.allWithinCoveredSet input
          Unicode.Restriction.coveredChinese ||
        Unicode.Restriction.allWithinCoveredSet input
          Unicode.Restriction.coveredKorean
      if inAnyCJK then
        .hazard (.cjkMix scriptsUnion.size) #[] ByteArray.empty
      else
        .hazard (.scriptMixOther scriptsUnion.size) #[] ByteArray.empty
    else if level = .Unrestricted then
      .hazard .unrestrictedLevel #[] ByteArray.empty
    else
      .clear
  { input := input,
    classify := classification,
    scripts := scriptsIntersect,
    level := level,
    restrictedCps := restrictedCps,
    hasLatin := hasLatn,
    hasCyrillic := hasCyrl,
    hasGreek := hasGrek }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Fixture-row tag string for each `SubThreat` constructor. -/
def SubThreat.tag : SubThreat → String
  | .restrictedStatusCp firstPos firstCp =>
      Function.const (Nat × Nat) "RestrictedStatusCp" (firstPos, firstCp)
  | .latinCyrillic      cyrPositions    =>
      Function.const (Array Nat) "LatinCyrillic" cyrPositions
  | .latinGreek         greekPositions  =>
      Function.const (Array Nat) "LatinGreek" greekPositions
  | .cjkMix             scriptCount     =>
      Function.const Nat "CjkMix" scriptCount
  | .scriptMixOther     scriptCount     =>
      Function.const Nat "ScriptMixOther" scriptCount
  | .unrestrictedLevel                  => "UnrestrictedLevel"

/-- True iff the classification is `.clear`. -/
def Classification.isClear : Classification → Bool
  | .clear                     => true
  | .hazard sub positions decoded =>
      Function.const (SubThreat × Array Nat × ByteArray) false
        (sub, positions, decoded)

/-- Tag string of a classification. -/
def Classification.tag : Classification → Option String
  | .clear                     => none
  | .hazard sub positions decoded =>
      Function.const (Array Nat × ByteArray) (some sub.tag) (positions, decoded)

/-- Positions array of a classification. -/
def Classification.positions : Classification → Array Nat
  | .clear                     => #[]
  | .hazard sub positions decoded =>
      Function.const (SubThreat × ByteArray) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear. -/
theorem detect_empty_clear : (detect #[]).classify.isClear = true := by
  native_decide

/-- Pure ASCII is clear at `.ASCIIOnly`. -/
theorem detect_ascii_clear :
    (detect #[0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  native_decide

/-- Pure Cyrillic "привет" is single-script-clear. -/
theorem detect_cyrillic_single_clear :
    (detect #[0x043F, 0x0440, 0x0438, 0x0432, 0x0435, 0x0442]).classify.isClear
      = true := by native_decide

/-- Pure Greek "αλφα" is single-script-clear. -/
theorem detect_greek_single_clear :
    (detect #[0x03B1, 0x03BB, 0x03C6, 0x03B1]).classify.isClear = true := by
  native_decide

/-- Latin + Cyrillic mix — fires `.latinCyrillic`. -/
theorem detect_latin_cyrillic :
    (detect #[0x0061, 0x0440, 0x0061]).classify.tag = some "LatinCyrillic" := by
  native_decide

/-- Latin + Greek mix — fires `.latinGreek`. -/
theorem detect_latin_greek :
    (detect #[0x0061, 0x03B1, 0x0061]).classify.tag = some "LatinGreek" := by
  native_decide

/-- Hangul filler U+115F is Identifier_Status = Restricted — fires
    `.restrictedStatusCp`. -/
theorem detect_restricted_hangul_filler :
    (detect #[0x115F]).classify.tag = some "RestrictedStatusCp" := by
  native_decide

end Unicode.Security.Identity.MixedScriptAdmissibility
