/-
  Unicode.Security.Form.LocaleCaseInversion

  Detection of inputs whose case-fold result inverts across
  locales, the canonical homograph-via-locale attack vector
  (CVE-2007-6692, CVE-2021-30245, the Spotify "İSTANBUL" /
  "iSTANBUL" incident class).

  Threat model.  Tier A₂.  An attacker submits text containing
  Turkish / Azeri / Lithuanian-conditional codepoints.  The
  receiver folds the input under one locale (typically `default`)
  to compare against a stored credential, while another stage
  folds the same input under a Turkish or Lithuanian locale.  The
  two folds diverge, and the attacker controls which fold is
  used at each stage.

  Examples the detector covers:

    * U+0049 LATIN CAPITAL LETTER I
        toLower default  → U+0069 (i)
        toLower turkish  → U+0131 (ı  dotless)
    * U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE
        toLower default  → U+0069 U+0307 (i + dot above)
        toLower turkish  → U+0069 (i)
    * U+0049 followed by a ccc = 230 combining mark (e.g. U+0300)
        toLower default     → U+0069 + mark
        toLower lithuanian  → U+0069 U+0307 + mark   (dot above inserted)

  Detection uses per-position `lowerCodepoint` comparison rather
  than whole-string `toLower` diffing, because `lowerCodepoint`
  already evaluates the SpecialCasing context predicates
  (`AfterI`, `MoreAbove`, `NotBeforeDot`, `AfterSoftDotted`,
  `FinalSigma`) with full input context — so a per-position diff
  is sound under context-sensitive conditional rules.

  Sub-threats (priority order):

    1. `turkishCaseDivergence (basePos, cp)` — first position
       whose `lowerCodepoint .turkish` differs from `.default`.
       Covers both Turkish and Azeri (SpecialCasing.txt v16 has
       no codepoint with `az` but not `tr`).
    2. `lithuanianCaseDivergence (basePos, cp)` — first position
       whose `lowerCodepoint .lithuanian` differs from `.default`,
       reached only when no Turkish divergence is found first.
-/

import Unicode.Security.Calculus
import Unicode.Casing

namespace Unicode.Security.Form.LocaleCaseInversion

set_option maxRecDepth 1000000

open Unicode.Security.Calculus
open Unicode.Casing (Locale lowerCodepoint)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Per-position divergence scan
-- ═══════════════════════════════════════════════════════════════════════════════

/-- First input position whose `lowerCodepoint` under `loc`
    differs from the default-locale result.  Returns
    `(basePos, cp)` on hit. -/
def firstLocaleDivergence (loc : Locale) (input : Array Nat) :
    Option (Nat × Nat) :=
  (Array.range input.size).findSome? (fun i =>
    if h : i < input.size then
      let cp := input[i]
      let defLower := lowerCodepoint .default input i cp
      let locLower := lowerCodepoint loc input i cp
      if defLower != locLower then some (i, cp) else none
    else none)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Types
-- ═══════════════════════════════════════════════════════════════════════════════

inductive SubThreat where
  | turkishCaseDivergence    (basePos : Nat) (cp : Nat)
  | lithuanianCaseDivergence (basePos : Nat) (cp : Nat)
  deriving DecidableEq, Repr, Inhabited

inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : Array Nat) (decoded : ByteArray)
  deriving Inhabited

structure Verdict where
  input    : Array Nat
  classify : Classification
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The LocaleCaseInversion detection function. -/
def detect (input : Array Nat) : Verdict :=
  let classification : Classification :=
    match firstLocaleDivergence .turkish input with
    | some (pos, cp) =>
      .hazard (.turkishCaseDivergence pos cp) #[pos] ByteArray.empty
    | none =>
      match firstLocaleDivergence .lithuanian input with
      | some (pos, cp) =>
        .hazard (.lithuanianCaseDivergence pos cp) #[pos] ByteArray.empty
      | none => .clear
  { input := input, classify := classification }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

def SubThreat.tag : SubThreat → String
  | .turkishCaseDivergence    basePos cp =>
    Function.const (Nat × Nat) "TurkishCaseDivergence"    (basePos, cp)
  | .lithuanianCaseDivergence basePos cp =>
    Function.const (Nat × Nat) "LithuanianCaseDivergence" (basePos, cp)

def Classification.isClear : Classification → Bool
  | .clear                       => true
  | .hazard sub positions decoded =>
    Function.const (SubThreat × Array Nat × ByteArray) false
      (sub, positions, decoded)

def Classification.tag : Classification → Option String
  | .clear                       => none
  | .hazard sub positions decoded =>
    Function.const (Array Nat × ByteArray) (some sub.tag) (positions, decoded)

def Classification.positions : Classification → Array Nat
  | .clear                       => #[]
  | .hazard sub positions decoded =>
    Function.const (SubThreat × ByteArray) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear. -/
theorem detect_empty_clear : (detect #[]).classify.isClear = true := by
  decide +kernel

/-- Pure ASCII without I/i is clear. -/
theorem detect_ascii_clear :
    (detect #[0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  decide +kernel

/-- Capital I alone fires `turkishCaseDivergence` at position 0. -/
theorem detect_capital_I_turkish :
    (detect #[0x0049]).classify.tag = some "TurkishCaseDivergence" := by
  decide +kernel

/-- Dotted İ (U+0130) fires `turkishCaseDivergence` at position 0. -/
theorem detect_dotted_I_turkish :
    (detect #[0x0130]).classify.tag = some "TurkishCaseDivergence" := by
  decide +kernel

/-- "I" + combining grave above (ccc = 230) fires `lithuanianCaseDivergence`
    only if Turkish divergence isn't already firing.  Since "I" alone
    already drives `turkishCaseDivergence`, this row's verdict is
    Turkish, not Lithuanian.  Demonstrates priority order. -/
theorem detect_I_with_grave_picks_turkish_first :
    (detect #[0x0049, 0x0300]).classify.tag = some "TurkishCaseDivergence" := by
  decide +kernel

/-- "J" + combining grave above (ccc = 230) — Lithuanian-only divergence.
    J has no Turkish-conditional row, so `firstLocaleDivergence .turkish`
    returns `none` and the detector falls through to Lithuanian. -/
theorem detect_J_with_grave_lithuanian :
    (detect #[0x004A, 0x0300]).classify.tag =
      some "LithuanianCaseDivergence" := by
  decide +kernel

end Unicode.Security.Form.LocaleCaseInversion
