/-
  Unicode.Security.Form.CaseExpansionMismatch

  F4 — Detection of codepoints whose UAX #21 case mapping
  expands or contracts the string under the default locale.
  Any input cp whose `toLower` or `toUpper` result is longer
  than 1 codepoint can break naive length-bounded buffers,
  fixed-width database columns, and length-based credential
  comparisons.

  Threat model.  Tier A₁..A₂.  An attacker submits text whose
  case-mapped form has a different codepoint count than the
  input.  Examples:

    * U+00DF ß           toUpper → U+0053 U+0053 ("SS")
    * U+FB01 ﬁ           toUpper → U+0046 U+0049 ("FI")
    * U+FB03 ﬃ           toUpper → U+0046 U+0046 U+0049
    * U+0149 ŉ           toUpper → U+02BC U+004E ("ʼN")
    * U+0130 İ           toLower → U+0069 U+0307 ("i + dot above")

  A receiver that fixes a 16-byte username column and stores
  `toUpper(username)` overflows when the user picks "ßßßßßßßß"
  (8 chars in → 16 chars stored).  A receiver that compares
  `len(stored) == len(input)` rejects valid logins of users
  whose names contain ß after upper-folding for case-insensitive
  match.

  Distinct from F3 `LocaleCaseInversion`, which detects shapes
  whose case mapping changes ACROSS locales.  F4 fires on shapes
  whose case mapping is locale-stable but length-changing under
  the default locale itself.

  Sub-threats (priority order):

    1. `upperExpansion (basePos, cp, expansionLen)` — first
       input position whose `upperCodepoint .default` produces
       a sequence of length > 1.
    2. `lowerExpansion (basePos, cp, expansionLen)` — first
       input position whose `lowerCodepoint .default` produces
       a sequence of length > 1; reached only when no upper
       expansion fires first.
-/

import Unicode.Security.Calculus
import Unicode.Casing

namespace Unicode.Security.Form.CaseExpansionMismatch

set_option maxRecDepth 1000000

open Unicode.Security.Calculus
open Unicode.Casing (lowerCodepoint upperCodepoint)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Per-position expansion scan
-- ═══════════════════════════════════════════════════════════════════════════════

/-- First input position whose `upperCodepoint .default` expands
    to more than one codepoint.  Returns `(basePos, cp, expansionLen)`.
    The SpecialCasing context predicates read the surrounding
    characters, so each position is scanned through its reversed
    prefix and forward suffix via `Unicode.Casing.contextSplits`. -/
def firstUpperExpansion (input : List Nat) : Option (Nat × Nat × Nat) :=
  (Unicode.Casing.contextSplits input).findSome? (fun w =>
    let up := upperCodepoint .default w.2.1 w.2.2.2 w.2.2.1
    if up.length > 1 then some (w.1, w.2.2.1, up.length) else none)

/-- First input position whose `lowerCodepoint .default` expands
    to more than one codepoint. -/
def firstLowerExpansion (input : List Nat) : Option (Nat × Nat × Nat) :=
  (Unicode.Casing.contextSplits input).findSome? (fun w =>
    let lo := lowerCodepoint .default w.2.1 w.2.2.2 w.2.2.1
    if lo.length > 1 then some (w.1, w.2.2.1, lo.length) else none)

/-- Count of input positions whose `upperCodepoint .default` expands. -/
def upperExpansionCount (input : List Nat) : Nat :=
  (Unicode.Casing.contextSplits input).foldl (init := 0) (fun acc w =>
    if (upperCodepoint .default w.2.1 w.2.2.2 w.2.2.1).length > 1 then
      acc + 1
    else acc)

/-- Count of input positions whose `lowerCodepoint .default` expands. -/
def lowerExpansionCount (input : List Nat) : Nat :=
  (Unicode.Casing.contextSplits input).foldl (init := 0) (fun acc w =>
    if (lowerCodepoint .default w.2.1 w.2.2.2 w.2.2.1).length > 1 then
      acc + 1
    else acc)

/-- Maximum expansion length across all input positions (max of upper
    and lower mappings combined). -/
def maxExpansionLen (input : List Nat) : Nat :=
  (Unicode.Casing.contextSplits input).foldl (init := 0) (fun acc w =>
    let u := (upperCodepoint .default w.2.1 w.2.2.2 w.2.2.1).length
    let l := (lowerCodepoint .default w.2.1 w.2.2.2 w.2.2.1).length
    let m := if u > l then u else l
    if m > acc then m else acc)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Types
-- ═══════════════════════════════════════════════════════════════════════════════

inductive SubThreat where
  | upperExpansion (basePos : Nat) (cp : Nat) (expansionLen : Nat)
  | lowerExpansion (basePos : Nat) (cp : Nat) (expansionLen : Nat)
  deriving DecidableEq, Repr, Inhabited

inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : List Nat) (decoded : List UInt8)
  deriving Inhabited

structure Verdict where
  input               : List Nat
  classify            : Classification
  upperExpansionCount : Nat
  lowerExpansionCount : Nat
  maxExpansionLen     : Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The F4 detection function. -/
def detect (input : List Nat) : Verdict :=
  let classification : Classification :=
    match firstUpperExpansion input with
    | some (pos, cp, len) =>
      .hazard (.upperExpansion pos cp len) [pos] []
    | none =>
      match firstLowerExpansion input with
      | some (pos, cp, len) =>
        .hazard (.lowerExpansion pos cp len) [pos] []
      | none => .clear
  { input := input,
    classify := classification,
    upperExpansionCount := upperExpansionCount input,
    lowerExpansionCount := lowerExpansionCount input,
    maxExpansionLen := maxExpansionLen input }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

def SubThreat.tag : SubThreat → String
  | .upperExpansion basePos cp expansionLen =>
    Function.const (Nat × Nat × Nat) "UpperExpansion"
      (basePos, cp, expansionLen)
  | .lowerExpansion basePos cp expansionLen =>
    Function.const (Nat × Nat × Nat) "LowerExpansion"
      (basePos, cp, expansionLen)

def Classification.isClear : Classification → Bool
  | .clear                       => true
  | .hazard sub positions decoded =>
    Function.const (SubThreat × List Nat × List UInt8) false
      (sub, positions, decoded)

def Classification.tag : Classification → Option String
  | .clear                       => none
  | .hazard sub positions decoded =>
    Function.const (List Nat × List UInt8) (some sub.tag) (positions, decoded)

def Classification.positions : Classification → List Nat
  | .clear                       => []
  | .hazard sub positions decoded =>
    Function.const (SubThreat × List UInt8) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear. -/
theorem detect_empty_clear : (detect []).classify.isClear = true := by
  decide +kernel

/-- Pure ASCII is clear; every ASCII cp case-maps to a single cp. -/
theorem detect_ascii_clear :
    (detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  decide +kernel

/-- ß (U+00DF) fires `upperExpansion` at position 0 — toUpper → "SS". -/
theorem detect_sharp_s_upper :
    (detect [0x00DF]).classify.tag = some "UpperExpansion" := by
  decide +kernel

/-- ﬁ ligature (U+FB01) fires `upperExpansion` at position 0 — toUpper → "FI". -/
theorem detect_fi_ligature_upper :
    (detect [0xFB01]).classify.tag = some "UpperExpansion" := by
  decide +kernel

/-- İ (U+0130) fires `lowerExpansion` at position 0 — toLower under
    default → "i + 0307".  No upper expansion (İ stays İ), so the
    detector falls through to the lower scan. -/
theorem detect_dotted_I_lower :
    (detect [0x0130]).classify.tag = some "LowerExpansion" := by
  decide +kernel

end Unicode.Security.Form.CaseExpansionMismatch
