/-
  Unicode.Security.Form.WidthClassConfusion

  Detection of UAX #11 East Asian Width class confusion.
  Inputs that contain Fullwidth (EAW = F) or Halfwidth (EAW = H)
  codepoints whose NFKD form has a different EAW class are
  flagged.  These are the canonical compatibility-fold homograph
  shapes:

    * U+FF21 'Ａ' (F)  →  U+0041 'A' (Na)
    * U+FF11 '１' (F)  →  U+0031 '1' (Na)
    * U+FF71 'ｱ' (H)  →  U+30A2 'ア' (W)

  Threat model.  Tier A₂.  Two-system bypass shape: a validator
  that whitelists ASCII rejects `Ａ` (the fullwidth form), while
  a downstream NFKC step at storage / comparison time folds it
  to plain `A`.  The attacker uses `ＡＤＭＩＮ` to claim the
  username `ADMIN` against a system that did not normalise
  before whitelisting.

  Distinct from RendererDivergence's `FullwidthVariance`, which
  fires on F-class codepoints for *renderer-cohort* divergence
  reasons (Chrome vs. Safari rendering of fullwidth glyphs).
  This detector is the NFKC-fold-driven verdict.  The two
  detectors can fire on the same input independently.

  Detection is per-input-position and uses NFKD because every
  compatibility decomposition path goes through it; we compare
  EAW class of the input cp against EAW class of the first
  NFKD output cp.  Hangul syllables decompose to jamos that are
  still W class, so pure Hangul stays clear.

  Sub-threats (priority order):

    1. `fullwidthFold (basePos, cp, foldedCp)` — first input cp
       whose EAW = F and whose NFKD head has EAW ≠ F.  Reports
       the input cp, the position, and the NFKD-head fold target.
    2. `halfwidthFold (basePos, cp, foldedCp)` — first input cp
       whose EAW = H and whose NFKD head has EAW ≠ H.  Reached
       only when no fullwidth fold fires first.
-/

import Unicode.Security.Calculus
import Unicode.Generated.EastAsianWidth
import Unicode.Normalization.NFKD

namespace Unicode.Security.Form.WidthClassConfusion

open Unicode.Security.Calculus
open Unicode.Generated.EastAsianWidth (EastAsianWidthClass)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Per-position width-fold scan
-- ═══════════════════════════════════════════════════════════════════════════════

/-- East Asian Width class of `cp`. -/
@[inline]
def widthClass (cp : Nat) : EastAsianWidthClass :=
  Unicode.Generated.EastAsianWidth.lookup cp

/-- True iff `cp` has a non-trivial NFKD whose first output cp
    has EAW class different from `cp`'s EAW class. -/
def hasWidthFold (cp : Nat) : Option Nat :=
  let d := Unicode.Normalization.NFKD.toNFKD #[cp]
  if h : 0 < d.size then
    let head := d[0]
    if widthClass head = widthClass cp then none else some head
  else none

/-- First input position whose cp has EAW = F and folds to a
    different width class. -/
def firstFullwidthFold (input : Array Nat) : Option (Nat × Nat × Nat) :=
  (Array.range input.size).findSome? (fun i =>
    if h : i < input.size then
      let cp := input[i]
      if widthClass cp = .F then
        match hasWidthFold cp with
        | some folded => some (i, cp, folded)
        | none        => none
      else none
    else none)

/-- First input position whose cp has EAW = H and folds to a
    different width class. -/
def firstHalfwidthFold (input : Array Nat) : Option (Nat × Nat × Nat) :=
  (Array.range input.size).findSome? (fun i =>
    if h : i < input.size then
      let cp := input[i]
      if widthClass cp = .H then
        match hasWidthFold cp with
        | some folded => some (i, cp, folded)
        | none        => none
      else none
    else none)

/-- Count of input positions whose cp has EAW = F and folds to
    a different class. -/
def fullwidthFoldCount (input : Array Nat) : Nat :=
  (Array.range input.size).foldl (init := 0) (fun acc i =>
    if h : i < input.size then
      let cp := input[i]
      if widthClass cp = .F then
        if (hasWidthFold cp).isSome then acc + 1 else acc
      else acc
    else acc)

/-- Count of input positions whose cp has EAW = H and folds to
    a different class. -/
def halfwidthFoldCount (input : Array Nat) : Nat :=
  (Array.range input.size).foldl (init := 0) (fun acc i =>
    if h : i < input.size then
      let cp := input[i]
      if widthClass cp = .H then
        if (hasWidthFold cp).isSome then acc + 1 else acc
      else acc
    else acc)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Types
-- ═══════════════════════════════════════════════════════════════════════════════

inductive SubThreat where
  | fullwidthFold (basePos : Nat) (cp : Nat) (foldedCp : Nat)
  | halfwidthFold (basePos : Nat) (cp : Nat) (foldedCp : Nat)
  deriving DecidableEq, Repr, Inhabited

inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : Array Nat) (decoded : ByteArray)
  deriving Inhabited

structure Verdict where
  input              : Array Nat
  classify           : Classification
  fullwidthFoldCount : Nat
  halfwidthFoldCount : Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The WidthClassConfusion detection function. -/
def detect (input : Array Nat) : Verdict :=
  let classification : Classification :=
    match firstFullwidthFold input with
    | some (pos, cp, folded) =>
      .hazard (.fullwidthFold pos cp folded) #[pos] ByteArray.empty
    | none =>
      match firstHalfwidthFold input with
      | some (pos, cp, folded) =>
        .hazard (.halfwidthFold pos cp folded) #[pos] ByteArray.empty
      | none => .clear
  { input := input,
    classify := classification,
    fullwidthFoldCount := fullwidthFoldCount input,
    halfwidthFoldCount := halfwidthFoldCount input }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

def SubThreat.tag : SubThreat → String
  | .fullwidthFold basePos cp foldedCp =>
    Function.const (Nat × Nat × Nat) "FullwidthFold" (basePos, cp, foldedCp)
  | .halfwidthFold basePos cp foldedCp =>
    Function.const (Nat × Nat × Nat) "HalfwidthFold" (basePos, cp, foldedCp)

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
  decide

/-- Pure ASCII is clear; every ASCII cp is EAW = Na with identity NFKD. -/
theorem detect_ascii_clear :
    (detect #[0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  decide

/-- Korean Hangul 한 stays clear: NFKD = three jamos, all EAW = W. -/
theorem detect_hangul_clear :
    (detect #[0xD55C]).classify.isClear = true := by decide

/-- Han 中文 stays clear: both cps are EAW = W with identity NFKD. -/
theorem detect_han_clear :
    (detect #[0x4E2D, 0x6587]).classify.isClear = true := by decide

/-- Fullwidth A (U+FF21) fires `fullwidthFold` at position 0 — folds to 'A'. -/
theorem detect_fullwidth_A :
    (detect #[0xFF21]).classify.tag = some "FullwidthFold" := by
  decide

/-- Halfwidth katakana A (U+FF71) fires `halfwidthFold` at position 0. -/
theorem detect_halfwidth_ka_A :
    (detect #[0xFF71]).classify.tag = some "HalfwidthFold" := by
  decide

end Unicode.Security.Form.WidthClassConfusion
