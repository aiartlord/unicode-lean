/-
  Unicode.Security.Boundary.IdentifierFormDrift

  X1 — Cross-Layer Identifier × Form Drift.  Layer-5 boundary
  detector that fires on inputs where the UTS #39
  `Identifier_Status` (Allowed / Restricted) of any codepoint
  differs from the `Identifier_Status` of that codepoint's NFKD
  head.  This is the canonical Identity-validator ↔ Form-
  normalizer disagreement surface.

  Threat model.  Tier A₂.  Two-system bypass shape spanning
  Layer 2 (Identity) and Layer 4 (Form):

    * stage A runs `isAllowedIdentifier` before normalisation —
      rejects U+1D44E 'Mathematical Italic Small A' because its
      `Identifier_Status` is Restricted;
    * stage B normalises first, then runs the same check — sees
      U+0061 'a' (Allowed) and accepts;

  attacker controls which stage processes the input and exploits
  the disagreement.

  The same shape applies to:

    * U+FF21 Fullwidth Capital A      Restricted → Allowed (A)
    * U+24B6 Circled Capital A        Restricted → Allowed (A)
    * U+FB01 'ﬁ' ligature             Restricted → Allowed (f)
    * U+2163 Roman Numeral IV         Restricted → Allowed (I)

  Note on Hangul: precomposed syllables (e.g. U+D55C 한) are
  Allowed under UTS #39 IdentifierStatus.txt while their
  NFKD-head jamos (e.g. U+1112 HANGUL CHOSEONG HIEUH) are
  Restricted.  Pure Korean text therefore fires X1.  Callers
  intending to accept Korean identifiers should apply NFC
  before evaluating admissibility.

  Distinct from Layer 2 family detectors (I1 HomoglyphConfusable,
  I2 MixedScriptAdmissibility, I3/I4 emoji-side identity
  detectors) which examine the input under a single form.  X1
  fires on the *form transition* itself, which the single-form
  detectors miss by construction.

  Distinct also from F5 WidthClassConfusion (UAX #11 EAW class
  fold) and F6 NfcIdempotenceWitness (form-of-input fold): X1
  asks the orthogonal question "does the identifier verdict
  change under normalisation?", which is a stronger statement
  than "does any output bit change".

  Sub-threat (v1, single):

    1. `identifierStatusShift (basePos, cp)` — first input
       position whose `Identifier_Status` differs from the
       `Identifier_Status` of its NFKD-head.  Direction-agnostic;
       the verdict carries the shift count for downstream
       policy.
-/

import Unicode.Security.Calculus
import Unicode.Identifier
import Unicode.Normalization.NFKD

namespace Unicode.Security.Boundary.IdentifierFormDrift

open Unicode.Security.Calculus
open Unicode.Identifier (isAllowedStatus)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Per-position shift scan
-- ═══════════════════════════════════════════════════════════════════════════════

/-- `Identifier_Status` of the first codepoint of `cp`'s NFKD form,
    or `cp`'s own status when NFKD is empty (defensive — `toNFKD`
    is total and returns at least `#[cp]` for any cp). -/
def nfkdHeadAllowed (cp : Nat) : Bool :=
  let d := Unicode.Normalization.NFKD.toNFKD #[cp]
  if h : 0 < d.size then isAllowedStatus d[0] else isAllowedStatus cp

/-- First input position whose `isAllowedStatus` differs from its
    NFKD-head's `isAllowedStatus`. -/
def firstStatusShift (input : Array Nat) : Option (Nat × Nat) :=
  (Array.range input.size).findSome? (fun i =>
    if h : i < input.size then
      let cp := input[i]
      if isAllowedStatus cp != nfkdHeadAllowed cp then some (i, cp)
      else none
    else none)

/-- Total count of input positions where the per-cp status shifts
    under NFKD. -/
def statusShiftCount (input : Array Nat) : Nat :=
  (Array.range input.size).foldl (init := 0) (fun acc i =>
    if h : i < input.size then
      let cp := input[i]
      if isAllowedStatus cp != nfkdHeadAllowed cp then acc + 1 else acc
    else acc)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Types
-- ═══════════════════════════════════════════════════════════════════════════════

inductive X1SubThreat where
  | identifierStatusShift (basePos : Nat) (cp : Nat)
  deriving DecidableEq, Repr, Inhabited

inductive X1Classification where
  | clear
  | hazard (sub : X1SubThreat) (positions : Array Nat) (decoded : ByteArray)
  deriving Inhabited

structure X1Verdict where
  input      : Array Nat
  classify   : X1Classification
  shiftCount : Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The X1 detection function. -/
def detect (input : Array Nat) : X1Verdict :=
  let classification : X1Classification :=
    match firstStatusShift input with
    | some (pos, cp) =>
      .hazard (.identifierStatusShift pos cp) #[pos] ByteArray.empty
    | none => .clear
  { input := input,
    classify := classification,
    shiftCount := statusShiftCount input }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

def X1SubThreat.tag : X1SubThreat → String
  | .identifierStatusShift basePos cp =>
    Function.const (Nat × Nat) "IdentifierStatusShift" (basePos, cp)

def X1Classification.isClear : X1Classification → Bool
  | .clear                       => true
  | .hazard sub positions decoded =>
    Function.const (X1SubThreat × Array Nat × ByteArray) false
      (sub, positions, decoded)

def X1Classification.tag : X1Classification → Option String
  | .clear                       => none
  | .hazard sub positions decoded =>
    Function.const (Array Nat × ByteArray) (some sub.tag) (positions, decoded)

def X1Classification.positions : X1Classification → Array Nat
  | .clear                       => #[]
  | .hazard sub positions decoded =>
    Function.const (X1SubThreat × ByteArray) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear. -/
theorem detect_empty_clear : (detect #[]).classify.isClear = true := by
  native_decide

/-- Pure ASCII is clear; every ASCII letter is Allowed, identity NFKD. -/
theorem detect_ascii_clear :
    (detect #[0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  native_decide

/-- Greek lowercase α is Allowed with identity NFKD — clear. -/
theorem detect_greek_alpha_clear :
    (detect #[0x03B1]).classify.isClear = true := by native_decide

/-- Math Italic Small A (U+1D44E) is Restricted; NFKD head U+0061
    is Allowed.  The canonical X1 case. -/
theorem detect_math_italic_a_shift :
    (detect #[0x1D44E]).classify.tag = some "IdentifierStatusShift" := by
  native_decide

/-- Fullwidth A (U+FF21) is Restricted (compatibility form); NFKD head
    U+0041 is Allowed. -/
theorem detect_fullwidth_A_shift :
    (detect #[0xFF21]).classify.tag = some "IdentifierStatusShift" := by
  native_decide

end Unicode.Security.Boundary.IdentifierFormDrift
