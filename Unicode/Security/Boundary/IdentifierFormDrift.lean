/-
  Unicode.Security.Boundary.IdentifierFormDrift

  Cross-Layer Identifier × Form Drift.  Layer-5 boundary
  detector that fires on inputs where the UTS #39
  `Identifier_Status` (Allowed / Restricted) of any codepoint
  differs from the `Identifier_Status` of that codepoint's NFKD
  head.  This is the canonical Identity-validator ↔ Form-
  normalizer disagreement surface.

  Threat model.  Tier A₂.  Two-system bypass shape spanning
  identity-spoofing detectors and form-stability detectors:

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

  The shift is directional: Restricted before NFKD and Allowed
  after.  That is the direction an attacker gains from, since a
  character a validator rejects becomes one it accepts, and it is
  the direction all three cases above take.

  Note on Hangul: precomposed syllables (e.g. U+D55C 한) are
  Allowed under UTS #39 IdentifierStatus.txt while their
  NFKD-head jamos (e.g. U+1112 HANGUL CHOSEONG HIEUH) are
  Restricted.  That is the opposite direction, where normalizing
  makes the character less acceptable rather than more, so it
  yields the attacker nothing and is not reported.  An equality
  test would report all 11,172 precomposed syllables and so all
  Korean text.

  Distinct from the identity-spoofing detectors
  (HomoglyphConfusable,
  MixedScriptAdmissibility, EmojiZwjIntegrity /
  SkinToneVariationForgery) which examine the input under a
  single form.  This detector fires on the *form transition*
  itself, which the single-form detectors miss by construction.

  Distinct also from WidthClassConfusion (UAX #11 EAW class
  fold) and NfcIdempotenceWitness (form-of-input fold): this
  detector asks the orthogonal question "does the identifier
  verdict change under normalisation?", which is a stronger
  statement than "does any output bit change".

  Sub-threat (direction-agnostic):

    `identifierStatusShift (basePos, cp)` — first input position
    whose `Identifier_Status` differs from the `Identifier_Status`
    of its NFKD-head.  The verdict carries the shift count for
    downstream policy.
-/

import Unicode.Security.Calculus
import Unicode.Identifier
import Unicode.Normalization.NFKD

namespace Unicode.Security.Boundary.IdentifierFormDrift

open Unicode.Security.Calculus
open Unicode.Identifier (isAllowedStatus)

-- The `detect` spot checks reduce the NFKD + identifier-status pipeline on
-- concrete inputs; that nests deeper than the default reducer recursion budget.
set_option maxRecDepth 100000

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Per-position shift scan
-- ═══════════════════════════════════════════════════════════════════════════════

/-- `Identifier_Status` of the first codepoint of `cp`'s NFKD form,
    or `cp`'s own status when NFKD is empty (defensive — `toNFKD`
    is total and returns at least `[cp]` for any cp). -/
def nfkdHeadAllowed (cp : Nat) : Bool :=
  match Unicode.Normalization.NFKD.toNFKD [cp] with
  | []           => isAllowedStatus cp
  | head :: rest => Function.const (List Nat) (isAllowedStatus head) rest

/-- First input position whose `isAllowedStatus` differs from its
    NFKD-head's `isAllowedStatus`. -/
def firstStatusShift (input : List Nat) : Option (Nat × Nat) :=
  input.zipIdx.findSome? (fun cpWithIdx =>
    if !isAllowedStatus cpWithIdx.1 && nfkdHeadAllowed cpWithIdx.1 then
      some (cpWithIdx.2, cpWithIdx.1)
    else none)

/-- Total count of input positions where the per-cp status shifts
    under NFKD. -/
def statusShiftCount (input : List Nat) : Nat :=
  input.foldl (init := 0) (fun acc cp =>
    if !isAllowedStatus cp && nfkdHeadAllowed cp then acc + 1 else acc)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Types
-- ═══════════════════════════════════════════════════════════════════════════════

inductive SubThreat where
  | identifierStatusShift (basePos : Nat) (cp : Nat)
  deriving DecidableEq, Repr, Inhabited

inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : List Nat) (decoded : List UInt8)
  deriving Inhabited

structure Verdict where
  input      : List Nat
  classify   : Classification
  shiftCount : Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The IdentifierFormDrift detection function. -/
def detect (input : List Nat) : Verdict :=
  let classification : Classification :=
    match firstStatusShift input with
    | some (pos, cp) =>
      .hazard (.identifierStatusShift pos cp) [pos] []
    | none => .clear
  { input := input,
    classify := classification,
    shiftCount := statusShiftCount input }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

def SubThreat.tag : SubThreat → String
  | .identifierStatusShift basePos cp =>
    Function.const (Nat × Nat) "IdentifierStatusShift" (basePos, cp)

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
  decide

/-- Pure ASCII is clear; every ASCII letter is Allowed, identity NFKD. -/
theorem detect_ascii_clear :
    (detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  decide

/-- Greek lowercase α is Allowed with identity NFKD — clear. -/
theorem detect_greek_alpha_clear :
    (detect [0x03B1]).classify.isClear = true := by decide

/-- Math Italic Small A (U+1D44E) is Restricted; NFKD head U+0061
    is Allowed.  The canonical IdentifierFormDrift case. -/
theorem detect_math_italic_a_shift :
    (detect [0x1D44E]).classify.tag = some "IdentifierStatusShift" := by
  decide

/-- Fullwidth A (U+FF21) is Restricted (compatibility form); NFKD head
    U+0041 is Allowed. -/
theorem detect_fullwidth_A_shift :
    (detect [0xFF21]).classify.tag = some "IdentifierStatusShift" := by
  decide

end Unicode.Security.Boundary.IdentifierFormDrift
