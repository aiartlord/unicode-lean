/-
  Unicode.Security.Boundary.AdmissibilityFormDrift

  X4 — Cross-Layer Identifier-Admissibility × Form Drift.  Fires
  on inputs whose UTS #39 `isAllowedIdentifier` verdict differs
  between the input and its NFKC form.

  X4 is the string-level complement of X1: X1 scans per-codepoint
  `Identifier_Status` against the NFKD-head, while X4 evaluates
  the whole-string `isAllowedIdentifier` predicate twice — once
  on the input and once on `toNFKC(input)`.  The two detectors
  are not redundant.  In particular, an input consisting entirely
  of decomposed Hangul jamos passes X1 cleanly (each jamo has
  identity NFKD and `Identifier_Status = Restricted` on both
  sides) but fires X4 (the jamo sequence is rejected by
  `isAllowedIdentifier`, while its NFKC composition into a
  precomposed Hangul syllable is accepted).

  Sub-threat (v1, single, direction-agnostic):

    1. `admissibilityFormDrift (inputAdmissible, nfkcAdmissible)` —
       `isAllowedIdentifier input ≠ isAllowedIdentifier (toNFKC input)`.
       The pair of booleans is carried so the verdict records
       which direction the drift goes.  No position is reported
       because the predicate is whole-string.
-/

import Unicode.Security.Calculus
import Unicode.Identifier
import Unicode.Normalization.NFKC

namespace Unicode.Security.Boundary.AdmissibilityFormDrift

open Unicode.Security.Calculus
open Unicode.Identifier (isAllowedIdentifier)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

inductive X4SubThreat where
  | admissibilityFormDrift
      (inputAdmissible : Bool) (nfkcAdmissible : Bool)
  deriving DecidableEq, Repr, Inhabited

inductive X4Classification where
  | clear
  | hazard (sub : X4SubThreat) (positions : Array Nat) (decoded : ByteArray)
  deriving Inhabited

structure X4Verdict where
  input            : Array Nat
  classify         : X4Classification
  inputAdmissible  : Bool
  nfkcAdmissible   : Bool
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The X4 detection function. -/
def detect (input : Array Nat) : X4Verdict :=
  let nfkc   := Unicode.Normalization.NFKC.toNFKC input
  let inOk   := isAllowedIdentifier input
  let nfkcOk := isAllowedIdentifier nfkc
  let classification : X4Classification :=
    if inOk = nfkcOk then .clear
    else .hazard (.admissibilityFormDrift inOk nfkcOk) #[] ByteArray.empty
  { input := input,
    classify := classification,
    inputAdmissible := inOk,
    nfkcAdmissible := nfkcOk }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

def X4SubThreat.tag : X4SubThreat → String
  | .admissibilityFormDrift inOk nfkcOk =>
    Function.const (Bool × Bool) "AdmissibilityFormDrift" (inOk, nfkcOk)

def X4Classification.isClear : X4Classification → Bool
  | .clear                       => true
  | .hazard sub positions decoded =>
    Function.const (X4SubThreat × Array Nat × ByteArray) false
      (sub, positions, decoded)

def X4Classification.tag : X4Classification → Option String
  | .clear                       => none
  | .hazard sub positions decoded =>
    Function.const (Array Nat × ByteArray) (some sub.tag) (positions, decoded)

def X4Classification.positions : X4Classification → Array Nat
  | .clear                       => #[]
  | .hazard sub positions decoded =>
    Function.const (X4SubThreat × ByteArray) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear: both `isAllowedIdentifier` calls return
    `false` (the empty sequence is not a default identifier), so
    the booleans agree. -/
theorem detect_empty_clear : (detect #[]).classify.isClear = true := by
  native_decide

/-- Pure ASCII admissible identifier — clear on both sides. -/
theorem detect_ascii_clear :
    (detect #[0x61, 0x64, 0x6D, 0x69, 0x6E]).classify.isClear = true := by
  native_decide

/-- ﬁ ligature (U+FB01) — not admissible (Restricted), but NFKC
    decomposes it to "fi" (admissible).  Fires drift. -/
theorem detect_fi_ligature_drift :
    (detect #[0xFB01]).classify.tag = some "AdmissibilityFormDrift" := by
  native_decide

/-- Decomposed Hangul jamos #[0x1112, 0x1161, 0x11AB] — each jamo
    is Restricted (input not admissible), NFKC composes to U+D55C
    (admissible Hangul syllable).  This is the canonical case
    that X1 misses by construction. -/
theorem detect_jamo_sequence_drift :
    (detect #[0x1112, 0x1161, 0x11AB]).classify.tag =
      some "AdmissibilityFormDrift" := by
  native_decide

end Unicode.Security.Boundary.AdmissibilityFormDrift
