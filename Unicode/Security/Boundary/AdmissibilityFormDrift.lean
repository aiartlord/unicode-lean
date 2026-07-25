/-
  Unicode.Security.Boundary.AdmissibilityFormDrift

  Cross-Layer Identifier-Admissibility × Form Drift.  Fires
  on inputs whose UTS #39 `isAllowedIdentifier` verdict differs
  between the input and its NFKC form.

  This is the string-level complement of
  `IdentifierFormDrift`: the per-codepoint detector scans
  `Identifier_Status` against the NFKD-head, while this
  detector evaluates the whole-string `isAllowedIdentifier`
  predicate twice — once on the input and once on
  `toNFKC(input)`.  The two are not redundant.  In particular,
  an input consisting entirely of decomposed Hangul jamos
  passes the per-codepoint scan cleanly (each jamo has
  identity NFKD and `Identifier_Status = Restricted` on both
  sides) but fires here (the jamo sequence is rejected by
  `isAllowedIdentifier`, while its NFKC composition into a
  precomposed Hangul syllable is accepted).

  Sub-threat (direction-agnostic):

    `admissibilityFormDrift (inputAdmissible, nfkcAdmissible)` —
    `isAllowedIdentifier input ≠ isAllowedIdentifier (toNFKC input)`.
    The pair of booleans is carried so the verdict records which
    direction the drift goes.  No position is reported because
    the predicate is whole-string.
-/

import Unicode.Security.Calculus
import Unicode.Identifier
import Unicode.Normalization.NFKC
import Unicode.Normalization.LowCodepointNfkc
import Unicode.Normalization.DetectorFormVectors

namespace Unicode.Security.Boundary.AdmissibilityFormDrift

open Unicode.Security.Calculus
open Unicode.Identifier (isAllowedIdentifier)

-- The `detect` spot checks evaluate the whole-string admissibility predicate on
-- concrete inputs and their NFKC forms; the NFKC form is supplied structurally
-- (never reducing the composition or row tables), leaving only the admissibility
-- range scans, which nest deeper than the default reducer recursion budget.
set_option maxRecDepth 100000

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

inductive SubThreat where
  | admissibilityFormDrift
      (inputAdmissible : Bool) (nfkcAdmissible : Bool)
  deriving DecidableEq, Repr, Inhabited

inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : List Nat) (decoded : ByteArray)
  deriving Inhabited

structure Verdict where
  input            : List Nat
  classify         : Classification
  inputAdmissible  : Bool
  nfkcAdmissible   : Bool
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The AdmissibilityFormDrift detection function. -/
def detect (input : List Nat) : Verdict :=
  let nfkc   := Unicode.Normalization.NFKC.toNFKC input
  let inOk   := isAllowedIdentifier input
  let nfkcOk := isAllowedIdentifier nfkc
  let classification : Classification :=
    if inOk = nfkcOk then .clear
    else .hazard (.admissibilityFormDrift inOk nfkcOk) [] ByteArray.empty
  { input := input,
    classify := classification,
    inputAdmissible := inOk,
    nfkcAdmissible := nfkcOk }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

def SubThreat.tag : SubThreat → String
  | .admissibilityFormDrift inOk nfkcOk =>
    Function.const (Bool × Bool) "AdmissibilityFormDrift" (inOk, nfkcOk)

def Classification.isClear : Classification → Bool
  | .clear                       => true
  | .hazard sub positions decoded =>
    Function.const (SubThreat × List Nat × ByteArray) false
      (sub, positions, decoded)

def Classification.tag : Classification → Option String
  | .clear                       => none
  | .hazard sub positions decoded =>
    Function.const (List Nat × ByteArray) (some sub.tag) (positions, decoded)

def Classification.positions : Classification → List Nat
  | .clear                       => []
  | .hazard sub positions decoded =>
    Function.const (SubThreat × ByteArray) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear: both `isAllowedIdentifier` calls return
    `false` (the empty sequence is not a default identifier), so
    the booleans agree. -/
theorem detect_empty_clear : (detect []).classify.isClear = true := by
  decide

/-- Pure ASCII admissible identifier — clear on both sides. NFKC is the identity
    on the all-ASCII input, established structurally, so the admissibility
    verdict agrees on both sides. -/
theorem detect_ascii_clear :
    (detect [0x61, 0x64, 0x6D, 0x69, 0x6E]).classify.isClear = true := by
  unfold detect
  rw [Unicode.Normalization.LowCodepointNfkc.toNFKC_id_of_starters
        [0x61, 0x64, 0x6D, 0x69, 0x6E] (by decide) (by decide)]
  decide

/-- ﬁ ligature (U+FB01) — not admissible (Restricted), but NFKC
    decomposes it to "fi" (admissible).  Fires drift. -/
theorem detect_fi_ligature_drift :
    (detect [0xFB01]).classify.tag = some "AdmissibilityFormDrift" := by
  unfold detect
  rw [Unicode.Normalization.DetectorFormVectors.toNFKC_ligature_fi]
  decide

/-- Decomposed Hangul jamos [0x1112, 0x1161, 0x11AB] — each jamo
    has identity NFKD and `Identifier_Status = Restricted` (so
    X1's per-cp scan reports no shift), but NFKC composes the
    sequence to U+D55C 한 (Allowed), flipping the whole-string
    admissibility verdict. -/
theorem detect_jamo_sequence_drift :
    (detect [0x1112, 0x1161, 0x11AB]).classify.tag =
      some "AdmissibilityFormDrift" := by
  unfold detect
  rw [Unicode.Normalization.DetectorFormVectors.toNFKC_jamo_han]
  decide

end Unicode.Security.Boundary.AdmissibilityFormDrift
