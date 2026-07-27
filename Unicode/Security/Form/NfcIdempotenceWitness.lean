/-
  Unicode.Security.Form.NfcIdempotenceWitness

  F6 — Detection of inputs that are not in NFC or NFKC, the
  canonical "form mismatch" surface for cross-stage normalisation
  bugs.  Per UAX #15, NFC and NFKC are idempotent — but only if
  applied.  A receiver that compares `input` against a stored
  value without normalising first will silently miss the match
  when the peer's input is canonically equivalent but in a
  different form.

  Threat model.  Tier A₂.  Two-system bypass shape: the
  attacker submits text in a non-NFC form (e.g. `e + combining
  acute` for `é`) that:

    * passes a validator that normalises and compares against
      a stored canonical form, OR
    * fails one validator but passes another that doesn't
      normalise.

  Either way, the attacker controls the form that reaches each
  stage and exploits the mismatch.

  Detection compares `input` against `toNFC(input)` and
  `toNFKC(input)` element-wise, reporting the first divergent
  position.

  Distinct from neighbouring detectors:

    * F1 NormalizationBomb         — large-size expansions
    * F4 CaseExpansionMismatch     — length change under case
    * F5 WidthClassConfusion       — EAW class change under NFKD

  F6 is the residual catch-all: any cp where NFC or NFKC alters
  the input form, regardless of size, case, or width class.
  F6 fires on shapes the other detectors do not, especially
  compatibility ligatures with EAW = N (e.g. U+FB01 ﬁ) which
  F5 misses by design.

  Sub-threats (priority order):

    1. `nonNfcForm (basePos)` — `input != NFC(input)`.  The
       input is not in canonical composition form; any
       comparison against a canonical-stored peer silently
       misses.
    2. `nonNfkcCompatForm (basePos)` — `input == NFC(input)`
       but `input != NFKC(input)`.  Canonical form is fine,
       but compatibility decomposition would re-fold.  Reached
       only when nonNfcForm doesn't fire first.
-/

import Unicode.Security.Calculus
import Unicode.Normalization.NFC
import Unicode.Normalization.NFKC
import Unicode.Normalization.LowCodepointNfc
import Unicode.Normalization.LowCodepointNfkc
import Unicode.Normalization.DetectorFormVectors

namespace Unicode.Security.Form.NfcIdempotenceWitness

open Unicode.Security.Calculus

-- The `detect` spot checks reduce the normalization pipeline on concrete inputs;
-- that nests deeper than the default reducer recursion budget.
set_option maxRecDepth 100000

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 First-divergent-position helper
-- ═══════════════════════════════════════════════════════════════════════════════

/-- First index at which the two lists differ, or the position
    immediately past the shared prefix when one is a strict prefix
    of the other.  Returns `none` when the lists are identical.
    Structural recursion — one traversal, no index arithmetic. -/
def firstDivergence : List Nat → List Nat → Option Nat
  | [], [] => none
  | [], bHead :: bTail =>
    Function.const (Nat × List Nat) (some 0) (bHead, bTail)
  | aHead :: aTail, [] =>
    Function.const (Nat × List Nat) (some 0) (aHead, aTail)
  | aHead :: aTail, bHead :: bTail =>
    if aHead != bHead then some 0
    else (firstDivergence aTail bTail).map (fun i => i + 1)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Types
-- ═══════════════════════════════════════════════════════════════════════════════

inductive SubThreat where
  | nonNfcForm        (basePos : Nat)
  | nonNfkcCompatForm (basePos : Nat)
  deriving DecidableEq, Repr, Inhabited

inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : List Nat) (decoded : List UInt8)
  deriving Inhabited

structure Verdict where
  input    : List Nat
  classify : Classification
  nfcLen   : Nat
  nfkcLen  : Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The F6 detection function. -/
def detect (input : List Nat) : Verdict :=
  let nfc  := Unicode.Normalization.NFC.toNFC input
  let nfkc := Unicode.Normalization.NFKC.toNFKC input
  let classification : Classification :=
    match firstDivergence input nfc with
    | some pos =>
      .hazard (.nonNfcForm pos) [pos] []
    | none =>
      match firstDivergence input nfkc with
      | some pos =>
        .hazard (.nonNfkcCompatForm pos) [pos] []
      | none => .clear
  { input := input,
    classify := classification,
    nfcLen := nfc.length,
    nfkcLen := nfkc.length }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

def SubThreat.tag : SubThreat → String
  | .nonNfcForm        basePos =>
    Function.const Nat "NonNfcForm" basePos
  | .nonNfkcCompatForm basePos =>
    Function.const Nat "NonNfkcCompatForm" basePos

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

/-- Pure ASCII is in NFC and NFKC. Both normal forms are the identity on an
    all-ASCII sequence — established structurally, so neither the composition
    table nor the `UnicodeData` row scan is reduced. -/
theorem detect_ascii_clear :
    (detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  unfold detect
  rw [Unicode.Normalization.LowCodepointNfc.toNFC_id_all_lt
        [0x48, 0x65, 0x6C, 0x6C, 0x6F] (by decide),
      Unicode.Normalization.LowCodepointNfkc.toNFKC_id_of_starters
        [0x48, 0x65, 0x6C, 0x6C, 0x6F] (by decide) (by decide)]
  decide

/-- Pre-composed é (U+00E9) is canonical NFC; NFKC = NFC for this cp. -/
theorem detect_precomposed_e_clear :
    (detect [0x00E9]).classify.isClear = true := by decide

/-- e + combining acute (decomposed é) fires `nonNfcForm` — NFC
    folds the pair into U+00E9, so `input != NFC(input)` at position 0. -/
theorem detect_decomposed_e_nfc :
    (detect [0x0065, 0x0301]).classify.tag = some "NonNfcForm" := by
  decide

/-- ﬁ ligature (U+FB01) is canonical NFC (no canonical decomp),
    but NFKC = "fi" so `input != NFKC(input)` — fires
    `nonNfkcCompatForm`.  EAW = N so F5 doesn't catch this. -/
theorem detect_fi_ligature_nfkc :
    (detect [0xFB01]).classify.tag = some "NonNfkcCompatForm" := by
  unfold detect
  rw [Unicode.Normalization.DetectorFormVectors.toNFC_ligature_fi,
      Unicode.Normalization.DetectorFormVectors.toNFKC_ligature_fi]
  decide

end Unicode.Security.Form.NfcIdempotenceWitness
