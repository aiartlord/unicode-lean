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

namespace Unicode.Security.Form.NfcIdempotenceWitness

open Unicode.Security.Calculus

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 First-divergent-position helper
-- ═══════════════════════════════════════════════════════════════════════════════

/-- First index `i` at which `a[i] != b[i]`, or `min a.size b.size`
    when one is a strict prefix of the other (the position
    immediately past the shared prefix).  Returns `none` when the
    arrays are identical. -/
def firstDivergence (a b : Array Nat) : Option Nat :=
  let n := if a.size ≤ b.size then a.size else b.size
  match (Array.range n).findSome? (fun i =>
    if ha : i < a.size then
      if hb : i < b.size then
        if a[i] != b[i] then some i else none
      else none
    else none) with
  | some i => some i
  | none   => if a.size = b.size then none else some n

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Types
-- ═══════════════════════════════════════════════════════════════════════════════

inductive F6SubThreat where
  | nonNfcForm        (basePos : Nat)
  | nonNfkcCompatForm (basePos : Nat)
  deriving DecidableEq, Repr, Inhabited

inductive F6Classification where
  | clear
  | hazard (sub : F6SubThreat) (positions : Array Nat) (decoded : ByteArray)
  deriving Inhabited

structure F6Verdict where
  input    : Array Nat
  classify : F6Classification
  nfcLen   : Nat
  nfkcLen  : Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The F6 detection function. -/
def detect (input : Array Nat) : F6Verdict :=
  let nfc  := Unicode.Normalization.NFC.toNFC input
  let nfkc := Unicode.Normalization.NFKC.toNFKC input
  let classification : F6Classification :=
    match firstDivergence input nfc with
    | some pos =>
      .hazard (.nonNfcForm pos) #[pos] ByteArray.empty
    | none =>
      match firstDivergence input nfkc with
      | some pos =>
        .hazard (.nonNfkcCompatForm pos) #[pos] ByteArray.empty
      | none => .clear
  { input := input,
    classify := classification,
    nfcLen := nfc.size,
    nfkcLen := nfkc.size }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

def F6SubThreat.tag : F6SubThreat → String
  | .nonNfcForm        basePos =>
    Function.const Nat "NonNfcForm" basePos
  | .nonNfkcCompatForm basePos =>
    Function.const Nat "NonNfkcCompatForm" basePos

def F6Classification.isClear : F6Classification → Bool
  | .clear                       => true
  | .hazard sub positions decoded =>
    Function.const (F6SubThreat × Array Nat × ByteArray) false
      (sub, positions, decoded)

def F6Classification.tag : F6Classification → Option String
  | .clear                       => none
  | .hazard sub positions decoded =>
    Function.const (Array Nat × ByteArray) (some sub.tag) (positions, decoded)

def F6Classification.positions : F6Classification → Array Nat
  | .clear                       => #[]
  | .hazard sub positions decoded =>
    Function.const (F6SubThreat × ByteArray) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear. -/
theorem detect_empty_clear : (detect #[]).classify.isClear = true := by
  native_decide

/-- Pure ASCII is in NFC and NFKC. -/
theorem detect_ascii_clear :
    (detect #[0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  native_decide

/-- Pre-composed é (U+00E9) is canonical NFC; NFKC = NFC for this cp. -/
theorem detect_precomposed_e_clear :
    (detect #[0x00E9]).classify.isClear = true := by native_decide

/-- e + combining acute (decomposed é) fires `nonNfcForm` — NFC
    folds the pair into U+00E9, so `input != NFC(input)` at position 0. -/
theorem detect_decomposed_e_nfc :
    (detect #[0x0065, 0x0301]).classify.tag = some "NonNfcForm" := by
  native_decide

/-- ﬁ ligature (U+FB01) is canonical NFC (no canonical decomp),
    but NFKC = "fi" so `input != NFKC(input)` — fires
    `nonNfkcCompatForm`.  EAW = N so F5 doesn't catch this. -/
theorem detect_fi_ligature_nfkc :
    (detect #[0xFB01]).classify.tag = some "NonNfkcCompatForm" := by
  native_decide

end Unicode.Security.Form.NfcIdempotenceWitness
