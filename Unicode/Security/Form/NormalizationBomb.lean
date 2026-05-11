/-
  Unicode.Security.Form.NormalizationBomb

  F1 — Detection of normalization-expansion-bomb DoS shapes per
  UAX #15.  Inputs whose NFD or NFKD expansion ratio exceeds a
  documented per-codepoint or per-sequence bound are flagged.

  Threat model.  Tier A₁..A₂.  Adversary submits a small input
  that expands to a very large normalized form, exhausting
  memory or CPU at the receiving layer.  The classic shapes:

    * Arabic ligature `U+FDFA SALLALLAHOU ALAYHE WASALLAM`
      decomposes to 18 codepoints under NFKD.
    * Korean Hangul syllables decompose to 2-3 jamos under NFD.
    * Parenthesized digits (`①` → `1`, `⓪` → `0`) and circled
      letters expand under NFKD/NFKC.

  v1 detection strategy.  Pure-functional, no normalization
  loop required: we compute `(NFD.toNFD input).size` and
  `(NFKD.toNFKD input).size`, then test against two
  whole-sequence thresholds plus a per-codepoint scan.

  Ratios are expressed in hundredths to avoid floats.

  Sub-threats (priority order):

    1. `singleCpBlowup`  — any single codepoint whose NFD form
                          has size > `maxNfdPerCp` (4).
    2. `nfkdHighExpansion` — overall NFKD ratio > `nfkdRatioPct`
                          (400 = 4×).
    3. `nfdHighExpansion`  — overall NFD ratio > `nfdRatioPct`
                          (300 = 3×).
-/

import Unicode.Security.Calculus
import Unicode.Normalization.NFC
import Unicode.Normalization.NFKD

namespace Unicode.Security.Form.NormalizationBomb

open Unicode.Security.Calculus

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Constants
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Maximum allowed NFKD expansion per single codepoint.
    Korean Hangul syllables decompose to ≤ 3 jamos under NFKD;
    most other codepoints stay within 4.  Anything > 4 is
    flagged.  NFKD is checked rather than NFD because Arabic
    ligatures like U+FDFA carry a *compatibility* decomposition
    (18 codepoints) — they do not decompose at all under pure
    NFD, but their NFKD form is the canonical bomb shape. -/
def maxNfkdPerCp : Nat := 4

/-- Overall-sequence NFD expansion ratio threshold, expressed
    in hundredths.  `300` means the NFD form may be at most 3×
    the input length before firing the hazard. -/
def nfdRatioPct : Nat := 300

/-- Overall-sequence NFKD expansion ratio threshold, in
    hundredths.  `400` = 4× input length. -/
def nfkdRatioPct : Nat := 400

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Types
-- ═══════════════════════════════════════════════════════════════════════════════

inductive F1SubThreat where
  | singleCpBlowup    (basePos : Nat) (cp : Nat) (expandsTo : Nat)
  | nfkdHighExpansion (nfkdLen : Nat) (inputLen : Nat)
  | nfdHighExpansion  (nfdLen : Nat) (inputLen : Nat)
  deriving DecidableEq, Repr, Inhabited

inductive F1Classification where
  | clear
  | hazard (sub : F1SubThreat) (positions : Array Nat) (decoded : ByteArray)
  deriving Inhabited

structure F1Verdict where
  input              : Array Nat
  classify           : F1Classification
  nfdLen             : Nat
  nfkdLen            : Nat
  inputLen           : Nat
  maxPerCpExpansion  : Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Sub-detectors
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Find the first position in `input` whose single-codepoint
    NFKD expansion exceeds `maxNfkdPerCp`.  Returns
    `some (pos, cp, expansionLen)`.  NFKD (compatibility) is
    checked rather than NFD (canonical) because the canonical
    examples of normalization bombs — Arabic ligatures, parenthesised
    digits — carry only compatibility decompositions. -/
def firstBlowupCp (input : Array Nat) : Option (Nat × Nat × Nat) :=
  (Array.range input.size).findSome? (fun i =>
    if h : i < input.size then
      let cp := input[i]
      let expand := (Unicode.Normalization.NFKD.toNFKD #[cp]).size
      if expand > maxNfkdPerCp then some (i, cp, expand) else none
    else none)

/-- Maximum NFKD-expansion any single codepoint in `input` produces. -/
def maxPerCpExpansion (input : Array Nat) : Nat :=
  input.foldl (init := 0) (fun acc cp =>
    let e := (Unicode.Normalization.NFKD.toNFKD #[cp]).size
    if e > acc then e else acc)

/-- NFD ratio percentage = `100 * nfdLen / inputLen`.  Returns
    `0` for an empty input (vacuously within bound). -/
def nfdRatioPctOf (input : Array Nat) : Nat :=
  if input.size = 0 then 0
  else (Unicode.Normalization.NFC.toNFD input).size * 100 / input.size

/-- NFKD ratio percentage = `100 * nfkdLen / inputLen`. -/
def nfkdRatioPctOf (input : Array Nat) : Nat :=
  if input.size = 0 then 0
  else (Unicode.Normalization.NFKD.toNFKD input).size * 100 / input.size

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The F1 detection function. -/
def detect (input : Array Nat) : F1Verdict :=
  let nfdLen := (Unicode.Normalization.NFC.toNFD input).size
  let nfkdLen := (Unicode.Normalization.NFKD.toNFKD input).size
  let inputLen := input.size
  let maxPer := maxPerCpExpansion input
  let classification : F1Classification :=
    -- Priority 1: per-codepoint blow-up.
    match firstBlowupCp input with
    | some (pos, cp, expand) =>
      .hazard (.singleCpBlowup pos cp expand) #[pos] ByteArray.empty
    | none =>
      -- Priority 2: NFKD ratio.
      if nfkdRatioPctOf input > nfkdRatioPct then
        .hazard (.nfkdHighExpansion nfkdLen inputLen) #[] ByteArray.empty
      -- Priority 3: NFD ratio (lower than NFKD; usually triggers
      -- only on extreme cases).
      else if nfdRatioPctOf input > nfdRatioPct then
        .hazard (.nfdHighExpansion nfdLen inputLen) #[] ByteArray.empty
      else
        .clear
  { input := input,
    classify := classification,
    nfdLen := nfdLen,
    nfkdLen := nfkdLen,
    inputLen := inputLen,
    maxPerCpExpansion := maxPer }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

def F1SubThreat.tag : F1SubThreat → String
  | .singleCpBlowup     basePos cp expand =>
      Function.const (Nat × Nat × Nat) "SingleCpBlowup" (basePos, cp, expand)
  | .nfkdHighExpansion  nfkdLen inputLen =>
      Function.const (Nat × Nat) "NfkdHighExpansion" (nfkdLen, inputLen)
  | .nfdHighExpansion   nfdLen inputLen =>
      Function.const (Nat × Nat) "NfdHighExpansion" (nfdLen, inputLen)

def F1Classification.isClear : F1Classification → Bool
  | .clear                     => true
  | .hazard sub positions decoded =>
      Function.const (F1SubThreat × Array Nat × ByteArray) false
        (sub, positions, decoded)

def F1Classification.tag : F1Classification → Option String
  | .clear                     => none
  | .hazard sub positions decoded =>
      Function.const (Array Nat × ByteArray) (some sub.tag) (positions, decoded)

def F1Classification.positions : F1Classification → Array Nat
  | .clear                     => #[]
  | .hazard sub positions decoded =>
      Function.const (F1SubThreat × ByteArray) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear. -/
theorem detect_empty_clear : (detect #[]).classify.isClear = true := by
  native_decide

/-- Pure ASCII is clear (no expansion). -/
theorem detect_ascii_clear :
    (detect #[0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  native_decide

/-- Korean Hangul `한` (U+D55C) decomposes to 3 jamos under NFD —
    within the per-cp bound of 4, so this stays clear. -/
theorem detect_korean_within_bound :
    (detect #[0xD55C]).classify.isClear = true := by native_decide

/-- The Arabic ligature `U+FDFA SALLALLAHOU ALAYHE WASALLAM`
    decomposes to 18 codepoints under NFKD — fires
    `.singleCpBlowup` because NFD alone exceeds 4. -/
theorem detect_arabic_ligature_blowup :
    (detect #[0xFDFA]).classify.tag = some "SingleCpBlowup" := by
  native_decide

/-- Parenthesized digit `①` (U+2460) expands under NFKD to `1`
    (1 cp → 1 cp), so it does NOT trigger NFD blow-up.  Under
    pure NFD it stays as-is.  v1 detector classifies as clear. -/
theorem detect_circled_one_clear :
    (detect #[0x2460]).classify.isClear = true := by native_decide

end Unicode.Security.Form.NormalizationBomb
