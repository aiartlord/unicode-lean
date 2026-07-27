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

  Detection strategy.  Pure-functional, no normalization loop
  required: compute `(NFD.toNFD input).length` and
  `(NFKD.toNFKD input).length`, then test against two
  whole-sequence thresholds plus a per-codepoint scan.

  Ratios are expressed in hundredths to avoid floats.

  Sub-threats (priority order):

    1. `singleCpBlowup`  — any single codepoint whose NFKD form
                          has size > `maxNfkdPerCp` (8). Catches
                          FDFA (18) and any future ligature whose
                          compatibility decomposition exceeds 8 cps.
    2. `nfkdHighExpansion` — overall NFKD ratio > `nfkdRatioPct`
                          (400 = 4×). Catches FDFB-class shapes
                          (per-cp NFKD = 8, ratio 800%) that pass
                          the per-cp scan but dominate the sequence.
    3. `nfdHighExpansion`  — overall NFD ratio > `nfdRatioPct`
                          (300 = 3×). Catches sequences of Greek
                          extended forms `U+1F82..1FA7` whose
                          canonical decomposition is 4 codepoints
                          each (ratio 400%). Pure Hangul stays clear
                          at exactly 300% under strict `>`.

  Threshold reachability is verified by the F1 fixture: each
  sub-threat has at least one row that fires it.
-/

import Unicode.Security.Calculus
import Unicode.Normalization.NFC
import Unicode.Normalization.NFKD

namespace Unicode.Security.Form.NormalizationBomb

open Unicode.Security.Calculus

-- The `detect` spot checks reduce the normalization pipeline on concrete inputs;
-- that nests deeper than the default reducer recursion budget.
set_option maxRecDepth 100000

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Constants
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Maximum allowed NFKD expansion per single codepoint.
    Korean Hangul syllables decompose to ≤ 3 jamos; Greek
    extended forms with smooth/rough + varia/oxia + ypogegrammeni
    expand to 4; the largest non-FDFA Arabic ligature (FDFB)
    expands to 8.  Anything > 8 is flagged.  NFKD is checked
    rather than NFD because Arabic ligatures like U+FDFA carry a
    *compatibility* decomposition (18 codepoints) — they do not
    decompose at all under pure NFD, but their NFKD form is the
    canonical bomb shape.  Chosen so FDFB (8 NFKD) passes the
    per-cp gate and falls through to the NFKD ratio check. -/
def maxNfkdPerCp : Nat := 8

/-- Overall-sequence NFD expansion ratio threshold, expressed
    in hundredths.  `300` means the NFD form may be at most 3×
    the input length before firing the hazard.  Pure Hangul has
    NFD ratio = exactly 300 and stays clear under strict `>`. -/
def nfdRatioPct : Nat := 300

/-- Overall-sequence NFKD expansion ratio threshold, in
    hundredths.  `400` = 4× input length.  Greek-only sequences
    of `1F82..1FA7` family (NFKD = 4) sit at exactly 400 and
    stay clear under strict `>` — they are picked up instead by
    `nfdHighExpansion`, since NFD = NFKD for these codepoints. -/
def nfkdRatioPct : Nat := 400

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Types
-- ═══════════════════════════════════════════════════════════════════════════════

inductive SubThreat where
  | singleCpBlowup    (basePos : Nat) (cp : Nat) (expandsTo : Nat)
  | nfkdHighExpansion (nfkdLen : Nat) (inputLen : Nat)
  | nfdHighExpansion  (nfdLen : Nat) (inputLen : Nat)
  deriving DecidableEq, Repr, Inhabited

inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : List Nat) (decoded : List UInt8)
  deriving Inhabited

structure Verdict where
  input              : List Nat
  classify           : Classification
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
def firstBlowupCp (input : List Nat) : Option (Nat × Nat × Nat) :=
  input.zipIdx.findSome? (fun cpWithIdx =>
    let expand := (Unicode.Normalization.NFKD.toNFKD [cpWithIdx.1]).length
    if expand > maxNfkdPerCp then
      some (cpWithIdx.2, cpWithIdx.1, expand)
    else none)

/-- Maximum NFKD-expansion any single codepoint in `input` produces. -/
def maxPerCpExpansion (input : List Nat) : Nat :=
  input.foldl (init := 0) (fun acc cp =>
    let e := (Unicode.Normalization.NFKD.toNFKD [cp]).length
    if e > acc then e else acc)

/-- NFD ratio percentage = `100 * nfdLen / inputLen`.  Returns
    `0` for an empty input (vacuously within bound). -/
def nfdRatioPctOf (input : List Nat) : Nat :=
  if input.length = 0 then 0
  else (Unicode.Normalization.NFC.toNFD input).length * 100 / input.length

/-- NFKD ratio percentage = `100 * nfkdLen / inputLen`. -/
def nfkdRatioPctOf (input : List Nat) : Nat :=
  if input.length = 0 then 0
  else (Unicode.Normalization.NFKD.toNFKD input).length * 100 / input.length

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The F1 detection function. -/
def detect (input : List Nat) : Verdict :=
  let nfdLen := (Unicode.Normalization.NFC.toNFD input).length
  let nfkdLen := (Unicode.Normalization.NFKD.toNFKD input).length
  let inputLen := input.length
  let maxPer := maxPerCpExpansion input
  let classification : Classification :=
    -- Priority 1: per-codepoint blow-up.
    match firstBlowupCp input with
    | some (pos, cp, expand) =>
      .hazard (.singleCpBlowup pos cp expand) [pos] []
    | none =>
      -- Priority 2: NFKD ratio.
      if nfkdRatioPctOf input > nfkdRatioPct then
        .hazard (.nfkdHighExpansion nfkdLen inputLen) [] []
      -- Priority 3: NFD ratio (lower than NFKD; usually triggers
      -- only on extreme cases).
      else if nfdRatioPctOf input > nfdRatioPct then
        .hazard (.nfdHighExpansion nfdLen inputLen) [] []
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

def SubThreat.tag : SubThreat → String
  | .singleCpBlowup     basePos cp expand =>
      Function.const (Nat × Nat × Nat) "SingleCpBlowup" (basePos, cp, expand)
  | .nfkdHighExpansion  nfkdLen inputLen =>
      Function.const (Nat × Nat) "NfkdHighExpansion" (nfkdLen, inputLen)
  | .nfdHighExpansion   nfdLen inputLen =>
      Function.const (Nat × Nat) "NfdHighExpansion" (nfdLen, inputLen)

def Classification.isClear : Classification → Bool
  | .clear                     => true
  | .hazard sub positions decoded =>
      Function.const (SubThreat × List Nat × List UInt8) false
        (sub, positions, decoded)

def Classification.tag : Classification → Option String
  | .clear                     => none
  | .hazard sub positions decoded =>
      Function.const (List Nat × List UInt8) (some sub.tag) (positions, decoded)

def Classification.positions : Classification → List Nat
  | .clear                     => []
  | .hazard sub positions decoded =>
      Function.const (SubThreat × List UInt8) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear. -/
theorem detect_empty_clear : (detect []).classify.isClear = true := by
  decide

/-- Pure ASCII is clear (no expansion). -/
theorem detect_ascii_clear :
    (detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  decide

/-- Korean Hangul `한` (U+D55C) decomposes to 3 jamos under NFD —
    within the per-cp bound of 4, so this stays clear. -/
theorem detect_korean_within_bound :
    (detect [0xD55C]).classify.isClear = true := by decide

/-- The Arabic ligature `U+FDFA SALLALLAHOU ALAYHE WASALLAM`
    decomposes to 18 codepoints under NFKD — fires
    `.singleCpBlowup` because NFD alone exceeds 4. -/
theorem detect_arabic_ligature_blowup :
    (detect [0xFDFA]).classify.tag = some "SingleCpBlowup" := by
  decide

/-- Parenthesized digit `①` (U+2460) expands under NFKD to `1`
    (1 cp → 1 cp), so it does not trigger NFD blow-up.  Under
    pure NFD it stays as-is.  The detector classifies as clear. -/
theorem detect_circled_one_clear :
    (detect [0x2460]).classify.isClear = true := by decide

end Unicode.Security.Form.NormalizationBomb
