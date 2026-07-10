/-
  Unicode.Security.Form.StreamSafeViolation

  F2 — Detection of Stream-Safe Text Format violations per
  UAX #15 § 13.  Inputs whose consecutive non-starter (non-zero
  Canonical_Combining_Class) run exceeds the streamSafeLimit of
  30 force unbounded combining-mark buffers in receiver-side
  normalization and are a known DoS vector.

  Threat model.  Tier A₁.  An adversary submits an input that
  contains a single base codepoint followed by a long combining-
  mark run (the canonical "Zalgo" shape):

      "a" + U+0301 × N        — for N > 30 the buffer used by
                                streaming `toNFC` / `toNFD` /
                                `toNFKC` / `toNFKD` grows
                                unboundedly with N.

  UAX #15 § 13 defines Stream-Safe Text Format as the canonical
  remediation: insert U+034F COMBINING GRAPHEME JOINER (a starter)
  after every 30 consecutive non-starters.  The 30-codepoint cap
  bounds the normalization buffer by `O(input.size)` plus a fixed
  constant.

  StreamSafeViolation is the security verdict over the same
  property.  Distinct from RendererDivergence's
  `combiningStackOverflow` (which fires at the cosmetic Zalgo
  threshold of 4 marks per base for renderer-divergence reasons)
  — StreamSafeViolation is the spec-mandated DoS-prevention bound.

  Sub-threat:

    `streamSafeOverrun (basePos, runLen)` — first non-starter
    run whose length exceeds `streamSafeLimit`.
-/

import Unicode.Security.Calculus
import Unicode.StreamSafe
import Unicode.Normalization.Reorder

namespace Unicode.Security.Form.StreamSafeViolation

open Unicode.Security.Calculus
open Unicode.StreamSafe (streamSafeLimit isNonStarter)
open Unicode.Normalization.Lookup (canonicalCombiningClass
  canonicalCombiningClass_of_lookupRow_none lookupRow_none_of_all_outside)
open Unicode.Normalization.Reorder (ccc_combining_acute)
open Unicode.Generated.UnicodeData (rowsList)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Run inventory
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Recursive scan that accumulates `(runStart, runLen)` pairs for
    every maximal non-starter run in the input.  `curStart` is
    `some i` while we are inside an open run, `none` otherwise.
    Fuel is bounded by `input.size + 1` so termination is automatic. -/
def collectRunsGo (input : Array Nat) (i : Nat)
    (curStart : Option Nat) (curLen : Nat)
    (runs : Array (Nat × Nat)) (fuel : Nat) : Array (Nat × Nat) :=
  match fuel with
  | 0 => runs
  | fuel' + 1 =>
    if h : i < input.size then
      let cp := input[i]
      if isNonStarter cp then
        let s := curStart.getD i
        collectRunsGo input (i + 1) (some s) (curLen + 1) runs fuel'
      else
        let runs' :=
          match curStart with
          | some s => runs.push (s, curLen)
          | none   => runs
        collectRunsGo input (i + 1) none 0 runs' fuel'
    else
      match curStart with
      | some s => runs.push (s, curLen)
      | none   => runs

/-- Inventory of `(startIndex, length)` for every maximal non-starter
    run in `input`. -/
def nonStarterRuns (input : Array Nat) : Array (Nat × Nat) :=
  collectRunsGo input 0 none 0 #[] (input.size + 1)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1a Uniform-run evaluation
--
-- The concrete spot-check vectors below are a starter followed by a block
-- of identical non-starters. Reducing `collectRunsGo` over such a block by
-- unfolding it element by element (`simp` / `decide`) explodes the proof
-- term. Instead these two lemmas evaluate an all-non-starter suffix
-- abstractly by induction on the fuel — the run scan never touches the row
-- tables, and the term stays O(1) in the block length.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- An open non-starter run that continues to the end of the input closes
    into a single `(start, length)` entry, its length extended by the count
    of remaining codepoints. -/
theorem collectRunsGo_open_to_end (input : Array Nat) :
    ∀ (fuel i s curLen : Nat) (runs : Array (Nat × Nat)),
      input.size - i < fuel →
      (∀ j, i ≤ j → (hj : j < input.size) → isNonStarter input[j] = true) →
      collectRunsGo input i (some s) curLen runs fuel
        = runs.push (s, curLen + (input.size - i)) := by
  intro fuel
  induction fuel with
  | zero =>
    intro i s curLen runs hFuel _hAll
    exact absurd hFuel (by omega)
  | succ fuel' ih =>
    intro i s curLen runs hFuel hAll
    unfold collectRunsGo
    by_cases h : i < input.size
    · rw [dif_pos h]
      have hns : isNonStarter input[i] = true := hAll i (Nat.le_refl i) h
      simp only [hns, if_true, Option.getD_some]
      rw [ih (i + 1) s (curLen + 1) runs (by omega)
            (fun j hj hjs => hAll j (by omega) hjs)]
      have harith : curLen + 1 + (input.size - (i + 1)) = curLen + (input.size - i) := by
        omega
      rw [harith]
    · rw [dif_neg h]
      have hEmpty : input.size - i = 0 := by omega
      simp only [hEmpty, Nat.add_zero]

/-- Reaching a non-starter block from a closed state (`curStart = none`)
    opens and then closes it into one `(start, length)` entry. The closed
    state always carries `curLen = 0`, so the opened run's length is
    exactly the count of remaining codepoints. -/
theorem collectRunsGo_none_to_end (input : Array Nat)
    (fuel i : Nat) (runs : Array (Nat × Nat))
    (hFuel : input.size - i < fuel) (hi : i < input.size)
    (hAll : ∀ j, i ≤ j → (hj : j < input.size) → isNonStarter input[j] = true) :
    collectRunsGo input i none 0 runs fuel
      = runs.push (i, input.size - i) := by
  cases fuel with
  | zero => exact absurd hFuel (by omega)
  | succ fuel' =>
    unfold collectRunsGo
    rw [dif_pos hi]
    have hns : isNonStarter input[i] = true := hAll i (Nat.le_refl i) hi
    simp only [hns, if_true, Option.getD_none]
    rw [collectRunsGo_open_to_end input fuel' (i + 1) i (0 + 1) runs (by omega)
          (fun j hj hjs => hAll j (by omega) hjs)]
    have harith : 0 + 1 + (input.size - (i + 1)) = input.size - i := by omega
    rw [harith]

/-- Peel one leading starter: from a closed state a starter advances the
    index without opening a run. Only the left side is unfolded, so the
    residual scan on the right stays folded. -/
theorem collectRunsGo_starter_step (input : Array Nat)
    (fuel i curLen : Nat) (runs : Array (Nat × Nat))
    (hi : i < input.size) (hs : isNonStarter input[i] = false) :
    collectRunsGo input i none curLen runs (fuel + 1)
      = collectRunsGo input (i + 1) none 0 runs fuel := by
  rw [collectRunsGo.eq_def]
  simp [hi, hs]

/-- An all-starter suffix contributes no runs. -/
theorem collectRunsGo_none_all_starters (input : Array Nat) :
    ∀ (fuel i curLen : Nat) (runs : Array (Nat × Nat)),
      input.size - i < fuel →
      (∀ j, i ≤ j → (hj : j < input.size) → isNonStarter input[j] = false) →
      collectRunsGo input i none curLen runs fuel = runs := by
  intro fuel
  induction fuel with
  | zero =>
    intro i curLen runs hFuel _hAll
    exact absurd hFuel (by omega)
  | succ fuel' ih =>
    intro i curLen runs hFuel hAll
    unfold collectRunsGo
    by_cases h : i < input.size
    · rw [dif_pos h]
      have hs : isNonStarter input[i] = false := hAll i (Nat.le_refl i) h
      simp only [hs, Bool.false_eq_true, if_false]
      exact ih (i + 1) 0 runs (by omega) (fun j hj hjs => hAll j (by omega) hjs)
    · rw [dif_neg h]

/-- First non-starter run whose length exceeds `streamSafeLimit`. -/
def firstOverrun (input : Array Nat) : Option (Nat × Nat) :=
  (nonStarterRuns input).find? (fun p => p.2 > streamSafeLimit)

/-- Longest non-starter run length in `input`. -/
def maxRunLen (input : Array Nat) : Nat :=
  (nonStarterRuns input).foldl (init := 0) (fun acc p =>
    if p.2 > acc then p.2 else acc)

/-- Number of distinct non-starter runs that exceed `streamSafeLimit`. -/
def overrunCount (input : Array Nat) : Nat :=
  (nonStarterRuns input).foldl (init := 0) (fun acc p =>
    if p.2 > streamSafeLimit then acc + 1 else acc)

/-- Total non-starter codepoints in `input` (sum of all run lengths). -/
def totalNonStarters (input : Array Nat) : Nat :=
  (nonStarterRuns input).foldl (init := 0) (fun acc p => acc + p.2)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Types
-- ═══════════════════════════════════════════════════════════════════════════════

inductive SubThreat where
  | streamSafeOverrun (basePos : Nat) (runLen : Nat)
  deriving DecidableEq, Repr, Inhabited

inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : Array Nat) (decoded : ByteArray)
  deriving Inhabited

structure Verdict where
  input            : Array Nat
  classify         : Classification
  maxRunLen        : Nat
  overrunCount     : Nat
  totalNonStarters : Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The F2 detection function. -/
def detect (input : Array Nat) : Verdict :=
  let classification : Classification :=
    match firstOverrun input with
    | some (basePos, runLen) =>
      .hazard (.streamSafeOverrun basePos runLen) #[basePos] ByteArray.empty
    | none => .clear
  { input := input,
    classify := classification,
    maxRunLen := maxRunLen input,
    overrunCount := overrunCount input,
    totalNonStarters := totalNonStarters input }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

def SubThreat.tag : SubThreat → String
  | .streamSafeOverrun basePos runLen =>
    Function.const (Nat × Nat) "StreamSafeOverrun" (basePos, runLen)

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
--
-- The run inventory consults `canonicalCombiningClass` per codepoint via
-- `isNonStarter`, which must never reduce the row scan (see the
-- fact-transport section of `Unicode.Normalization.Lookup`). The ASCII
-- starters in these vectors are covered by one interval-absence pass;
-- the combining acute reuses `Reorder.ccc_combining_acute`. The run
-- scan then evaluates by simp at concrete arguments only.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- No pinned row carries a codepoint in the `H`..`o` ASCII band used by
    the spot-check vectors. -/
theorem rows_omit_ascii_band :
    rowsList.all (fun r =>
      decide (¬ (0x0048 ≤ r.codepoint ∧ r.codepoint ≤ 0x006F))) = true := by
  decide +kernel

/-- Every ASCII letter in the `H`..`o` band is a starter (`CCC = 0`). -/
theorem ccc_ascii_band (cp : Nat) (hLo : 0x0048 ≤ cp) (hHi : cp ≤ 0x006F) :
    canonicalCombiningClass cp = 0 :=
  canonicalCombiningClass_of_lookupRow_none cp
    (lookupRow_none_of_all_outside 0x0048 0x006F cp rows_omit_ascii_band hLo hHi)

/-- The ASCII starters used by the vectors register as non-non-starters —
    pre-resolved so the run scan never exposes the CCC row lookup. -/
theorem isNonStarter_H : isNonStarter 0x48 = false := by
  simp [isNonStarter, ccc_ascii_band 0x48 (by omega) (by omega)]
theorem isNonStarter_e : isNonStarter 0x65 = false := by
  simp [isNonStarter, ccc_ascii_band 0x65 (by omega) (by omega)]
theorem isNonStarter_l : isNonStarter 0x6C = false := by
  simp [isNonStarter, ccc_ascii_band 0x6C (by omega) (by omega)]
theorem isNonStarter_o : isNonStarter 0x6F = false := by
  simp [isNonStarter, ccc_ascii_band 0x6F (by omega) (by omega)]
theorem isNonStarter_a : isNonStarter 0x61 = false := by
  simp [isNonStarter, ccc_ascii_band 0x61 (by omega) (by omega)]

/-- COMBINING ACUTE ACCENT is a non-starter (`CCC = 230`). -/
theorem isNonStarter_acute : isNonStarter 0x0301 = true := by
  simp [isNonStarter, ccc_combining_acute]

/-- Empty input is clear. -/
theorem detect_empty_clear : (detect #[]).classify.isClear = true := by
  decide

-- Each spot-check input is named so the run lemmas and the per-index
-- witnesses reference one array. The per-index facts come from a
-- `List.range` certificate closed by `decide +kernel`: it indexes the
-- literal array and compares codepoints — no `canonicalCombiningClass`
-- appears, so the row table is never scanned. The one CCC value per
-- distinct codepoint is discharged once by the `isNonStarter_*` lemmas.

/-- The pure-ASCII "Hello" input. -/
def vAscii : Array Nat := #[0x48, 0x65, 0x6C, 0x6C, 0x6F]

/-- The starter + single combining mark input. -/
def vOneCombine : Array Nat := #[0x61, 0x0301]

/-- The 30-mark boundary input (a starter then 30 combining marks). -/
def vThirty : Array Nat :=
  #[0x61,
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301]

/-- The 31-mark overrun input. -/
def vThirtyOne : Array Nat :=
  #[0x61,
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
    0x0301]

/-- Every codepoint in `vAscii` is one of the four ASCII starters. -/
theorem vAscii_vals :
    (List.range 5).all (fun k => decide
      (vAscii[k]! = 0x48 ∨ vAscii[k]! = 0x65 ∨ vAscii[k]! = 0x6C
        ∨ vAscii[k]! = 0x6F)) = true := by decide +kernel

/-- Any of the four ASCII starter codepoints registers as a starter. -/
theorem isNonStarter_ascii_val (v : Nat)
    (hv : v = 0x48 ∨ v = 0x65 ∨ v = 0x6C ∨ v = 0x6F) :
    isNonStarter v = false := by
  rcases hv with h | h | h | h
  · rw [h]; exact isNonStarter_H
  · rw [h]; exact isNonStarter_e
  · rw [h]; exact isNonStarter_l
  · rw [h]; exact isNonStarter_o

/-- Every codepoint of `vOneCombine` past the leading starter is acute. -/
theorem vOneCombine_tail :
    (List.range 2).all (fun k => decide
      (k = 0 ∨ vOneCombine[k]! = 0x0301)) = true := by decide +kernel

/-- Every codepoint of `vThirty` past the leading starter is acute. -/
theorem vThirty_tail :
    (List.range 31).all (fun k => decide
      (k = 0 ∨ vThirty[k]! = 0x0301)) = true := by decide +kernel

/-- Every codepoint of `vThirtyOne` past the leading starter is acute. -/
theorem vThirtyOne_tail :
    (List.range 32).all (fun k => decide
      (k = 0 ∨ vThirtyOne[k]! = 0x0301)) = true := by decide +kernel

/-- Uniform-tail non-starter witness for the starter-then-marks inputs:
    every index past the leading starter carries the acute accent. -/
theorem tail_all_nonstarter (V : Array Nat) (n : Nat)
    (hsz : V.size = n)
    (hcert : (List.range n).all
      (fun k => decide (k = 0 ∨ V[k]! = 0x0301)) = true) :
    ∀ j, 1 ≤ j → (hjs : j < V.size) → isNonStarter V[j] = true := by
  intro j hj hjs
  have hjr : j ∈ List.range n := List.mem_range.mpr (hsz ▸ hjs)
  have hd := of_decide_eq_true (List.all_eq_true.mp hcert j hjr)
  rcases hd with hz | hval
  · omega
  · have hveq : V[j] = 0x0301 := (getElem!_pos V j hjs).symm.trans hval
    rw [hveq]; exact isNonStarter_acute

/-- Pure ASCII is clear (zero non-starters). -/
theorem detect_ascii_clear : (detect vAscii).classify.isClear = true := by
  have hAll : ∀ j, 0 ≤ j → (hjs : j < vAscii.size) →
      isNonStarter vAscii[j] = false := by
    intro j hj hjs
    have hsz : vAscii.size = 5 := by decide
    have hjr : j ∈ List.range 5 := List.mem_range.mpr (hsz ▸ hjs)
    have hd := of_decide_eq_true (List.all_eq_true.mp vAscii_vals j hjr)
    have hveq : vAscii[j] = vAscii[j]! := (getElem!_pos vAscii j hjs).symm
    rw [hveq]
    exact isNonStarter_ascii_val vAscii[j]! hd
  have h : firstOverrun vAscii = none := by
    unfold firstOverrun nonStarterRuns
    rw [collectRunsGo_none_all_starters]
    · rfl
    · decide
    · exact hAll
  rw [show (detect vAscii).classify = Classification.clear by
        unfold detect; rw [h]]
  rfl

/-- A single combining mark following a starter is clear. -/
theorem detect_one_combine_clear :
    (detect vOneCombine).classify.isClear = true := by
  have h : firstOverrun vOneCombine = none := by
    unfold firstOverrun nonStarterRuns
    rw [collectRunsGo_starter_step]
    · rw [collectRunsGo_none_to_end]
      · decide
      · decide
      · decide
      · exact tail_all_nonstarter vOneCombine 2 (by decide) vOneCombine_tail
    · decide
    · exact isNonStarter_a
  rw [show (detect vOneCombine).classify = Classification.clear by
        unfold detect; rw [h]]
  rfl

/-- Exactly 30 combining marks (boundary case) stays clear under strict `>`. -/
theorem detect_thirty_marks_clear : (detect vThirty).classify.isClear = true := by
  have h : firstOverrun vThirty = none := by
    unfold firstOverrun nonStarterRuns
    rw [collectRunsGo_starter_step]
    · rw [collectRunsGo_none_to_end]
      · decide
      · decide
      · decide
      · exact tail_all_nonstarter vThirty 31 (by decide) vThirty_tail
    · decide
    · exact isNonStarter_a
  rw [show (detect vThirty).classify = Classification.clear by
        unfold detect; rw [h]]
  rfl

/-- Thirty-one combining marks fires `StreamSafeOverrun`. -/
theorem detect_thirtyone_marks_hazard :
    (detect vThirtyOne).classify.tag = some "StreamSafeOverrun" := by
  have h : firstOverrun vThirtyOne = some (1, 31) := by
    unfold firstOverrun nonStarterRuns
    rw [collectRunsGo_starter_step]
    · rw [collectRunsGo_none_to_end]
      · decide
      · decide
      · decide
      · exact tail_all_nonstarter vThirtyOne 32 (by decide) vThirtyOne_tail
    · decide
    · exact isNonStarter_a
  rw [show (detect vThirtyOne).classify
        = Classification.hazard (.streamSafeOverrun 1 31) #[1] ByteArray.empty by
        unfold detect; rw [h]]
  rfl

end Unicode.Security.Form.StreamSafeViolation
