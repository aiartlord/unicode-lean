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
  bounds the normalization buffer by `O(input.length)` plus a fixed
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
    `i` tracks the absolute index of the current head; the recursion
    is structural on the remaining input. -/
def collectRunsGo (i : Nat) (curStart : Option Nat) (curLen : Nat)
    (runs : List (Nat × Nat)) : List Nat → List (Nat × Nat)
  | [] =>
    match curStart with
    | some s => runs ++ [(s, curLen)]
    | none   => runs
  | cp :: rest =>
    if isNonStarter cp then
      collectRunsGo (i + 1) (some (curStart.getD i)) (curLen + 1) runs rest
    else
      match curStart with
      | some s => collectRunsGo (i + 1) none 0 (runs ++ [(s, curLen)]) rest
      | none   => collectRunsGo (i + 1) none 0 runs rest

/-- Inventory of `(startIndex, length)` for every maximal non-starter
    run in `input`. -/
def nonStarterRuns (input : List Nat) : List (Nat × Nat) :=
  collectRunsGo 0 none 0 [] input

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1a Uniform-run evaluation
--
-- The concrete spot-check vectors below are a starter followed by a block
-- of identical non-starters. Reducing `collectRunsGo` over such a block by
-- unfolding it element by element (`simp` / `decide`) explodes the proof
-- term. Instead these lemmas evaluate an all-non-starter suffix
-- abstractly by induction on the remaining input — the run scan never
-- touches the row tables, and the term stays O(1) in the block length.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- An open non-starter run that continues to the end of the input closes
    into a single `(start, length)` entry, its length extended by the count
    of remaining codepoints. -/
theorem collectRunsGo_open_to_end (rest : List Nat) :
    ∀ (i s curLen : Nat) (runs : List (Nat × Nat)),
      (∀ cp ∈ rest, isNonStarter cp = true) →
      collectRunsGo i (some s) curLen runs rest
        = runs ++ [(s, curLen + rest.length)] := by
  induction rest with
  | nil =>
    intro i s curLen runs _hAll
    simp [collectRunsGo]
  | cons cp tail ih =>
    intro i s curLen runs hAll
    have hns : isNonStarter cp = true := hAll cp List.mem_cons_self
    simp only [collectRunsGo, hns, if_true, Option.getD_some]
    rw [ih (i + 1) s (curLen + 1) runs
          (fun c hc => hAll c (List.mem_cons_of_mem cp hc))]
    have harith : curLen + 1 + tail.length = curLen + (cp :: tail).length := by
      rw [List.length_cons]
      omega
    rw [harith]

/-- Reaching a non-empty all-non-starter block from a closed state
    (`curStart = none`) opens and then closes it into one
    `(start, length)` entry.  The closed state always carries
    `curLen = 0`, so the opened run's length is exactly the count of
    remaining codepoints. -/
theorem collectRunsGo_none_to_end (i : Nat) (runs : List (Nat × Nat))
    (rest : List Nat) (hNE : 0 < rest.length)
    (hAll : ∀ cp ∈ rest, isNonStarter cp = true) :
    collectRunsGo i none 0 runs rest = runs ++ [(i, rest.length)] := by
  cases rest with
  | nil => exact absurd hNE (by simp)
  | cons cp tail =>
    have hns : isNonStarter cp = true := hAll cp List.mem_cons_self
    simp only [collectRunsGo, hns, if_true, Option.getD_none]
    rw [collectRunsGo_open_to_end tail (i + 1) i (0 + 1) runs
          (fun c hc => hAll c (List.mem_cons_of_mem cp hc))]
    have harith : 0 + 1 + tail.length = (cp :: tail).length := by
      rw [List.length_cons]
      omega
    rw [harith]

/-- Peel one leading starter: from a closed state a starter advances the
    index without opening a run.  Only the head is consumed, so the
    residual scan on the tail stays folded. -/
theorem collectRunsGo_starter_step (i curLen : Nat)
    (runs : List (Nat × Nat)) (cp : Nat) (rest : List Nat)
    (hs : isNonStarter cp = false) :
    collectRunsGo i none curLen runs (cp :: rest)
      = collectRunsGo (i + 1) none 0 runs rest := by
  simp [collectRunsGo, hs]

/-- An all-starter suffix contributes no runs. -/
theorem collectRunsGo_none_all_starters (rest : List Nat) :
    ∀ (i curLen : Nat) (runs : List (Nat × Nat)),
      (∀ cp ∈ rest, isNonStarter cp = false) →
      collectRunsGo i none curLen runs rest = runs := by
  induction rest with
  | nil =>
    intro i curLen runs _hAll
    rfl
  | cons cp tail ih =>
    intro i curLen runs hAll
    have hs : isNonStarter cp = false := hAll cp List.mem_cons_self
    rw [collectRunsGo_starter_step i curLen runs cp tail hs]
    exact ih (i + 1) 0 runs (fun c hc => hAll c (List.mem_cons_of_mem cp hc))

/-- First non-starter run whose length exceeds `streamSafeLimit`. -/
def firstOverrun (input : List Nat) : Option (Nat × Nat) :=
  (nonStarterRuns input).find? (fun p => p.2 > streamSafeLimit)

/-- Longest non-starter run length in `input`. -/
def maxRunLen (input : List Nat) : Nat :=
  (nonStarterRuns input).foldl (init := 0) (fun acc p =>
    if p.2 > acc then p.2 else acc)

/-- Number of distinct non-starter runs that exceed `streamSafeLimit`. -/
def overrunCount (input : List Nat) : Nat :=
  (nonStarterRuns input).foldl (init := 0) (fun acc p =>
    if p.2 > streamSafeLimit then acc + 1 else acc)

/-- Total non-starter codepoints in `input` (sum of all run lengths). -/
def totalNonStarters (input : List Nat) : Nat :=
  (nonStarterRuns input).foldl (init := 0) (fun acc p => acc + p.2)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Types
-- ═══════════════════════════════════════════════════════════════════════════════

inductive SubThreat where
  | streamSafeOverrun (basePos : Nat) (runLen : Nat)
  deriving DecidableEq, Repr, Inhabited

inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : List Nat) (decoded : List UInt8)
  deriving Inhabited

structure Verdict where
  input            : List Nat
  classify         : Classification
  maxRunLen        : Nat
  overrunCount     : Nat
  totalNonStarters : Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The F2 detection function. -/
def detect (input : List Nat) : Verdict :=
  let classification : Classification :=
    match firstOverrun input with
    | some (basePos, runLen) =>
      .hazard (.streamSafeOverrun basePos runLen) [basePos] []
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
--
-- The run inventory consults `canonicalCombiningClass` per codepoint via
-- `isNonStarter`, which must never reduce the row scan (see the
-- fact-transport section of `Unicode.Normalization.Lookup`). The ASCII
-- starters in these vectors are covered by one interval-absence pass;
-- the combining acute reuses `Reorder.ccc_combining_acute`. The run
-- scan then evaluates through the uniform-run lemmas at concrete
-- arguments only.
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
theorem detect_empty_clear : (detect []).classify.isClear = true := by
  decide

-- Each spot-check input is a leading starter plus a named block of
-- combining marks. Membership certificates over the mark blocks close by
-- plain `decide` (literal comparisons only — no `canonicalCombiningClass`
-- appears, so the row table is never scanned); the one CCC value per
-- distinct codepoint is discharged once by the `isNonStarter_*` lemmas.

/-- The pure-ASCII "Hello" input. -/
def vAscii : List Nat := [0x48, 0x65, 0x6C, 0x6C, 0x6F]

/-- The single-mark block. -/
def vOneCombineMarks : List Nat := [0x0301]

/-- The starter + single combining mark input. -/
def vOneCombine : List Nat := 0x61 :: vOneCombineMarks

/-- The 30-mark block. -/
def vThirtyMarks : List Nat :=
  [0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
   0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
   0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
   0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
   0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
   0x0301, 0x0301, 0x0301, 0x0301, 0x0301]

/-- The 30-mark boundary input (a starter then 30 combining marks). -/
def vThirty : List Nat := 0x61 :: vThirtyMarks

/-- The 31-mark block. -/
def vThirtyOneMarks : List Nat := 0x0301 :: vThirtyMarks

/-- The 31-mark overrun input. -/
def vThirtyOne : List Nat := 0x61 :: vThirtyOneMarks

/-- Every codepoint in `vAscii` is one of the four ASCII starters. -/
theorem vAscii_vals :
    vAscii.all (fun v => decide
      (v = 0x48 ∨ v = 0x65 ∨ v = 0x6C ∨ v = 0x6F)) = true := by decide

/-- Any of the four ASCII starter codepoints registers as a starter. -/
theorem isNonStarter_ascii_val (v : Nat)
    (hv : v = 0x48 ∨ v = 0x65 ∨ v = 0x6C ∨ v = 0x6F) :
    isNonStarter v = false := by
  rcases hv with h | h | h | h
  · rw [h]; exact isNonStarter_H
  · rw [h]; exact isNonStarter_e
  · rw [h]; exact isNonStarter_l
  · rw [h]; exact isNonStarter_o

/-- Every codepoint of the 30-mark block is the combining acute. -/
theorem vThirtyMarks_all_acute :
    vThirtyMarks.all (fun v => decide (v = 0x0301)) = true := by decide

/-- Every codepoint of the 31-mark block is the combining acute. -/
theorem vThirtyOneMarks_all_acute :
    vThirtyOneMarks.all (fun v => decide (v = 0x0301)) = true := by decide

/-- Every codepoint of the single-mark block is the combining acute. -/
theorem vOneCombineMarks_all_acute :
    vOneCombineMarks.all (fun v => decide (v = 0x0301)) = true := by decide

/-- A block certified all-acute is all-non-starter. -/
theorem marks_all_nonstarter (marks : List Nat)
    (hcert : marks.all (fun v => decide (v = 0x0301)) = true) :
    ∀ cp ∈ marks, isNonStarter cp = true := by
  intro cp hMem
  have hveq : cp = 0x0301 :=
    of_decide_eq_true (List.all_eq_true.mp hcert cp hMem)
  rw [hveq]
  exact isNonStarter_acute

/-- Pure ASCII is clear (zero non-starters). -/
theorem detect_ascii_clear : (detect vAscii).classify.isClear = true := by
  have hAll : ∀ cp ∈ vAscii, isNonStarter cp = false := by
    intro cp hMem
    exact isNonStarter_ascii_val cp
      (of_decide_eq_true (List.all_eq_true.mp vAscii_vals cp hMem))
  have h : firstOverrun vAscii = none := by
    unfold firstOverrun nonStarterRuns
    rw [collectRunsGo_none_all_starters vAscii 0 0 [] hAll]
    rfl
  rw [show (detect vAscii).classify = Classification.clear by
        unfold detect; rw [h]]
  rfl

/-- A single combining mark following a starter is clear. -/
theorem detect_one_combine_clear :
    (detect vOneCombine).classify.isClear = true := by
  have h : firstOverrun vOneCombine = none := by
    unfold firstOverrun nonStarterRuns vOneCombine
    rw [collectRunsGo_starter_step 0 0 [] 0x61 vOneCombineMarks isNonStarter_a,
        collectRunsGo_none_to_end 1 [] vOneCombineMarks (by decide)
          (marks_all_nonstarter vOneCombineMarks vOneCombineMarks_all_acute)]
    decide
  rw [show (detect vOneCombine).classify = Classification.clear by
        unfold detect; rw [h]]
  rfl

/-- Exactly 30 combining marks (boundary case) stays clear under strict `>`. -/
theorem detect_thirty_marks_clear : (detect vThirty).classify.isClear = true := by
  have h : firstOverrun vThirty = none := by
    unfold firstOverrun nonStarterRuns vThirty
    rw [collectRunsGo_starter_step 0 0 [] 0x61 vThirtyMarks isNonStarter_a,
        collectRunsGo_none_to_end 1 [] vThirtyMarks (by decide)
          (marks_all_nonstarter vThirtyMarks vThirtyMarks_all_acute)]
    decide
  rw [show (detect vThirty).classify = Classification.clear by
        unfold detect; rw [h]]
  rfl

/-- Thirty-one combining marks fires `StreamSafeOverrun`. -/
theorem detect_thirtyone_marks_hazard :
    (detect vThirtyOne).classify.tag = some "StreamSafeOverrun" := by
  have h : firstOverrun vThirtyOne = some (1, 31) := by
    unfold firstOverrun nonStarterRuns vThirtyOne
    rw [collectRunsGo_starter_step 0 0 [] 0x61 vThirtyOneMarks isNonStarter_a,
        collectRunsGo_none_to_end 1 [] vThirtyOneMarks (by decide)
          (marks_all_nonstarter vThirtyOneMarks vThirtyOneMarks_all_acute)]
    decide
  rw [show (detect vThirtyOne).classify
        = Classification.hazard (.streamSafeOverrun 1 31) [1] [] by
        unfold detect; rw [h]]
  rfl

end Unicode.Security.Form.StreamSafeViolation
