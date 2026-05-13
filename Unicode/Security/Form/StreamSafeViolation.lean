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

  F2 is the security verdict over the same property.  Distinct
  from D4 `combiningStackOverflow` (which fires at the cosmetic
  Zalgo threshold of 4 marks per base for renderer-divergence
  reasons) — F2 is the spec-mandated DoS-prevention bound.

  Sub-threats (v1):

    1. `streamSafeOverrun (basePos, runLen)` — first non-starter
       run whose length exceeds `streamSafeLimit`.
-/

import Unicode.Security.Calculus
import Unicode.StreamSafe

namespace Unicode.Security.Form.StreamSafeViolation

open Unicode.Security.Calculus
open Unicode.StreamSafe (streamSafeLimit isNonStarter)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Run inventory
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Recursive scan that accumulates `(runStart, runLen)` pairs for
    every maximal non-starter run in the input.  `curStart` is
    `some i` while we are inside an open run, `none` otherwise.
    Fuel is bounded by `input.size + 1` so termination is automatic. -/
private def collectRunsGo (input : Array Nat) (i : Nat)
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
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear. -/
theorem detect_empty_clear : (detect #[]).classify.isClear = true := by
  native_decide

/-- Pure ASCII is clear (zero non-starters). -/
theorem detect_ascii_clear :
    (detect #[0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  native_decide

/-- A single combining mark following a starter is clear. -/
theorem detect_one_combine_clear :
    (detect #[0x61, 0x0301]).classify.isClear = true := by native_decide

/-- Exactly 30 combining marks (boundary case) stays clear under strict `>`. -/
theorem detect_thirty_marks_clear :
    (detect #[0x61,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301]).classify.isClear = true := by
  native_decide

/-- Thirty-one combining marks fires `StreamSafeOverrun`. -/
theorem detect_thirtyone_marks_hazard :
    (detect #[0x61,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301]).classify.tag = some "StreamSafeOverrun" := by
  native_decide

end Unicode.Security.Form.StreamSafeViolation
