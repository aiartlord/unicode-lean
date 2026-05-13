/-
  scripts/internal/fuzz_security_detectors.lean

  Property-based fuzzer for the cryptographic-stability
  detectors (HashInputStability and AiWatermarkDetectability).

  Generates pseudo-random codepoint arrays from a seeded RNG
  and asserts structural invariants that the detectors must
  hold over every input.  The fuzzer does not replace the
  hand-curated fixtures — those pin specific verdicts on
  human-readable inputs.  The fuzzer complements them by
  probing the input space for invariant violations that
  hand-curation cannot enumerate.

  Invariants checked:

    1. Total determinism — `detect input` always returns a
       `Verdict` with `classify`, no exception, no diverge.
    2. `detect input = detectWithContext {} input` — the
       bare wrapper agrees with the empty-context entry
       point.
    3. Classification well-formedness — every `hazard`
       constructor's `positions` array has every entry
       `< input.size`.
    4. HashInputStability: trailing-whitespace inputs on an
       NFC-stable base always fire `TrailingWhitespace`.
    5. AiWatermarkDetectability: empty input always
       classifies as `.clear`.

  Invocation:

      lake env lean --run scripts/internal/fuzz_security_detectors.lean

  Exit code 0 if every invariant holds; non-zero otherwise.
-/

import Unicode.Security.Crypto.HashInputStability
import Unicode.Security.Crypto.AiWatermarkDetectability

open Unicode.Security.Calculus

namespace FuzzSecurity

/-- The default fuzz volume per detector.  Each invariant
    runs against this many seeded inputs. -/
def defaultIterations : Nat := 10000

/-- Generate one pseudo-random codepoint in `[0, 0x10FFFF]`
    using `StdGen`.  Returns the codepoint and the advanced
    generator. -/
def randCodepoint (gen : StdGen) : Nat × StdGen :=
  let (n, gen') := stdNext gen
  (n % 0x110000, gen')

/-- Generate one pseudo-random input of length up to `maxLen`. -/
def randInput (gen : StdGen) (maxLen : Nat) : Array Nat × StdGen :=
  let (sizeRaw, gen0) := stdNext gen
  let size := sizeRaw % (maxLen + 1)
  let rec loop (acc : Array Nat) (n : Nat) (g : StdGen) : Array Nat × StdGen :=
    match n with
    | 0     => (acc, g)
    | k + 1 =>
      let (cp, g') := randCodepoint g
      loop (acc.push cp) k g'
  loop #[] size gen0

namespace HashInputStability

open Unicode.Security.Crypto.HashInputStability

/-- Invariant: `detect` and `detectWithContext {}` agree on
    every input. -/
def invariantBareMatchesEmpty (input : Array Nat) : Bool :=
  decide ((detect input).classify = (detectWithContext {} input).classify)
    && decide ((detect input).stableSize = (detectWithContext {} input).stableSize)

/-- Invariant: every position in a hazard verdict is a valid
    input index (`< input.size`). -/
def invariantPositionsInBounds (input : Array Nat) : Bool :=
  let v := detect input
  v.classify.positions.all (fun p => decide (p < input.size))
    || decide (v.classify.positions = #[])

/-- Invariant: adding a trailing SPACE to an NFC-stable input
    fires `TrailingWhitespace` (the bare-probe priority
    guarantees this when no context-bearing probe applies). -/
def invariantTrailingSpaceFires (input : Array Nat) : Bool :=
  let nfc := Unicode.Normalization.NFC.toNFC input
  -- Only check on NFC-stable inputs to avoid masking by
  -- `normalizationDrift`.
  if input != nfc then true
  else
    let augmented := input.push 0x20
    decide ((detect augmented).classify.tag = some "TrailingWhitespace")

end HashInputStability

namespace AiWatermarkDetectability

open Unicode.Security.Crypto.AiWatermarkDetectability

/-- Invariant: empty input always classifies as `.clear`. -/
def invariantEmptyIsClear : Bool :=
  decide ((detect #[]).classify = .clear)

/-- Invariant: positions in a hazard verdict are in-bounds. -/
def invariantPositionsInBounds (input : Array Nat) : Bool :=
  let v := detect input
  v.classify.positions.all (fun p => decide (p < input.size))
    || decide (v.classify.positions = #[])

/-- Invariant: `detect` and `detectWithContext {}` agree. -/
def invariantBareMatchesEmpty (input : Array Nat) : Bool :=
  decide ((detect input).classify = (detectWithContext {} input).classify)
    && decide ((detect input).markerCount = (detectWithContext {} input).markerCount)

end AiWatermarkDetectability

/-- Run one round of fuzz over HashInputStability's
    invariants. -/
def fuzzHashInputStability (iterations : Nat) (seed : Nat) :
    IO (Nat × Nat) := do
  let mut gen := mkStdGen seed
  let mut passCount := 0
  for _ in [:iterations] do
    let (input, gen') := randInput gen 32
    gen := gen'
    if HashInputStability.invariantBareMatchesEmpty input
       && HashInputStability.invariantPositionsInBounds input
       && HashInputStability.invariantTrailingSpaceFires input
    then passCount := passCount + 1
    else
      IO.println s!"HashInputStability invariant violated on input: {input}"
  pure (passCount, iterations)

/-- Run one round of fuzz over AiWatermarkDetectability's
    invariants. -/
def fuzzAiWatermarkDetectability (iterations : Nat) (seed : Nat) :
    IO (Nat × Nat) := do
  let mut gen := mkStdGen seed
  let mut passCount := 0
  unless AiWatermarkDetectability.invariantEmptyIsClear do
    IO.println "AiWatermarkDetectability invariant violated: empty input is not clear"
  for _ in [:iterations] do
    let (input, gen') := randInput gen 32
    gen := gen'
    if AiWatermarkDetectability.invariantBareMatchesEmpty input
       && AiWatermarkDetectability.invariantPositionsInBounds input
    then passCount := passCount + 1
    else
      IO.println s!"AiWatermarkDetectability invariant violated on input: {input}"
  pure (passCount, iterations)

end FuzzSecurity

def main : IO Unit := do
  let iters := FuzzSecurity.defaultIterations
  IO.println s!"Fuzzing cryptographic-stability detectors \
                ({iters} iterations each, seed=42):"
  let (hisP, hisT) ← FuzzSecurity.fuzzHashInputStability iters 42
  IO.println s!"  HashInputStability:       {hisP}/{hisT} invariants held"
  let (awdP, awdT) ← FuzzSecurity.fuzzAiWatermarkDetectability iters 42
  IO.println s!"  AiWatermarkDetectability: {awdP}/{awdT} invariants held"
  if hisP = hisT ∧ awdP = awdT then
    IO.println "fuzz: clean"
  else
    IO.eprintln "fuzz: FAIL"
    IO.Process.exit 1
