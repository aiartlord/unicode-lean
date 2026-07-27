/-
  Unicode.Security.Covert.BidiControlBalance

  Detection of Trojan-Source-class attacks and related
  bidi-control hazards (CVE-2021-42574 / CVE-2021-42694).

  Threat model.  Tier A₁ (local injector).  Adversary embeds
  Unicode bidi format-control characters (LRE / RLE / LRO / RLO /
  PDF / LRI / RLI / FSI / PDI) inside source code or
  identifier-bearing text to reorder the visible glyph stream
  away from the byte order that compilers and runtime
  tokenizers see.  Bidi-balance attacks are the underlying
  mechanism for the 2021 Boucher-Anderson "Trojan Source"
  attack class.

  Detection strategy.  Walk the input with a per-type stack and
  produce four independent sub-threats:

    * `depthExceeded`        — nesting > 125 (UAX #9 §3.3.2 cap).
    * `orphanPop`            — PDF or PDI with no matching opener.
    * `unbalancedEmbedding`  — LRE/RLE/LRO opens unclosed at end.
    * `unbalancedIsolate`    — LRI/RLI/FSI opens unclosed at end.

  An input that has bidi controls but is properly balanced and
  within depth produces a `.clear` verdict — this is the case
  for legitimate inline-Arabic or inline-Hebrew text.

  The standalone codepoint-level predicates here are re-exports
  of those already proven in `Unicode.TrojanSource`; the
  combinator and verdict structure are new in this module
  because `Unicode.TrojanSource` collapses orphan and unbalanced
  cases into a single `hasUnbalancedBidi` boolean.
-/

import Unicode.Security.Calculus
import Unicode.TrojanSource

namespace Unicode.Security.Covert.BidiControlBalance

open Unicode.Security.Calculus
open Unicode.TrojanSource (isBidiFormatControl opensEmbedding isPDF opensIsolate isPDI)

set_option maxRecDepth 1000000
set_option maxHeartbeats 10000000

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Sub-threat enumeration for BidiControlBalance.

    Priority order (highest first):
      1. `depthExceeded`        DoS-class nesting beyond UAX #9 §3.3.2
      2. `orphanPop`            clear UAX #9 violation
      3. `unbalancedEmbedding`  Trojan Source CVE-2021-42574 shape
      4. `unbalancedIsolate`    Trojan Source CVE-2021-42694 shape
-/
inductive SubThreat where
  | depthExceeded       (maxDepth : Nat)
  | orphanPop           (positions : List Nat)
  | unbalancedEmbedding (openCount : Nat) (popCount : Nat)
  | unbalancedIsolate   (openCount : Nat) (popCount : Nat)
  deriving DecidableEq, Repr, Inhabited

/-- Top-level classification for BidiControlBalance. -/
inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : List Nat) (decoded : List UInt8)
  deriving Inhabited

/-- The depth bound from UAX #9 §3.3.2. -/
def uaxDepthLimit : Nat := 125

/-- Verdict — the structured output of `detect`. -/
structure Verdict where
  input          : List Nat
  classify       : Classification
  bidiPositions  : List Nat                        -- every bidi format-control position
  embOpenCount   : Nat                              -- LRE+RLE+LRO occurrences
  embPopCount    : Nat                              -- PDF occurrences
  isoOpenCount   : Nat                              -- LRI+RLI+FSI occurrences
  isoPopCount    : Nat                              -- PDI occurrences
  maxDepth       : Nat                              -- peak stack-of-stacks depth
  orphans        : List Nat                        -- positions of unmatched pops
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Walk state — pure accumulator
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Per-iteration walk state.  Each opener pushes; each popper
    pops or records an orphan position.  `maxDepth` tracks the
    peak combined embedding-plus-isolate stack height.  `orphans`
    and `bidiPositions` accumulate in reverse (newest-first) and are
    reversed at verdict-build time. -/
structure WalkState where
  pos            : Nat
  embStack       : Nat
  isoStack       : Nat
  embOpenCount   : Nat
  embPopCount    : Nat
  isoOpenCount   : Nat
  isoPopCount    : Nat
  maxDepth       : Nat
  orphansRev     : List Nat
  bidiPositionsRev : List Nat
  deriving Inhabited

def WalkState.initial : WalkState :=
  { pos := 0,
    embStack := 0, isoStack := 0,
    embOpenCount := 0, embPopCount := 0,
    isoOpenCount := 0, isoPopCount := 0,
    maxDepth := 0,
    orphansRev := [],
    bidiPositionsRev := [] }

/-- Single-step transition for the walk. -/
def WalkState.step (st : WalkState) (cp : Nat) : WalkState :=
  if ¬ isBidiFormatControl cp then
    { st with pos := st.pos + 1 }
  else
    let bidiPositions' := st.pos :: st.bidiPositionsRev
    if opensEmbedding cp then
      let emb' := st.embStack + 1
      let mx := Nat.max st.maxDepth (emb' + st.isoStack)
      { st with
          pos := st.pos + 1,
          embStack := emb',
          embOpenCount := st.embOpenCount + 1,
          maxDepth := mx,
          bidiPositionsRev := bidiPositions' }
    else if isPDF cp then
      if st.embStack > 0 then
        { st with
            pos := st.pos + 1,
            embStack := st.embStack - 1,
            embPopCount := st.embPopCount + 1,
            bidiPositionsRev := bidiPositions' }
      else
        { st with
            pos := st.pos + 1,
            embPopCount := st.embPopCount + 1,
            orphansRev := st.pos :: st.orphansRev,
            bidiPositionsRev := bidiPositions' }
    else if opensIsolate cp then
      let iso' := st.isoStack + 1
      let mx := Nat.max st.maxDepth (st.embStack + iso')
      { st with
          pos := st.pos + 1,
          isoStack := iso',
          isoOpenCount := st.isoOpenCount + 1,
          maxDepth := mx,
          bidiPositionsRev := bidiPositions' }
    else if isPDI cp then
      if st.isoStack > 0 then
        { st with
            pos := st.pos + 1,
            isoStack := st.isoStack - 1,
            isoPopCount := st.isoPopCount + 1,
            bidiPositionsRev := bidiPositions' }
      else
        { st with
            pos := st.pos + 1,
            isoPopCount := st.isoPopCount + 1,
            orphansRev := st.pos :: st.orphansRev,
            bidiPositionsRev := bidiPositions' }
    else
      -- Unreachable: every bidi format-control falls in one of the
      -- four classes above by `Unicode.TrojanSource.isBidiFormatControl`.
      { st with pos := st.pos + 1, bidiPositionsRev := bidiPositions' }

/-- Run the walk over the entire `input`. -/
def runWalk (input : List Nat) : WalkState :=
  input.foldl (init := WalkState.initial) WalkState.step

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Sub-threat selection + top-level detect
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Pick the sub-threat from a non-empty walk state.

    Priority order: depth exceeded → orphan pop → unbalanced
    embedding → unbalanced isolate.  Returns `none` when the
    bidi controls are properly balanced and within depth — in
    which case the verdict is `.clear` even though bidi
    controls are present. -/
private def pickSubThreat (st : WalkState) : Option SubThreat :=
  if st.maxDepth > uaxDepthLimit then
    some (.depthExceeded st.maxDepth)
  else if st.orphansRev.length > 0 then
    some (.orphanPop st.orphansRev.reverse)
  else if st.embStack > 0 then
    some (.unbalancedEmbedding st.embOpenCount st.embPopCount)
  else if st.isoStack > 0 then
    some (.unbalancedIsolate st.isoOpenCount st.isoPopCount)
  else
    none

/-- The BidiControlBalance detection function.  Returns a
    structured verdict over the codepoint sequence `input`. -/
def detect (input : List Nat) : Verdict :=
  let st := runWalk input
  let bidiPositions := st.bidiPositionsRev.reverse
  if bidiPositions.isEmpty then
    { input := input,
      classify := .clear,
      bidiPositions := [],
      embOpenCount := 0, embPopCount := 0,
      isoOpenCount := 0, isoPopCount := 0,
      maxDepth := 0, orphans := [] }
  else
    match pickSubThreat st with
    | none =>
      -- Bidi present but balanced + within depth (legitimate RTL).
      { input := input,
        classify := .clear,
        bidiPositions := bidiPositions,
        embOpenCount := st.embOpenCount, embPopCount := st.embPopCount,
        isoOpenCount := st.isoOpenCount, isoPopCount := st.isoPopCount,
        maxDepth := st.maxDepth, orphans := [] }
    | some sub =>
      -- Positions semantics: orphan-pop is per-codepoint (one
      -- entry per stray PDF/PDI).  Depth-exceeded is a
      -- whole-string verdict — the stack-of-stacks is the
      -- problem, not any single codepoint — so we report an
      -- empty positions list and let the `max_depth` metadata
      -- field carry the quantitative signal.  Unbalanced
      -- embedding / isolate likewise report all detected bidi
      -- positions; the diagnostic is "look at these controls,
      -- something is missing a partner".
      let positions : List Nat :=
        match sub with
        | .orphanPop ps                            => ps
        | .depthExceeded maxDepth                  =>
            Function.const Nat ([] : List Nat) maxDepth
        | .unbalancedEmbedding openCount popCount  =>
            Function.const (Nat × Nat) bidiPositions (openCount, popCount)
        | .unbalancedIsolate openCount popCount    =>
            Function.const (Nat × Nat) bidiPositions (openCount, popCount)
      { input := input,
        classify := .hazard sub positions [],
        bidiPositions := bidiPositions,
        embOpenCount := st.embOpenCount, embPopCount := st.embPopCount,
        isoOpenCount := st.isoOpenCount, isoPopCount := st.isoPopCount,
        maxDepth := st.maxDepth, orphans := st.orphansRev.reverse }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Fixture-row tag string for each `SubThreat` constructor. -/
def SubThreat.tag : SubThreat → String
  | .depthExceeded       maxDepth               =>
      Function.const Nat "DepthExceeded" maxDepth
  | .orphanPop           orphanPositions        =>
      Function.const (List Nat) "OrphanPop" orphanPositions
  | .unbalancedEmbedding openCount popCount     =>
      Function.const (Nat × Nat) "UnbalancedEmbedding" (openCount, popCount)
  | .unbalancedIsolate   openCount popCount     =>
      Function.const (Nat × Nat) "UnbalancedIsolate" (openCount, popCount)

/-- True iff the classification is `.clear`. -/
def Classification.isClear : Classification → Bool
  | .clear                     => true
  | .hazard sub positions decoded =>
      Function.const (SubThreat × List Nat × List UInt8) false
        (sub, positions, decoded)

/-- Tag string of a classification (`none` for `.clear`). -/
def Classification.tag : Classification → Option String
  | .clear                     => none
  | .hazard sub positions decoded =>
      Function.const (List Nat × List UInt8) (some sub.tag) (positions, decoded)

/-- Positions list of a classification (empty for `.clear`). -/
def Classification.positions : Classification → List Nat
  | .clear                     => []
  | .hazard sub positions decoded =>
      Function.const (SubThreat × List UInt8) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear. -/
theorem detect_empty_clear : (detect []).classify.isClear = true := by
  decide

/-- Plain ASCII is clear (no bidi controls). -/
theorem detect_ascii_clear :
    (detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  decide

/-- Balanced LRE … PDF is clear (legitimate left-to-right embedding). -/
theorem detect_balanced_embedding_clear :
    (detect [0x202A, 0x41, 0x202C]).classify.isClear = true := by
  decide

/-- Balanced LRI … PDI is clear (legitimate left-to-right isolate). -/
theorem detect_balanced_isolate_clear :
    (detect [0x2066, 0x41, 0x2069]).classify.isClear = true := by
  decide

/-- Lone LRE (no PDF) — unbalanced embedding (Trojan Source CVE-2021-42574). -/
theorem detect_lone_lre :
    (detect [0x202A, 0x41]).classify.tag = some "UnbalancedEmbedding" := by
  decide

/-- Lone RLO (no PDF) — unbalanced embedding override. -/
theorem detect_lone_rlo :
    (detect [0x202E, 0x41]).classify.tag = some "UnbalancedEmbedding" := by
  decide

/-- Lone PDF (no preceding opener) — orphan pop. -/
theorem detect_lone_pdf :
    (detect [0x202C]).classify.tag = some "OrphanPop" := by
  decide

/-- Lone PDI (no preceding isolate) — orphan pop. -/
theorem detect_lone_pdi :
    (detect [0x2069]).classify.tag = some "OrphanPop" := by
  decide

/-- Lone LRI (no PDI) — unbalanced isolate (CVE-2021-42694). -/
theorem detect_lone_lri :
    (detect [0x2067, 0x41]).classify.tag = some "UnbalancedIsolate" := by
  decide

/-- The Boucher-Anderson 2021 canonical "commenting-out" attack
    minimum shape — balanced (one RLO + one PDF), so this particular
    repro is `.clear`.  The actual hazard surfaces when the PDF is
    elided (next theorem). -/
theorem detect_trojan_source_shape :
    (detect [0x69, 0x66, 0x20, 0x202E, 0x29, 0x202C,
             0x7B]).classify.isClear = true := by
  decide

/-- Same shape with the closing PDF removed — the actual
    Trojan-Source attack class. -/
theorem detect_trojan_source_unbalanced :
    (detect [0x69, 0x66, 0x20, 0x202E, 0x29, 0x7B]).classify.tag
      = some "UnbalancedEmbedding" := by decide

/-- Deep-nesting attack — 126 nested LRE's exceed UAX #9 §3.3.2's 125 cap. -/
theorem detect_depth_exceeded :
    let deepInput : List Nat :=
      List.replicate 126 0x202A ++ List.replicate 126 0x202C
    (detect deepInput).classify.tag = some "DepthExceeded" := by
  decide

/-- Exactly 125-deep nesting is within the UAX #9 cap. -/
theorem detect_depth_at_limit_clear :
    let okInput : List Nat :=
      List.replicate 125 0x202A ++ List.replicate 125 0x202C
    (detect okInput).classify.isClear = true := by
  decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Predicate sanity checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The four embedding-opener controls. -/
theorem is_bidi_lre : isBidiFormatControl 0x202A = true := by decide
theorem is_bidi_rle : isBidiFormatControl 0x202B = true := by decide
theorem is_bidi_lro : isBidiFormatControl 0x202D = true := by decide
theorem is_bidi_rlo : isBidiFormatControl 0x202E = true := by decide

/-- PDF is the embedding pop. -/
theorem is_bidi_pdf : isBidiFormatControl 0x202C = true := by decide

/-- The three isolate-opener controls. -/
theorem is_bidi_lri : isBidiFormatControl 0x2066 = true := by decide
theorem is_bidi_rli : isBidiFormatControl 0x2067 = true := by decide
theorem is_bidi_fsi : isBidiFormatControl 0x2068 = true := by decide

/-- PDI is the isolate pop. -/
theorem is_bidi_pdi : isBidiFormatControl 0x2069 = true := by decide

/-- ASCII is not bidi. -/
theorem is_bidi_ascii : isBidiFormatControl 0x41 = false := by decide

end Unicode.Security.Covert.BidiControlBalance
