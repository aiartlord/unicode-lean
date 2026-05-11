/-
  Unicode.Security.Covert.BidiControlBalance

  C5 — Detection of Trojan-Source-class attacks and related
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

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Sub-threat enumeration for C5.

    Priority order (highest first):
      1. `depthExceeded`        DoS-class nesting beyond UAX #9 §3.3.2
      2. `orphanPop`            clear UAX #9 violation
      3. `unbalancedEmbedding`  Trojan Source CVE-2021-42574 shape
      4. `unbalancedIsolate`    Trojan Source CVE-2021-42694 shape
-/
inductive C5SubThreat where
  | depthExceeded       (maxDepth : Nat)
  | orphanPop           (positions : Array Nat)
  | unbalancedEmbedding (openCount : Nat) (popCount : Nat)
  | unbalancedIsolate   (openCount : Nat) (popCount : Nat)
  deriving DecidableEq, Repr, Inhabited

/-- Top-level classification for C5. -/
inductive C5Classification where
  | clear
  | hazard (sub : C5SubThreat) (positions : Array Nat) (decoded : ByteArray)
  deriving Inhabited

/-- The depth bound from UAX #9 §3.3.2. -/
def uaxDepthLimit : Nat := 125

/-- C5 verdict — the structured output of `detect`. -/
structure C5Verdict where
  input          : Array Nat
  classify       : C5Classification
  bidiPositions  : Array Nat                       -- every bidi format-control position
  embOpenCount   : Nat                              -- LRE+RLE+LRO occurrences
  embPopCount    : Nat                              -- PDF occurrences
  isoOpenCount   : Nat                              -- LRI+RLI+FSI occurrences
  isoPopCount    : Nat                              -- PDI occurrences
  maxDepth       : Nat                              -- peak stack-of-stacks depth
  orphans        : Array Nat                       -- positions of unmatched pops
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Walk state — pure accumulator
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Per-iteration walk state.  Each opener pushes; each popper
    pops or records an orphan position.  `maxDepth` tracks the
    peak combined embedding-plus-isolate stack height. -/
private structure WalkState where
  pos            : Nat
  embStack       : Nat
  isoStack       : Nat
  embOpenCount   : Nat
  embPopCount    : Nat
  isoOpenCount   : Nat
  isoPopCount    : Nat
  maxDepth       : Nat
  orphans        : Array Nat
  bidiPositions  : Array Nat
  deriving Inhabited

private def WalkState.initial : WalkState :=
  { pos := 0,
    embStack := 0, isoStack := 0,
    embOpenCount := 0, embPopCount := 0,
    isoOpenCount := 0, isoPopCount := 0,
    maxDepth := 0,
    orphans := #[],
    bidiPositions := #[] }

/-- Single-step transition for the walk. -/
private def WalkState.step (st : WalkState) (cp : Nat) : WalkState :=
  if ¬ isBidiFormatControl cp then
    { st with pos := st.pos + 1 }
  else
    let bidiPositions' := st.bidiPositions.push st.pos
    if opensEmbedding cp then
      let emb' := st.embStack + 1
      let mx := Nat.max st.maxDepth (emb' + st.isoStack)
      { st with
          pos := st.pos + 1,
          embStack := emb',
          embOpenCount := st.embOpenCount + 1,
          maxDepth := mx,
          bidiPositions := bidiPositions' }
    else if isPDF cp then
      if st.embStack > 0 then
        { st with
            pos := st.pos + 1,
            embStack := st.embStack - 1,
            embPopCount := st.embPopCount + 1,
            bidiPositions := bidiPositions' }
      else
        { st with
            pos := st.pos + 1,
            embPopCount := st.embPopCount + 1,
            orphans := st.orphans.push st.pos,
            bidiPositions := bidiPositions' }
    else if opensIsolate cp then
      let iso' := st.isoStack + 1
      let mx := Nat.max st.maxDepth (st.embStack + iso')
      { st with
          pos := st.pos + 1,
          isoStack := iso',
          isoOpenCount := st.isoOpenCount + 1,
          maxDepth := mx,
          bidiPositions := bidiPositions' }
    else if isPDI cp then
      if st.isoStack > 0 then
        { st with
            pos := st.pos + 1,
            isoStack := st.isoStack - 1,
            isoPopCount := st.isoPopCount + 1,
            bidiPositions := bidiPositions' }
      else
        { st with
            pos := st.pos + 1,
            isoPopCount := st.isoPopCount + 1,
            orphans := st.orphans.push st.pos,
            bidiPositions := bidiPositions' }
    else
      -- Unreachable: every bidi format-control falls in one of the
      -- four classes above by `Unicode.TrojanSource.isBidiFormatControl`.
      { st with pos := st.pos + 1, bidiPositions := bidiPositions' }

/-- Run the walk over the entire `input`. -/
private def runWalk (input : Array Nat) : WalkState :=
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
private def pickSubThreat (st : WalkState) : Option C5SubThreat :=
  if st.maxDepth > uaxDepthLimit then
    some (.depthExceeded st.maxDepth)
  else if st.orphans.size > 0 then
    some (.orphanPop st.orphans)
  else if st.embStack > 0 then
    some (.unbalancedEmbedding st.embOpenCount st.embPopCount)
  else if st.isoStack > 0 then
    some (.unbalancedIsolate st.isoOpenCount st.isoPopCount)
  else
    none

/-- The C5 detection function.  Returns a structured verdict
    over the codepoint sequence `input`. -/
def detect (input : Array Nat) : C5Verdict :=
  let st := runWalk input
  if st.bidiPositions.isEmpty then
    { input := input,
      classify := .clear,
      bidiPositions := #[],
      embOpenCount := 0, embPopCount := 0,
      isoOpenCount := 0, isoPopCount := 0,
      maxDepth := 0, orphans := #[] }
  else
    match pickSubThreat st with
    | none =>
      -- Bidi present but balanced + within depth (legitimate RTL).
      { input := input,
        classify := .clear,
        bidiPositions := st.bidiPositions,
        embOpenCount := st.embOpenCount, embPopCount := st.embPopCount,
        isoOpenCount := st.isoOpenCount, isoPopCount := st.isoPopCount,
        maxDepth := st.maxDepth, orphans := #[] }
    | some sub =>
      let positions : Array Nat :=
        match sub with
        | .orphanPop ps => ps
        | _             => st.bidiPositions
      { input := input,
        classify := .hazard sub positions ByteArray.empty,
        bidiPositions := st.bidiPositions,
        embOpenCount := st.embOpenCount, embPopCount := st.embPopCount,
        isoOpenCount := st.isoOpenCount, isoPopCount := st.isoPopCount,
        maxDepth := st.maxDepth, orphans := st.orphans }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear. -/
theorem detect_empty_clear : (detect #[]).classify matches .clear := by
  native_decide

/-- Plain ASCII is clear (no bidi controls). -/
theorem detect_ascii_clear :
    (detect #[0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify matches .clear := by
  native_decide

/-- Balanced LRE … PDF is clear (legitimate left-to-right embedding). -/
theorem detect_balanced_embedding_clear :
    (detect #[0x202A, 0x41, 0x202C]).classify matches .clear := by
  native_decide

/-- Balanced LRI … PDI is clear (legitimate left-to-right isolate). -/
theorem detect_balanced_isolate_clear :
    (detect #[0x2066, 0x41, 0x2069]).classify matches .clear := by
  native_decide

/-- Lone LRE (no PDF) — unbalanced embedding (Trojan Source CVE-2021-42574). -/
theorem detect_lone_lre :
    (detect #[0x202A, 0x41]).classify matches
      .hazard (.unbalancedEmbedding 1 0) _ _ := by
  native_decide

/-- Lone RLO (no PDF) — unbalanced embedding override. -/
theorem detect_lone_rlo :
    (detect #[0x202E, 0x41]).classify matches
      .hazard (.unbalancedEmbedding 1 0) _ _ := by
  native_decide

/-- Lone PDF (no preceding opener) — orphan pop. -/
theorem detect_lone_pdf :
    (detect #[0x202C]).classify matches
      .hazard (.orphanPop _) _ _ := by
  native_decide

/-- Lone PDI (no preceding isolate) — orphan pop. -/
theorem detect_lone_pdi :
    (detect #[0x2069]).classify matches
      .hazard (.orphanPop _) _ _ := by
  native_decide

/-- Lone LRI (no PDI) — unbalanced isolate (CVE-2021-42694). -/
theorem detect_lone_lri :
    (detect #[0x2067, 0x41]).classify matches
      .hazard (.unbalancedIsolate 1 0) _ _ := by
  native_decide

/-- The Boucher-Anderson 2021 canonical "commenting-out" attack:
    `if access_level != "user"` with `"user"` interpolated through
    an RLO + PDF dance so the visible text reads differently from
    the byte order.  The bytes here are the minimal repro of the
    bidi-control shape (the surrounding text is omitted). -/
theorem detect_trojan_source_shape :
    (detect #[0x69, 0x66, 0x20, 0x202E, 0x29, 0x202C,
              0x7B]).classify matches .clear := by
  -- This particular minimal shape happens to be balanced
  -- (one RLO opener + one PDF closer).  The hazard would
  -- surface if the closer were elided — the real Trojan
  -- Source attacks rely on a missing PDF to keep the
  -- reordering "leaking" past the intended scope.
  native_decide

/-- Same shape with the closing PDF removed — the actual
    Trojan-Source attack class. -/
theorem detect_trojan_source_unbalanced :
    (detect #[0x69, 0x66, 0x20, 0x202E, 0x29, 0x7B]).classify matches
      .hazard (.unbalancedEmbedding _ _) _ _ := by
  native_decide

/-- Deep-nesting attack — 126 nested LRE's exceed UAX #9 §3.3.2's 125 cap. -/
theorem detect_depth_exceeded :
    let deepInput : Array Nat :=
      Array.replicate 126 0x202A ++ Array.replicate 126 0x202C
    (detect deepInput).classify matches
      .hazard (.depthExceeded _) _ _ := by
  native_decide

/-- Exactly 125-deep nesting is within the UAX #9 cap. -/
theorem detect_depth_at_limit_clear :
    let okInput : Array Nat :=
      Array.replicate 125 0x202A ++ Array.replicate 125 0x202C
    (detect okInput).classify matches .clear := by
  native_decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Predicate sanity checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The four embedding-opener controls. -/
theorem is_bidi_lre : isBidiFormatControl 0x202A = true := by native_decide
theorem is_bidi_rle : isBidiFormatControl 0x202B = true := by native_decide
theorem is_bidi_lro : isBidiFormatControl 0x202D = true := by native_decide
theorem is_bidi_rlo : isBidiFormatControl 0x202E = true := by native_decide

/-- PDF is the embedding pop. -/
theorem is_bidi_pdf : isBidiFormatControl 0x202C = true := by native_decide

/-- The three isolate-opener controls. -/
theorem is_bidi_lri : isBidiFormatControl 0x2066 = true := by native_decide
theorem is_bidi_rli : isBidiFormatControl 0x2067 = true := by native_decide
theorem is_bidi_fsi : isBidiFormatControl 0x2068 = true := by native_decide

/-- PDI is the isolate pop. -/
theorem is_bidi_pdi : isBidiFormatControl 0x2069 = true := by native_decide

/-- ASCII is not bidi. -/
theorem is_bidi_ascii : isBidiFormatControl 0x41 = false := by native_decide

end Unicode.Security.Covert.BidiControlBalance
