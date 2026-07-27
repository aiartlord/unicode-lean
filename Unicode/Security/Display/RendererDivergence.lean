/-
  Unicode.Security.Display.RendererDivergence

  Detection of codepoint / sequence shapes known to render
  differently across font + terminal + browser stacks.

  Threat model.  Tier A₁..A₂.  Adversary crafts content that
  renders one way in the auditor's renderer (a benign glyph or
  an empty span) and a different way in the consumer's renderer
  (a misleading glyph, a wider glyph, or a different sequence).
  This is the "fingerprint stability" family — clear inputs
  render the same across the renderer cohort the Standard
  documents as stable.

  Three-value classification per spec:

    * `.stable`           rendering is consistent across the
                          documented renderer cohort.
    * `.knownVariance`    one of the documented variance modes
                          fires — VS presence, combining-mark
                          stack overflow, unregistered ZWJ
                          shape, fullwidth display, mixed
                          direction.
    * `.unknown`          we cannot decide — treat conservatively
                          as `.knownVariance` with the `.unknown`
                          sub-threat tag, so callers always get a
                          binary stable / non-stable answer
                          through the universal Classification
                          carrier.

  Scope.  Heuristic-driven detection of empirically-known
  variance triggers, without a renderer-cohort membership
  table.  Downstream consumers that need (renderer-id,
  codepoint) precision should pair this detector's verdict
  with their own renderer inventory; the heuristic verdict
  here is sufficient to flag the variance class without
  asserting which specific renderer pair will diverge.

  Sub-threats (priority order):

    1. `combiningStackOverflow`  Zalgo-like combining-mark stack
                                ≥ 4 on a single base.
    2. `variationSelectorVariance` any VS codepoint present.
    3. `unregisteredZwjVariance` ZWJ-containing input not in
                                the registered RGI ZWJ set.
    4. `fullwidthVariance`       fullwidth / halfwidth codepoint
                                present.
    5. `mixedDirectionVariance`  both strong-LTR AND strong-RTL
                                codepoints in the same input.
-/

import Unicode.Security.Calculus
import Unicode.Security.Covert.VariationSelectorPayload
import Unicode.Security.Display.RtlInjection
import Unicode.Generated.EmojiSequences
import Unicode.Generated.GraphemeBreakProperty

namespace Unicode.Security.Display.RendererDivergence

open Unicode.Security.Calculus

set_option maxRecDepth 1000000

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

inductive SubThreat where
  | combiningStackOverflow   (basePos : Nat) (stackLen : Nat)
  | variationSelectorVariance (firstVsPos : Nat) (firstVsCp : Nat)
  | unregisteredZwjVariance  (firstZwjPos : Nat)
  | fullwidthVariance        (firstFwPos : Nat) (firstFwCp : Nat)
  | mixedDirectionVariance   (ltrCount : Nat) (rtlCount : Nat)
  deriving DecidableEq, Repr, Inhabited

inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : List Nat) (decoded : List UInt8)
  deriving Inhabited

structure Verdict where
  input              : List Nat
  classify           : Classification
  vsCount            : Nat
  combiningCount     : Nat
  fullwidthCount     : Nat
  hasZwj             : Bool
  strongLTRCount     : Nat
  strongRTLCount     : Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Core predicates
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cp` is a variation selector (FE00-FE0F or
    E0100-E01EF or 180B-180D). -/
@[inline]
def isVariationSelector (cp : Nat) : Bool :=
  Unicode.Security.Covert.VariationSelectorPayload.isVariationSelector cp

/-- True iff `cp` is the ZWJ codepoint. -/
@[inline]
def isZwj (cp : Nat) : Bool := cp = 0x200D

/-- True iff `cp` is in the Halfwidth/Fullwidth Forms block. -/
@[inline]
def isFullwidthHalfwidth (cp : Nat) : Bool :=
  0xFF01 ≤ cp ∧ cp ≤ 0xFFEF

/-- True iff `cp` has `Grapheme_Cluster_Break = Extend`. -/
def isGraphemeExtend (cp : Nat) : Bool :=
  match Unicode.Generated.GraphemeBreakProperty.lookupGCB cp with
  | .Extend => true
  | other   =>
    Function.const Unicode.Generated.GraphemeBreakProperty.GCBClass false other

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Sub-detectors
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Count of variation selectors in `input`. -/
def countVS (input : List Nat) : Nat :=
  input.foldl (fun n cp => if isVariationSelector cp then n + 1 else n) 0

/-- Count of combining (Extend) marks in `input`. -/
def countCombining (input : List Nat) : Nat :=
  input.foldl (fun n cp => if isGraphemeExtend cp then n + 1 else n) 0

/-- Count of fullwidth/halfwidth chars in `input`. -/
def countFullwidth (input : List Nat) : Nat :=
  input.foldl (fun n cp => if isFullwidthHalfwidth cp then n + 1 else n) 0

/-- True iff `input` contains any ZWJ. -/
def hasZwj (input : List Nat) : Bool :=
  input.any isZwj

/-- Position of the first variation selector in `input`. -/
def firstVsPos (input : List Nat) : Option (Nat × Nat) :=
  input.zipIdx.findSome? (fun cpWithIdx =>
    if isVariationSelector cpWithIdx.1 then some (cpWithIdx.2, cpWithIdx.1)
    else none)

/-- Position of the first ZWJ. -/
def firstZwjPos (input : List Nat) : Option Nat :=
  input.zipIdx.findSome? (fun cpWithIdx =>
    if isZwj cpWithIdx.1 then some cpWithIdx.2 else none)

/-- Position of the first fullwidth/halfwidth char. -/
def firstFullwidthPos (input : List Nat) : Option (Nat × Nat) :=
  input.zipIdx.findSome? (fun cpWithIdx =>
    if isFullwidthHalfwidth cpWithIdx.1 then some (cpWithIdx.2, cpWithIdx.1)
    else none)

/-- Find the first base position `p` (a non-Extend codepoint)
    immediately followed by ≥ `minStack` consecutive Extend
    codepoints (Zalgo-like stack).  Returns `some (basePos, minStack)`
    on hit: the `minStack` codepoints following `p` are taken and
    tested for the full run of Extend. -/
def firstCombiningStack
    (input : List Nat) (minStack : Nat) : Option (Nat × Nat) :=
  input.zipIdx.findSome? (fun cpWithIdx =>
    if ¬ isGraphemeExtend cpWithIdx.1 then
      let following := (input.drop (cpWithIdx.2 + 1)).take minStack
      if following.length = minStack ∧ following.all isGraphemeExtend then
        some (cpWithIdx.2, minStack)
      else none
    else none)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The RendererDivergence detection function. -/
def detect (input : List Nat) : Verdict :=
  let vsCount := countVS input
  let combCount := countCombining input
  let fwCount := countFullwidth input
  let zwjPresent := hasZwj input
  let ltrCount := Unicode.Security.Display.RtlInjection.countStrongLTR input
  let rtlCount := Unicode.Security.Display.RtlInjection.countStrongRTL input
  let classification : Classification :=
    -- Priority 1: combining-mark stack overflow (Zalgo).
    match firstCombiningStack input 4 with
    | some (basePos, stackLen) =>
      .hazard (.combiningStackOverflow basePos stackLen)
        [basePos] []
    | none =>
      -- Priority 2: any VS triggers presentation variance.
      match firstVsPos input with
      | some (pos, cp) =>
        .hazard (.variationSelectorVariance pos cp) [pos] []
      | none =>
        -- Priority 3: ZWJ-containing input not in registered RGI.
        if zwjPresent ∧
           ¬ Unicode.Generated.EmojiSequences.isRegisteredZwjSequence input then
          match firstZwjPos input with
          | some pos =>
            .hazard (.unregisteredZwjVariance pos) [pos] []
          | none => .clear
        -- Priority 4: fullwidth/halfwidth.
        else
          match firstFullwidthPos input with
          | some (pos, cp) =>
            .hazard (.fullwidthVariance pos cp) [pos] []
          | none =>
            -- Priority 5: mixed direction.
            if ltrCount > 0 ∧ rtlCount > 0 then
              .hazard (.mixedDirectionVariance ltrCount rtlCount)
                [] []
            else
              .clear
  { input := input,
    classify := classification,
    vsCount := vsCount,
    combiningCount := combCount,
    fullwidthCount := fwCount,
    hasZwj := zwjPresent,
    strongLTRCount := ltrCount,
    strongRTLCount := rtlCount }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Fixture-row tag string for each `SubThreat` constructor. -/
def SubThreat.tag : SubThreat → String
  | .combiningStackOverflow    basePos stackLen =>
      Function.const (Nat × Nat) "CombiningStackOverflow" (basePos, stackLen)
  | .variationSelectorVariance firstVsPos firstVsCp =>
      Function.const (Nat × Nat) "VariationSelectorVariance"
        (firstVsPos, firstVsCp)
  | .unregisteredZwjVariance   firstZwjPos =>
      Function.const Nat "UnregisteredZwjVariance" firstZwjPos
  | .fullwidthVariance         firstFwPos firstFwCp =>
      Function.const (Nat × Nat) "FullwidthVariance" (firstFwPos, firstFwCp)
  | .mixedDirectionVariance    ltrCount rtlCount =>
      Function.const (Nat × Nat) "MixedDirectionVariance" (ltrCount, rtlCount)

/-- True iff the classification is `.clear` (i.e. stable). -/
def Classification.isClear : Classification → Bool
  | .clear                     => true
  | .hazard sub positions decoded =>
      Function.const (SubThreat × List Nat × List UInt8) false
        (sub, positions, decoded)

/-- Tag string of a classification. -/
def Classification.tag : Classification → Option String
  | .clear                     => none
  | .hazard sub positions decoded =>
      Function.const (List Nat × List UInt8) (some sub.tag) (positions, decoded)

/-- Positions array of a classification. -/
def Classification.positions : Classification → List Nat
  | .clear                     => []
  | .hazard sub positions decoded =>
      Function.const (SubThreat × List UInt8) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is stable. -/
theorem detect_empty_clear : (detect []).classify.isClear = true := by
  decide +kernel

/-- Plain ASCII is stable. -/
theorem detect_ascii_clear :
    (detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  decide +kernel

/-- Plain Han is stable. -/
theorem detect_han_clear :
    (detect [0x4E2D, 0x6587]).classify.isClear = true := by decide +kernel

/-- A single VS (FE0F) — variance. -/
theorem detect_vs_variance :
    (detect [0x1F600, 0xFE0F]).classify.tag
      = some "VariationSelectorVariance" := by decide +kernel

/-- Registered RGI family ZWJ sequence — stable. -/
theorem detect_rgi_family_clear :
    (detect [0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467,
              0x200D, 0x1F466]).classify.isClear = true := by decide +kernel

/-- Unregistered ZWJ chain (man + ZWJ + woman, not in RGI) — variance. -/
theorem detect_unregistered_zwj_variance :
    (detect [0x1F468, 0x200D, 0x1F469]).classify.tag
      = some "UnregisteredZwjVariance" := by decide +kernel

/-- 4-deep combining stack (Zalgo-shape) — variance. -/
theorem detect_zalgo_variance :
    (detect [0x0061, 0x0301, 0x0302, 0x0303, 0x0304]).classify.tag
      = some "CombiningStackOverflow" := by decide +kernel

/-- Fullwidth A — variance. -/
theorem detect_fullwidth_variance :
    (detect [0xFF21]).classify.tag = some "FullwidthVariance" := by
  decide +kernel

/-- Mixed Latin + Hebrew — variance. -/
theorem detect_mixed_direction :
    (detect [0x41, 0x42, 0x05D0, 0x05D1]).classify.tag
      = some "MixedDirectionVariance" := by decide +kernel

end Unicode.Security.Display.RendererDivergence
