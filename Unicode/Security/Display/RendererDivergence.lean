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
    * `.unknown`          we cannot decide — for v1 we treat
                          this conservatively as `.knownVariance`
                          with the `.unknown` sub-threat tag,
                          so callers always get a binary
                          stable / non-stable answer through
                          the universal Classification carrier.

  v1 scope.  Heuristic-driven detection of empirically-known
  variance triggers.  The v2 readiness item is a renderer-cohort
  membership table (Chrome / Firefox / Safari / iTerm /
  Windows Terminal / common font-fallback chains) that pins
  variance to specific (renderer-id, codepoint-or-sequence)
  pairs.

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
  | hazard (sub : SubThreat) (positions : Array Nat) (decoded : ByteArray)
  deriving Inhabited

structure Verdict where
  input              : Array Nat
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
  | other   => Function.const _ false other

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Sub-detectors
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Count of variation selectors in `input`. -/
def countVS (input : Array Nat) : Nat :=
  input.foldl (fun n cp => if isVariationSelector cp then n + 1 else n) 0

/-- Count of combining (Extend) marks in `input`. -/
def countCombining (input : Array Nat) : Nat :=
  input.foldl (fun n cp => if isGraphemeExtend cp then n + 1 else n) 0

/-- Count of fullwidth/halfwidth chars in `input`. -/
def countFullwidth (input : Array Nat) : Nat :=
  input.foldl (fun n cp => if isFullwidthHalfwidth cp then n + 1 else n) 0

/-- True iff `input` contains any ZWJ. -/
def hasZwj (input : Array Nat) : Bool :=
  input.any isZwj

/-- Position of the first variation selector in `input`. -/
def firstVsPos (input : Array Nat) : Option (Nat × Nat) :=
  (Array.range input.size).findSome? (fun i =>
    if h : i < input.size then
      if isVariationSelector input[i] then some (i, input[i]) else none
    else none)

/-- Position of the first ZWJ. -/
def firstZwjPos (input : Array Nat) : Option Nat :=
  (Array.range input.size).findSome? (fun i =>
    if h : i < input.size then
      if isZwj input[i] then some i else none
    else none)

/-- Position of the first fullwidth/halfwidth char. -/
def firstFullwidthPos (input : Array Nat) : Option (Nat × Nat) :=
  (Array.range input.size).findSome? (fun i =>
    if h : i < input.size then
      if isFullwidthHalfwidth input[i] then some (i, input[i]) else none
    else none)

/-- Find the first base position `p` followed by ≥ `minStack`
    consecutive Extend codepoints (Zalgo-like stack).  Returns
    `some (basePos, minStack)` on hit.  Pure-functional shape:
    for each candidate base `p`, check that the next `minStack`
    positions are all Extend. -/
def firstCombiningStack
    (input : Array Nat) (minStack : Nat) : Option (Nat × Nat) :=
  (Array.range input.size).findSome? (fun p =>
    if h : p < input.size ∧ p + minStack < input.size then
      if ¬ isGraphemeExtend input[p] then
        let allExtend :=
          (Array.range minStack).all (fun k =>
            if hk : p + 1 + k < input.size then
              isGraphemeExtend input[p + 1 + k]
            else false)
        if allExtend then some (p, minStack) else none
      else none
    else none)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The RendererDivergence detection function. -/
def detect (input : Array Nat) : Verdict :=
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
        #[basePos] ByteArray.empty
    | none =>
      -- Priority 2: any VS triggers presentation variance.
      match firstVsPos input with
      | some (pos, cp) =>
        .hazard (.variationSelectorVariance pos cp) #[pos] ByteArray.empty
      | none =>
        -- Priority 3: ZWJ-containing input not in registered RGI.
        if zwjPresent ∧
           ¬ Unicode.Generated.EmojiSequences.isRegisteredZwjSequence input then
          match firstZwjPos input with
          | some pos =>
            .hazard (.unregisteredZwjVariance pos) #[pos] ByteArray.empty
          | none => .clear
        -- Priority 4: fullwidth/halfwidth.
        else
          match firstFullwidthPos input with
          | some (pos, cp) =>
            .hazard (.fullwidthVariance pos cp) #[pos] ByteArray.empty
          | none =>
            -- Priority 5: mixed direction.
            if ltrCount > 0 ∧ rtlCount > 0 then
              .hazard (.mixedDirectionVariance ltrCount rtlCount)
                #[] ByteArray.empty
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
      Function.const (SubThreat × Array Nat × ByteArray) false
        (sub, positions, decoded)

/-- Tag string of a classification. -/
def Classification.tag : Classification → Option String
  | .clear                     => none
  | .hazard sub positions decoded =>
      Function.const (Array Nat × ByteArray) (some sub.tag) (positions, decoded)

/-- Positions array of a classification. -/
def Classification.positions : Classification → Array Nat
  | .clear                     => #[]
  | .hazard sub positions decoded =>
      Function.const (SubThreat × ByteArray) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is stable. -/
theorem detect_empty_clear : (detect #[]).classify.isClear = true := by
  native_decide

/-- Plain ASCII is stable. -/
theorem detect_ascii_clear :
    (detect #[0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  native_decide

/-- Plain Han is stable. -/
theorem detect_han_clear :
    (detect #[0x4E2D, 0x6587]).classify.isClear = true := by native_decide

/-- A single VS (FE0F) — variance. -/
theorem detect_vs_variance :
    (detect #[0x1F600, 0xFE0F]).classify.tag
      = some "VariationSelectorVariance" := by native_decide

/-- Registered RGI family ZWJ sequence — stable. -/
theorem detect_rgi_family_clear :
    (detect #[0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467,
              0x200D, 0x1F466]).classify.isClear = true := by native_decide

/-- Unregistered ZWJ chain (man + ZWJ + woman, not in RGI) — variance. -/
theorem detect_unregistered_zwj_variance :
    (detect #[0x1F468, 0x200D, 0x1F469]).classify.tag
      = some "UnregisteredZwjVariance" := by native_decide

/-- 4-deep combining stack (Zalgo-shape) — variance. -/
theorem detect_zalgo_variance :
    (detect #[0x0061, 0x0301, 0x0302, 0x0303, 0x0304]).classify.tag
      = some "CombiningStackOverflow" := by native_decide

/-- Fullwidth A — variance. -/
theorem detect_fullwidth_variance :
    (detect #[0xFF21]).classify.tag = some "FullwidthVariance" := by
  native_decide

/-- Mixed Latin + Hebrew — variance. -/
theorem detect_mixed_direction :
    (detect #[0x41, 0x42, 0x05D0, 0x05D1]).classify.tag
      = some "MixedDirectionVariance" := by native_decide

end Unicode.Security.Display.RendererDivergence
