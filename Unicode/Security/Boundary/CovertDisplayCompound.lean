/-
  Unicode.Security.Boundary.CovertDisplayCompound

  Boundary detector that fires on inputs which combine a
  covert channel (unregistered variation selectors per
  VariationSelectorPayload, or tag-block characters per
  TagBlockPayload) with a display-deception channel (UAX #9
  bidi format controls per RtlInjection).

  Threat model.  Tier A₂..A₃.  A single payload simultaneously
  carries:

    * a covert byte stream encoded in VS bytes or tag-block
      bytes (invisible to human review); and
    * a bidi-format-control sequence that re-orders the visible
      text so the bytes appear in a different position from
      where they execute.

  The compound is strictly worse than the sum:

    * VariationSelectorPayload / TagBlockPayload alone catch
      the covert payload but cannot tell whether the visible-
      text context has been re-ordered.
    * RtlInjection alone catches the bidi controls but cannot
      tell whether the input is also carrying a covert payload.

  CovertDisplayCompound reports the simultaneous occurrence.

  Sub-threats (priority order, both reachable):

    1. `bidiPlusUnregisteredVs (bidiPos, vsPos)` — input
       contains a UAX #9 bidi format control AND a VS occurrence
       whose `classifyVSPosition` returns `.suspicious` (no
       matching row in StandardizedVariants.txt or
       emoji-variation-sequences.txt).
    2. `bidiPlusTagBlock (bidiPos, tagPos)` — input contains a
       bidi format control AND a tag-block character
       (U+E0000..U+E007F).  Reached when no unregistered VS
       fires first.
-/

import Unicode.Security.Calculus
import Unicode.TrojanSource
import Unicode.Security.Covert.VariationSelectorPayload

namespace Unicode.Security.Boundary.CovertDisplayCompound

open Unicode.Security.Calculus
open Unicode.TrojanSource (isBidiFormatControl)
open Unicode.Security.Covert.VariationSelectorPayload
  (VSUseClass classifyPositions)

set_option maxRecDepth 1000000

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Per-position scans
-- ═══════════════════════════════════════════════════════════════════════════════

/-- First input position holding a UAX #9 bidi format control. -/
def firstBidiPos (input : List Nat) : Option Nat :=
  input.zipIdx.findSome? (fun cpWithIdx =>
    if isBidiFormatControl cpWithIdx.1 then some cpWithIdx.2 else none)

/-- First input position whose classification under
    `classifyPositions` is `.suspicious` — i.e. a VS with no matching
    StandardizedVariants or emoji-variation-sequences row. -/
def firstSuspiciousVsPos (input : List Nat) : Option Nat :=
  (classifyPositions input).zipIdx.findSome? (fun clsWithIdx =>
    match clsWithIdx.1 with
    | .suspicious => some clsWithIdx.2
    | .nonVS | .registeredStandardized | .registeredEmojiPresentation
    | .registeredTextPresentation => none)

/-- True iff `cp` is in the tag-block range U+E0000..U+E007F.
    Tag characters are the second covert-channel class detected
    by SurrogateReassembly. -/
@[inline]
def isTagBlockChar (cp : Nat) : Bool :=
  Nat.ble 0xE0000 cp && Nat.ble cp 0xE007F

/-- First input position holding a tag-block character. -/
def firstTagBlockPos (input : List Nat) : Option Nat :=
  input.zipIdx.findSome? (fun cpWithIdx =>
    if isTagBlockChar cpWithIdx.1 then some cpWithIdx.2 else none)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Types
-- ═══════════════════════════════════════════════════════════════════════════════

inductive SubThreat where
  | bidiPlusUnregisteredVs (bidiPos : Nat) (vsPos : Nat)
  | bidiPlusTagBlock       (bidiPos : Nat) (tagPos : Nat)
  deriving DecidableEq, Repr, Inhabited

inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : List Nat) (decoded : ByteArray)
  deriving Inhabited

structure Verdict where
  input    : List Nat
  classify : Classification
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The CovertDisplayCompound detection function. -/
def detect (input : List Nat) : Verdict :=
  let classification : Classification :=
    match firstBidiPos input with
    | none => .clear
    | some bidiPos =>
      match firstSuspiciousVsPos input with
      | some vsPos =>
        .hazard (.bidiPlusUnregisteredVs bidiPos vsPos)
          [bidiPos, vsPos] ByteArray.empty
      | none =>
        match firstTagBlockPos input with
        | some tagPos =>
          .hazard (.bidiPlusTagBlock bidiPos tagPos)
            [bidiPos, tagPos] ByteArray.empty
        | none => .clear
  { input := input, classify := classification }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

def SubThreat.tag : SubThreat → String
  | .bidiPlusUnregisteredVs bidiPos vsPos =>
    Function.const (Nat × Nat) "BidiPlusUnregisteredVs" (bidiPos, vsPos)
  | .bidiPlusTagBlock       bidiPos tagPos =>
    Function.const (Nat × Nat) "BidiPlusTagBlock"       (bidiPos, tagPos)

def Classification.isClear : Classification → Bool
  | .clear                       => true
  | .hazard sub positions decoded =>
    Function.const (SubThreat × List Nat × ByteArray) false
      (sub, positions, decoded)

def Classification.tag : Classification → Option String
  | .clear                       => none
  | .hazard sub positions decoded =>
    Function.const (List Nat × ByteArray) (some sub.tag) (positions, decoded)

def Classification.positions : Classification → List Nat
  | .clear                       => []
  | .hazard sub positions decoded =>
    Function.const (SubThreat × ByteArray) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear. -/
theorem detect_empty_clear : (detect []).classify.isClear = true := by
  decide +kernel

/-- Pure ASCII is clear; no bidi, no VS, no tag block. -/
theorem detect_ascii_clear :
    (detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  decide +kernel

/-- Bidi-only (RLO alone) is clear here; the compound is
    not present. -/
theorem detect_bidi_only_clear :
    (detect [0x202E]).classify.isClear = true := by decide +kernel

/-- VS-only (ASCII + VS1) is clear here; the compound is
    not present. -/
theorem detect_vs_only_clear :
    (detect [0x0041, 0xFE00]).classify.isClear = true := by decide +kernel

/-- Compound RLO + ASCII + VS1 fires `bidiPlusUnregisteredVs`.
    VS1 attached to ASCII A is not in any standardized table, so
    its classification is `.suspicious`. -/
theorem detect_compound_bidi_vs :
    (detect [0x202E, 0x0041, 0xFE00]).classify.tag =
      some "BidiPlusUnregisteredVs" := by
  decide +kernel

/-- Compound RLO + ASCII + tag block (no suspicious VS) fires
    `bidiPlusTagBlock`. -/
theorem detect_compound_bidi_tag :
    (detect [0x202E, 0x0041, 0xE0001]).classify.tag =
      some "BidiPlusTagBlock" := by
  decide +kernel

end Unicode.Security.Boundary.CovertDisplayCompound
