/-
  Unicode.Security.Boundary.ConfusableBidiCompound

  X3 — Cross-Layer Identity × Display Compound.  Layer-5 boundary
  detector that fires on inputs which combine a Layer-2 identity
  hazard (confusable codepoint per I1, UTS #39 §4) with a Layer-3
  display-deception channel (UAX #9 bidi format control per D3).

  Threat model.  Tier A₂..A₃.  The canonical IDN homograph plus
  Trojan Source compound:

    * attacker registers a domain or username using Cyrillic
      'а' (U+0430) in place of Latin 'a' (the I1 layer);
    * AND wraps the visible string in RLO/PDF so the rendered
      text matches a legitimate identifier (the D3 layer);
    * the receiver sees `admin`, the resolver / comparator sees
      a different identifier.

  Distinct from I1 alone (which catches the confusable cp but
  misses the visual reorder) and D3 alone (which catches the
  bidi but misses the script confusion).  X3 is the
  simultaneity verdict — the right output for source-code
  commits, IDN labels, package metadata, filename fields, and
  any other domain where both visual review and string
  comparison gate access.

  Note on the confusables table: confusables.txt v16 maps
  U+006D 'm' to the sequence U+0072 U+006E ('rn').  Plain
  ASCII inputs containing 'm' combined with any bidi format
  control therefore fire `confusableInOverride` at the 'm'
  position.

  Sub-threats (priority order, both reachable):

    1. `confusableInOverride (confusablePos, bidiPos)` —
       confusable cp + override-class bidi control (LRE / RLE /
       LRO / RLO / PDF, per `isBidiEmbeddingControl`).  This is
       the high-severity Trojan-Source CVE-2021-42574 class.
    2. `confusableInIsolate (confusablePos, bidiPos)` —
       confusable cp + isolate-class bidi control (LRI / RLI /
       FSI / PDI, per `isBidiIsolateControl`).  Reached when no
       override control fires first; softer attack class but
       still a compound hazard.
-/

import Unicode.Security.Calculus
import Unicode.TrojanSource
import Unicode.Confusables

namespace Unicode.Security.Boundary.ConfusableBidiCompound

open Unicode.Security.Calculus
open Unicode.TrojanSource (isBidiEmbeddingControl isBidiIsolateControl)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Per-position scans
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cp` is a confusable source per UTS #39 §4 — i.e. it
    has a row in confusables.txt mapping it to a different
    skeleton sequence.  Plain ASCII letters return `false`; only
    homoglyph forms (Cyrillic а, Greek ο, mathematical-italic
    letters, etc.) return `true`. -/
@[inline]
def isConfusableCp (cp : Nat) : Bool :=
  (Unicode.Confusables.lookupConfusable? cp).isSome

/-- First input position holding a confusable cp. -/
def firstConfusablePos (input : Array Nat) : Option Nat :=
  (Array.range input.size).findSome? (fun i =>
    if h : i < input.size then
      if isConfusableCp input[i] then some i else none
    else none)

/-- First input position holding an override-class bidi control
    (LRE / RLE / LRO / RLO / PDF). -/
def firstOverridePos (input : Array Nat) : Option Nat :=
  (Array.range input.size).findSome? (fun i =>
    if h : i < input.size then
      if isBidiEmbeddingControl input[i] then some i else none
    else none)

/-- First input position holding an isolate-class bidi control
    (LRI / RLI / FSI / PDI). -/
def firstIsolatePos (input : Array Nat) : Option Nat :=
  (Array.range input.size).findSome? (fun i =>
    if h : i < input.size then
      if isBidiIsolateControl input[i] then some i else none
    else none)

/-- Total count of confusable cps in `input`. -/
def confusableCount (input : Array Nat) : Nat :=
  (Array.range input.size).foldl (init := 0) (fun acc i =>
    if h : i < input.size then
      if isConfusableCp input[i] then acc + 1 else acc
    else acc)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Types
-- ═══════════════════════════════════════════════════════════════════════════════

inductive X3SubThreat where
  | confusableInOverride (confusablePos : Nat) (bidiPos : Nat)
  | confusableInIsolate  (confusablePos : Nat) (bidiPos : Nat)
  deriving DecidableEq, Repr, Inhabited

inductive X3Classification where
  | clear
  | hazard (sub : X3SubThreat) (positions : Array Nat) (decoded : ByteArray)
  deriving Inhabited

structure X3Verdict where
  input           : Array Nat
  classify        : X3Classification
  confusableCount : Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The X3 detection function. -/
def detect (input : Array Nat) : X3Verdict :=
  let classification : X3Classification :=
    match firstConfusablePos input with
    | none => .clear
    | some confusablePos =>
      match firstOverridePos input with
      | some bidiPos =>
        .hazard (.confusableInOverride confusablePos bidiPos)
          #[confusablePos, bidiPos] ByteArray.empty
      | none =>
        match firstIsolatePos input with
        | some bidiPos =>
          .hazard (.confusableInIsolate confusablePos bidiPos)
            #[confusablePos, bidiPos] ByteArray.empty
        | none => .clear
  { input := input,
    classify := classification,
    confusableCount := confusableCount input }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

def X3SubThreat.tag : X3SubThreat → String
  | .confusableInOverride confusablePos bidiPos =>
    Function.const (Nat × Nat) "ConfusableInOverride" (confusablePos, bidiPos)
  | .confusableInIsolate  confusablePos bidiPos =>
    Function.const (Nat × Nat) "ConfusableInIsolate"  (confusablePos, bidiPos)

def X3Classification.isClear : X3Classification → Bool
  | .clear                       => true
  | .hazard sub positions decoded =>
    Function.const (X3SubThreat × Array Nat × ByteArray) false
      (sub, positions, decoded)

def X3Classification.tag : X3Classification → Option String
  | .clear                       => none
  | .hazard sub positions decoded =>
    Function.const (Array Nat × ByteArray) (some sub.tag) (positions, decoded)

def X3Classification.positions : X3Classification → Array Nat
  | .clear                       => #[]
  | .hazard sub positions decoded =>
    Function.const (X3SubThreat × ByteArray) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear. -/
theorem detect_empty_clear : (detect #[]).classify.isClear = true := by
  native_decide

/-- Pure ASCII is clear; no confusables, no bidi. -/
theorem detect_ascii_clear :
    (detect #[0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  native_decide

/-- ASCII + override bidi is clear under X3 — D3 covers the
    bidi-only case.  No confusable, no compound. -/
theorem detect_ascii_plus_override_clear :
    (detect #[0x202E, 0x0041, 0x0042, 0x0043]).classify.isClear = true := by
  native_decide

/-- Cyrillic а alone is clear under X3 — I1 covers the
    confusable-only case.  No bidi, no compound. -/
theorem detect_cyrillic_a_alone_clear :
    (detect #[0x0430]).classify.isClear = true := by native_decide

/-- RLO + Cyrillic а fires `confusableInOverride` — the canonical
    Trojan-Source + IDN-homograph compound. -/
theorem detect_rlo_cyrillic_compound :
    (detect #[0x202E, 0x0430]).classify.tag = some "ConfusableInOverride" := by
  native_decide

/-- LRI + Greek ο fires `confusableInIsolate` — the isolate-class
    soft compound. -/
theorem detect_lri_greek_compound :
    (detect #[0x2066, 0x03BF]).classify.tag = some "ConfusableInIsolate" := by
  native_decide

end Unicode.Security.Boundary.ConfusableBidiCompound
