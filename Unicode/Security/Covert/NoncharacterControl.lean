/-
  Unicode.Security.Covert.NoncharacterControl

  Detection of designated Unicode noncharacters (U+FDD0..U+FDEF and every
  U+..FFFE / U+..FFFF) and C0 / C1 control codepoints in interchange text.

  These codepoints are legal Unicode scalars but are never appropriate in
  interchanged identifier-, header-, or display-bearing text: noncharacters are
  reserved for internal use and must not cross an interchange boundary (UAX #44),
  and the C0/C1 control blocks carry no printable meaning in such contexts and are a
  classic smuggling / terminal-injection surface. Lean already decides membership at
  the codec layer (`Unicode.Codec.Noncharacters.isNoncharacter`); this detector lifts
  that core predicate, plus explicit C0/C1 ranges, into the Security-layer verdict
  vocabulary so a single `scan` reports them alongside the attack-pattern detectors.

  Sub-threat: the first flagged position, tagged by which class it is —
  `Noncharacter`, `C0Control`, or `C1Control`.
-/

import Unicode.Security.Calculus
import Unicode.Codec.Noncharacters

namespace Unicode.Security.Covert.NoncharacterControl

open Unicode.Security.Calculus
open Unicode.Codec.Noncharacters (isNoncharacter)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Per-codepoint scan
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A C0 control: U+0000..U+001F excluding the structured whitespace TAB (U+0009),
    LF (U+000A), and CR (U+000D), plus DEL (U+007F). The excluded whitespace is
    legitimate interchange structure and is not flagged. -/
def isC0Control (cp : Nat) : Bool :=
  (cp ≤ 0x1F ∧ cp ≠ 0x09 ∧ cp ≠ 0x0A ∧ cp ≠ 0x0D) ∨ cp = 0x7F

/-- A C1 control: U+0080..U+009F. -/
def isC1Control (cp : Nat) : Bool :=
  0x80 ≤ cp ∧ cp ≤ 0x9F

/-- First input position carrying a noncharacter or C0/C1 control, as
    `(position, codepoint, isC0, isC1)`. Noncharacter takes priority and is signalled
    by both flags false. -/
def firstHit (input : List Nat) : Option (Nat × Nat × Bool × Bool) :=
  input.zipIdx.findSome? (fun cpWithIdx =>
    let cp  := cpWithIdx.1
    let pos := cpWithIdx.2
    if isNoncharacter cp then some (pos, cp, false, false)
    else if isC0Control cp then some (pos, cp, true, false)
    else if isC1Control cp then some (pos, cp, false, true)
    else none)

/-- Total count of flagged positions (noncharacter or C0/C1 control). -/
def hitCount (input : List Nat) : Nat :=
  input.foldl (init := 0) (fun acc cp =>
    if isNoncharacter cp ∨ isC0Control cp ∨ isC1Control cp then acc + 1 else acc)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Types
-- ═══════════════════════════════════════════════════════════════════════════════

inductive SubThreat where
  | noncharacter (pos : Nat) (cp : Nat)
  | c0Control    (pos : Nat) (cp : Nat)
  | c1Control    (pos : Nat) (cp : Nat)
  deriving DecidableEq, Repr, Inhabited

inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : List Nat) (decoded : List UInt8)
  deriving Inhabited

structure Verdict where
  input    : List Nat
  classify : Classification
  hitCount : Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The NoncharacterControl detection function. -/
def detect (input : List Nat) : Verdict :=
  let classification : Classification :=
    match firstHit input with
    | some (pos, cp, isC0, isC1) =>
      if isC0 then .hazard (.c0Control pos cp) [pos] []
      else if isC1 then .hazard (.c1Control pos cp) [pos] []
      else .hazard (.noncharacter pos cp) [pos] []
    | none => .clear
  { input := input,
    classify := classification,
    hitCount := hitCount input }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Fixture-row tag string for each `SubThreat` constructor. -/
def SubThreat.tag : SubThreat → String
  | .noncharacter pos cp => Function.const (Nat × Nat) "Noncharacter" (pos, cp)
  | .c0Control    pos cp => Function.const (Nat × Nat) "C0Control" (pos, cp)
  | .c1Control    pos cp => Function.const (Nat × Nat) "C1Control" (pos, cp)

def Classification.isClear : Classification → Bool
  | .clear                        => true
  | .hazard sub positions decoded =>
      Function.const (SubThreat × List Nat × List UInt8) false
        (sub, positions, decoded)

def Classification.tag : Classification → Option String
  | .clear                        => none
  | .hazard sub positions decoded =>
      Function.const (List Nat × List UInt8) (some sub.tag) (positions, decoded)

def Classification.positions : Classification → List Nat
  | .clear                        => []
  | .hazard sub positions decoded =>
      Function.const (SubThreat × List UInt8) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Pure ASCII text is clear. -/
theorem detect_ascii_clear :
    (detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by decide

/-- A BMP-block noncharacter (U+FDD0) fires `Noncharacter`. -/
theorem detect_bmp_noncharacter :
    (detect [0xFDD0]).classify.tag = some "Noncharacter" := by decide

/-- A plane-end noncharacter (U+10FFFF) fires `Noncharacter`. -/
theorem detect_plane_end_noncharacter :
    (detect [0x10FFFF]).classify.tag = some "Noncharacter" := by decide

/-- A C0 control (U+0000) fires `C0Control`. -/
theorem detect_c0_control :
    (detect [0x41, 0x00, 0x42]).classify.tag = some "C0Control" := by decide

/-- A C1 control (U+0080) fires `C1Control`. -/
theorem detect_c1_control :
    (detect [0x41, 0x80, 0x42]).classify.tag = some "C1Control" := by decide

end Unicode.Security.Covert.NoncharacterControl
