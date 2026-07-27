/-
  Unicode.Identifier

  UAX #31 — Unicode Identifier and Pattern Syntax. Defines the
  default identifier rule R1-D1 and the optional UAX #31 §5.2
  general security profile derived from `IdentifierStatus.txt` and
  `IdentifierType.txt`.

  Two layers are exposed:

    * `isDefaultIdentifier` — the default UAX #31 R1-D1 rule:
      first codepoint is in `XID_Start ∪ {U+005F LOW LINE}`, every
      subsequent codepoint is in `XID_Continue`.

    * `isAllowedIdentifier` — adds the General security profile
      from UTS #39: every codepoint must additionally have
      `Identifier_Status = Allowed`. This is the recommendation
      for systems that want to reject confusable / mixed-script
      / restricted-use identifiers in addition to non-XID input.
-/

import Unicode.Generated.DerivedCoreProperties
import Unicode.Generated.IdentifierStatus

namespace Unicode.Identifier

set_option maxRecDepth 100000

open Unicode.Generated.DerivedCoreProperties (xidStart xidContinue)
open Unicode.Generated.IdentifierStatus
  (allowedRanges IdentifierStatus defaultStatus)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 LOW-LEVEL PREDICATES
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cp` lies inside any `(lo, hi)` inclusive range in `rs`.
    Ranges are held as a `List` so a per-codepoint membership test reduces
    linearly in the kernel. -/
def inRanges (cp : Nat) (rs : List (Nat × Nat)) : Bool :=
  rs.any (fun lh => decide (lh.fst ≤ cp ∧ cp ≤ lh.snd))

/-- True iff `cp` has `XID_Start = Yes` per `DerivedCoreProperties.txt`. -/
def isXIDStart (cp : Nat) : Bool := inRanges cp xidStart

/-- True iff `cp` has `XID_Continue = Yes` per `DerivedCoreProperties.txt`. -/
def isXIDContinue (cp : Nat) : Bool := inRanges cp xidContinue

/-- Identifier_Status of `cp` per `IdentifierStatus.txt`. Codepoints
    not explicitly listed default to `Restricted`. -/
def identifierStatus (cp : Nat) : IdentifierStatus :=
  if inRanges cp allowedRanges then .Allowed else defaultStatus

/-- True iff `cp` has `Identifier_Status = Allowed` per UTS #39. -/
def isAllowedStatus (cp : Nat) : Bool :=
  match identifierStatus cp with
  | .Allowed    => true
  | .Restricted => false

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 UAX #31 R1-D1 — DEFAULT IDENTIFIER
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cp` is admissible as the first codepoint of a default
    identifier per UAX #31 R1-D1: `XID_Start = Yes` or U+005F LOW LINE. -/
def isDefaultIdStart (cp : Nat) : Bool :=
  isXIDStart cp || cp == 0x005F

/-- True iff `cp` is admissible as a continuation codepoint of a
    default identifier per UAX #31 R1-D1: `XID_Continue = Yes`. -/
def isDefaultIdContinue (cp : Nat) : Bool :=
  isXIDContinue cp

/-- True iff `cps` is a well-formed default identifier per UAX #31
    R1-D1. The empty sequence is rejected. -/
def isDefaultIdentifier (cps : List Nat) : Bool :=
  match cps with
  | []            => false
  | first :: rest => isDefaultIdStart first && rest.all isDefaultIdContinue

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 UTS #39 GENERAL SECURITY PROFILE
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cps` is a well-formed default identifier AND every
    codepoint has `Identifier_Status = Allowed` per UTS #39. -/
def isAllowedIdentifier (cps : List Nat) : Bool :=
  isDefaultIdentifier cps && cps.all isAllowedStatus

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 KNOWN-CODEPOINT PREDICATES
-- ═══════════════════════════════════════════════════════════════════════════════

/-- ASCII letters are valid XID_Start. -/
theorem isXIDStart_a : isXIDStart 0x0061 = true := by decide +kernel
theorem isXIDStart_z : isXIDStart 0x007A = true := by decide +kernel
theorem isXIDStart_A : isXIDStart 0x0041 = true := by decide +kernel
theorem isXIDStart_Z : isXIDStart 0x005A = true := by decide +kernel

/-- ASCII digits are NOT XID_Start (they're XID_Continue only). -/
theorem isXIDStart_d0 : isXIDStart 0x0030 = false := by decide +kernel
theorem isXIDStart_d9 : isXIDStart 0x0039 = false := by decide +kernel
theorem isXIDContinue_d0 : isXIDContinue 0x0030 = true := by decide +kernel

/-- LOW LINE is NOT XID_Start but is accepted as default-id start by R1-D1. -/
theorem isXIDStart_underscore        : isXIDStart 0x005F = false := by decide +kernel
theorem isDefaultIdStart_underscore  : isDefaultIdStart 0x005F = true := by decide +kernel
theorem isDefaultIdContinue_underscore : isDefaultIdContinue 0x005F = true := by decide +kernel

/-- ASCII space is neither start nor continue. -/
theorem isDefaultIdStart_space    : isDefaultIdStart 0x0020 = false := by decide +kernel
theorem isDefaultIdContinue_space : isDefaultIdContinue 0x0020 = false := by decide +kernel

/-- Greek small alpha is XID_Start (Allowed under UTS #39). -/
theorem isAllowedStatus_alpha : isAllowedStatus 0x03B1 = true := by decide +kernel

/-- HANGUL CHOSEONG TIKEUT-MIEUM (U+115F) is in the default-ignorable
    Hangul filler range that UTS #39 marks Restricted. -/
theorem isAllowedStatus_hangul_filler : isAllowedStatus 0x115F = false := by decide +kernel

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 SAMPLE STRINGS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- `"abc"` is a valid default identifier. -/
theorem isDefaultIdentifier_abc :
    isDefaultIdentifier [0x0061, 0x0062, 0x0063] = true := by decide +kernel

/-- `"_abc"` is valid (underscore can lead). -/
theorem isDefaultIdentifier_underscoreLead :
    isDefaultIdentifier [0x005F, 0x0061, 0x0062, 0x0063] = true := by decide +kernel

/-- `"a1b2"` is valid (digits OK after start). -/
theorem isDefaultIdentifier_a1b2 :
    isDefaultIdentifier [0x0061, 0x0031, 0x0062, 0x0032] = true := by decide +kernel

/-- `"123abc"` is rejected (digit cannot start). -/
theorem isDefaultIdentifier_digitStart :
    isDefaultIdentifier [0x0031, 0x0032, 0x0033, 0x0061, 0x0062, 0x0063] = false := by
  decide +kernel

/-- `"a b"` is rejected (space is neither start nor continue). -/
theorem isDefaultIdentifier_withSpace :
    isDefaultIdentifier [0x0061, 0x0020, 0x0062] = false := by decide +kernel

/-- The empty sequence is rejected. -/
theorem isDefaultIdentifier_empty :
    isDefaultIdentifier [] = false := by decide +kernel

/-- Greek "λόγος" is a valid identifier (all XID_Continue, λ is XID_Start). -/
theorem isDefaultIdentifier_logos :
    isDefaultIdentifier [0x03BB, 0x03CC, 0x03B3, 0x03BF, 0x03C2] = true := by decide +kernel

/-- Default id pass + Allowed status pass for "abc". -/
theorem isAllowedIdentifier_abc :
    isAllowedIdentifier [0x0061, 0x0062, 0x0063] = true := by decide +kernel

end Unicode.Identifier
