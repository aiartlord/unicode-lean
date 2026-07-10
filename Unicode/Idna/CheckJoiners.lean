/-
  Unicode.Idna.CheckJoiners

  RFC 5892 Appendix A.1 / A.2 — the "CONTEXTJ" rules. These guard
  the contextual usage of U+200C (ZERO WIDTH NON-JOINER) and U+200D
  (ZERO WIDTH JOINER) in IDNA labels.

  A.2 — ZWJ:
    May appear only when preceded by a Virama (canonical combining
    class 9). ZWJ-after-Virama signals an explicit join in scripts
    like Devanagari.

  A.1 — ZWNJ:
    May appear when either (a) preceded by a Virama, or (b) embedded
    inside a Joining_Type context where it interrupts the natural
    join, with the regex:

        (JT:{L,D}) (JT:T)* U+200C (JT:T)* (JT:{R,D})

    Transparent characters on either side of ZWNJ are skipped; the
    first non-Transparent character on the left must be {L,D} and on
    the right must be {R,D}.
-/

import Unicode.Generated.DerivedJoiningType
import Unicode.Normalization.Lookup

namespace Unicode.Idna.CheckJoiners

set_option maxRecDepth 100000

open Unicode.Generated.DerivedJoiningType (JoiningType joiningType)

/-- True iff `cp` has Canonical_Combining_Class = 9 (Virama). -/
def isVirama (cp : Nat) : Bool :=
  decide (Unicode.Normalization.Lookup.canonicalCombiningClass cp = 9)

/-- Walk backward from index `j` (inclusive) skipping Transparent
    characters; return the joining type of the first non-Transparent
    character encountered. Returns `none` if the walk runs off the
    start of the label or all preceding characters are Transparent. -/
def firstNonTransparentDown : Nat → Array Nat → Nat → Option JoiningType
  | 0,        label, j  =>
    Function.const Nat (Function.const (Array Nat) (none : Option JoiningType) label) j
  | fuel+1,   label, j  =>
    match label[j]? with
    | none    => none
    | some cp =>
      let jt := joiningType cp
      match jt with
      | .Transparent =>
        if j = 0 then none
        else firstNonTransparentDown fuel label (j - 1)
      | .RightJoining => some .RightJoining
      | .LeftJoining  => some .LeftJoining
      | .DualJoining  => some .DualJoining
      | .JoinCausing  => some .JoinCausing
      | .NonJoining   => some .NonJoining

/-- Walk forward from index `j` (inclusive) skipping Transparent
    characters; return the joining type of the first non-Transparent
    character encountered. Returns `none` if the walk runs off the
    end of the label or all following characters are Transparent. -/
def firstNonTransparentUp : Nat → Array Nat → Nat → Option JoiningType
  | 0,        label, j  =>
    Function.const Nat (Function.const (Array Nat) (none : Option JoiningType) label) j
  | fuel+1,   label, j  =>
    match label[j]? with
    | none    => none
    | some cp =>
      let jt := joiningType cp
      match jt with
      | .Transparent  => firstNonTransparentUp fuel label (j + 1)
      | .RightJoining => some .RightJoining
      | .LeftJoining  => some .LeftJoining
      | .DualJoining  => some .DualJoining
      | .JoinCausing  => some .JoinCausing
      | .NonJoining   => some .NonJoining

/-- First non-Transparent joining type strictly before index `i`. -/
def joiningTypeBefore (label : Array Nat) (i : Nat) : Option JoiningType :=
  if i = 0 then none
  else firstNonTransparentDown i label (i - 1)

/-- First non-Transparent joining type strictly after index `i`. -/
def joiningTypeAfter (label : Array Nat) (i : Nat) : Option JoiningType :=
  firstNonTransparentUp (label.size - i) label (i + 1)

/-- True iff the joining type is `LeftJoining` or `DualJoining` —
    the class permitted on the left of ZWNJ in RFC 5892 A.1's regex. -/
def isLeftOrDual : Option JoiningType → Bool
  | none                => false
  | some .RightJoining  => false
  | some .LeftJoining   => true
  | some .DualJoining   => true
  | some .JoinCausing   => false
  | some .Transparent   => false
  | some .NonJoining    => false

/-- True iff the joining type is `RightJoining` or `DualJoining` —
    the class permitted on the right of ZWNJ. -/
def isRightOrDual : Option JoiningType → Bool
  | none                => false
  | some .RightJoining  => true
  | some .LeftJoining   => false
  | some .DualJoining   => true
  | some .JoinCausing   => false
  | some .Transparent   => false
  | some .NonJoining    => false

/-- RFC 5892 A.1: a ZWNJ at position `i` is contextually valid iff
    the preceding character is a Virama, or the joining-type regex
    `(L|D) T* ZWNJ T* (R|D)` matches around it. -/
def checkContextJZwnj (label : Array Nat) (i : Nat) : Bool :=
  let viramaPrev :=
    if i = 0 then false
    else match label[i - 1]? with
      | none      => false
      | some prev => isVirama prev
  if viramaPrev then true
  else
    isLeftOrDual (joiningTypeBefore label i)
      && isRightOrDual (joiningTypeAfter label i)

/-- RFC 5892 A.2: a ZWJ at position `i` is contextually valid iff
    the preceding character is a Virama. -/
def checkContextJZwj (label : Array Nat) (i : Nat) : Bool :=
  if i = 0 then false
  else match label[i - 1]? with
    | none      => false
    | some prev => isVirama prev

/-- Check every ZWNJ / ZWJ occurrence from index `i` onward, `AND`-ing
    each position's contextual validity (non-joiner positions contribute
    `true`). `fuel` bounds the recursion structurally so the predicate
    reduces in the kernel; callers pass `label.size`. Equivalent to a
    short-circuiting scan: the result is `false` iff some joiner in the
    label has an invalid context. -/
def checkJoinersFrom (label : Array Nat) (fuel : Nat) (i : Nat) : Bool :=
  match fuel with
  | 0 => true
  | fuel + 1 =>
    if h : i < label.size then
      let cp := label[i]
      let ok :=
        if cp = 0x200C then checkContextJZwnj label i
        else if cp = 0x200D then checkContextJZwj label i
        else true
      ok && checkJoinersFrom label fuel (i + 1)
    else
      true

def checkJoiners (label : Array Nat) : Bool :=
  checkJoinersFrom label label.size 0

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 SAMPLE CHECKS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A label with no ZWNJ / ZWJ trivially passes. -/
theorem checkJoiners_pure_ascii :
    checkJoiners #[0x0061, 0x0062, 0x0063] = true := by decide +kernel

/-- A bare ZWJ at the start of a label fails A.2 (no preceding Virama). -/
theorem checkJoiners_bare_zwj :
    checkJoiners #[0x200D] = false := by decide +kernel

/-- A bare ZWNJ at the start of a label fails A.1 (no preceding Virama
    and no joining-type context to its left). -/
theorem checkJoiners_bare_zwnj :
    checkJoiners #[0x200C] = false := by decide +kernel

/-- ZWJ after Devanagari Virama (U+094D) followed by another consonant
    is valid — the canonical use case for the explicit-join request. -/
theorem checkJoiners_zwj_after_virama :
    checkJoiners #[0x0915, 0x094D, 0x200D, 0x0937] = true := by decide +kernel

/-- ZWNJ after Devanagari Virama is valid (Virama rule of A.1). -/
theorem checkJoiners_zwnj_after_virama :
    checkJoiners #[0x0915, 0x094D, 0x200C, 0x0937] = true := by decide +kernel

end Unicode.Idna.CheckJoiners
