/-
  Unicode.Precis.OpaqueStringCore

  Executable RFC 8265 OpaqueString profile definitions. Idempotence and output
  invariant proofs live in `Unicode.Precis.OpaqueString`.
-/

import Unicode.Normalization.NFC
import Unicode.Precis.ZsMapping
import Unicode.Precis.BidiRule
import Unicode.Precis.Categories

namespace Unicode.Precis.OpaqueString

open Unicode.Normalization.NFC (toNFC)
open Unicode.Precis.ZsPreservation (remapZsToAscii)
open Unicode.Precis.BidiRule (satisfiesBidiRule)

/-- OpaqueString admissibility per RFC 8264 §4.3 FreeformClass. -/
def isOpaqueStringAdmissible (cp : Nat) : Bool :=
  Unicode.Precis.Categories.isFreeformClassAdmissibleGC cp

def allOpaqueAdmissible (cps : List Nat) : Bool :=
  cps.all isOpaqueStringAdmissible

/-- Combined gate for OpaqueString: FreeformClass admissibility AND
    RFC 5893 §2 Bidi Rule. -/
def isOpaqueGatePass (cps : List Nat) : Bool :=
  allOpaqueAdmissible cps && satisfiesBidiRule cps

/-- OpaqueString mapping: non-ASCII-space remap to U+0020, then NFC. -/
def precisMapOpaque (cps : List Nat) : List Nat :=
  toNFC (remapZsToAscii cps)

/-- OpaqueString preparation: apply the mapping stages, then reject if
    the result fails `isOpaqueGatePass`. -/
def precisPreparationOpaque (cps : List Nat) : Option (List Nat) :=
  let mapped := precisMapOpaque cps
  if isOpaqueGatePass mapped then some mapped else none

end Unicode.Precis.OpaqueString
