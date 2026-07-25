/-
  Unicode.Precis.PreparationCore

  Executable PRECIS preparation pipeline definitions. Idempotence and output
  invariant proofs live in `Unicode.Precis.Preparation`.
-/

import Unicode.Normalization.NFC
import Unicode.Precis.BidiRule
import Unicode.Precis.IdentifierClass
import Unicode.Precis.WidthMapping
import Unicode.Precis.CaseMapping
import Unicode.Precis.Categories

namespace Unicode.Precis.Preparation

open Unicode.Normalization.NFC (toNFC)
open Unicode.Precis.IdentifierClass (isAllowedInIdentifierClass)
open Unicode.Precis.WidthMapping (widthMap)
open Unicode.Precis.CaseMapping (caseFold)
open Unicode.Precis.Categories (isPrecisAdmissible)
open Unicode.Precis.BidiRule (satisfiesBidiRule)

/-- The RFC 8264/8265 mapping stages: width-map, then case-fold,
    then NFC. Admissibility is NOT checked here; it is applied to
    the output by `precisPreparation` below. -/
def precisMap (cps : List Nat) : List Nat :=
  toNFC (caseFold (widthMap cps))

/-- Per-codepoint admissibility check against the post-mapping
    sequence. -/
def allAdmissible (cps : List Nat) : Bool :=
  cps.all isPrecisAdmissible

/-- Combined gate for UsernameCaseMapped / UsernameCasePreserved:
    IdentifierClass admissibility (RFC 8264 §5.6) AND RFC 5893 §2
    Bidi Rule (mandated by RFC 8265 §5.5). -/
def isGatePass (cps : List Nat) : Bool :=
  allAdmissible cps && satisfiesBidiRule cps

/-- The full PRECIS Preparation: apply the mapping stages, then
    reject if the result fails `isGatePass`. -/
def precisPreparation (cps : List Nat) : Option (List Nat) :=
  let mapped := precisMap cps
  if isGatePass mapped then some mapped else none

/-- UsernameCasePreserved mapping: width-map, then NFC, without case folding. -/
def precisMapPreserved (cps : List Nat) : List Nat :=
  toNFC (widthMap cps)

/-- UsernameCasePreserved preparation: apply preserved mapping, then gate. -/
def precisPreparationPreserved (cps : List Nat) : Option (List Nat) :=
  let mapped := precisMapPreserved cps
  if isGatePass mapped then some mapped else none

end Unicode.Precis.Preparation
