/-
  Unicode.Security

  Root import for the Security Conformance Layer. Each per-family module
  under `Unicode.Security.{Covert,Identity,Display,Form,Boundary,Crypto}.*`
  refines the shared `Unicode.Security.Calculus` vocabulary into a
  family-specific verdict.

  Sits below the UAX/UTS conformance proof base in this repository:
  the existing `Unicode.Conformance.*` modules pin algorithm
  correctness against published Unicode test fixtures; the
  `Unicode.Security.*` modules pin *security verdicts* against an
  adversarial threat model that the Unicode Consortium has declined to
  extend its scope to cover.
-/

import Unicode.Security.Calculus
import Unicode.Security.Verdict
import Unicode.Security.Fixture

import Unicode.Security.Covert.VariationSelectorPayload
import Unicode.Security.Covert.TagBlockPayload
import Unicode.Security.Covert.BidiControlBalance
import Unicode.Security.Covert.ZeroWidthPayload
import Unicode.Security.Covert.SurrogateReassembly
import Unicode.Security.Covert.NoncharacterControl
import Unicode.Security.Identity.HomoglyphConfusable
import Unicode.Security.Identity.HomoglyphConfusableSkeletonGate
import Unicode.Security.Identity.MixedScriptAdmissibility
import Unicode.Security.Identity.EmojiZwjIntegrity
import Unicode.Security.Identity.SkinToneVariationForgery
import Unicode.Security.Display.SourceDisplayDivergence
import Unicode.Security.Display.FilenameDisguise
import Unicode.Security.Display.RtlInjection
import Unicode.Security.Display.RendererDivergence
import Unicode.Security.Form.NormalizationBomb
import Unicode.Security.Form.StreamSafeViolation
import Unicode.Security.Form.LocaleCaseInversion
import Unicode.Security.Form.CaseExpansionMismatch
import Unicode.Security.Form.WidthClassConfusion
import Unicode.Security.Form.NfcIdempotenceWitness
import Unicode.Security.Boundary.IdentifierFormDrift
import Unicode.Security.Boundary.CovertDisplayCompound
import Unicode.Security.Boundary.ConfusableBidiCompound
import Unicode.Security.Boundary.AdmissibilityFormDrift
import Unicode.Security.Crypto.Bip39Canonical
import Unicode.Security.Crypto.WordlistOrder
import Unicode.Security.Crypto.HashInputStability
import Unicode.Security.Crypto.AiWatermarkDetectability
