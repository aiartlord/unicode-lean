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

-- Layer 1 — Covert Channels
import Unicode.Security.Covert.VariationSelectorPayload
import Unicode.Security.Covert.TagBlockPayload
import Unicode.Security.Covert.BidiControlBalance
import Unicode.Security.Covert.ZeroWidthPayload
import Unicode.Security.Covert.SurrogateReassembly

-- Layer 2 — Identity Spoofing
import Unicode.Security.Identity.HomoglyphConfusable
import Unicode.Security.Identity.MixedScriptAdmissibility
import Unicode.Security.Identity.EmojiZwjIntegrity
import Unicode.Security.Identity.SkinToneVariationForgery

-- Layer 3 — Display Integrity (compound detectors)
import Unicode.Security.Display.SourceDisplayDivergence
import Unicode.Security.Display.FilenameDisguise
import Unicode.Security.Display.RtlInjection
import Unicode.Security.Display.RendererDivergence

-- Layer 4 — Form Stability (normalization / DoS / locale)
import Unicode.Security.Form.NormalizationBomb
import Unicode.Security.Form.StreamSafeViolation
import Unicode.Security.Form.LocaleCaseInversion
import Unicode.Security.Form.CaseExpansionMismatch
import Unicode.Security.Form.WidthClassConfusion
import Unicode.Security.Form.NfcIdempotenceWitness

-- Layer 5 — Cross-Layer Boundaries
import Unicode.Security.Boundary.IdentifierFormDrift
