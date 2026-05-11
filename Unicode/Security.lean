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
