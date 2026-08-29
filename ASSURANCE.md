# Assurance Brief

This file summarizes the evidence an enterprise reviewer can verify from the
repository without trusting marketing claims.

## Scope

`unicode-lean` is a Lean 4.33.1, Lean-core-only specification and conformance
library for Unicode algorithms, data tables, codecs, identifiers, and
security-oriented Unicode threat detectors.

The primary assurance boundary is source-level verification: the repository is
designed so the committed Lean source, pinned data files, and CI scripts are
sufficient to rebuild and audit the claimed theorem and conformance surface.
Every proof closes in the Lean kernel (`decide` / `decide +kernel`);
`native_decide` and `bv_decide` have zero occurrences in the tree.

## Verifiable Evidence

- `lake build` elaborates the default audited root import `Unicode`.
- `lake build UnicodeFullConformance` elaborates the explicit full-corpus
  conformance root `Unicode.FullConformance`, including the heavyweight
  official NormalizationTest, BidiTest, CollationTest, and IdnaTestV2 suites.
- `scripts/check-sorry.sh` rejects `sorry` and `admit`.
- `scripts/check-no-axiom.sh` rejects project-local `axiom`, `unsafe`,
  `unsafePerformIO`, `unsafeCast`, `Lean.ofReduceBool`, and `Lean.reduceBool`.
- `scripts/check-axiom-footprint.sh` walks every declaration across the full
  audited closure — the runtime root `Unicode`, the twenty-seven detector
  families under `Unicode.SecurityRoot`, the conformance harnesses under
  `Unicode.FullConformance`, and the theorem layer under `Unicode.Assurance` —
  and rejects any transitive axiom dependency beyond the Lean-core `propext`,
  `Quot.sound`, and `Classical.choice`. `Classical.choice` is the expected
  third Lean-core axiom, reached the moment any classical lemma is touched; the
  gate's teeth are the hard rejection of `sorryAx`, `Lean.ofReduceBool`,
  `Lean.trustCompiler`, and project-local axioms.
- `scripts/check-olean-recheck.sh` builds the independent `lean4checker` proof
  checker from a commit-pinned checkout and replays every built olean through
  the Lean kernel, confirming the artifacts hold only kernel-accepted proofs.
  This catches an unsound elaborator or tactic; it is not a diverse-compilation
  defense against a Thompson attack, which is a separate axis documented in
  `docs/explanation/tcb.md`.
- Both of the above build the heavy security and full-conformance roots, so
  they run in the nightly `assurance` workflow and on release tags, not on
  every push. Per-push CI (`ci.yml`) runs the source-level guards — including
  `check-no-axiom.sh` — plus the default-root build and smoke check.
- `scripts/check-orphan-files.sh` rejects `.lean` files under `Unicode/` that
  are not transitively imported from the audited roots.
- `scripts/check-ucd-hashes.sh` verifies the UCD/UCA source-data manifest.
- `scripts/check-security-coverage.sh` verifies every detector has a paired
  `Unicode/Conformance/Security/*Test.lean` harness with `all_rows_pass`.
- `scripts/check-security-hashes.sh` verifies the security-fixture manifest.
- `scripts/check-bip39-hashes.sh` verifies BIP-39 wordlists.
- `scripts/check-curated-hashes.sh` verifies curated baseline tables.
- `scripts/check-actions-pinned.sh` rejects mutable external GitHub Actions
  refs.
- `scripts/release-evidence.sh` emits a source archive, CycloneDX JSON SBOM,
  and SHA-256 manifest for a specified release tag.
- `scripts/check-release-evidence.sh` smoke-tests release evidence generation
  and validates the emitted SHA-256 manifest.
- `nix flake check --no-build` exposes the hardening checks as Nix check
  derivations; full `nix flake check` additionally includes the Lean build.

## Supply-Chain Controls

- Lean toolchain version is pinned in `lean-toolchain`.
- Nix inputs are pinned in `flake.lock` and updated by a scheduled PR workflow.
- External GitHub Actions dependencies are pinned to full commit SHAs.
- Dependabot is enabled for GitHub Actions metadata updates.
- CODEOWNERS covers all files, with explicit entries for source-of-truth
  artifacts such as UCD data, toolchain pins, Nix files, scripts, workflows,
  license, and notice files.
- The nightly reproducibility workflow performs two clean default
  `lake build` passes and compares `.olean` SHA-256 manifests.
- The nightly `assurance` workflow builds the full audited closure and runs the
  artifact-level axiom footprint and the independent `lean4checker` re-check
  over it; both also run in `release-evidence` on version tags.
- The `release-evidence` workflow runs on version tags, reruns hardening,
  default build checks, the explicit full-corpus conformance target, publishes
  release assets, and emits GitHub artifact attestations for the source archive,
  SBOM, and SHA-256 manifest.

## Standards Mapping

This repository is not claiming certification under any external compliance
program. The current controls map naturally onto several enterprise review
rubrics:

- NIST SP 800-218 SSDF: source integrity, reproducible build evidence,
  vulnerability reporting, and verification gates.
- SLSA build track: scripted build, version-controlled source, pinned
  dependencies, reproducibility evidence, and GitHub artifact attestations on
  release tags.
- OpenSSF Scorecard: branch protection, maintained dependency updates,
  pinned workflow actions, security policy, and CI tests.
- SBOM expectations: dependency inventory is low because the Lean library has
  no Mathlib or external Lean dependencies; the release workflow emits a
  source/data-boundary CycloneDX SBOM for tagged releases.

Reference links:

- NIST SSDF: https://csrc.nist.gov/pubs/sp/800/218/final
- SLSA specification: https://slsa.dev/spec/latest/
- OpenSSF Scorecard: https://openssf.org/scorecard/
- GitHub artifact attestations: https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds
- CISA SBOM minimum elements: https://www.cisa.gov/resources-tools/resources/2025-minimum-elements-software-bill-materials-sbom

## Current Limits

- The full-corpus official conformance root is intentionally explicit because
  several fixture suites are slow under Lean 4.33.1. Routine CI builds the
  audited default root; release/audit evidence can demand
  `UnicodeFullConformance`.
- The Nix package fetches the Lean toolchain through `elan` during the build.
  This is pinned, but not fully hermetic.
- Existing tags created before the `release-evidence` workflow do not contain
  the new release assets unless they are deliberately backfilled.
- The emitted SBOM is source/data-boundary evidence. It is not a binary package
  SBOM for downstream distributions that repackage the library.
- Branch protection settings are documented in `CONTRIBUTING.md`, but GitHub
  branch-protection state is repository-hosted configuration and cannot be
  proven from files alone.
- No third-party audit, SOC 2, ISO 27001, or FedRAMP certification is claimed.

## Enterprise Hardening Backlog

1. Exercise the `release-evidence` workflow on the next tag and verify the
   published release assets and artifact attestations.
2. Decide whether to backfill evidence artifacts for older release tags.
3. Export branch-protection/ruleset settings as code where GitHub supports it,
   or archive periodic `gh api` evidence for auditors.
