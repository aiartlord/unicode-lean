# Security Policy

## Threat Model

This repository is a machine-checked specification of the Unicode standard.
The artifacts that downstream consumers rely on are:

- The Lean source files under `Unicode/`, which type-check zero `sorry`
  and zero project-local `axiom`s under Lean 4.32.0.
- The UCD source files under `Unicode/Ucd/`, which are pinned by
  SHA-256 in `Unicode/Ucd/SHA256SUMS` and verified in CI.
- The Generated tables under `Unicode/Generated/`, which are derived
  deterministically from the UCD source files at build time.
- The Security Conformance Layer fixtures under
  `Unicode/Ucd/Security/`, which are pinned by SHA-256 in
  `Unicode/Ucd/Security/SHA256SUMS` and verified in CI.  Each fixture
  drives a kernel-checked `all_rows_pass` theorem in
  `Unicode/Conformance/Security/`, so a byte change to a fixture
  changes the verdict the conformance harness commits to.

A security-relevant defect is anything that allows the headline
theorems (NFC quick-check soundness, PRECIS preparation idempotence,
Bidirectional Algorithm pipeline shape, confusable-skeleton
equivalence) or the Security Conformance Layer verdicts to be
subverted without the build failing. Examples:

- A proof gap in a load-bearing module not caught by the `sorry` /
  `admit` guards.
- A drift between a UCD `.txt` file and its pinned SHA-256 not
  caught by `scripts/check-ucd-hashes.sh`.
- A drift between a Security fixture under `Unicode/Ucd/Security/`
  and its pinned SHA-256 not caught by
  `scripts/check-security-hashes.sh`.
- A detector module under `Unicode/Security/` with no matching
  `*Test.lean` harness, slipping past
  `scripts/check-security-coverage.sh`.
- A project-local `axiom` introduced under a name not recognised
  by `scripts/check-no-axiom.sh`, or an axiom dependency reaching
  the built artifacts past the source scan without being caught by
  `scripts/check-axiom-footprint.sh`.
- An orphan `.lean` file present on disk but not transitively
  imported from `Unicode.lean`, so it skips the headline build.
- A runtime escape hatch (`unsafe`, `unsafePerformIO`, `unsafeCast`,
  `Lean.ofReduceBool`, `Lean.reduceBool`) introduced under a name
  not recognised by `scripts/check-no-axiom.sh`.

Build reproducibility — two consecutive `lake build` runs producing
byte-identical `.olean` artifacts — is verified by the nightly
reproducibility workflow.

## Security Conformance Layer

The 27 detector families under `Unicode/Security/` extend the
machine-checked surface to threats that the Unicode Consortium has
declined to bring inside the scope of UAX / UTS conformance
(UTS #39 §5.4, §6).  Each family is a Tier-A₁..A₃ adversary
verdict — local injector, pipeline injector, or supply-chain
compromise — over an input codepoint sequence.

The families ship across six layers:

| Layer | Concern | Families |
|---|---|---|
| Covert Channels | bytes hidden in plain sight — variation selectors, tag block, zero-width runs, surrogates, bidi balance, noncharacters | 6 |
| Identity Spoofing | identifier confusables and emoji-sequence forgery | 4 |
| Display Integrity | source vs execute divergence, filename disguise, RTL injection, renderer-cohort variance | 4 |
| Form Stability | normalization bombs, stream-safe violations, locale-sensitive case folds, case-expansion mismatch, width confusion, NFC idempotence | 6 |
| Cross-Layer Boundaries | admissibility and form drift, covert × display and identity × display compounds | 4 |
| Cryptographic Stability | BIP-39 mnemonic canonical form, hash-input stability, watermark detectability | 3 |

The cryptographic-stability detectors run in an explicit crypto
context rather than the default scan.  `ports/DETECTOR_COVERAGE.md`
records what each detector is and its per-port coverage — all 27
families implemented in all sixteen runtime ports.

The shared verdict vocabulary lives in
`Unicode/Security/Calculus.lean` (`ClassificationKind` ∈ {`clear`,
`hazard`, `compound`, `informational`}; `ConformanceLevel` ∈
{`basic`, `strict`, `full`}).  Each family refines the calculus
into its own `<F>SubThreat`, `<F>Classification`, and `<F>Verdict`
types and emits a `detect : List Nat → <F>Verdict` function.

## Reporting a Vulnerability

Security reports should be sent privately, not in a public issue.
Use GitHub's private-vulnerability-reporting form on this repository,
or email the maintainer listed in `.github/CODEOWNERS`.

A report should include:

- The affected file path and line range.
- The class of defect (proof gap, table drift, axiom introduction,
  orphan file, runtime escape, build nondeterminism, or other).
- Where applicable, a minimal reproduction: the Lean expression that
  type-checks against an unsound hypothesis, or the UCD byte
  sequence that bypasses the SHA-256 check.

The maintainer will acknowledge a report within seven days and will
share a remediation plan, including the affected commit range, before
public disclosure.

## Supported Versions

Only the most recent minor release on `main` is supported. The
project follows semantic versioning at the level of the headline
theorem signatures: a major-version bump signals that a theorem name
or statement on the public surface changed.

## Cryptographic Provenance

The UCD source files in `Unicode/Ucd/` are byte-exact copies of the
Unicode 17.0.0 publication. Their SHA-256 hashes are pinned in
`Unicode/Ucd/SHA256SUMS` and verified by `scripts/check-ucd-hashes.sh`
on every push and pull request. Tampering with a UCD `.txt` file
without updating the manifest will fail the `ci / hardening` job.

The nightly reproducibility workflow publishes a manifest of `.olean`
SHA-256 hashes as a build artifact (`oleans-sha256-<commit-sha>`) so
downstream auditors can verify their local build matches the canonical
build. Artefacts are retained for 90 days per the default
`actions/upload-artifact` policy.

Source-of-truth artifacts — the UCD source files under `Unicode/Ucd/`,
the lakefile, the `lean-toolchain` pin, the flake declaration, and
the CI scripts under `scripts/` — are listed individually in
`.github/CODEOWNERS` so that tampering shows up in `git blame` and
requires CODEOWNER review at merge time.
