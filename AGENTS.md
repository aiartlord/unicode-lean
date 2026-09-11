# AGENTS.md — what to run, and when

This file is the command index for automated contributors. It exists so a
session does not reconstruct the workflow from scratch: every recurring task
below names the *exact* command and the artifact it produces. The prose
runbook is [`docs/how-to/build.md`](docs/how-to/build.md); the evidence tiers
are [`docs/reference/build-tiers.md`](docs/reference/build-tiers.md); the trust
boundary is [`docs/explanation/tcb.md`](docs/explanation/tcb.md).

The single source of truth is the Lean development under `Unicode/`. The ports
under `ports/` are runtime surfaces held to it. Read
[`docs/how-to/build.md`](docs/how-to/build.md) before any Lean build.

## Ground rules

- **The default path is the runtime, not Lean.** Lean assurance and full
  conformance are opt-in evidence paths. Never run a broad cold-cache
  `lake build` as a casual check.
- **Heavy Lean work is memory-bound, not CPU-bound.** Build one module per
  process through `scripts/lean-cache-stages.py` with `LEAN_NUM_THREADS=1` and
  `JOBS=1`, in dependency order, stopping at the first failure. The full
  closure's peak is tens of GB.
- **A long job must outlive the turn.** Launch it detached
  (`setsid bash -c '…; echo EXIT=$?' > log 2>&1 &`) and watch the log for the
  exit marker; a harness-tracked background job can be reaped on memory
  pressure, a detached one is not. Never kill a running build — its artifacts
  are not cheaply replaced.
- **Do not download toolchains speculatively.** The runtime/port toolchains
  come from `nix develop .#runtime`, which is large. Prefer the already-built
  artifacts named below when they are current.
- **Stop at the first failure**, record the exact command and module, fix the
  smallest root that explains it, and rerun the same bounded step.

## Which artifact is "current"

- **Reference CLI:** `ports/rust/target/release/unicode-security`. It is current
  iff its mtime is newer than the newest file under `ports/rust/src`. It is
  self-contained (`include_str!`s its data at build time), so it runs
  standalone with no data files on disk.
- **Lean `.olean` closure:** present under `.lake/build` after a full staged
  build. `conformance-run.py` reports the recorded build under
  `dist/lean-cache-stages*/status.json` (`by_status`, `recorded_at`, and
  `sources_changed_since` — a non-empty list means the oleans are stale).
- **`conformance-run.py` never infers a result it did not observe**: a section
  it could not measure is reported as unavailable, naming the command that
  would produce it. Trust its `observed` flags over any recollection.

## Task → command

| Goal | Command |
|---|---|
| **Full reviewer evidence report** (pinned inputs, suites, proof/axioms, detectors, ports, CVEs, supply-chain corpus) | `python3 scripts/conformance-run.py --run-corpus --run-proofs --json report.json` |
| **Acceptance corpus** (attack cases detected with class; negative controls clean) | `python3 scripts/conformance-run.py --run-corpus` — scans `fixtures/security/supply-chain-corpus.json` with the reference CLI; read each case's `met` and `expected_family_fired` |
| **Conformance suites** (Bidi/Normalization/segmentation/IDNA/collation totals, skipped honest) | recorded in `fixtures/conformance/executed-runs.json`; summarized by `conformance-run.py` §2 (no build needed) |
| **Named-theorem axiom footprint** (Trojan Source display-order, normalization stability, zero-width sanction) | `lake env lean scripts/print-load-bearing-axioms.lean` — needs the built closure; **detach** |
| **Artifact-level axiom footprint** over the whole closure | `bash scripts/check-axiom-footprint.sh` — needs the built closure; **detach** |
| **Independent kernel re-check** of the built oleans | `bash scripts/check-olean-recheck.sh` — toolchain's bundled `leanchecker`; needs the built closure; **detach** |
| **Pin the conformance inputs** | `python3 scripts/conformance-run.py --emit-inputs-manifest` → `fixtures/conformance/CONFORMANCE-INPUTS.sha256` |
| **Detector fixtures ↔ Lean parity** (5000-case corpus) | `bash scripts/check-lean-replay.sh` — builds+runs the native `corpus_differential` exe |
| **Lightweight source/hash/doc gates** | `check-no-axiom.sh`, `check-sorry.sh`, `check-security-hashes.sh`, `check-security-coverage.sh`, `check-ucd-hashes.sh`, `check-curated-hashes.sh`, `check-bip39-hashes.sh`, `check-doc-claims.py`, `check-conformance-inputs.sh`, `check-orphan-files.sh`, `check-lean-cache-plan-fixtures.py` — none build Lean |
| **SARIF schema check** | `python3 scripts/check-sarif-output.py` — validates emitted SARIF against `fixtures/sarif/sarif-schema-2.1.0.json`; needs the devshell's `jsonschema` |
| **Runtime build + port smokes** | `nix develop .#runtime -c scripts/build-runtime.sh`, then `… scripts/test-runtime-ports.sh --smoke` (see `docs/how-to/build.md` "Fast Product Path") |
| **Staged Lean build** (one stage) | `scripts/lean-cache-stages.py --preset <default\|product\|evidence\|full> --stage <name> --run --resume --max-rss-gb N --min-available-gb M --timeout-sec 0` |
| **Plan a build without invoking Lean** | `scripts/lean-cache-stages.py --preset <preset> --explain-plan --out-dir <dir>` |

## CI / release

- `.github/workflows/ci.yml` — per-push: source guards, full from-source
  `lake build`, `check-lean-replay.sh`, runtime package + cross-port smokes.
- `.github/workflows/assurance.yml` — nightly + dispatch: full-closure axiom
  footprint and independent re-check (builds the heavy roots first, then the
  gates). Dispatch with `gh workflow run assurance.yml --ref main`.
- `.github/workflows/release-evidence.yml` — on a `v*` tag: builds the closure,
  runs the assurance gates, and publishes the reviewer evidence to the release.
- The heavy re-check and axiom-footprint gates need the full closure built
  first (`lake build UnicodeFullConformance UnicodeSecurity UnicodeAssurance`)
  — see `assurance.yml`, whose ordering is the reference.

## The reviewer acceptance map

The external acceptance criteria are the supply-chain attack/control corpus
(`fixtures/security/supply-chain-corpus.json`), the public Unicode conformance
suites (`executed-runs.json`), the load-bearing theorem axiom footprints
(`print-load-bearing-axioms.lean`), and SARIF 2.1.0 output. One command,
`python3 scripts/conformance-run.py --run-corpus --run-proofs --json report.json`,
assembles all of it into a single artifact a reviewer can read without building
anything themselves.
