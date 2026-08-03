# Build Tiers And Budgets

This repository has separate runtime, assurance, and full-conformance paths.
The runtime path is the default user workflow. Assurance and full conformance
are opt-in evidence workflows.

## Budget Table

| Tier | Command | Lean? | Expected Use | Budget |
|---|---|---:|---|---|
| Runtime shell | `nix develop .#runtime` | no | Toolchain for ports, packaging, and CLI work | Fits normal developer machines; no Lean toolchain hook |
| Runtime build | `scripts/build-runtime.sh` | no | Fast API/CLI build gate | Target: under 10 minutes and under 8 GB RSS |
| Runtime ports | `scripts/test-runtime-ports.sh --smoke` | no | Rust, Python, C++, Haskell, JVM, Go, TypeScript, .NET, Swift, Zig contract gate | Target: under 10 minutes and under 8 GB RSS |
| Runtime package | `scripts/package-runtime.sh` | no | Installable artifacts and package smoke evidence | Target: under 10 minutes and under 8 GB RSS |
| Tracked Nix runtime packages | `scripts/check-nix-runtime-packages.sh` | no | Flake package output smoke gate | Target: under 15 minutes and under 8 GB RSS |
| CLI install | `scripts/install-unicode-security.sh dist/runtime/rust` | no | Smallest consumer-facing CLI install path | Target: under 5 minutes and under 4 GB RSS |
| API root | `lake build Unicode` | yes | Lean API root only | Must stay below consumer-machine limits before launch |
| Assurance root | `UNICODE_BUILD_HEAVY=1 scripts/build-assurance.sh` | yes | Theorem/audit evidence | Opt-in only; run on proof-capable machines |
| Full conformance | `UNICODE_BUILD_HEAVY=1 scripts/build-full-conformance.sh` | yes | Official Unicode fixture evidence | Release/nightly only |

## Runtime Rule

Runtime commands must not import `UnicodeAssurance` or `UnicodeFullConformance`.
They must remain safe for ordinary cold-start validation:

```bash
nix develop .#runtime -c scripts/build-runtime.sh
nix develop .#runtime -c scripts/test-runtime-ports.sh --smoke
nix develop .#runtime -c scripts/package-runtime.sh
nix develop .#runtime -c scripts/check-nix-runtime-packages.sh
nix develop .#runtime -c scripts/check-release-runtime-preflight.sh
```

`scripts/package-runtime.sh` writes a checked artifact tree and then runs
`scripts/check-runtime-package.sh` against that tree before exiting.

## Heavy Tier Rule

Heavy Lean roots are not normal user workflows. They require explicit
`UNICODE_BUILD_HEAVY=1` opt-in and should run only on machines sized for proof
work or on release/nightly infrastructure.

Known risk area: row-backed kernel table proofs can consume tens of gigabytes
when too much table work lives in one compilation unit. The architecture rule is
to keep those facts isolated, split, and out of runtime import paths.

## Measurement Policy

When a budget is updated, record:

- command
- date
- host class
- warm or cold cache state
- wall time
- maximum RSS when available
- whether Lean was invoked

Use the measurement wrapper for local evidence:

```bash
nix develop .#runtime -c scripts/measure-runtime-budgets.sh --only runtime-package
```

Do not replace the budget table with optimistic warm-cache measurements. Warm
measurements are useful evidence, but the launch target is a cold build that
does not surprise normal users.
