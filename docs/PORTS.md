# Multi-Language Ports

The security layer is not Lean-only. Lean is the specification and assurance
source of truth; the deployable product needs ports for the runtime environments
where gateways, routers, agents, and services actually run.

Current and planned language surfaces:

- Lean: source-of-truth algorithms, proof surface, conformance roots
- Rust: production systems/runtime crate
- C++: header/library surface for embedded, router, and native integration
- Python: scripting, ops tooling, fixtures, demos, and service integration
- Haskell: functional peer port/reference implementation under
  `ports/haskell`
- Zig: static edge binaries and router/appliance deployment
- Go: service mesh, gateway, reverse-proxy, and Kubernetes deployment
- TypeScript / WebAssembly: browser, edge worker, dashboard, and developer-tool
  deployment
- Java / Kotlin: JVM services, Android, and enterprise identity providers
- C# / .NET: Windows gateway agents and enterprise server deployment
- Swift: Apple client and local-device filtering
- COBOL: mainframe/banking integration
- Erlang / Elixir: telecom and resilient control-plane integration
- Lua / OpenResty: NGINX/OpenResty gateway filtering
- Ruby / PHP: web-framework integration

## Repository Paths

Current non-Lean paths in this checkout:

- Rust crate: `Cargo.toml`, `src/*.rs`, `src/security/**`, `tests/*.rs`
- C++ interface: `CMakeLists.txt`, `include/unicode_cpp/**`, `test/*.cpp`
- Python package: `pyproject.toml`, `src/unicode_python/**`, `tests/*.py`
- Haskell package: `ports/haskell/unicode-haskell.cabal`,
  `ports/haskell/src/**`, `ports/haskell/test/**`
- Go package: `ports/go/go.mod`, `ports/go/security/**`
- Java/Kotlin package: `ports/jvm/src/main/java/**`,
  `ports/jvm/src/main/resources/**`, `ports/jvm/src/test/java/**`
- TypeScript/WASM package: `ports/typescript/package.json`,
  `ports/typescript/src/**`, `ports/typescript/test/**`
- C#/.NET package: `ports/dotnet/src/**`, `ports/dotnet/test/**`
- Swift package: `ports/swift/Package.swift`, `ports/swift/Sources/**`,
  `ports/swift/ContractTests/**`
- Zig package: `ports/zig/build.zig`, `ports/zig/src/**`, `ports/zig/test/**`

## Implementation Order

The deployment requirement includes more languages than the ports currently in
this checkout. The order matters: first stabilize the ports we already have,
then add the additional deployment ports against the same policy contract,
fixtures, and reason-code namespace.

### Phase 0: Existing First-Class Ports

These are the current core project surfaces and must reach parity first:

- **Rust** — production services, agents, gateway daemons, `no_std`/embedded
  direction, and eventual C ABI export.
- **C / C++** — routers, native gateways, embedded firmware, NGINX/Envoy/module
  integration, and downstream language FFI.
- **Python** — operator tooling, test orchestration, fixture generation, demos,
  and policy experimentation.
- **Haskell** — functional reference port, property-testing surface, and
  high-assurance peer implementation in `ports/haskell`.

Phase 0 exit criteria:

- each port exposes `scan(profile, mode, input) -> verdict`
- each port exposes a stable verdict JSON helper for the shared wire shape
- each port emits the shared reason-code namespace
- each port passes shared codec, detector, policy, and red-team fixtures
- each port can run tests without `UnicodeAssurance` or `UnicodeFullConformance`

### Phase 1: Next First-Class Deployment Ports

These are committed next ports after Phase 0 parity. Go, TypeScript/WASM, Zig,
Java/Kotlin, C#/.NET, and Swift now have contract-first scaffolds under
`ports/`; they are not full detector ports yet.

- **Go** — cloud-native gateways, Kubernetes controllers, service meshes,
  reverse proxies, and ops teams that standardize on Go.
- **Zig** — small static binaries, router/edge appliances, low-level systems
  integration, and C ABI consumers.
- **TypeScript / WebAssembly** — browser, edge workers, dashboards, developer
  tools, and client-side preview of policy decisions.
- **Java / Kotlin** — JVM enterprise services, Android, and large identity
  providers.
- **C# / .NET** — Windows gateway agents, enterprise desktop/server products,
  and Azure-heavy deployments.
- **Swift** — Apple client surfaces and local-device filtering.

Phase 1 ports may use a shared Rust/C/Zig core internally where that is the
best engineering choice, but the public package for each language is still a
first-class deliverable with shared fixtures and documented APIs.

### Phase 2: Enterprise, Legacy, And Gateway Embedding Ports

These are deployment-required ports for specific environments. They should be
implemented after Phase 0 parity and after the Phase 1 port template is proven:

- **COBOL** — mainframe/banking batch and transaction-processing integration.
- **Erlang / Elixir** — telecom, distributed-control-plane, and resilient mesh
  routing integration.
- **Lua / NGINX / OpenResty** — in-process gateway and reverse-proxy request
  filtering.
- **Ruby** — Rails and Ruby service integration.
- **PHP** — PHP web stack and CMS/plugin integration.

Phase 2 ports can be native, generated, or ABI-backed depending on the
deployment constraints, but they are still committed compatibility targets, not
throwaway demos.

Phase 2 intake directories do not live in the active tree yet. When added, they
must define the acceptance contract for each future port before any packaging
claim is made. They are not included in runtime packaging until the port
implements the shared fixtures, vendors its own data, and has a bounded
`scripts/test.sh` gate.

## Porting Rule

New ports must start from the shared policy contract, not from isolated helper
functions. The first public API for every port should be:

```text
scan(profile, mode, input) -> verdict
```

Only after that API is stable should ports expose lower-level Unicode helpers.
This keeps every language aligned with the gateway/security product rather than
becoming a disconnected Unicode utility library.

## Source Of Truth

Lean owns:

- Unicode data pinning
- normative algorithm definitions
- proof and assurance modules
- stable detector-family vocabulary
- stable policy/reason-code vocabulary

Ports own:

- deployable runtime ergonomics
- language-native API shape
- package manager integration
- performance work
- platform integration

Ports must not silently diverge from Lean semantics. Any intentional divergence
must be named, documented, tested, and reflected in the shared fixtures.

## Shared Runtime Contract

Every port should expose the same conceptual security API:

```text
scan(profile, mode, input) -> verdict
scan_utf8(profile, mode, bytes) -> verdict
scan_utf16be(profile, mode, bytes) -> verdict
scan_utf16le(profile, mode, bytes) -> verdict
scan_utf32be(profile, mode, bytes) -> verdict
scan_utf32le(profile, mode, bytes) -> verdict
verdict_to_json(verdict) -> compact-json
```

The first API scans decoded codepoints. The raw-byte APIs are the gateway-facing
paths: they strictly validate the selected wire encoding, report malformed input
as `unicode.security.C.malformed-utf8.<Kind>`,
`unicode.security.C.malformed-utf16.<Kind>`, or
`unicode.security.C.malformed-utf32.<Kind>`, and only then fall through to the
codepoint policy scanner. The concrete type names may differ by language, but
the fields must map back to the Lean runtime policy surface:

- `Profile`
- `Mode`
- `Action`
- `Finding`
- `Verdict`
- detector family
- stable reason code
- severity
- positions/spans
- normalized output when applicable

The JSON helper emits the exact compact shape guarded by
`fixtures/security/verdict_contract.json`: `action`, `profile`, `mode`,
`input`, `findings`, and `normalized`, with finding fields ordered as `code`,
`family`, `severity`, `positions`, `sub_threat`, and `detail`. Language names
may be idiomatic (`VerdictJSON` in Go, `verdictJson` in Haskell,
`writeVerdictJson` in Zig), but the serialized wire shape is shared.

## Reason Codes

Reason codes are product API, not internal debug text.

All ports must use the same stable namespace:

```text
unicode.security.<layer>.<family>.<subthreat-or-hazard>
```

Examples:

```text
unicode.security.C.malformed-utf8.InvalidStartByte
unicode.security.C.malformed-utf16.InvalidSurrogatePair
unicode.security.C.malformed-utf32.CodepointBeyondMax
unicode.security.C.zero-width-payload.<subthreat>
unicode.security.I.homoglyph-confusable.<subthreat>
unicode.security.F.normalization-bomb.<subthreat>
```

The Lean module `Unicode.Security.Policy` defines the initial family-level code
shape. Port implementations should treat those strings as compatibility
contracts.

Current v0 runtime surfaces:

- Lean: `Unicode.Security.Policy`
- Rust: `unicode_rust::security::policy`
- Python: `unicode_python.security.policy`
- C/C++: `unicode_cpp/security/policy.hpp`
- Haskell: `ports/haskell` package `unicode-haskell`
- Go: `ports/go/security`
- Java/Kotlin: `ports/jvm`
- TypeScript/WASM: `ports/typescript`
- C#/.NET: `ports/dotnet`
- Swift: `ports/swift`
- Zig: `ports/zig/src/security.zig`

The v0 native `scan` implementations cover the detector families already
present in the runtime ports. Adding more detector families must preserve the
same public `Action`, `Mode`, `Profile`, `Finding`, `Verdict`, and reason-code
shape.

Current shared v0 detector fixture families:

- `tag-block-payload`
- `variation-selector-payload`
- `zero-width-payload`
- `bidi-control-balance`
- `noncharacter-control`
- `homoglyph-confusable` identity sub-threat slice:
  `TargetMatch`, `MathAlpha`, `WidthClass`, `DecompositionSwap`, and
  `CrossScriptMix`

## Shared Fixtures

The ports need one shared fixture strategy instead of independent ad hoc tests.

Required fixture layers:

- codec fixtures: UTF-8, UTF-16, UTF-32, BOM, noncharacters
- detector fixtures: one shared file per detector family
- policy fixtures: profile/mode/input/action/findings
- JSON verdict fixtures: stable serialized shape
- red-team fixtures: real attack strings and expected decisions

The policy fixture format should be language-neutral:

```json
{
  "name": "bidi-control-in-source",
  "profile": "source-code",
  "mode": "enforce",
  "input": [8238, 97, 98, 99],
  "action": "reject",
  "required_findings": [
    "unicode.security.C.bidi-control-balance.hazard"
  ]
}
```

Ports may include additional language-native tests, but shared fixtures are the
cross-port compatibility gate. Detector fixtures assert both required findings
and, when `required_findings` is empty, absence of findings for that detector
family.

The current shared fixture set is:

- `fixtures/security/policy_contract.json` — profile, mode, action, input, and
  required reason-code contract.
- `fixtures/security/verdict_contract.json` — stable JSON verdict shape for
  action/profile/mode/input/findings/normalized output and the public
  verdict JSON helpers.
- `fixtures/security/decode_contract.json` — shared raw UTF-8 admission
  contract for valid bytes, malformed byte classes, reject/observe behavior,
  decoded input, and byte-offset positions.
- `fixtures/security/decode_multiencoding_contract.json` — shared UTF-16BE/LE
  and UTF-32BE/LE admission contract for valid bytes, malformed code units,
  surrogate failures, decoded input, and byte-offset positions.
- `fixtures/security/detectors/*.json` — per-detector fixture files for the
  shared runtime families, including the data-backed
  `homoglyph-confusable` `identity-subthreat-v0` slice. The lighter ports vendor
  `confusables.txt` and `KnownAttackTargets.txt`. Haskell, JVM, Go,
  TypeScript, .NET, and Swift parse the vendored confusables map directly; Zig uses
  `ports/zig/src/confusables_data.zig`, generated from the vendored UTS #39 file by
  `ports/zig/tools/generate_confusables_data.py`. The shared v0 slice also
  covers decomposed combining-sequence swaps and Latin/Greek/Cyrillic script
  mixing. Python vendors the same UCD/security text inputs under
  `src/unicode_python/data`, and `scripts/check-runtime-data.sh` compares those
  files byte-for-byte with the canonical `data/` symlink targets. JVM, Go,
  TypeScript, .NET, Swift, and Zig pin their vendored bytes with port-local
  `SHA256SUMS` manifests, and Zig checks that its generated lookup table is
  reproducible from `confusables.txt`. `RestrictionLow` remains outside the shared detector
  fixture: Rust/Python can reach low restriction levels internally, but the
  reference detector currently emits the higher-priority `CrossScriptMix`
  sub-threat first. The reference-only audit fixture
  `fixtures/security/audits/homoglyph_restriction_low.json` pins that behavior.

## Runtime Data Refresh

Canonical runtime UCD/security inputs live behind the root `data/` symlink
surface, backed by `Unicode/Ucd/` and `Unicode/Ucd/Curated/`. Runtime ports that
need vendored copies must be synchronized from those canonical bytes, not from
ad hoc downloads.

After updating the canonical UCD files and `data/UCD-VERSION`, run:

```bash
scripts/sync-runtime-data.sh --apply
```

That command refreshes `data/SHA256SUMS`, syncs Python vendored data, syncs the
Haskell/JVM/Go/TypeScript/.NET/Swift/Zig runtime data copies, refreshes their
`SHA256SUMS` manifests, regenerates Haskell generated normalization tables,
regenerates Zig `confusables_data.zig`, and finishes with
`scripts/check-runtime-data.sh`.

For CI or preflight checks without writing files, run:

```bash
scripts/sync-runtime-data.sh --check
```

The sync workflow is local and bounded: it does not download Unicode data, build
Lean, or run proof/full-conformance roots.

## Build Commands

Expected local commands:

```bash
scripts/check-policy-contract.sh
scripts/sync-runtime-data.sh --check
scripts/check-runtime-data.sh
scripts/test-runtime-ports.sh
scripts/package-runtime.sh
scripts/build-runtime.sh
scripts/test-runtime-ports.sh --all   # exhaustive Rust red-team/diff tier
cmake -S . -B build -DUNICODE_CPP_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build
uv run pytest
cd ports/go && go test ./...
cd ports/jvm && scripts/test.sh
cd ports/typescript && node --test test/*.test.js
cd ports/dotnet && dotnet run --project test/UnicodeSecurity.Tests/UnicodeSecurity.Tests.csproj
cd ports/swift && scripts/test.sh
cd ports/zig && zig build test
```

Haskell port command:

```bash
cd ports/haskell
cabal test all --offline
```

Future Phase 2 port commands are not committed yet. Add each command only with
the corresponding port tree, shared fixtures, vendored data, and bounded test
gate.

These are runtime-port checks. They must not require `UnicodeAssurance` or
`UnicodeFullConformance`.

## Rust Warning Policy

The Rust crate keeps public API documentation linting visible with
`missing_docs = "warn"` in `Cargo.toml` and `#![warn(missing_docs)]` in
`src/lib.rs`. The runtime smoke gate and CLI installer suppress warning output
by default so consumer-facing checks stay readable; set `RUST_WARNINGS=1` when
burning down public API docs or auditing the warning set.

`scripts/check-rust-warning-policy.sh` guards that policy. Warnings here are a
release polish burn-down item, not a runtime safety escape hatch.

## Port Parity CI

CI should eventually have separate jobs:

- `runtime / lean`
- `runtime / rust`
- `runtime / cpp`
- `runtime / python`
- `runtime / haskell`
- `runtime / go`
- `runtime / zig`
- `runtime / typescript-wasm`
- `runtime / jvm`
- `runtime / dotnet`
- `runtime / swift`
- `runtime / cobol`
- `runtime / erlang-elixir`
- `runtime / openresty`
- `runtime / ruby`
- `runtime / php`
- `assurance / lean`
- `full-conformance / lean`

Runtime jobs should be fast and safe for every pull request once their ports
exist. Assurance and full conformance jobs should remain opt-in, scheduled, or
release-gated until their memory profile is proven safe.

## FFI And Packaging

The deployment path likely needs multiple packaging surfaces:

- Rust crate for services, agents, and gateway daemons
- C ABI or C++ wrapper for routers, native extensions, and embedded products
- Python wheel for ops tooling and integration tests
- Haskell package for functional runtime users
- Go module for cloud-native network services
- Zig package/static binaries for edge devices
- WASM package for browser and edge-worker policy checks
- JVM package for Java/Kotlin services
- .NET package for Windows and C# services
- Swift package for Apple platforms
- COBOL/mainframe integration package or ABI bridge
- Erlang/Elixir package for telecom/control-plane systems
- Lua/OpenResty module for gateway filtering
- Ruby and PHP packages for web-framework integration

The first FFI target should be the policy verdict API, not every internal
Unicode helper.

## Current Packaging Commands

The current in-repo runtime package command is:

```bash
nix develop .#runtime -c scripts/package-runtime.sh
```

It packages the live working tree into `dist/runtime/` without building Lean,
then runs:

```bash
nix develop .#runtime -c scripts/check-runtime-package.sh dist/runtime
nix develop .#runtime -c scripts/check-deployment-smokes.sh --dist-dir dist/runtime
```

The verifier can also be run by itself against an existing artifact tree. It
checks `SHA256SUMS`, the installed CLI smoke scan, Python wheel install/import,
C++ installed-header compile/run plus installed C++ data files, installed
loopback server `/healthz`, `/scan`, `/batch`, and `/metrics`, Haskell source
distribution contents, packaged JVM tests, packaged Go module tests, packaged
TypeScript tests, packaged .NET tests, packaged Swift tests, Zig install
artifact, and manifest.
The deployment-smoke gate then proves a product-facing install shape: a
loopback gateway sidecar plus downstream Python, C++, Haskell, JVM, Go,
TypeScript edge-worker, .NET, SwiftPM, and Zig module consumers.
The manifest records package version, git commit, git tree state, UCD manifest
hash, and `lean: not built`. That matters while runtime files are still being
stabilized and before every new port file is committed into the flake source.

Every runtime port must be self-contained: shipped runtime code may use data
vendored into its own package or installed package tree, but it must not depend
on Lean roots, another language port, top-level test fixtures, or repo-relative
working-directory files at runtime. `scripts/check-port-self-contained.sh`
enforces this contract.

Tracked flake package outputs have a separate smoke gate:

```bash
nix develop .#runtime -c scripts/check-nix-runtime-packages.sh
```

That command builds and smokes `.#unicode-security`, `.#unicode-python`,
`.#unicode-cpp`, `.#unicode-haskell`, `.#unicode-jvm`, `.#unicode-go`,
`.#unicode-typescript`, `.#unicode-dotnet`, `.#unicode-swift`, and
`.#unicode-zig` from tracked source.

Language-specific install/build paths:

```bash
# Whole runtime package tree
scripts/check-runtime-package.sh dist/runtime
scripts/check-deployment-smokes.sh --dist-dir dist/runtime
scripts/check-nix-runtime-packages.sh

# Rust CLI and Rust library crate
scripts/install-unicode-security.sh dist/runtime/rust
cargo install --path . --bin unicode-security --locked
cargo build --release --bin unicode-security

# Python wheel/source distribution
python -m build --no-isolation --outdir dist/runtime/python

# C++ header install tree
cmake -S . -B build/package-cpp -DUNICODE_CPP_BUILD_TESTS=OFF \
  -DCMAKE_INSTALL_PREFIX="$PWD/dist/runtime/cpp"
cmake --build build/package-cpp
cmake --install build/package-cpp

# Haskell package
cd ports/haskell
cabal sdist --offline
cabal install --offline --lib unicode-haskell

# Go module
cd ports/go
go test ./...
go list ./...

# Java / Kotlin package
cd ports/jvm
scripts/test.sh

# TypeScript / WASM package
cd ports/typescript
node --test test/*.test.js

# C# / .NET package
cd ports/dotnet
dotnet run --project test/UnicodeSecurity.Tests/UnicodeSecurity.Tests.csproj

# Swift package
cd ports/swift
scripts/test.sh

# Zig package/library artifact
cd ports/zig
zig build install --prefix ../../dist/runtime/zig
```

Clean tracked Nix release surfaces:

```bash
nix build .#unicode-security
nix build .#unicode-python
nix build .#unicode-cpp
nix build .#unicode-haskell
nix build .#unicode-jvm
nix build .#unicode-go
nix build .#unicode-typescript
nix build .#unicode-dotnet
nix build .#unicode-swift
nix build .#unicode-zig
nix run .#unicode-security -- scan --profile gateway-header --input sample.txt --json
```

Go is consumed as a module from `ports/go`; `scripts/package-runtime.sh` and
the `.#unicode-go` flake output both ship a self-contained module tree with
vendored data and local contract fixtures.

Java/Kotlin is consumed as a dependency-free JVM package tree from `ports/jvm`;
`scripts/package-runtime.sh` and the `.#unicode-jvm` flake output both ship a
self-contained source/resource/test tree with vendored data and local contract
fixtures.

TypeScript/WASM is consumed as a dependency-free package from
`ports/typescript`; `scripts/package-runtime.sh` and the
`.#unicode-typescript` flake output both ship a self-contained package tree
with vendored data and local contract fixtures. Node consumers import
`@unicode-security/runtime`; browser and edge-worker consumers import
`@unicode-security/runtime/edge` and call `instantiateSecurity` with injected
data or a fetchable package data URL. The `./edge` and `./wasm` entries do not
import Node filesystem APIs.

C#/.NET is consumed as a dependency-free .NET package tree from `ports/dotnet`;
`scripts/package-runtime.sh` and the `.#unicode-dotnet` flake output both ship a
self-contained source/test tree with vendored data and local contract fixtures.

Swift is consumed as a Swift Package Manager tree from `ports/swift`;
`scripts/package-runtime.sh` and the `.#unicode-swift` flake output both ship a
self-contained package with vendored data and local contract fixtures.

The CLI installer writes `UNICODE_SECURITY_INSTALL.txt` next to the installed
binary and runs a gateway-header/enforce JSON smoke scan. It is the smallest
consumer-facing install path and is safe to run without Lean.

## Acceptance Criteria

The port strategy is working when:

- every runtime port exposes profile/mode scan semantics
- every runtime port emits the same reason codes for shared fixtures
- port tests run without proof-heavy Lean roots
- JSON verdict fixtures are stable across languages
- CI prevents a port from drifting from the shared policy contract
- docs tell users which language package to install for their deployment
- new ports are added only after the existing port set has parity on shared
  policy fixtures

## Current Decision

Lean defines the semantics.

Rust, C++, Python, and Haskell are the initial deployable runtime surface.

Go, TypeScript/WASM, Zig, Java/Kotlin, C#/.NET, and Swift now have
contract-first deployment scaffolds. COBOL, Erlang/Elixir, Lua/OpenResty, Ruby,
and PHP are planned deployment ports after the current ports reach parity.

Shared fixtures and reason codes are the compatibility contract between them.
