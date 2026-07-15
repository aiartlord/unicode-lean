# Runtime Deployment

The deployable surface is the runtime security layer, not the proof build. Use
`nix develop .#runtime` for packaging, local smoke checks, and port tests.

## Package Everything

```bash
nix develop .#runtime -c scripts/package-runtime.sh
nix develop .#runtime -c scripts/check-runtime-package.sh dist/runtime
nix develop .#runtime -c scripts/check-deployment-smokes.sh --dist-dir dist/runtime
```

The package tree contains Rust CLI, Python, C++, Haskell, JVM, Go,
TypeScript/edge, .NET, Swift, and Zig artifacts. The manifest records
`lean: not built`.

`scripts/check-deployment-smokes.sh` proves the packaged deployment shape by
running a loopback gateway sidecar smoke and compiling/loading downstream
Python, C++, Haskell, JVM, Go, TypeScript edge, .NET, Swift, and Zig consumers
against the package tree.

## Smallest CLI Install

```bash
nix develop .#runtime -c scripts/install-unicode-security.sh dist/runtime/rust
```

Run a gateway-header scan:

```bash
printf 'hello' | dist/runtime/rust/bin/unicode-security scan \
  --profile gateway-header --mode enforce --json
```

Run the loopback gateway server:

```bash
dist/runtime/rust/bin/unicode-security serve \
  --listen 127.0.0.1:8787 \
  --profile gateway-header \
  --mode enforce \
  --max-request-bytes 1048576 \
  --max-batch-records 1000 \
  --log-requests
```

Health and scan probes:

```bash
curl -s http://127.0.0.1:8787/healthz
curl -sS http://127.0.0.1:8787/scan \
  -H 'Content-Type: application/json' \
  --data '{"text":"hello"}'
printf '%s\n' '{"id":"a","text":"hello"}' '{"id":"b","text":"a\u200Bb"}' |
  curl -sS http://127.0.0.1:8787/batch \
    -H 'Content-Type: application/x-ndjson' \
    --data-binary @-
curl -s http://127.0.0.1:8787/metrics
```

Local sidecars can bind an HTTP server on a Unix domain socket instead of TCP:

```bash
dist/runtime/rust/bin/unicode-security serve \
  --unix-socket /tmp/unicode-security.sock \
  --profile gateway-header \
  --mode enforce
```

Supervisor-managed filters can avoid HTTP and use newline-framed stdio:

```bash
printf '%s\n' '{"id":"a","text":"hello"}' '{"id":"b","text":"a\u200Bb"}' |
  dist/runtime/rust/bin/unicode-security serve \
    --stdio-jsonl \
    --profile source-code \
    --mode strict
```

## Deployment Targets

Gateway/router appliance:

```bash
nix develop .#runtime -c zig build --prefix dist/runtime/zig --build-file ports/zig/build.zig
nix develop .#runtime -c scripts/install-unicode-security.sh dist/runtime/rust
```

Service mesh or reverse proxy:

```bash
cd ports/go
go test ./...
go list ./...
```

Enterprise JVM service:

```bash
cd ports/jvm
scripts/test.sh
```

Windows or Azure-heavy agent:

```bash
cd ports/dotnet
dotnet run --project test/UnicodeSecurity.Tests/UnicodeSecurity.Tests.csproj
```

Apple client or local-device filter:

```bash
cd ports/swift
scripts/test.sh
```

Browser, dashboard, or edge worker:

```bash
cd ports/typescript
node --test test/*.test.js
```

Use `@unicode-security/runtime/edge` in browser/edge code and call
`instantiateSecurity` with either injected package data (`confusables`,
`caseFolding`, known targets, and variation data) or a fetchable package data
URL.

## Release Gate

For release evidence, use a clean tracked source tree:

```bash
nix develop .#runtime -c env JOBS=1 scripts/check-release-runtime-preflight.sh
```

That gate runs source guards, data guards, self-contained port checks, runtime
packaging, packaged deployment-consumer smokes, and tracked Nix runtime package
smokes. It intentionally does not invoke Lean assurance or full-conformance
builds.
