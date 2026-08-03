# Getting started

This tutorial builds a port and runs the first scan. It takes a few minutes and
needs only Nix.

## Build a port

Every port builds and runs its test suite as part of its Nix build. Build the
Rust port:

```bash
nix build .#unicode-rust
```

A green build is the authoritative signal that the port is correct on its pinned
toolchain: it compiles the port and runs its contract tests, including the shared
detector fixtures. The other fifteen ports build the same way, from
`.#unicode-python` through `.#unicode-cobol`.

## Run a scan from the command line

Install the CLI and scan a payload:

```bash
nix develop .#runtime -c scripts/install-unicode-security.sh dist/runtime/rust
printf 'hello' | dist/runtime/rust/bin/unicode-security scan \
  --profile gateway-header --mode enforce --json
```

Clean text returns an allow verdict. Scan a payload with a zero-width character
between letters and the verdict reports a hazard with a stable reason code under
`unicode.security.C.zero-width-payload`.

## Run the gateway

Start the loopback server and probe it:

```bash
dist/runtime/rust/bin/unicode-security serve \
  --listen 127.0.0.1:8787 --profile gateway-header --mode enforce
curl -s http://127.0.0.1:8787/healthz
curl -sS http://127.0.0.1:8787/scan \
  -H 'Content-Type: application/json' --data '{"text":"hello"}'
```

## Next steps

- Wire the engine into a service: [`../how-to/integrate.md`](../how-to/integrate.md).
- Understand the layers: [`../explanation/architecture.md`](../explanation/architecture.md).
- Look up a detector or the verdict shape:
  [`../../ports/DETECTOR_COVERAGE.md`](../../ports/DETECTOR_COVERAGE.md).
