# Unicode Security CLI

`unicode-security` is the product-facing runtime scanner. It is a Rust binary
that reads text bytes, strictly decodes them to codepoints, runs the shared
policy engine, and emits either a human summary or stable JSON verdict. It also
ships the first loopback server mode for gateway sidecar integration.

## Build

From the repository root:

```sh
nix develop .#runtime -c cargo build --bin unicode-security
```

The bounded runtime gate also builds and tests the CLI:

```sh
nix develop .#runtime -c scripts/test-runtime-ports.sh --smoke
```

## Install

Install the CLI from the working tree:

```sh
nix develop .#runtime -c cargo install --path . --bin unicode-security --locked
```

Or install it through the repository installer, which writes into a local
prefix and smoke-tests the installed binary:

```sh
nix develop .#runtime -c scripts/install-unicode-security.sh dist/runtime/rust
```

Package all current runtime surfaces into `dist/runtime/`:

```sh
nix develop .#runtime -c scripts/package-runtime.sh
```

Run the strict runtime release preflight:

```sh
nix develop .#runtime -c scripts/check-release-runtime-preflight.sh
```

Verify an existing runtime package tree without rebuilding it:

```sh
nix develop .#runtime -c scripts/check-runtime-package.sh dist/runtime
```

The packaging script writes:

- `dist/runtime/rust/bin/unicode-security`
- `dist/runtime/rust/UNICODE_SECURITY_INSTALL.txt`
- `dist/runtime/MANIFEST.txt`
- `dist/runtime/SHA256SUMS`
- Python wheel and source distribution under `dist/runtime/python/`
- C++ installed headers under `dist/runtime/cpp/include/unicode_cpp/` and
  runtime data under `dist/runtime/cpp/share/unicode_cpp/data/`
- Haskell Cabal source distribution under `dist/runtime/haskell/`
- JVM package tree under `dist/runtime/jvm/`
- Go module tree under `dist/runtime/go/` plus package-list evidence under
  `dist/runtime/go-packages.txt`
- TypeScript package tree under `dist/runtime/typescript/`
- .NET package tree under `dist/runtime/dotnet/`
- Swift package tree under `dist/runtime/swift/`
- Zig install prefix under `dist/runtime/zig/`

`scripts/package-runtime.sh` runs the verifier before it exits. The manifest
records package version, git commit, git tree state, UCD manifest hash, and
the fact that Lean was not built. `SHA256SUMS` covers the emitted runtime
artifacts, and the verifier checks those hashes before checking the installed
CLI smoke scan, installed loopback server `/healthz`, `/scan`, `/batch`, and
`/metrics`, Python wheel install/import, C++ installed-header compile/run,
Haskell sdist contents, packaged JVM tests, packaged Go module tests, packaged
TypeScript tests, packaged .NET tests, packaged Swift tests, Zig install
artifact, and package manifest.

For clean tracked release builds, the flake also exposes:

```sh
nix build .#unicode-security
nix build .#unicode-jvm
nix build .#unicode-go
nix build .#unicode-typescript
nix build .#unicode-dotnet
nix build .#unicode-swift
nix run .#unicode-security -- scan --profile gateway-header --input sample.txt --json
```

## Scan A File

```sh
nix develop .#runtime -c cargo run --quiet --bin unicode-security -- \
  scan --profile gateway-header --mode enforce --input sample.txt --json
```

## Scan Stdin

```sh
printf 'hello' | nix develop .#runtime -c cargo run --quiet --bin unicode-security -- \
  scan --profile gateway-header --mode enforce --json
```

`--input -` also means stdin. If `--input` is omitted, stdin is used.

## Serve Loopback HTTP

Start the local server:

```sh
nix develop .#runtime -c cargo run --quiet --bin unicode-security -- \
  serve --listen 127.0.0.1:8787 --profile gateway-header --mode enforce
```

Operational limits and logs:

```sh
nix develop .#runtime -c cargo run --quiet --bin unicode-security -- \
  serve \
    --listen 127.0.0.1:8787 \
    --profile gateway-header \
    --mode enforce \
    --max-request-bytes 1048576 \
    --max-batch-records 1000 \
    --request-timeout-ms 5000 \
    --policy-file policy.json \
    --reload-policy-per-request \
    --log-requests
```

`--max-request-bytes` bounds each HTTP request body. `--max-batch-records`
bounds non-empty JSONL records accepted by `POST /batch`. `--request-timeout-ms`
sets socket read/write deadlines. `--policy-file` loads a validated JSON policy
snapshot at startup; `--reload-policy-per-request` revalidates it before each
`/scan` or `/batch` request. `--log-requests` emits one compact JSON event per
routed HTTP request to stderr with method, path, status, request byte length,
response byte length, and `redacted: true`; payload text, byte arrays, decoded
codepoints, and verdict bodies are not written to logs.

Unix socket transport for local sidecars:

```sh
nix develop .#runtime -c cargo run --quiet --bin unicode-security -- \
  serve --unix-socket /tmp/unicode-security.sock --profile gateway-header --mode enforce
```

`--unix-socket` exposes the same HTTP endpoints as `--listen`, but over a Unix
domain socket instead of TCP. It is mutually exclusive with explicit
`--listen` and `--stdio-jsonl`.

Supervisor-managed framed transport:

```sh
printf '%s\n' '{"id":"a","text":"Hello"}' '{"id":"b","text":"a\u200Bb"}' |
  nix develop .#runtime -c cargo run --quiet --bin unicode-security -- \
    serve --stdio-jsonl --profile source-code --mode strict
```

`--stdio-jsonl` does not bind a TCP listener. It reads one newline-delimited
JSON frame from stdin at a time and writes one newline-delimited verdict frame
to stdout, using the same record schema as `scan --jsonl` and `POST /batch`.

Policy file shape:

```json
{"profile":"source-code","mode":"strict","encoding":"utf-8","allow_request_policy":false}
```

Policy-file fields are optional and validated atomically. Reload failures return
HTTP `500` and do not accept the request.

Readiness:

```sh
curl -s http://127.0.0.1:8787/healthz
```

Scan one payload:

```sh
curl -sS http://127.0.0.1:8787/scan \
  -H 'Content-Type: application/json' \
  --data '{"text":"hello"}'
```

`POST /scan` accepts the same conceptual fields as JSONL records, except there
is no `id`: `text`, `bytes`, `profile`, `mode`, and `encoding`. Each request
must set exactly one of `text` or `bytes`. Server profile and mode are locked
by default; request-level `profile` or `mode` overrides require starting the
server with `--allow-request-policy`.

Non-UTF-8 input uses byte arrays and an explicit encoding:

```json
{"encoding":"utf-16le","bytes":[97,0,11,32,98,0]}
```

Policy rejects still return HTTP `200` with a verdict body. Malformed request
control data returns HTTP `400` with `{"error":"..."}`.

Batch scan over the same loopback server:

```sh
printf '%s\n' '{"id":"a","text":"Hello"}' '{"id":"b","text":"a\u200Bb"}' |
  curl -sS http://127.0.0.1:8787/batch \
    -H 'Content-Type: application/x-ndjson' \
    --data-binary @-
```

`POST /batch` accepts the same newline-delimited JSON records as
`unicode-security scan --jsonl`, including optional `id`, `text`, `bytes`, and
`encoding`. Server profile and mode are locked by default, so per-record
`profile` or `mode` overrides require `--allow-request-policy`. A valid batch
returns HTTP `200` with `application/x-ndjson`; malformed control records return
HTTP `400` and stop before emitting partial batch output. Batches exceeding
`--max-batch-records` also return HTTP `400`.

Metrics:

```sh
curl -s http://127.0.0.1:8787/metrics
```

`GET /metrics` returns compact JSON counters for total routed requests,
`/scan` requests, `/batch` requests, malformed request control data, malformed
decode verdicts, actions, reason codes, and structured latency metrics. The
`latency_ms.scan`, `latency_ms.batch`, and `latency_ms.policy_reload` objects
include `count`, `sum_ms`, `max_ms`, and fixed `buckets`.

## Batch JSONL

`--jsonl` reads newline-delimited JSON records from stdin or `--input` and
emits one verdict JSON object per line:

```sh
printf '%s\n' '{"id":"a","text":"Hello"}' '{"id":"b","profile":"source-code","mode":"strict","text":"a\u200Bb"}' |
  nix develop .#runtime -c cargo run --quiet --bin unicode-security -- scan --jsonl
```

Accepted record fields:

- `id`: optional string copied into the output object.
- `text`: UTF-8 string input.
- `bytes`: byte array input such as `[72,101,108,108,111]`.
- `profile`: optional profile override for this record.
- `mode`: optional mode override for this record.
- `encoding`: optional encoding override for this record.

The accepted fields are exhaustive. Unknown fields and duplicate fields are
rejected so operator typos cannot silently change scan behavior. Each record
must set exactly one of `text` or `bytes`. If any record rejects or quarantines,
the process exits `1` after processing all records.

`text` is JSON text and is therefore already UTF-8 at the JSONL boundary.
Escaped JSON surrogate pairs such as `\uD83D\uDE00` are decoded to their single
Unicode scalar before scanning. `text` records require `utf-8` encoding. Use
`bytes` when scanning UTF-16, UTF-32, or BOM-detected payloads in batch mode:

```json
{"id":"u16","profile":"source-code","mode":"strict","encoding":"utf-16le","bytes":[97,0,11,32,98,0]}
```

`bytes` arrays must be strict JSON arrays of integers in `0..255`; trailing
commas are rejected. Malformed JSONL control records are usage/data errors:
the process exits `2`, reports `jsonl line N` on stderr, and stops at the
offending line. Records emitted before the bad line remain on stdout.

## Encodings

Accepted encoding tags:

```text
utf-8
utf-16be
utf-16le
utf-32be
utf-32le
bom
```

If omitted, `--encoding` defaults to `utf-8`. `--encoding bom` detects and
strips a leading UTF-8, UTF-16, or UTF-32 BOM; if no BOM is present, it falls
back to UTF-8.

Example:

```sh
  nix develop .#runtime -c cargo run --quiet --bin unicode-security -- \
  scan --encoding bom --profile source-code --mode strict --input sample.txt --json
```

## Profiles

Accepted profile tags:

```text
gateway-header
domain-name
dns-label
url
username
display-name
chat-message
source-code
opaque-secret
binary-blob
```

The CLI also accepts the roadmap camelCase aliases such as `gatewayHeader`.
If omitted, `--profile` defaults to `gateway-header`.

## Modes

```text
observe
warn
enforce
strict
```

`observe` and `warn` report findings without a blocking exit status.
`enforce` follows the profile policy. `strict` rejects any finding.
If omitted, `--mode` defaults to `enforce`.

## Exit Codes

- `0`: action is `allow`, `observe`, or `rewrite`
- `1`: action is `reject` or `quarantine`
- `2`: CLI usage, input I/O, or option parsing error

## JSON Shape

For valid UTF-8, JSON output follows the shared runtime verdict contract and
adds CLI byte diagnostics to each finding:

```json
{"action":"allow","profile":"gateway-header","mode":"enforce","input":[72,101,108,108,111],"findings":[],"normalized":null}
```

Finding objects keep `positions` as codepoint offsets and add `byte_spans`.
Byte spans are half-open byte ranges and use 1-based line/column coordinates:

```json
{"code":"unicode.security.C.zero-width-payload.BareZeroWidth","family":"zero-width-payload","severity":2,"positions":[1],"byte_spans":[{"cp_offset":1,"start_byte":1,"end_byte":4,"line":1,"column":2}],"sub_threat":"BareZeroWidth","detail":"zero-width-payload"}
```

Malformed UTF-8 is rejected by the shared runtime byte-scan API before
codepoint scanning and uses the stable boundary reason-code family
`malformed-utf8`, for example:

```text
unicode.security.C.malformed-utf8.InvalidStartByte
```

The malformed UTF-8 `positions` value is a byte offset; its `byte_spans` entry
uses `cp_offset: null`. The cross-language decode fixture
`fixtures/security/decode_contract.json` guards the shared byte-level verdict;
the CLI adds byte/line/column spans for operator diagnostics.

Runtime port JSON helpers emit the base verdict shape guarded by
`fixtures/security/verdict_contract.json`. The CLI keeps that shape and adds
`byte_spans` for operator diagnostics.

Malformed UTF-16/UTF-32 in CLI-selected encodings is rejected by the same shared
runtime byte-scan contract and reported with the same JSON verdict shape. These
reason-code families are:

```text
unicode.security.C.malformed-utf16.<Kind>
unicode.security.C.malformed-utf32.<Kind>
```

For valid UTF-16/UTF-32 input, `positions` remain codepoint offsets and
`byte_spans` point to the original input byte ranges, including skipped BOM
bytes when `--encoding bom` is used.

The CLI integration tests mirror the shared multi-encoding decode contract and
cover UTF-16BE/LE, UTF-32BE/LE, malformed code units, malformed surrogate
pairs, BOM-detected UTF-8/16/32, JSONL per-record encoded bytes, and hardened
JSONL record parsing.
