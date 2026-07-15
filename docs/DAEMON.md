# Daemon Mode Design

`unicode-security serve` is the long-running gateway mode for the runtime
scanner. It wraps the same policy engine used by `scan`; it must not create a
second policy implementation.

## Goals

- enforce profile/mode decisions on streaming traffic
- emit stable JSON verdicts and counters by reason code
- support fail-closed startup and reload behavior
- keep proof-heavy Lean roots outside the serving path

## Process Model

Initial command shape:

```bash
unicode-security serve \
  --listen 127.0.0.1:8787 \
  --profile gateway-header \
  --mode enforce \
  --json
```

First transport:

- HTTP loopback service
- `GET /healthz` for readiness: implemented in v0
- `POST /scan` for one payload: implemented in v0
- `POST /batch` for JSONL-style records: implemented in v0
- `GET /metrics` for counters: implemented in v0
- stdin/stdout JSONL framed mode for supervisor-managed filters:
  implemented by `--stdio-jsonl`
- Unix socket HTTP transport for local sidecars: implemented by
  `--unix-socket`

Later transports:

- C ABI or FFI bridge for in-process gateway modules

## Request Contract

Accepted scan request:

```json
{"profile":"gateway-header","mode":"enforce","encoding":"utf-8","bytes":[72,101,108,108,111]}
```

Rules:

- `POST /scan` accepts exactly one of `text` or `bytes`
- `POST /batch` accepts newline-delimited JSON records with exactly one of
  `text` or `bytes` per record
- `serve --stdio-jsonl` accepts the same newline-delimited records on stdin and
  writes one newline-delimited verdict frame per input frame on stdout
- `serve --unix-socket` exposes the same HTTP request contract as TCP `serve`
  over a Unix domain socket
- strict known fields
- explicit encoding for non-UTF-8 bytes
- same verdict JSON shape as CLI
- request-level profile/mode overrides are rejected unless the server starts
  with `--allow-request-policy`
- policy rejects still return HTTP `200` with a verdict body; malformed request
  control data returns HTTP `400`

## Operational Controls

- max request bytes: implemented by `--max-request-bytes`
- max batch records: implemented by `--max-batch-records`
- redacted request logs: implemented by `--log-requests`; payload text, byte
  arrays, decoded codepoints, and verdict bodies are not logged
- profile/mode ceiling: implemented by default; request overrides require
  `--allow-request-policy`
- socket read/write timeout: implemented by `--request-timeout-ms`
- reloadable policy file with atomic validation: implemented by
  `--policy-file` and `--reload-policy-per-request`
- fail closed on malformed config: implemented for startup policy validation
  and per-request reload validation
- stdio framed transport: implemented by `--stdio-jsonl`
- Unix socket transport: implemented by `--unix-socket`

Policy file:

```json
{"profile":"source-code","mode":"strict","encoding":"utf-8","allow_request_policy":false}
```

## Metrics

Counters:

- requests total
- verdict action total
- finding reason-code total
- malformed decode total
- scan request total
- batch request total
- malformed request control total

Latency:

- scan duration histogram: implemented as `latency_ms.scan`
- batch duration histogram: implemented as `latency_ms.batch`
- policy reload duration: implemented as `latency_ms.policy_reload`

## Implementation Order

1. Keep `scan` and `serve` on the same Rust policy execution path.
2. Add deployment examples for gateway sidecar, service mesh, and Windows
   agent modes.
3. Add C ABI or FFI bridge for in-process gateway modules.
