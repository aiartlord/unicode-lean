# Roadmap

Forward-looking work only. What already ships — the verified `unicode` library,
the `unicode security` reference-monitor engine, all sixteen language ports (27
detector families each), and the machine-checked proof tree — is recorded in
[`CHANGELOG.md`](../CHANGELOG.md), not here. This document is the set of things
that are **not** done.

The theme is one step: turn the shipped per-message reference monitor into a
real-time sanitization layer that runs inline in a mesh — gateways, routers, and
data centers — at production traffic volume. Each workstream below states its
mechanism and its completion criterion.

## 1. Ingress wiring (the middle-layer contract)

The engine mediates a message stream inline; it does not sit off to the side.
The raw `scan(List Nat)` entrypoint skips decoding by construction, so a mesh
ingress must call the byte-level `scan_utf8` / `scan_utf16be|le` / `scan_utf32be|le`
entrypoints and never lenient-decode to U+FFFD before scanning.

- **Mechanism:** a documented ingress contract (see
  [`how-to/integrate.md`](how-to/integrate.md)) plus a conformance fixture that
  fails a consumer which hands pre-decoded codepoints to `scan`.
- **Done when:** every reference consumer (in-process port, `serve` sidecar)
  routes raw bytes through a `scan_*` entrypoint, and the contract is gated in CI.

## 2. Load-time table attestation and fail-closed

A node whose vendored UCD/security tables have drifted classifies differently —
a routing-dependent bypass. The engine must attest its tables at startup and
fail closed if they do not match the pinned digests.

- **Mechanism:** each port verifies its vendored data against its `SHA256SUMS`
  manifest at load, refuses to serve on mismatch, and exposes the attested
  version on `/healthz`.
- **Done when:** a tampered table makes the node refuse traffic rather than
  serve wrong verdicts, proven by a fixture, in every port that serves inline.

## 3. Decode-boundary enforcement

The byte-level entrypoints already strict-decode and reject malformed input with
a specific reason code and byte offset (`decode_contract.json`,
`decode_multiencoding_contract.json`). The decoders must additionally be proven
total against adversarial input so malformed bytes cannot hang or crash the
decode stage before the scan runs.

- **Done when:** decoder totality is established for every wire encoding and the
  malformed-input corpus runs clean across all ports.

## 4. Hot-path performance (data-center throughput)

At mesh volume the dominant input is short and sub-U+0080. An ASCII-clear
fast-path must short-circuit to a clear verdict before the Unicode machinery runs,
and the per-message monitor must stay allocation-light so throughput scales
linearly with cores and nodes.

- **Mechanism:** an ASCII/`< 0x80` pre-check on the hot path; per-detector cost
  budgets; a published throughput measurement per data-plane port (Rust, Go, Zig,
  C++) under bounded message sizes.
- **Done when:** each data-plane port meets a stated per-core throughput budget on
  the ASCII-clear path with the budgets tracked in
  [`reference/build-tiers.md`](reference/build-tiers.md).

## 5. Delta cache

Repeated identical payloads across a stream should not be re-scanned from
scratch. A verdict cache keyed on exact input bytes (never a normalized form —
`HashInputStability` exists precisely because representation drift changes bytes)
amortizes repeated traffic.

- **Done when:** the cache is bounded, keyed on raw bytes, and measured to
  improve throughput on repeated-payload traffic without changing any verdict.

## 6. In-process gateway module (FFI)

Sidecar `serve` is available now; the lowest-latency path is a C-ABI/FFI bridge so
a router links the engine as an in-process stage rather than crossing a socket.

- **Done when:** a stable C ABI exposes the `scan_*` entrypoints and the verdict
  wire shape, with a linked-in consumer example for the router data plane.

## 7. Cross-port determinism enforcement

Identical bytes must yield an identical verdict across all sixteen ports,
exhaustively — a port that classifies differently is a routing-dependent bypass.

- **Mechanism:** `fixtures/security/differential_corpus.json`, generated from the
  reference by `scripts/internal/generate_differential_corpus.py` over a seeded
  input stream cycling every profile. It carries the wire schema every port
  already replays for `verdict_contract.json`, so each port checks it through
  the loop it has rather than through a runner written per language. The
  reference is held to the same file by `--check`, which regenerates at the
  committed corpus's own size and compares, so the verdicts fifteen ports trust
  cannot drift away from the port that produced them.
- **Done when:** the differential runner covers all sixteen ports and is gated in
  CI. Both hold: every port replays the corpus, and the `cross-port determinism`
  job in `ci.yml` runs `scripts/test-runtime-ports.sh`, which drives all sixteen
  tiers in the runtime devshell.

  What the corpus does not reach is stated in
  [`../ports/DETECTOR_COVERAGE.md`](../ports/DETECTOR_COVERAGE.md): its stream
  produces no tag character and no bidi control, so those two families draw zero
  findings from it and rest on their own detector fixtures instead.

## 8. Runtime-data product layout

The ports carry vendored data but not in a uniform package shape (root `data/`,
`src/.../data`, package resources, generated compile-time tables). Normalize this
so every package has one explicit self-contained data story across its manifest,
install tree, package verifier, and port docs.

- **Done when:** the data layout is consistent and each port's verifier requires
  the exact data closure it reads.

## 9. Consumer integration

Wire the engine into production consumers as the inline sanitization layer. The
generic mechanism is documented in [`how-to/integrate.md`](how-to/integrate.md);
the consumer-specific wiring lives in each consuming repository, not here.

- **Router / gateway data plane** — link the matching port in-process at ingress,
  route raw bytes through `scan_*`, carry the verdict inline downstream
  (workstreams 1, 2, 4, 6).
- **Other services** — link the matching port in-process, or use the `serve`
  sidecar where the language has no native port.
- **Done when:** each consumer mediates its untrusted-text ingress through the
  engine with a documented profile and mode.
