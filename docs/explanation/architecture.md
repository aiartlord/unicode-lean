# Architecture

This project is three layers with a strict dependency direction. Understanding
the separation is the key to understanding everything else, because each layer
has a different purpose, a different audience, and a different deployment story.

```
  unicode            verified Unicode algorithms and their proofs   (Lean)
     ▲
     │  depends on
     │
  unicode security   the reference-monitor engine over those        (Lean)
     ▲                algorithms
     │  transliterated into
     │
  ports              the engine in sixteen runtime languages        (deployable)
```

## Layer 1 — `unicode`: the verified library

The `Unicode/` Lean development is a general, machine-checked implementation of
the Unicode Standard's algorithms: normalization under UAX #15, the
bidirectional algorithm under UAX #9, line, grapheme, word, and sentence
segmentation under UAX #14 and UAX #29, collation under UTS #10, IDNA under
UTS #46, the default identifier rule under UAX #31, PRECIS under RFC 8264 and
8265, Punycode under RFC 3492, the strict UTF-8, UTF-16, and UTF-32 codecs, BOM
detection, and noncharacter detection.

It is organized as several independent product roots over a shared normalization,
codec, and property base — `UnicodeSecurity`, `UnicodeIdna`, `UnicodeUca`,
`UnicodeUnihan`, `UnicodeSegmentationSpecs` — across three build tiers described
in [`../reference/build-tiers.md`](../reference/build-tiers.md): `Unicode` for the
runtime API, `UnicodeAssurance` for the proofs, and `UnicodeFullConformance` for
the official Unicode fixtures.

This layer is where correctness is established. Its output is proof, not a
deployed binary. The trust argument for it is stated in
[`tcb.md`](tcb.md).

## Layer 2 — `unicode security`: the reference monitor

`Unicode/Security/` builds a security engine on top of the verified algorithms.
Where the conformance modules pin algorithm correctness against published Unicode
test data, the security layer pins security verdicts against an adversarial threat
model that the Unicode Consortium places outside its own scope. The threat model
is documented in [`threat-model.md`](threat-model.md).

The engine is a per-message reference monitor with a fixed pipeline:

1. **Decode** — strict UTF-8, UTF-16, or UTF-32 validation; malformed input is
   rejected with a specific reason code and byte offset before anything else runs.
2. **Normalize** — profile-specific NFC or NFKC, exposing whether the payload
   changed and detecting instability and expansion hazards.
3. **Classify** — the twenty-seven detector families run over the decoded
   codepoints. Each returns a verdict; it classifies, it does not rewrite.
4. **Decide** — the caller's policy maps the classification to an action: allow,
   reject, quarantine, rewrite, or observe, selected by profile and mode.
5. **Explain** — every hazard carries a stable reason code, the matched family,
   severity, and positions.

The public entry point is `scan : Profile → Mode → List Nat → Verdict`, with
byte-level `scan_utf8` / `scan_utf16be|le` / `scan_utf32be|le` entry points that
decode first. The detectors, the verdict shape, and the reason-code namespace are
specified in [`../reference/detectors.md`](../../ports/DETECTOR_COVERAGE.md) and
the port contract in [`../reference/ports.md`](../reference/ports.md).

Each detector is an automaton over the message: `BidiControlBalance` is a depth
counter, `StreamSafeViolation` accumulates a non-starter run, the codecs are
byte-level decoders. `StreamSafeViolation` is load-bearing for deployment: the
UAX #15 Stream-Safe bound is the property that keeps per-message state bounded,
which is what lets the monitor run inline at volume.

## Layer 3 — `ports`: the deployable engine

`ports/` carries layer 2 into sixteen runtime languages: Rust, C++, Python, Go,
JVM, TypeScript, .NET, Swift, Zig, Haskell, Ruby, Lua, PHP, Elixir, Erlang, and
COBOL. Each port is a byte-faithful transliteration of the Lean-proven Rust
reference — the same algorithm, not an output-equivalent substitute — and each
carries its own test suite green under its own toolchain.

A port contains the reference monitor and only the Unicode substrate the monitor
needs: the codecs, noncharacter and identifier support, segmentation, and the
normalization, casing, and confusables tables the detectors read. A port does not
contain the broader algorithm library — no bidirectional algorithm, collation,
IDNA, PRECIS, or Punycode — and it does not contain the Lean proofs. The proofs
stay in layer 1 as the assurance behind the deployed code.

Each port is self-contained. It vendors its own digest-pinned copies of the UCD
tables it reads and builds and tests offline;
`scripts/check-port-self-contained.sh` enforces that no port depends on Lean
roots, another port, or repo-relative files at runtime. The shared reason-code
namespace, the verdict wire shape in `fixtures/security/verdict_contract.json`,
and the per-detector fixtures in `fixtures/security/detectors/` are the
cross-port compatibility contract: a reason code means the same thing in every
port, so one policy is portable across a polyglot fleet.

## Deployment model — the inline middle layer

The ports exist so the engine runs where untrusted text enters a system, as the
middle layer every message transits, not as a side query.

- **In-process** is the hot path. A router or service links its native port and
  scans raw inbound bytes at the trust boundary through a `scan_*` entry point.
  The verdict travels inline with the message; downstream stages trust the
  boundary and do not re-scan.
- **The `serve` sidecar** is the polyglot fallback. A service that cannot link a
  native port calls a local endpoint over TCP, a Unix socket, or newline-framed
  stdio. Operating it is described in [`../how-to/operate.md`](../how-to/operate.md).

Scale to data-center volume comes from the monitor being per-message and its state
per-connection: bounded message size, an ASCII-clear fast path that short-circuits
before the Unicode machinery, and horizontal sharding by connection across mesh
nodes. Determinism across ports means a message classifies identically wherever it
lands, so no route is a bypass. The remaining performance and integration work is
tracked in [`../ROADMAP.md`](../ROADMAP.md), and the wiring is described in
[`../how-to/integrate.md`](../how-to/integrate.md).
