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

  Reach is gated, not described: `scripts/check-fixture-coverage.py` fails the
  shared contract check unless every reason code in
  `fixtures/security/reason_codes.json` is fired by the fixtures several times,
  under several profiles, with spec-shaped positions, and
  `Unicode/Conformance/Security/CorpusDifferential.lean` (the native
  `corpus_differential` executable, run by `scripts/check-lean-replay.sh` in
  CI) replays the fixtures through the Lean `scan` so the recorded verdicts
  are held to the spec and not only to the reference that recorded them. Details and the divergences found
  are in [`../ports/DETECTOR_COVERAGE.md`](../ports/DETECTOR_COVERAGE.md).

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

## 10. Analytic table facts (proof-layer memory)

Twenty-four modules peak above 2 GB when elaborated, led by
`Generated.CaseFoldingTargetFacts` at 8.14 GB. The cost is the shape of the
generated classifiers, not the size of the data: `Generated.CaseFolding.isSource`
is a chain of roughly 640 `decide` range tests joined by `||`, and a disjunction
short-circuits only on `true`, so every proof that a codepoint is **not** a
source evaluates all 640 branches. Doing that for the table's ~1,700 target
codepoints in one `decide +kernel` retains about 1.1 million `Decidable`
instance terms.

`NatIntervalUnion` already states the alternative in its header — a table given
as `List (Nat × Nat)` discharges `memUnion cp table = false` through
`OutsideAll`, reflecting non-membership to per-interval order facts closed by
`omega`, with no decision procedure run over the codepoint space. Only
`Assurance.lean` consumes it; the generated classifiers were emitted as
flattened chains instead and cannot reach it.

- **Mechanism:** emit range tables rather than disjunction chains, so
  `isSource cp = memUnion cp sourceIntervals` with an `Ascending` fact proved
  once, and close the table facts through `memUnion_eq_false_of_gap` instead of
  evaluating the classifier per codepoint. Where a fact is already proven
  elsewhere, restate it as a term rather than re-deriving it — this took
  `CaseFoldCommutation` from 21.54 GB to about 1 GB with no new lemmas.
  A genuine data fact with no analytic route keeps `decide +kernel` and keeps
  its own file, so its peak composes with nothing.
- **Done when:** no module's recorded `peak_tree_rss_kb` exceeds a pinned
  budget, and a check enforces that budget from the per-module logs the staged
  runner already writes.

## 11. The conformance dossier (external review)

An external reviewer has set acceptance criteria for a conformance run against
release 17.0.0. Eight criteria, A1 to A8.

**They are a floor, not a description.** The criteria name five standards; the
tree implements fourteen. They name eight corpora; the tree closes ten
conformance suites and carries a twenty-seven-family security layer that has no
official Unicode test file at all, replicated across sixteen language runtimes
under a shared wire contract. Measured: 497 Lean modules, 3,555 theorems, eleven
module roots — `Bidi`, `Codec`, `Conformance`, `Generated`, `Idna`,
`Normalization`, `Precis`, `Security`, `Segmentation`, `Uca`, `Ucd`.

Standards carried, by citation count in the sources:

| standard | refs | in the criteria? |
|---|---|---|
| UTS #39 security mechanisms | 94 | no |
| UAX #15 normalization | 56 | A2 |
| UTS #46 IDNA | 55 | A4 |
| UAX #9 bidirectional | 54 | A1 |
| UTS #51 emoji | 41 | no |
| UAX #29 segmentation | 37 | A3 |
| UAX #44 character database | 30 | no |
| RFC 8264 PRECIS framework | 29 | no |
| RFC 5893 IDNA bidi rule | 29 | no |
| RFC 8265 PRECIS usernames | 27 | no |
| UTS #10 collation | 17 | no |
| RFC 5892 IDNA CONTEXTJ | 16 | no |
| UAX #14 line breaking | 15 | A3 |
| RFC 3629 UTF-8 | 12 | no |

Nine of the fourteen are outside the criteria entirely, including the
most-cited one. The status below is therefore an audit against a partial
external checklist, not against the repository's own surface; each row names
what was counted and how it is established.

| | criterion | status |
|---|---|---|
| A1 | BidiTest + BidiCharacterTest, 100%, zero skipped | **met** — 490,846 rows expanding to 770,241 cases, and 91,707 rows across three published columns, both folded during the build |
| A2 | NormalizationTest, 100%, zero skipped, four forms | **met** — 20,034 rows × NFC/NFD/NFKC/NFKD |
| A3 | four `auxiliary/` break tests, 100%, zero skipped | **met** — Grapheme 766 and Sentence 512 closed in the kernel over a drift-gated mirror; Word 1,944 and Line 19,338 folded during the build |
| A4 | IdnaTestV2, 100% or a scoped statement | **met** — 6,391 rows × toUnicode/toAsciiN/toAsciiT, comparing output, error flag and the bracketed status set |
| A5 | `CONFORMANCE-INPUTS.sha256` attached | **partial** — emitted to `dist/`, which is untracked, so it is not attachable from a clean checkout |
| A6 | skipped stated everywhere, zero on A1–A3 | **met for A1–A3**; the two collation corpora report 437,928 skipped pairs, honestly, and that is the one gap |
| A7 | `lake build` completes, log attached | **partial** — 448 of 448 modules, but the run carried `--allow-dirty-source`; a clean-tree run is what makes it evidence |
| A8 | `#print axioms` clean on the load-bearing theorems | **partial** — the footprint gate covers the audited closure, but the specific property A8 names does not exist yet; see below |

### The gap that matters more than the table

The reviewer's own caveat: conformance to UAX #9 is not the property
*"no string renders differently than it lexes."* The first says the algorithm is
implemented correctly; the second is the Trojan Source security property, and it
needs its own theorem.

`Unicode/TrojanSource.lean` implements the defense — `containsBidiFormatControl`,
`hasUnbalancedBidi`, `safeForCodeContext` — and carries seventeen theorems.
**Every one is a point vector**: `safe_ascii`, `reject_rlo`, `detect_lre`,
`balanced_lre_pdf`, `reject_latin_cyrillic_mix`. Not one is universally
quantified over inputs. The flagship claim rests on examples.

Four detector families have an all-inputs soundness module
(`BidiControlBalanceSound`, `RtlInjectionSound`, `WidthClassConfusionSound`,
`SkinToneVariationForgerySound`), carrying seventeen `∀ input` theorems between
them — bounded counts, depth accounting, stack consistency. That is the right
shape and it covers four of twenty-seven families.

- **Mechanism:** state and prove the Trojan Source property as a theorem over
  all inputs — at minimum that `safeForCodeContext cps = true` implies the
  bidi-control set is empty and the resolved display order agrees with logical
  order, discharged against `Unicode.Bidi.Algorithm` rather than against
  examples. Extend the `*Sound.lean` pattern to the remaining twenty-three
  families.
- **Done when:** the Trojan Source property is a `∀ cps` theorem whose
  `#print axioms` shows only `propext`, `Classical.choice`, `Quot.sound`, and
  A8 can name it.

### Smaller items the dossier surfaced

- **`intentional.txt` is absent.** The reviewer lists it under the UTS #39
  security data beside `confusables.txt` (6,565 rows), `IdentifierStatus.txt`
  (1,649) and `IdentifierType.txt` (5,104), all of which are present and pinned.
- **`CONFORMANCE-INPUTS.sha256` needs a tracked home**, not `dist/`.
- **Wall time and peak memory are not in the report.** The staged runner records
  `peak_tree_rss_kb` per module; the conformance report should carry both, since
  whether the run is CI-viable is itself a product fact.
- **No ICU comparison row.** The security drills reference ICU behaviour but no
  suite is run side by side.
- **Collation is the only non-zero skip.** 437,928 adjacent-pair assertions
  across the two `CollationTest_*_SHORT.txt` corpora, recorded honestly as
  skipped. Closing it is a fold, not a proof.
