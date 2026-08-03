# Unicode security detectors — reference and port coverage

This directory holds sixteen independent language ports of the Unicode security
detector suite. Every port implements the same twenty-seven detectors, each a
byte-faithful transliteration of the Lean-proven Rust reference under
`ports/rust/`, and each backed by its own test suite in its own toolchain.

A **detector** answers one question about a codepoint sequence: *does this input
carry a specific Unicode-level security hazard?* The detectors do not sanitise or
rewrite text — they classify it, so a caller can decide whether to reject,
quarantine, or flag. The algorithms are proven correct in Lean; `Unicode/Security/` in the repository
root is the source of truth. The ports carry that behaviour into production
languages without re-deriving it.

This document is the reference for what each detector is, what a detector result
contains, and how to build and run the detectors in each port. The coverage
matrix at the end records which detectors are implemented and vouched per port.


## What a detector result contains

Every detector exposes a single entry point, `detect`, that takes the input as a
sequence of Unicode scalar values (`u32` / `Int` / `[]rune` / … depending on the
port) and returns a **verdict**. A verdict is made of:

- **`classification`** — either `Clear` when nothing fires, or `Hazard`. The shared
  vocabulary lives in each port's `Calculus`/`calculus` module as
  `ClassificationKind` = `Clear` · `Hazard` · `Compound` · `Informational`.
- **`sub_threat`** — when a hazard fires, which specific variant it is. Each
  detector defines its own closed set of sub-threats (for example
  `CaseExpansionMismatch` distinguishes `UpperExpansion` from `LowerExpansion`).
- **`positions`** — the indices in the input at which the hazard occurs, where
  the detector localises a hazard to specific codepoints. Whole-string detectors,
  which judge the input as a unit, carry an empty position list.
- Detector-specific metadata — for example the decoded payload a covert channel
  reconstructs, or the two admissibility verdicts a drift detector compares.

Every hazard maps to a stable **reason code** of the form

```
unicode.security.<layer>.<slug>.<SubThreat>
```

where `<layer>` is a single letter grouping the detector by the concern it
guards, `<slug>` is the detector's kebab-case name, and `<SubThreat>` is the
exact sub-threat tag. Reason codes are part of the public contract: they are
identical across all sixteen ports, so a policy expressed in reason codes is
portable. The layer letter reads as `C` for covert channel, `I` for identity,
`D` for display, `F` for form and normalization, `X` for cross-layer boundary,
and `K` for cryptographic stability.

Most detectors are **standalone**: a caller invokes `detect` directly. A subset
is additionally wired into a port's default `scan`, which runs the routine
default-policy detectors over an input and collects every reason code. The
aggregators and the crypto-context detectors are deliberately *not* in the
default scan — they are invoked explicitly by callers that want them.


## The twenty-seven detectors

The groupings below are by concern, matching the reason-code layer. Each entry
gives the reason-code prefix, the threat it catches, and what it reports.

### Covert-channel detectors — `unicode.security.C.*`

Hidden information smuggled through a codepoint stream that looks innocuous when
rendered.

- **TagBlockPayload** (`tag-block-payload`) — Tag characters (U+E0000–U+E007F)
  encode an invisible ASCII payload alongside visible text. Reports the decoded
  payload string and the tag positions.
- **VariationSelectorPayload** (`variation-selector-payload`) — Variation
  selectors (U+FE00–U+FE0F and U+E0100–U+E01EF) used as a data channel rather
  than to select a glyph variant. Reports the reconstructed bytes and positions.
- **ZeroWidthPayload** (`zero-width-payload`) — Runs of zero-width characters
  (ZWSP, ZWNJ, ZWJ, zero-width no-break space) carrying steganographic bits.
  Reports the payload and positions.
- **SurrogateReassembly** (`surrogate-reassembly`) — Lone or mis-paired
  surrogate code units that reassemble into scalars the visible text never
  showed. Reports the offending positions.
- **BidiControlBalance** (`bidi-control-balance`) — Unbalanced bidirectional
  formatting controls (RLO/LRO/RLE/LRE/PDF and the isolates RLI/LRI/FSI/PDI):
  the "Trojan Source" class, where reordering controls make source read
  differently from how it executes. Reports the unbalanced positions.
- **NoncharacterControl** (`noncharacter-control`) — Noncharacters
  (U+FDD0–U+FDEF and the two per-plane U+_FFFE/U+_FFFF) and disallowed C0/C1
  control characters appearing in text. Reports the positions.

### Identity-spoofing detectors — `unicode.security.I.*`

Text engineered to be mistaken for a different, trusted identity.

- **HomoglyphConfusable** (`homoglyph-confusable`) — Look-alike substitution
  using the UTS #39 confusables mapping (for example Cyrillic *е* U+0435 for
  Latin *e*). Reports the confusable positions.
- **MixedScriptAdmissibility** (`mixed-script-admissibility`) — Identifiers that
  mix scripts in ways the UTS #39 restriction levels disallow. Reports the
  offending run.
- **EmojiZwjIntegrity** (`emoji-zwj-integrity`) — Malformed or forged emoji
  ZWJ sequences whose joins do not correspond to a well-formed sequence.
- **SkinToneVariationForgery** (`skin-tone-variation-forgery`) — Skin-tone
  modifiers attached where the base does not admit them, or used to forge a
  distinct-looking sequence.

### Display-integrity detectors — `unicode.security.D.*`

What a reviewer sees diverging from what a machine reads.

- **SourceDisplayDivergence** (`source-display-divergence`) — The aggregate
  "rendered source differs from logical content" detector. It runs the five
  constituents TagBlockPayload, VariationSelectorPayload, ZeroWidthPayload,
  BidiControlBalance, and HomoglyphConfusable over the same input; zero firing is
  clear, exactly one passes that family's tag through, and two or more report
  `Compound`.
- **FilenameDisguise** (`filename-disguise`) — Filenames whose apparent
  extension is disguised via bidi or homoglyph tricks (for example an executable
  presented as a document).
- **RtlInjection** (`rtl-injection`) — Right-to-left override injection that
  visually reorders a string.
- **RendererDivergence** (`renderer-divergence`) — Text that renders differently
  across conforming renderers, so no single rendering is authoritative.

### Form-stability detectors — `unicode.security.F.*`

Hazards that arise from normalization and case behaviour.

- **NormalizationBomb** (`normalization-bomb`) — Input that expands
  disproportionately under a normalization form, a denial-of-service surface.
- **StreamSafeViolation** (`stream-safe-violation`) — Violations of the UAX #15
  Stream-Safe Text Format, that is, over-long non-starter sequences.
- **LocaleCaseInversion** (`locale-case-inversion`) — Locale-sensitive case
  mappings (Turkish/Azeri dotted-*i*, Lithuanian) that change meaning under a
  different locale.
- **CaseExpansionMismatch** (`case-expansion-mismatch`) — Codepoints whose case
  mapping changes length, for example *ß* → *SS* and *ﬃ* → *FFI*. Distinguishes
  `UpperExpansion` from `LowerExpansion` and reports the base position and
  expansion length.
- **WidthClassConfusion** (`width-class-confusion`) — Half-width / full-width
  confusion under East Asian Width.
- **NfcIdempotenceWitness** (`nfc-idempotence-witness`) — Witnesses inputs where
  a naive normalization pass is not stable, i.e. re-normalizing changes the
  result.

### Cross-layer boundary detectors — `unicode.security.X.*`

Hazards visible only when two layers are considered together.

- **IdentifierFormDrift** (`identifier-form-drift`) — An identifier whose
  admissibility changes when it is normalized, so acceptance depends on which
  form a consumer applies.
- **AdmissibilityFormDrift** (`admissibility-form-drift`) — Fires when the
  UTS #39 allowed-identifier verdict differs between the input and its NFKC form:
  `is_allowed_identifier(input) ≠ is_allowed_identifier(toNFKC(input))`. A
  whole-string verdict carrying both admissibility booleans.
- **CovertDisplayCompound** (`covert-display-compound`) — A compound signal
  combining a covert channel with a display-integrity hazard.
- **ConfusableBidiCompound** (`confusable-bidi-compound`) — A compound signal
  combining a confusable substitution with a bidi hazard.

### Cryptographic-stability detectors — `unicode.security.K.*`

Unicode representation drift that changes a cryptographic input. These run in an
explicit crypto context, not the default scan.

- **Bip39Canonical** (`bip39-canonical`) — Non-canonical encodings of a BIP-39
  mnemonic under NFKD and wordlist canonicalisation that would recover a different
  wallet than the one displayed.
- **HashInputStability** (`hash-input-stability`) — Representation differences
  that leave a string visually identical but change its bytes, and therefore any
  hash, signature, or audit-trail digest computed over it.
- **AiWatermarkDetectability** (`ai-watermark-detectability`) — Character-level
  watermark / steganographic patterns of the kind used to tag machine-generated
  text.


## How to run the detectors

Each port is self-contained: it bundles its own copy of the Unicode Character
Database tables it needs (digest-pinned and checked against the repository-root
copies by `scripts/check-port-self-contained.sh`) and builds and tests offline.

### Reproducible build and test via Nix

Every port has a flake output that builds it and runs its test suite as part of
the build (`doCheck`):

```bash
nix build .#unicode-rust      .#unicode-python  .#unicode-cpp   .#unicode-go
nix build .#unicode-jvm       .#unicode-ts      .#unicode-dotnet .#unicode-swift
nix build .#unicode-zig       .#unicode-haskell .#unicode-ruby  .#unicode-lua
nix build .#unicode-php       .#unicode-elixir  .#unicode-erlang .#unicode-cobol
```

A green `nix build .#unicode-<lang>` is the authoritative signal that a port is
correct on the pinned toolchain: it compiles the port and runs its contract
tests, including the shared detector fixtures.

### Native toolchain commands

For local iteration, each port also runs directly under its native toolchain.
The commands below assume the port's directory as the working directory.

| Port | Build + test |
|---|---|
| rust | `cargo test` |
| python | `PYTHONPATH=src pytest` |
| cpp | `cmake -S . -B build -G Ninja -DUNICODE_CPP_BUILD_TESTS=ON && cmake --build build && ctest --test-dir build` |
| go | `go test ./...` |
| jvm | `scripts/test.sh` (JDK) |
| ts | `node --test` |
| dotnet | `dotnet run --project test/UnicodeSecurity.Tests` |
| swift | `nix build .#unicode-swift` (pinned Swift 5.10.1; the bundled toolchain is required) |
| zig | `zig build test` |
| haskell | `nix build .#unicode-haskell` (GHC 9.12) |
| ruby | `ruby -Ilib -Itest test/<name>_test.rb`, or the port's `scripts/test.sh` |
| lua | `scripts/test.sh` (Lua 5.4) |
| php | `php test/<name>_test.php` |
| elixir | `scripts/test.sh` (`mix test`) |
| erlang | `scripts/test.sh` |
| cobol | `scripts/test.sh` (GnuCOBOL) |

### Calling a detector

The shape is the same in every port: decode input to scalar values, call the
detector, branch on the classification. In Rust:

```rust
use unicode_security::security::covert::bidi_control_balance;

let input: Vec<u32> = "…".chars().map(|c| c as u32).collect();
let verdict = bidi_control_balance::detect(&input);
if verdict.classify.kind != ClassificationKind::Clear {
    // reason code: unicode.security.C.bidi-control-balance.<SubThreat>
    reject(verdict);
}
```

To run the routine default-policy detectors in one pass and collect every reason
code, call the port's `scan`; to run a standalone detector (an aggregator such as
`SourceDisplayDivergence`, or a crypto-context detector such as `Bip39Canonical`),
call its `detect` directly.


## Coverage matrix — Unicode security families × language ports

All twenty-seven Lean-proven detector families are implemented and vouched in all
sixteen ports. A cell is "done" only when the detector is implemented
byte-faithfully **and** vouched — built, with its ground-truth vectors run, not
merely compiled. Coverage is counted from real detector implementations
cross-checked against the shared detector fixtures, never from an enum entry or a
fixture file: the `Family`/`Calculus` enums in every port declare family names as
taxonomy independent of whether a detector exists, and support modules without a
`detect` — GlitchTokenScan, WordlistOrder, EmojiPresentationRegistry — are not
detector families and are not counted.

Legend: `✓` implemented + vouched.

| Family (Lean module) | rust | python | cpp | go | jvm | ts | dotnet | swift | zig | haskell | ruby | lua | php | elixir | erlang | cobol |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| TagBlockPayload | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| VariationSelectorPayload | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| ZeroWidthPayload | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| SurrogateReassembly | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| BidiControlBalance | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| NoncharacterControl | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| HomoglyphConfusable | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| MixedScriptAdmissibility | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| EmojiZwjIntegrity | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| SkinToneVariationForgery | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| SourceDisplayDivergence | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| FilenameDisguise | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| RtlInjection | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| RendererDivergence | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| NormalizationBomb | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| StreamSafeViolation | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| LocaleCaseInversion | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| CaseExpansionMismatch | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| WidthClassConfusion | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| NfcIdempotenceWitness | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| IdentifierFormDrift | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| AdmissibilityFormDrift | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| CovertDisplayCompound | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| ConfusableBidiCompound | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Bip39Canonical | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| HashInputStability | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| AiWatermarkDetectability | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

**Totals:** every port 27/27 · overall 432/432. Each cell is a native detector —
the same algorithm as the Lean-proven Rust reference, not an output-equivalent
substitute — with its own test suite green under that port's toolchain.

The one detail below full uniformity: cobol's HomoglyphConfusable uses a bounded
target-skeleton iteration; deepening that bound is a refinement of an
implemented, fixture-passing detector, not a coverage gap.


## Provenance

The detectors are transliterations of the Lean specification under
`Unicode/Security/` in the repository root, which proves every family's verdict
against hand-curated fixtures and CVE-derived vectors. The Rust port is the
reference the other fifteen are checked against; the shared fixtures under
`fixtures/security/detectors/` are the common ground truth every port drives its
tests from. See the repository-root `README.md` for the assurance model and the
Lean proof base, and `docs/explanation/threat-model.md` for the threat model.
