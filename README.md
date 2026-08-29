# unicode-lean

Formally verified Unicode algorithms and a Unicode-level security detector
suite. The algorithms — normalization (UAX #15), the bidirectional algorithm
(UAX #9), line / grapheme / word / sentence segmentation (UAX #14, #29), the
collation algorithm (UTS #10), IDNA compatibility processing (UTS #46), the
default identifier rule (UAX #31), PRECIS identifier preparation (RFC 8264 /
8265), Punycode (RFC 3492), strict UTF-8 / UTF-16 / UTF-32 codecs, BOM
detection, and noncharacter detection — are machine-checked in Lean 4.33.1
against UCD 17.0.0 and UCA 17.0.0. On top of that proof base sits a security
layer of twenty-seven detectors for the Unicode-level attacks the standard's
own conformance scope declines to cover.

The Lean development is self-contained on Lean 4 core and kernel-checked end to
end. The security detectors are additionally shipped as sixteen independent
language ports so the same verdicts run wherever gateways, routers, agents, and
services do.

- **Assurance** lives in Lean (`Unicode/`) — the source of truth.
- **Deployment** lives in the ports (`ports/`) — sixteen native implementations,
  each checked against the Lean-proven behaviour.


## Algorithm pillars

| Pillar | Reference | Headline theorem |
|---|---|---|
| Normalization | UAX #15 | `Normalization.QuickCheckSoundnessTheorem.quickCheck_sound` — `isNFCQuickCheck cps = true → toNFC cps = cps` |
| Bidirectional Algorithm | UAX #9 | `Bidi.Algorithm.bidiParagraph` — P / X / W / N / I / L1 / L4 phases; full `BidiTest.txt` + `BidiCharacterTest.txt` conformance |
| Line / Grapheme / Word / Sentence breaks | UAX #14 / #29 | `Conformance.{LineBreak,GraphemeBreak,WordBreak,SentenceBreak}Test.all_pass` — every published row passes |
| Collation | UTS #10 (UCA 17.0) | `Conformance.CollationTest.{nonIgnorable,shifted}_conformance` — every adjacent pair in `CollationTest_*_SHORT.txt` orders correctly under both variable-handling policies |
| IDNA | UTS #46 | `Conformance.IdnaTestV2.{strict,all}_conformance` — 546/546 strict + 6389/6389 lenient against `IdnaTestV2.txt` |
| Identifiers | UAX #31 + UTS #39 | `Identifier.isDefaultIdentifier` (R1-D1) + `isAllowedIdentifier` (general security profile) |
| PRECIS | RFC 8264 / 8265 | `Precis.Preparation.precis_idempotent` — preparation pipeline is idempotent on its image |
| Confusables | UTS #39 §4 | `Confusables.areConfusable_trans` — confusable-skeleton equivalence relation |
| Punycode | RFC 3492 | `Idna.Punycode.{encode,decode}` — RFC §7.1 sample-string conformance |
| UTF-8 codec | RFC 3629 | `Codec.Utf8Roundtrip.decode_encode_codepoint` — closed-form per-codepoint roundtrip across every valid scalar codepoint |
| UTF-16 / UTF-32 codecs | UAX #44 §3 | `Codec.{Utf16,Utf32}.decodeOne{BE,LE}_encodeOne{BE,LE}` — closed-form per-codepoint roundtrip with surrogate-pair handling |
| BOM detection | UAX #41 | `Codec.Bom.detect` — UTF-8 / UTF-16 BE+LE / UTF-32 BE+LE precedence |
| Noncharacters | UAX #44 §5.6 | `Codec.Noncharacters.*` — exactly the 66 designated noncharacters, all in the valid scalar range |
| Security detectors | UTS #39 + UAX #9 / #15 (composed) + BIP-39 + RFC 8785 + UTS #51 | `Conformance.Security.<Family>Test.all_rows_pass` — every fixture row's verdict closes for each of the 27 detector families |


## The security layer

The `Unicode.Security.*` tree sits below the UAX / UTS conformance proof base.
Where the `Unicode.Conformance.*` modules pin *algorithm correctness* against
published Unicode test fixtures, the security layer pins *security verdicts*
against an adversarial threat model that the Unicode Consortium has explicitly
placed outside its scope (UTS #39 §5.4, §6).

A detector answers one question about a codepoint sequence — *does this input
carry a specific Unicode-level security hazard?* — and returns a verdict without
rewriting the text, so the caller decides whether to reject, quarantine, or
flag. Each of the twenty-seven families ships three artefacts:

1. A detector module under `Unicode/Security/<Layer>/<Family>.lean` exporting
   `detect : List Nat → Verdict`. The verdict carries the input, a
   `Classification` (`clear` or one-or-more `hazard` sub-threats), positions,
   and optional per-family metadata.
2. A hand-curated fixture under `Unicode/Ucd/Security/<Family>Test.txt` in the
   universal five-column format documented in `Unicode/Security/Fixture.lean`.
3. A conformance harness under `Unicode/Conformance/Security/<Family>Test.lean`
   that folds the fixture and closes `theorem all_rows_pass : rows.all verifyRow
   = true`, plus row-count and per-section coverage gates.

### The 27 detectors

Grouped by the concern each guards, which is also the reason-code layer. The
full reference — what each detector catches, what it reports, and how to call it
— is [`ports/DETECTOR_COVERAGE.md`](ports/DETECTOR_COVERAGE.md); the threat
model is in [`docs/explanation/threat-model.md`](docs/explanation/threat-model.md).

- **Covert channels** (`unicode.security.C.*`) — TagBlockPayload,
  VariationSelectorPayload, ZeroWidthPayload, SurrogateReassembly,
  BidiControlBalance, NoncharacterControl.
- **Identity spoofing** (`unicode.security.I.*`) — HomoglyphConfusable,
  MixedScriptAdmissibility, EmojiZwjIntegrity, SkinToneVariationForgery.
- **Display integrity** (`unicode.security.D.*`) — SourceDisplayDivergence,
  FilenameDisguise, RtlInjection, RendererDivergence.
- **Form stability** (`unicode.security.F.*`) — NormalizationBomb,
  StreamSafeViolation, LocaleCaseInversion, CaseExpansionMismatch,
  WidthClassConfusion, NfcIdempotenceWitness.
- **Cross-layer boundary** (`unicode.security.X.*`) — IdentifierFormDrift,
  AdmissibilityFormDrift, CovertDisplayCompound, ConfusableBidiCompound.
- **Cryptographic stability** (`unicode.security.K.*`) — Bip39Canonical,
  HashInputStability, AiWatermarkDetectability.

Every hazard maps to a stable reason code, `unicode.security.<layer>.<slug>.<SubThreat>`,
identical across every port, so a policy expressed in reason codes is portable.

### Shared vocabulary

The vocabulary lives in `Unicode/Security/Calculus.lean` and is mirrored by
every port:

- `ClassificationKind` — `clear` · `hazard` · `compound` · `informational`.
- `ConformanceLevel` — `basic` · `strict` · `full`.
- `KeyValueAttribution` — the per-row attribution dictionary parsed from column 4
  of the fixture format.

A consumer that wants every detector's verdict on an input imports
`Unicode.Security`, or the equivalent port module, and folds over the families
it cares about; the per-family modules are exposed under stable namespaces so
individual detectors can be wired into custom pipelines. Callers that want a
single admission predicate — "is this input acceptable at the declared
strictness?" — use `Unicode.Security.Level`, which defines three totally-ordered
levels (`restrictive ⊑ moderate ⊑ minimal`) and `admissibleAt : Level → List
Nat → Bool`. No level suppresses a hazard; every detector still runs, and the
level only answers whether the input meets the context's bar.

### Region-agnosticism

The detectors fire on hazardous codepoints unconditionally, regardless of which
source region — code, string literal, or comment — a language tokenizer would assign
them to. The threat model treats source bytes as uniformly suspect: real
incidents — the tj-actions/changed-files supply-chain attack (March 2025),
CVE-2025-29927 Next.js middleware bypass, prompt injection through docstring
comments, and npm-metadata-string backdoors — show that where a parser places
bytes does not change whether they are an attack surface.


## The sixteen ports

Every detector is implemented in all sixteen ports, each a byte-faithful
transliteration of the Lean-proven Rust reference — the same algorithm, not an
output-equivalent substitute — and each backed by its own test suite in its own
toolchain. Coverage is complete: 27 families × 16 ports.

| Port | Path | Deployment target |
|---|---|---|
| Rust | `ports/rust/` | production services, agents, gateway daemons, C ABI |
| C++ | `ports/cpp/` | routers, native gateways, embedded, language FFI |
| Python | `ports/python/` | operator tooling, integration, fixtures |
| Go | `ports/go/` | cloud-native gateways, service meshes, Kubernetes |
| JVM (Java) | `ports/jvm/` | JVM services, Android, enterprise identity |
| TypeScript | `ports/typescript/` | browser, edge workers, dashboards, dev tools |
| .NET (C#) | `ports/dotnet/` | Windows gateway agents, enterprise servers |
| Swift | `ports/swift/` | Apple clients, local-device filtering |
| Zig | `ports/zig/` | static edge binaries, router/appliance |
| Haskell | `ports/haskell/` | functional reference, high-assurance peer |
| Ruby | `ports/ruby/` | Rails and Ruby web services |
| Lua | `ports/lua/` | NGINX / OpenResty gateway filtering |
| PHP | `ports/php/` | PHP web stack, CMS/plugin integration |
| Elixir | `ports/elixir/` | telecom, resilient control planes |
| Erlang | `ports/erlang/` | telecom, distributed control planes |
| COBOL | `ports/cobol/` | mainframe / banking integration |

Each port is self-contained: it vendors its own digest-pinned copies of the UCD
tables it needs and builds and tests offline. `scripts/check-port-self-contained.sh`
enforces that no port depends on Lean roots, another port, or repo-relative
files at runtime. The shared reason-code namespace, the verdict wire shape
(`fixtures/security/verdict_contract.json`), and the per-detector fixtures
(`fixtures/security/detectors/*.json`) are the cross-port compatibility contract;
[`docs/reference/ports.md`](docs/reference/ports.md) documents that contract in full.


## Running it

### Ports

Every port builds and runs its test suite as part of its Nix build:

```bash
nix build .#unicode-rust      .#unicode-python  .#unicode-cpp    .#unicode-go
nix build .#unicode-jvm       .#unicode-ts      .#unicode-dotnet .#unicode-swift
nix build .#unicode-zig       .#unicode-haskell .#unicode-ruby   .#unicode-lua
nix build .#unicode-php       .#unicode-elixir  .#unicode-erlang .#unicode-cobol
```

A green `nix build .#unicode-<lang>` is the authoritative correctness signal for
a port on its pinned toolchain. For native-toolchain and per-detector commands,
see [`ports/DETECTOR_COVERAGE.md`](ports/DETECTOR_COVERAGE.md); for the
runtime-package workflow, see [`docs/how-to/build.md`](docs/how-to/build.md).

The default product workflow is runtime-only and does not build Lean:

```bash
nix develop .#runtime -c scripts/build-runtime.sh
nix develop .#runtime -c scripts/test-runtime-ports.sh --smoke
nix develop .#runtime -c scripts/package-runtime.sh
```

### Lean assurance

The Lean proof base is the opt-in evidence workflow. Do not use a broad
cold-cache Lean build as the default validation path; use the staged cache plan
in [`docs/how-to/build.md`](docs/how-to/build.md). `nix run` prints the live file / theorem
inventory.


## Repository layout

```
unicode-lean/
├── flake.nix                    # nix integration + per-port build outputs
├── lakefile.lean                # lake config
├── lean-toolchain               # pinned Lean version (4.33.1)
├── Unicode.lean                 # root import
├── Unicode/
│   ├── Bidi/Algorithm.lean      # UAX #9
│   ├── Codec/                   # UTF-8 / UTF-16 / UTF-32 codecs, BOM, noncharacters
│   ├── Confusables.lean         # UTS #39 §4
│   ├── Conformance/             # CollationTest / IdnaTestV2 / Bidi*Test / *BreakTest
│   ├── Generated/               # UCD- and UCA-derived tables (self-contained)
│   ├── Identifier.lean          # UAX #31 + UTS #39 general security profile
│   ├── Idna/                    # UTS #46 (Map / Punycode / CheckJoiners / Process)
│   ├── Normalization/           # NFC / NFKC / NFD / NFKD + soundness kernel
│   ├── Precis/                  # RFC 8264 / 8265
│   ├── Security/                # 27 detector families across Covert / Identity /
│   │                            #   Display / Form / Boundary / Crypto; per-family
│   │                            #   fixtures under Ucd/Security/ with SHA256SUMS
│   ├── Segmentation/            # UAX #14 line breaks, UAX #29 grapheme/word/sentence
│   ├── Uca/                     # UTS #10 collation — Lookup + SortKey
│   └── Ucd/                     # UCD 17.0.0 + UCA 17.0.0 source data + SHA256SUMS
├── ports/                       # 16 language ports + DETECTOR_COVERAGE.md
├── fixtures/security/           # shared cross-port contract fixtures
├── docs/                        # runbook, ports contract, CLI, deployment, specs
├── scripts/                     # CI hardening + runtime packaging
└── .github/                     # CI workflows + governance
```


## Generated tables — provenance

Every file under `Unicode/Generated/` is self-contained and auditable end to end
without any external code generator. The pattern is identical across all
generated tables:

1. The UCD source file, such as `Unicode/Ucd/CaseFolding.txt`, is byte-pinned in
   `Unicode/Ucd/SHA256SUMS` and verified by `scripts/check-ucd-hashes.sh`.
2. A Lean parser for that file's grammar lives **inline** in the generated
   module — `parseHex`, `parseRange`, `parse<Row>`, etc.
3. The raw `.txt` is embedded via `include_str "../Ucd/<file>.txt"`.
4. The typed table is computed by running the inline parser over the embedded
   string at module load.

There is no separate code-generation step and no external tool: the parser, the
input bytes, and the resulting typed data live in the same file and are verified
together by the build. To audit how a table was derived, open the corresponding
`Unicode/Generated/*.lean` file. The ports follow the same discipline with their
vendored copies, pinned per port with `SHA256SUMS` manifests and refreshed only
through `scripts/sync-runtime-data.sh`.


## Use it from another Lake project

Pin to a tagged release in your `lakefile.lean`:

```lean
require unicode from git
  "https://github.com/aiartlord/unicode-lean" @ "v1.0.0"
```

Then `lake update` and import the namespaces you need:

```lean
import Unicode

-- or pin to specific modules
import Unicode.Normalization.QuickCheckSoundnessTheorem
import Unicode.Uca.SortKey
import Unicode.Idna.Process
import Unicode.Security
```

Each tagged release reflects a state where every committed theorem closes and
every port's test suite is green, so downstream projects can bump their pin
deliberately rather than tracking moving `main`.


## License

Apache License 2.0. See [`LICENSE`](LICENSE).

The bundled UCD 17.0.0 source files under `Unicode/Ucd/` (and the vendored port
copies) are redistributed under the
[Unicode License v3](https://www.unicode.org/license.txt); see [`NOTICE`](NOTICE)
for attribution.
