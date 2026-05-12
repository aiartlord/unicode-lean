# unicode-lean

Unicode standard's algorithms — normalization (UAX #15), the
bidirectional algorithm (UAX #9), line / grapheme / word /
sentence segmentation (UAX #14, #29), the collation algorithm
(UTS #10), IDNA compatibility processing (UTS #46), the default
identifier rule (UAX #31), PRECIS identifier preparation
(RFC 8264 / 8265), Punycode (RFC 3492), strict UTF-8 / UTF-16 /
UTF-32 codecs, BOM detection, and noncharacter detection —
machine-checked in Lean 4.28.0 against UCD 17.0.0 (UCA 16.0.0
where the UCA shipped behind UCD). Lean core only — no Mathlib,
no external dependencies. Zero `sorry`, zero `admit`, zero
project-local `axiom`, zero runtime escape.

## Pillars

| Pillar | Reference | Headline theorem |
|---|---|---|
| Normalization | UAX #15 | `Normalization.QuickCheckSoundnessTheorem.quickCheck_sound` — `isNFCQuickCheck cps = true → toNFC cps = cps` |
| Bidirectional Algorithm | UAX #9 | `Bidi.Algorithm.bidiParagraph` — P / X / W / N / I / L1 / L4 phases; full `BidiTest.txt` + `BidiCharacterTest.txt` conformance |
| Line / Grapheme / Word / Sentence breaks | UAX #14 / #29 | `Conformance.{LineBreak,GraphemeBreak,WordBreak,SentenceBreak}Test.all_pass` — every published row passes |
| Collation | UTS #10 (UCA 16.0) | `Conformance.CollationTest.{nonIgnorable,shifted}_conformance` — every adjacent pair in `CollationTest_*_SHORT.txt` orders correctly under both variable-handling policies |
| IDNA | UTS #46 | `Conformance.IdnaTestV2.{strict,all}_conformance` — 546/546 strict + 6389/6389 lenient against `IdnaTestV2.txt` |
| Identifiers | UAX #31 + UTS #39 | `Identifier.isDefaultIdentifier` (R1-D1) + `isAllowedIdentifier` (general security profile) |
| PRECIS | RFC 8264 / 8265 | `Precis.Preparation.precis_idempotent` — preparation pipeline is idempotent on its image |
| Confusables | UTS #39 §4 | `Confusables.areConfusable_trans` — confusable-skeleton equivalence relation |
| Punycode | RFC 3492 | `Idna.Punycode.{encode,decode}` — RFC §7.1 sample-string conformance |
| UTF-8 codec | RFC 3629 | `Codec.Utf8Roundtrip.decode_encode_codepoint` — closed-form per-codepoint roundtrip across every valid scalar codepoint |
| UTF-16 / UTF-32 codecs | UAX #44 §3 | `Codec.{Utf16,Utf32}.decodeOne{BE,LE}_encodeOne{BE,LE}` — closed-form per-codepoint roundtrip with surrogate-pair handling |
| BOM detection | UAX #41 | `Codec.Bom.detect` — UTF-8 / UTF-16 BE+LE / UTF-32 BE+LE precedence |
| Noncharacters | UAX #44 §5.6 | `Codec.Noncharacters.{count_noncharacters,all_are_noncharacters,all_are_valid_codepoints}` — exactly the 66 designated noncharacters, all in the valid scalar range |
| Security Conformance Layer | UTS #39 + UAX #9 + UAX #15 (composed) | `Conformance.Security.<Family>Test.all_rows_pass` — every hand-curated fixture row's verdict closes for each of the 23 detector families |

## Workflow

```bash
nix develop          # dev shell with the pinned Lean toolchain
nix build            # full library; cold rebuilds elaborate every native_decide table
nix run              # status report — file / theorem / sorry counts, per pillar
nix flake check      # build + zero-sorry / zero-admit guard
```

Or with `lake` directly inside the dev shell:

```bash
lake build
lake build Unicode.Normalization.QuickCheckSoundnessTheorem
```

## Layout

```
unicode-lean/
├── flake.nix                    # nix integration
├── lakefile.lean                # lake config
├── lean-toolchain               # pinned Lean version
├── Unicode.lean                 # root import
├── Unicode/
│   ├── Bidi/Algorithm.lean      # UAX #9
│   ├── CaseFoldCommutation.lean # UAX #15 + UAX #44 §5.18
│   ├── CaseFoldRoundtrip.lean
│   ├── Codec/                   # UTF-8 / UTF-16 / UTF-32 codecs, BOM, noncharacters
│   ├── Confusables.lean         # UTS #39 §4
│   ├── Conformance/             # CollationTest / IdnaTestV2 / Bidi*Test / *BreakTest
│   ├── Generated/               # 25 files — UCD- and UCA-derived tables
│   ├── Identifier.lean          # UAX #31 + UTS #39 general security profile
│   ├── Idna/                    # UTS #46 (Map/Punycode/CheckJoiners/Process)
│   ├── Invariants.lean
│   ├── Normalization/           # 29 files — NFC/NFKC/NFD/NFKD + soundness kernel
│   ├── Precis/                  # 8 files — RFC 8264 / 8265
│   ├── Refined.lean
│   ├── Security/                # Security Conformance Layer — 23 detector
│   │                            #   families across Covert / Identity / Display /
│   │                            #   Form / Boundary; per-family fixtures under
│   │                            #   Ucd/Security/ with their own SHA256SUMS
│   ├── Segmentation/            # UAX #14 line breaks, UAX #29 grapheme/word/sentence
│   ├── Uca/                     # UTS #10 collation — Lookup + SortKey
│   └── Ucd/                     # UCD 17.0.0 + UCA 16.0.0 source data + SHA256SUMS
├── scripts/                     # CI hardening (see Guarantees)
└── .github/                     # CI workflows + governance
```

`nix run` prints the live file / theorem inventory.

## Guarantees

* **Zero `sorry`, zero `admit`** — proven, not assumed.
* **Zero project-local `axiom`** — only Lean 4 core's `propext`,
  `Quot.sound`, and `Classical.choice` are in the trusted base.
* **Zero runtime escape** — no `unsafe`, `unsafePerformIO`,
  `unsafeCast`, `Lean.ofReduceBool`, or `Lean.reduceBool`.
* **Zero Mathlib dependency** — Lean 4 core only; auditable from
  first principles.
* **Pinned UCD source** — UCD 17.0.0 files vendored under
  `Unicode/Ucd/` and SHA-256-pinned in `Unicode/Ucd/SHA256SUMS`.
  `include_str` embeds the bytes at build time; CI rejects drift.
* **`autoImplicit := false`** — explicit universes, explicit types,
  no implicit-argument inference at type-class boundaries.
* **Reproducible** — back-to-back `lake build` runs produce
  byte-identical `.olean` files. The nightly `reproducibility`
  workflow verifies this and publishes the SHA-256 manifest as an
  `oleans-sha256-<commit-sha>` build artifact for downstream
  auditors.

The four source-level guards (`check-sorry.sh`, `check-no-axiom.sh`,
`check-orphan-files.sh`, `check-ucd-hashes.sh`) live under `scripts/`
and run on every push and pull request via the `ci / hardening`
workflow.  Two additional guards specific to the Security
Conformance Layer (`check-security-coverage.sh`,
`check-security-hashes.sh`) verify that every detector module has a
paired fixture-driven harness and that every fixture matches its
SHA-256 pin.  `security-perf-report.sh` produces the per-family
build-time wall clock.

## Security Conformance Layer

The `Unicode.Security.*` tree sits below the UAX / UTS conformance
proof base.  Where the existing `Unicode.Conformance.*` modules pin
*algorithm correctness* against published Unicode test fixtures, the
Security layer pins *security verdicts* against an adversarial threat
model that the Unicode Consortium has declined to extend its scope to
cover (UTS #39 §5.4, §6).

Every family ships three artefacts:

1. A detector module under `Unicode/Security/<Layer>/<Family>.lean`
   that exports `detect : Array Nat → <Family>Verdict`.  The verdict
   carries the input, a `<Family>Classification` (a sum of `clear`
   and one or more `hazard` sub-threats), and optional per-family
   metadata.
2. A hand-curated fixture under `Unicode/Ucd/Security/<Family>Test.txt`
   in the universal five-column format documented in
   `Unicode/Security/Fixture.lean`.
3. A conformance harness under
   `Unicode/Conformance/Security/<Family>Test.lean` that folds the
   universal fixture parser and closes
   `theorem all_rows_pass : rows.all verifyRow = true` via
   `native_decide`, plus row-count and per-section coverage gates.

The 23 families ship across five layers:

| Layer | Families |
|---|---|
| 1 — Covert Channels | C1 TagBlockPayload · C2 VariationSelectorPayload · C3 ZeroWidthPayload · C4 SurrogateReassembly · C5 BidiControlBalance |
| 2 — Identity Spoofing | I1 HomoglyphConfusable · I2 MixedScriptAdmissibility · I3 EmojiZwjIntegrity · I4 SkinToneVariationForgery |
| 3 — Display Integrity | D1 SourceDisplayDivergence · D2 FilenameDisguise · D3 RtlInjection · D4 RendererDivergence |
| 4 — Form Stability | F1 NormalizationBomb · F2 StreamSafeViolation · F3 LocaleCaseInversion · F4 CaseExpansionMismatch · F5 WidthClassConfusion · F6 NfcIdempotenceWitness |
| 5 — Cross-Layer Boundaries | X1 IdentifierFormDrift · X2 CovertDisplayCompound · X3 ConfusableBidiCompound · X4 AdmissibilityFormDrift |

Layer 6 (Cryptographic Stability — K1..K3) is reserved.  The
opaque-axiomatized hash foundation it would build on lives upstream
in the `Continuity.Crypto` vocabulary; integrating it cross-repo is
deferred.

The shared vocabulary lives in `Unicode/Security/Calculus.lean`:

* `ClassificationKind` — `clear` · `hazard` · `compound` · `informational`.
* `ConformanceLevel`   — `basic` · `strict` · `full`.
* `KeyValueAttribution` — the per-row attribution dictionary parsed
  from column 4 of the fixture format.

A downstream consumer that wants every detector's verdict on a
single input imports `Unicode.Security` and folds over the families
it cares about; the per-family modules are exposed under stable
namespaces so individual detectors can be wired into custom
pipelines.

## Generated tables — provenance

Every file under `Unicode/Generated/` is self-contained and
auditable end-to-end without reference to any external code
generator. The pattern, identical across all 19 generated tables:

1. The corresponding UCD source file (e.g. `Unicode/Ucd/CaseFolding.txt`)
   is byte-pinned in `Unicode/Ucd/SHA256SUMS` and verified by
   `scripts/check-ucd-hashes.sh`.
2. A Lean parser for that file's grammar lives **inline** in the
   Generated module — `parseHex`, `parseRange`, `parse<Row>`, etc.
3. The raw `.txt` is embedded into the module via
   `include_str "../Ucd/<file>.txt"`, producing a `String` constant
   at compile time.
4. The typed table (`mappings`, `ranges`, etc.) is computed by
   running the inline parser over the embedded raw string at module
   load.

There is no separate code-generation step, no external tool, no
pre-commit hook that emits the tables — the parser, the input
bytes, and the resulting typed data all live in the same file and
are verified together by the build. To audit how a given table was
derived, open the corresponding `Unicode/Generated/*.lean` file.

## Use it from another Lake project

Pin to a tagged release in your `lakefile.lean`:

```lean
require unicode from git
  "https://github.com/jpyxal-straylight/unicode-lean" @ "v0.11.0"
```

Then `lake update` and import the namespaces you need:

```lean
import Unicode

-- or pin to specific modules
import Unicode.Normalization.QuickCheckSoundnessTheorem
import Unicode.Uca.SortKey
import Unicode.Idna.Process
```

Each tagged release reflects a state where every committed
theorem closes; downstream projects can bump their pin
deliberately rather than tracking moving `main`.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).

The bundled UCD 17.0.0 source files under `Unicode/Ucd/` are
redistributed under the
[Unicode License v3](https://www.unicode.org/license.txt); see
[`NOTICE`](NOTICE) for attribution.
