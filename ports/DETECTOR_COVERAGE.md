# Detector coverage matrix — Unicode security families × language ports

Tracks which of the 27 Lean-proven security-detector families are implemented in
each vouched language port. The Lean spec under `Unicode/Security/` is the
source of truth and all 27 families are proven there; a port cell is "done" only
when the detector is implemented byte-faithfully **and** vouched (built + its
ground-truth vectors run, not merely compiled).

> The 27 families are the detectors that export `detect` (see README §"The 27
> detectors"). Support modules without a `detect` (GlitchTokenScan, WordlistOrder,
> EmojiPresentationRegistry) are not detector families and are not counted here.
>
> Accuracy note: the `Family`/`Calculus` enums in every port declare family names
> as taxonomy independent of whether a detector exists. Coverage below is counted
> from real detector implementations (a detect function/file emitting the family's
> sub-threats, cross-checked against the shared detector fixtures), never from an
> enum entry or a fixture file.

Legend: `✓` implemented + vouched · `–` not yet ported (Lean spec exists)

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
| RtlInjection | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| ConfusableBidiCompound | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| CovertDisplayCompound | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| WidthClassConfusion | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Bip39Canonical | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| SourceDisplayDivergence | ✓ | – | – | – | – | – | – | – | – | – | – | – | – | – | – | – |
| LocaleCaseInversion | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| CaseExpansionMismatch | – | – | – | – | – | – | – | – | – | – | – | – | – | – | – | – |
| NfcIdempotenceWitness | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| NormalizationBomb | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| StreamSafeViolation | – | – | – | – | – | – | – | – | – | – | – | – | – | – | – | – |
| IdentifierFormDrift | – | – | – | – | – | – | – | – | – | – | – | – | – | – | – | – |
| AdmissibilityFormDrift | – | – | – | – | – | – | – | – | – | – | – | – | – | – | – | – |
| EmojiZwjIntegrity | – | – | – | – | – | – | – | – | – | – | – | – | – | – | – | – |
| SkinToneVariationForgery | – | – | – | – | – | – | – | – | – | – | – | – | – | – | – | – |
| FilenameDisguise | – | – | – | – | – | – | – | – | – | – | – | – | – | – | – | – |
| RendererDivergence | – | – | – | – | – | – | – | – | – | – | – | – | – | – | – | – |
| HashInputStability | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| AiWatermarkDetectability | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

**Totals:** rust 19/27 · all other vouched ports 18/27 · overall 289/432
cells. The 13 core families plus LocaleCaseInversion, NormalizationBomb,
NfcIdempotenceWitness, HashInputStability, and AiWatermarkDetectability are complete and vouched across
every listed port; everything below the line is spec-proven in Lean but not
yet ported.

## Interrupted new-port inventory

The following language-family ports exist in the worktree but are **not** counted
in the matrix until their source, policy wiring, and native fixture tests are
complete. Many of these directories already contain copied `testdata/fixtures`;
fixture presence is not coverage.

| Port | Current source state | Counted? | Next completion target |
|---|---|:--:|---|
| ruby | Vouched at the 16/27 non-Rust baseline: native policy/decode/verdict fixture tests, shared detector fixture tests, form-detector vectors, Bip39Canonical vectors, vendored-data parity pass, and `nix build .#unicode-ruby`. | yes | Continue only with fixture-backed detector fan-out; do not count copied fixtures as coverage. |
| lua | Vouched at the 16/27 non-Rust baseline: native policy/decode/verdict fixture tests, shared detector fixture tests, form-detector vectors, Bip39Canonical vectors, vendored-data parity pass, and `nix build .#unicode-lua`. | yes | Continue only with fixture-backed detector fan-out; do not count copied fixtures as coverage. |
| php | Vouched at the 16/27 non-Rust baseline: native policy/decode/verdict fixture tests, shared detector fixture tests, form-detector vectors, Bip39Canonical vectors, vendored-data parity pass, and `nix build .#unicode-php`. | yes | Continue only with fixture-backed detector fan-out; do not count copied fixtures as coverage. |
| elixir | Vouched at the 16/27 non-Rust baseline: native policy/decode/verdict fixture tests, shared detector fixture tests, form-detector vectors, Bip39Canonical vectors, vendored-data parity pass, and `nix build .#unicode-elixir`. | yes | Continue only with fixture-backed detector fan-out; do not count copied fixtures as coverage. |
| erlang | Vouched at the 16/27 non-Rust baseline: native policy/decode/verdict fixture tests, shared detector fixture tests, form-detector vectors, Bip39Canonical vectors, vendored-data parity pass, and `nix build .#unicode-erlang`. | yes | Continue only with fixture-backed detector fan-out; do not count copied fixtures as coverage. |
| cobol | Native GnuCOBOL scanner, UTF-8/UTF-16/UTF-32 decode checks, shared detector/policy/verdict fixture harness, form vectors, Bip39Canonical vectors, vendored-data parity pass, and `nix build .#unicode-cobol`. Variation-pair, Default_Ignorable, Scripts, DerivedBidiClass, confusable-source, BIP39 wordlist, and emoji membership lookups are generated from vendored data. Normalization is now a full general NFC engine (DECOMPOSE → REORDER → COMPOSE from UnicodeData/CompositionExclusions), added with HashInputStability. Counted at the same fixture-vouched 17/27 baseline as the other new ports. | yes | Deepen the homoglyph target-skeleton iteration to remove its remaining bound; this is a refinement, not a fixture-coverage gap. |

## Remaining work

9 detector families are unported. Each needs a reference implementation verified
against the Lean `detect_*` theorems, then a fan-out to all listed ports, each
vouched.

**Reference-only (1):** SourceDisplayDivergence
(`display/source_display_divergence.rs`) — rust reference exists and is vouched;
needs fan-out to the other 15 listed ports.

**Not started in any port (8):** CaseExpansionMismatch, StreamSafeViolation,
IdentifierFormDrift, AdmissibilityFormDrift, EmojiZwjIntegrity,
SkinToneVariationForgery, FilenameDisguise, RendererDivergence.

**Bip39 scan-wiring (follow-up):** Bip39Canonical ships standalone and
crypto-context-gated in all listed ports; it is deliberately not part of the default
sweep. Wiring it behind a crypto-context gate in each port's `scan`, plus a shared
`fixtures/security/detectors/bip39_canonical.json`, remains outstanding.

## Casing keystone (already landed)

`toLower` (UAX #21) is implemented and vouched in all listed ports — the shared
primitive LocaleCaseInversion and CaseExpansionMismatch build on. Those two
families skip the "build the casing dependency" step and go straight to the
divergence-scan detector.

## Method (proven on rtl-injection, surrogate-reassembly, bip39, casing, locale-case-inversion)

1. Write the reference implementation (Rust first) against the Lean `detect_*`
   theorems; confirm every spot-check vector.
2. Transliterate to each remaining port, pinning the identical vectors; keep the
   port's existing detector conventions (result struct, sub-threat tag strings,
   module wiring).
3. Vouch each port by building and running its tests — `nix build .#unicode-<lang>`
   for the ports whose derivation tests (go/jvm/dotnet/zig/swift/haskell), or
   `cargo test` / `ctest` / native runners (rust/cpp/python/ts) — never
   "compiled, therefore done".
4. Flip this matrix cell to `✓` only after the vouch passes.

## Suggested order

Fan out the two casing-dependent families that already have rust references
(LocaleCaseInversion, then CaseExpansionMismatch once its reference lands) while
the casing keystone is fresh, then proceed through the remaining families by
dependency depth: the pure-scan detectors (StreamSafeViolation, HashInputStability,
FilenameDisguise, RendererDivergence) before the ones that need new tables
(EmojiZwjIntegrity, SkinToneVariationForgery) or heavier normalization machinery
(NormalizationBomb, NfcIdempotenceWitness, AdmissibilityFormDrift,
IdentifierFormDrift, AiWatermarkDetectability).
