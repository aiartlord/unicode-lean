# Detector coverage matrix — Unicode security families × language ports

Tracks which of the 27 Lean-proven security-detector families are implemented in
each of the 10 language ports. The Lean spec under `Unicode/Security/` is the
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

| Family (Lean module) | rust | python | cpp | go | jvm | ts | dotnet | swift | zig | haskell |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| TagBlockPayload | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| VariationSelectorPayload | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| ZeroWidthPayload | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| SurrogateReassembly | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| BidiControlBalance | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| NoncharacterControl | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| HomoglyphConfusable | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| MixedScriptAdmissibility | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| RtlInjection | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| ConfusableBidiCompound | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| CovertDisplayCompound | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| WidthClassConfusion | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Bip39Canonical | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| SourceDisplayDivergence | ✓ | – | – | – | – | – | – | – | – | – |
| LocaleCaseInversion | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| CaseExpansionMismatch | – | – | – | – | – | – | – | – | – | – |
| NfcIdempotenceWitness | ✓ | – | – | – | – | – | – | – | – | – |
| NormalizationBomb | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| StreamSafeViolation | – | – | – | – | – | – | – | – | – | – |
| IdentifierFormDrift | – | – | – | – | – | – | – | – | – | – |
| AdmissibilityFormDrift | – | – | – | – | – | – | – | – | – | – |
| EmojiZwjIntegrity | – | – | – | – | – | – | – | – | – | – |
| SkinToneVariationForgery | – | – | – | – | – | – | – | – | – | – |
| FilenameDisguise | – | – | – | – | – | – | – | – | – | – |
| RendererDivergence | – | – | – | – | – | – | – | – | – | – |
| HashInputStability | – | – | – | – | – | – | – | – | – | – |
| AiWatermarkDetectability | – | – | – | – | – | – | – | – | – | – |

**Totals:** rust 16/27 · all other ports 15/27 · overall 151/270 cells. The 13
core families plus LocaleCaseInversion and NormalizationBomb are complete and
vouched across every port; everything below the line is spec-proven in Lean but
not yet ported.

## Remaining work

12 detector families are unported. Each needs a reference implementation verified
against the Lean `detect_*` theorems, then a fan-out to all ten ports, each vouched.

**Reference-only (1):** SourceDisplayDivergence
(`display/source_display_divergence.rs`) — rust reference exists and is vouched;
needs fan-out to the other nine ports.

**Not started in any port (11):** CaseExpansionMismatch, NfcIdempotenceWitness,
StreamSafeViolation, IdentifierFormDrift, AdmissibilityFormDrift,
EmojiZwjIntegrity, SkinToneVariationForgery, FilenameDisguise, RendererDivergence,
HashInputStability, AiWatermarkDetectability.

**Bip39 scan-wiring (follow-up):** Bip39Canonical ships standalone and
crypto-context-gated in all ten ports; it is deliberately not part of the default
sweep. Wiring it behind a crypto-context gate in each port's `scan`, plus a shared
`fixtures/security/detectors/bip39_canonical.json`, remains outstanding.

## Casing keystone (already landed)

`toLower` (UAX #21) is implemented and vouched in all ten ports — the shared
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
