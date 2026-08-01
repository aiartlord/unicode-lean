# Detector coverage matrix — Unicode security families × language ports

Tracks which of the 30 Lean-proven security-detector families are implemented
in each of the 10 language ports. The Lean spec under `Unicode/Security/` is the
source of truth; each port cell is "done" only when the detector is implemented
byte-faithfully **and** vouched (built + its ground-truth vectors run, not merely
compiled).

Legend: `✓` implemented + vouched · `–` not yet ported

| Family (Lean module) | rust | python | cpp | go | jvm | ts | dotnet | swift | zig | haskell |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| TagBlockPayload | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| ZeroWidthPayload | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| VariationSelectorPayload | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| BidiControlBalance | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| NoncharacterControl | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| SurrogateReassembly | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| HomoglyphConfusable | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| MixedScriptAdmissibility | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| RtlInjection | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| ConfusableBidiCompound | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| CovertDisplayCompound | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| WidthClassConfusion | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Bip39Canonical | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| SourceDisplayDivergence | ✓ | ✓ | ✓ | – | – | – | – | – | – | – |
| LocaleCaseInversion | ✓ | ✓ | ✓ | – | – | – | – | – | – | – |
| CaseExpansionMismatch | ✓ | ✓ | ✓ | – | – | – | – | – | – | – |
| NfcIdempotenceWitness | ✓ | ✓ | ✓ | – | – | – | – | – | – | – |
| NormalizationBomb | ✓ | ✓ | ✓ | – | – | – | – | – | – | – |
| IdentifierFormDrift | ✓ | ✓ | ✓ | – | – | – | – | – | – | – |
| AdmissibilityFormDrift | ✓ | ✓ | ✓ | – | – | – | – | – | – | – |
| EmojiZwjIntegrity | ✓ | ✓ | ✓ | – | – | – | – | – | – | – |
| SkinToneVariationForgery | ✓ | ✓ | ✓ | – | – | – | – | – | – | – |
| FilenameDisguise | ✓ | ✓ | ✓ | – | – | – | – | – | – | – |
| RendererDivergence | ✓ | ✓ | ✓ | – | – | – | – | – | – | – |
| HashInputStability | ✓ | ✓ | ✓ | – | – | – | – | – | – | – |
| StreamSafeViolation | ✓ | ✓ | ✓ | – | – | – | – | – | – | – |
| AiWatermarkDetectability | ✓ | ✓ | ✓ | – | – | – | – | – | – | – |
| GlitchTokenScan | – | – | – | – | – | – | – | – | – | – |
| WordlistOrder | – | – | – | – | – | – | – | – | – | – |
| EmojiPresentationRegistry | – | – | – | – | – | – | – | – | – | – |

**Totals:** rust/python/cpp 27/30 · go/jvm/ts/dotnet/swift/zig/haskell 13/30 ·
overall 164/300 cells.

## The three remaining tiers of work

1. **Fan-out (14 families → 7 ports each = 98 cells).** These live in the
   reference trio (rust/python/cpp) but not the other seven ports. The Rust
   implementation is the reference; each port transliterates it and pins the
   same Lean ground-truth vectors. Casing-dependent families
   (LocaleCaseInversion, CaseExpansionMismatch) build on the `toLower`/`toUpper`
   keystone already present in all ten ports.

2. **Net-new (3 families → 10 ports each = 30 cells).** GlitchTokenScan,
   WordlistOrder, and EmojiPresentationRegistry are not yet in any port. Each
   needs the Rust reference written + verified against the Lean spec first, then
   fanned out.

3. **Bip39 scan-wiring (follow-up).** Bip39Canonical ships as a standalone,
   crypto-context-gated detector in all ten ports; it is deliberately **not**
   part of the default sweep. Wiring it behind a crypto-context gate in each
   port's `scan`, plus a shared `fixtures/security/detectors/bip39_canonical.json`,
   remains outstanding.

## Method (proven on rtl-injection, surrogate-reassembly, bip39, casing)

1. Write/confirm the Rust reference against the Lean `detect_*` theorems.
2. Transliterate to each remaining port, pinning the identical spot-check
   vectors; keep the port's existing detector conventions (result struct,
   sub-threat tag strings, module wiring).
3. Vouch each port by building and running its tests — `nix build .#unicode-<lang>`
   where the derivation tests (go/jvm/dotnet/zig/swift/haskell), or `cargo test` /
   `ctest` / native runners (rust/cpp/python/ts) — never "compiled, therefore
   done".
4. Update this matrix cell to `✓` only after the vouch passes.

## Suggested next order (hardest → easiest within the fan-out tier)

AiWatermarkDetectability → NormalizationBomb → AdmissibilityFormDrift →
IdentifierFormDrift → NfcIdempotenceWitness → EmojiZwjIntegrity →
SkinToneVariationForgery → SourceDisplayDivergence → FilenameDisguise →
RendererDivergence → HashInputStability → StreamSafeViolation →
LocaleCaseInversion → CaseExpansionMismatch (the last two reuse the casing
keystone directly).
