# Changelog

All notable changes to `unicode-lean` are recorded here.  Each
released version is a tag in `git tag -l`; releases follow
semantic versioning at the level of headline-theorem signatures
on the public surface (a major-version bump signals that a
theorem name or statement changed in a way downstream consumers
might depend on).

## v0.10.0 — 2026-05-11

The "harness depth" release.  v0.9.0 shipped the 23-family
Security Conformance Layer with one row-pass theorem per family
checking classification + sub-threat + positions.  v0.10.0
deepens every harness's assertion surface and the fixture row
volume it folds against, plus fixes two detector flaws surfaced
by that deeper scrutiny.

### Fixed — detector reachability + position semantics

- **I1 `CrossScriptMix` reachability**.  The sub-threat was
  structurally unreachable in v0.9.0: `crossScriptCount` was
  computed off `Unicode.Restriction.stringResolvedScripts`, the
  UTS #39 §5.1.2 intersection-based primitive (Latin ∩ Cyrillic
  = ∅ ⇒ size 0 ⇒ `sc ≥ 2` never trips).  Introduces a
  union-side companion `stringScriptUnion` in
  `Unicode.Restriction` and routes `crossScriptCount` through
  it.  Inputs that previously fell through to RestrictionLow
  because intersection-size was 0 now correctly trip
  CrossScriptMix when union-size ≥ 2.  Verdict surface
  unchanged; behavioural delta is a new sub-threat now firing
  on appropriate inputs.

- **C5 `DepthExceeded` position semantics**.  Previously
  projected `bidiPositions` (every bidi control encountered)
  into the hazard's positions array — for a 126-cap-exceedance
  this was a 126-entry firehose with no diagnostic value.  The
  stack-of-stacks is the problem, not any single codepoint, so
  DepthExceeded is now a whole-string verdict with `positions =
  #[]`, mirroring the X4 AdmissibilityFormDrift convention.
  Callers that want the bidi-event firehose still get it via
  `v.bidiPositions` on the C5Verdict struct.

### Added — verdict-metadata gates

Every Security harness whose Verdict carries Nat / Bool / String
metadata fields (counters, lengths, restriction levels,
admissibility flags) now folds a `metadataMatches` predicate
into `verifyRow`, validating those fields against fixture
column-4 attribution — not just classification + sub-threat +
positions.  21 of 23 families gated; the remaining 2 (F3
LocaleCaseInversion, X2 CovertDisplayCompound) are classify-only
by Verdict structure.

`Unicode.Security.Calculus.KeyValueAttribution` gains three
shared helpers (`checkNatKey`, `checkStringKey`, `checkBoolKey`)
all with lenient-on-missing / strict-on-present semantics so
fixture column-4 can be populated incrementally without ever
breaking the row-pass theorem.

A reusable, idempotent script
`scripts/internal/populate_security_metadata.lean` regenerates
column 4 from detector output whenever any of the 13 newly-gated
detectors changes shape — re-running on a fully-populated
fixture is a no-op.

### Added — fixture row expansion

Every Security fixture expanded with CVE-anchored / incident-
anchored cases.  Aggregate: ~580 rows across 24 harnesses, up
from ~340.  Per-family deltas (selected):

- C5 BidiControlBalance: 18 → 27 rows; adds Boucher-Anderson
  CVE-2021-42574 stretched-string payload, CVE-2021-42694
  isolate variant, UAX #9 §3.3.2 depth-cap exceedance.
- I1 HomoglyphConfusable: 16 → 41 rows; every sub-threat now
  reachable and exercised (was 3 of 6); adds DecompositionSwap,
  CrossScriptMix (newly reachable), RestrictionLow sections;
  6 new Cyrillic-substitution typosquats (ethereum, openai,
  google, claude, github, react), 3 new MathAlpha witnesses,
  2 new WidthClass.
- F1 NormalizationBomb: 11 → 26 rows; adds 8 Greek-polytonic
  NfdHighExpansion witnesses covering every triple-diacritic
  base letter; pinned 300% strict-`>` boundary case via
  vulgar-fraction trio.
- D1 SourceDisplayDivergence: 16 → 32 rows; every inner-tag
  variant of all 5 constituent layers (C1, C2, C3, C5, I1) now
  exercised.
- C2 VariationSelectorPayload: 17 → 30 rows; adds typical
  GlassWorm 4-byte chunk size, bare-leading-VS payloads,
  trailing-VS edge cases.
- D2 FilenameDisguise: 15 → 27 rows; adds LRO override variant,
  FSI + PDI isolate, photo<RLO>gpj.exe Trojan, multi-combining
  stack in extension.
- D1-Tokenized (region-aware): 11 → 20 rows; pins TargetMatch's
  whole-string region-filter bypass via dedicated row +
  inline-comment documentation.

The CrossScriptMix reachability fix lifted the I1
`covers_cross_script_mix ≥ 7` gate from 0 (previously absent)
into the harness; the DepthExceeded fix added `covers_depth_
exceeded ≥ 1` to C5.

### Documentation

- Each family's `docs/specs/security/per-family/<F>.md` retained
  unchanged in shape (still 23 files) — the row expansion is
  documented through the fixture-comment surface, which is the
  primary spec discoverability layer.

## v0.9.0 — 2026-05-11

### Added — Security Conformance Layer

The big addition.  A new namespace `Unicode.Security` adjacent
to (and below) the existing UAX / UTS conformance proof base.
Where the existing `Unicode.Conformance.*` modules pin
*algorithm correctness* against published Unicode test fixtures,
the Security layer pins *security verdicts* against an
adversarial threat model that the Unicode Consortium has
declined to extend its scope to cover (UTS #39 §5.4, §6).

23 detector families across five layers, each shipping as a
triple of detector module, hand-curated fixture, and
`native_decide`-closed conformance harness:

- **Layer 1 — Covert Channels (5)**: `C1 TagBlockPayload`,
  `C2 VariationSelectorPayload` (GlassWorm), `C3 ZeroWidthPayload`,
  `C4 SurrogateReassembly`, `C5 BidiControlBalance`.
- **Layer 2 — Identity Spoofing (4)**: `I1 HomoglyphConfusable`
  (Nethereum), `I2 MixedScriptAdmissibility`,
  `I3 EmojiZwjIntegrity`, `I4 SkinToneVariationForgery`.
- **Layer 3 — Display Integrity (4)**: `D1 SourceDisplayDivergence`
  (v1 language-agnostic), `D2 FilenameDisguise`, `D3 RtlInjection`,
  `D4 RendererDivergence`.
- **Layer 4 — Form Stability (6)**: `F1 NormalizationBomb`,
  `F2 StreamSafeViolation`, `F3 LocaleCaseInversion`,
  `F4 CaseExpansionMismatch`, `F5 WidthClassConfusion`,
  `F6 NfcIdempotenceWitness`.
- **Layer 5 — Cross-Layer Boundaries (4)**: `X1 IdentifierFormDrift`,
  `X2 CovertDisplayCompound`, `X3 ConfusableBidiCompound`,
  `X4 AdmissibilityFormDrift`.

Layer 6 (Cryptographic Stability — K1..K3) is reserved.  The
opaque-axiomatized hash foundation it would build on lives in
the `Continuity.Crypto` vocabulary upstream; cross-repo
integration is deferred.

Shared vocabulary in `Unicode/Security/Calculus.lean`:
`ClassificationKind ∈ {clear, hazard, compound, informational}`,
`ConformanceLevel ∈ {basic, strict, full}`, `KeyValueAttribution`
for fixture column-4 metadata.  Every family refines the
calculus into its own `<F>SubThreat`, `<F>Classification`,
`<F>Verdict` types and emits `detect : Array Nat → <F>Verdict`.

### Added — `Unicode.Security.RunAll` aggregator

Single-call entry point that runs every Security detector on
one input and returns a flat `Array FamilyResult`.  Helpers:
`hazardsOnly`, `anyHazard`.  Shape invariants proved by
`native_decide`: `runAll_size = 23`, per-layer counts pinned.

### Added — pre-staged data tables

- `Unicode.Generated.BIP39` (10 wordlists × 2,048 words each,
  pinned in `Unicode/Ucd/BIP39/SHA256SUMS`).  Aggregate module
  with `Language` enum and `every_wordlist_2048` invariant.
- `Unicode.Generated.KnownAttackTargets` (48 entries drawn
  from documented typosquat / homoglyph incidents).
- `Unicode.Generated.WatermarkSchemes` (3 schemes with a fixed
  `CueClass` inductive vocabulary).
- `Unicode.Generated.GlitchTokens` (39 entries from the
  SolidGoldMagikarp catalog and DALL-E text-encoder catalog).

These tables have no current detector consumer; they are
pre-staging for I1 expansions, future X-family compositions,
and the deferred Layer-6 K1 / K3 families.

### Added — new gate scripts wired into CI

- `scripts/check-security-coverage.sh` — every detector module
  has a paired `*Test.lean` harness closing `all_rows_pass`.
- `scripts/check-security-hashes.sh` — every Security fixture
  matches its SHA-256 pin in `Unicode/Ucd/Security/SHA256SUMS`.
- `scripts/check-bip39-hashes.sh` — every BIP-39 wordlist
  matches its SHA-256 pin.
- `scripts/check-curated-hashes.sh` — every curated baseline
  file matches its SHA-256 pin.
- `scripts/security-perf-report.sh` — per-family build-time
  wall clock for the Security harnesses (~95 s cold total,
  dominated by `HomoglyphConfusableTest` and
  `SourceDisplayDivergenceTest` which fold against the full
  confusables skeleton table).

All four hash gates and the coverage gate run on every push
via the `hardening` job in `.github/workflows/ci.yml`.

### Documentation

- README adds a Security Conformance Layer pillar row to the
  pillars table, a Security entry under Layout, a Security
  section enumerating the 23 families across five layers, and
  references the new gate scripts under Guarantees.
- SECURITY.md adds the Security fixture manifest to the
  trusted-artifact list, extends the security-relevant-defect
  examples with the two new failure modes (fixture drift,
  missing harness), and adds a layer-by-layer Security
  Conformance Layer threat-model section.

## v0.8.0 — 2026-05-10

UAX #9 `BidiTest` strict conformance proven (490,846 / 490,846
rows pass `native_decide`).  Single-theorem `all_rows_pass`
covers level + L1/L2 reorder across every paragraph-level
setting.

## v0.7.1 — 2026-05-09

Strict UTS #46 IDNA conformance reduced to a single
machine-checked theorem `strict_conformance : rows.all
verifyRow = true := by native_decide`.

## v0.7.0 — 2026-05-09

UTS #46 IDNA: 100 % strict conformance against `IdnaTestV2.txt`
(UCD 17.0) — 6,389 / 6,389 rows pass.  19,167 strict equality
checks across rows × three pipelines × {output, hasErrors}.

## v0.6.0 — 2026-05-08

UAX #50 Vertical Text Layout (`Unicode.Vertical`), UAX #38
Unihan database (`Unicode.Unihan`), UTS #10 UCA tailoring,
UAX #44 §5.10 property and property-value alias resolution,
and a follow-on IDNA V6 fix.

## v0.5.0 — 2026-05-08

InputBoundary / defensive ontology release.  New modules
include `Unicode.Width` (UAX #11 East Asian Width), refined
codec helpers, and a wider noncharacter / control-character
defensive surface.

## v0.4.1 — 2026-05-08

Fixes UTS #46 §4.1 V2 hyphen-at-positions-3+4 check.  Removes
the `xn--` prefix exemption that incorrectly allowed
maliciously-chained inputs whose Punycode decoding lands on
ASCII hyphens at positions 3+4.

## v0.4.0 — 2026-05-07

Breaking change: UTS #46 IDNA `toUnicode` / `toAscii` /
`toAsciiTransitional` return `Map.Result` (output + hasErrors)
rather than `Option (Array Nat)`.  Each IDNA entry point gains
an optional `Options` argument exposing the five UTS #46 input
flags (`CheckHyphens`, `CheckBidi`, `CheckJoiners`,
`UseSTD3ASCIIRules`, `VerifyDnsLength`) with strict defaults.

## v0.3.1 — 2026-05-04

Dedupe `ForbiddenCategory` between `Codec.Printable` and
`Codec.Strict`.

## v0.3.0 — 2026-05-03

Spec-core text-codec predicates and refinement types
(`Unicode.Codec.OpaqueBlob`, `Codec.Printable`,
`Codec.Identifier`).

## v0.2.2 — 2026-05-03

`Utf8Roundtrip` §5–§8 building blocks.

## v0.2.1 — 2026-05-03

Programmatic UCD digest manifest at `Unicode.UCD`.

## v0.2.0 — 2026-05-03

UCA, IDNA, identifiers, codecs.

## v0.1.0 — 2026-04-27

Initial release.
