# Changelog

All notable changes to `unicode-lean` are recorded here.  Each
released version is a tag in `git tag -l`; releases follow
semantic versioning at the level of headline-theorem signatures
on the public surface (a major-version bump signals that a
theorem name or statement changed in a way downstream consumers
might depend on).

## v0.13.0 — 2026-05-12

The "K1 BIP-39 canonical form" release.  First family in
Layer 6 — Cryptographic Stability.  Moves the Security
Conformance Layer from 23 to 24 of the 26 planned families.

### Added — Layer 6, family K1

- `Unicode.Security.Crypto.Bip39Canonical` detector module.
  Implements the BIP-39 canonical-form check: input is passed
  through `NFKD → toLower (default locale) → collapse U+0020
  + U+3000 whitespace runs → trim leading/trailing U+0020`,
  then each canonical word is looked up against the ten
  pinned BIP-39 wordlists in `Unicode.Generated.BIP39`.
- Seven K1 sub-threats, fired in priority order:
  `trailingWhitespace`, `mixedCase`, `whitespaceAnomaly`,
  `nonNFKD`, `wordlistMismatch`, `languageAmbiguous`,
  `nonCanonicalForm` (catch-all).
- `Unicode/Ucd/Security/Bip39CanonicalTest.txt` — 20 hand-
  curated rows across 9 sections (Clear for English, Spanish,
  Italian, French, Czech, Portuguese, Japanese; hazards for
  NFC-instead-of-NFKD, FB01 ligature, NBSP, U+3000 separator,
  trailing/leading/double whitespace, title/all-caps,
  nonsense, mixed real+nonsense, Spanish-Italian collision).
- `Unicode.Conformance.Security.Bip39CanonicalTest` —
  `theorem all_rows_pass : rows.all verifyRow = true := by
  native_decide` plus per-section coverage gates.

### Threat model

A user types a BIP-39 recovery mnemonic; if the typed bytes
are not in NFKD form and the wallet hashes the bytes directly,
the derived seed differs from the seed produced by canonical
input.  Wallet recovery silently fails or derives a different
wallet.  K1 is the witness that an input satisfies BIP-39's
canonical-form contract.

### Behaviour — RunAll aggregator

- `Unicode.Security.RunAll.runAll` now returns 24 entries; K1
  is the 24th, at layer 6.
- `runAll_size` theorem bumped 23 → 24.
- `runAll_layer_6_count = 1` added.
- The pure-ASCII baseline theorem was reformulated:
  `ascii_hello_no_hazards` → `ascii_hello_no_unicode_hazards`
  filtered to `layer ≤ 5`.  K1 (correctly) fires `mixedCase`
  on the capital H in "Hello"; the renamed theorem makes
  explicit that the baseline is "no Unicode-layer detector
  fires", not "no detector fires anywhere".

### Behaviour — Level admission predicate (BREAKING CHANGE)

- `admissibleAt` now takes a `CryptoContext` parameter:
  ```
  def admissibleAt
    (level : Level) (cryptoCtx : CryptoContext) (input : Array Nat) : Bool
  ```
  The `CryptoContext` inductive has two constructors at v0.13.0:
  `nonCrypto` (general Unicode admission; K-family ignored) and
  `bip39Mnemonic` (adds K1 to the effective rejection set).  K2
  / K3 will extend the enum when those families ship.
- Existing callers must pass `.nonCrypto` to preserve v0.12.0
  semantics: `admissibleAt .restrictive #[..]` → `admissibleAt
  .restrictive .nonCrypto #[..]`.
- Rationale (per `L6-cryptographic-stability.md`): K-family is
  highly context-dependent — applicable only when the input is
  declared as a crypto-shaped input.  Without the context
  parameter, callers had two bad options: include K1 in
  rejection sets (constant-rejects general Unicode input that
  isn't BIP-39 vocabulary) OR silently exclude K1 (footgun for
  callers actually verifying mnemonics).  The parameter makes
  the choice explicit at the call site.
- The seven existing monotonicity theorems (`monotone_ascii_hello`,
  `monotone_lone_rlo`, `monotone_nethereum`,
  `monotone_math_italic_admin`, `monotone_greek_polytonic`,
  `monotone_fdfa`, `monotone_modified_utf8_nul`,
  `monotone_mixed_high_codepoint`) all close unchanged after
  threading `.nonCrypto` through.
- Two new theorems pin the context-gating behaviour:
  `crypto_ctx_gates_mixed_case` shows "Hello" admits under
  `nonCrypto` but rejects under `bip39Mnemonic` (K1's
  `mixedCase` fires on the capital H);
  `crypto_ctx_single_word_passes_both` shows that a single
  canonical-form BIP-39 word "abandon" admits under both
  contexts.
- File-level `set_option maxHeartbeats 4000000` added to
  `Level.lean` — `native_decide` on `admissibleAt` now
  elaborates against K1's 10 × 2,048-word wordlist tables,
  pushing isDefEq past the default heartbeat budget.

### Module / fixture / harness counts (post-K1)

- 24 detector modules (23 Unicode + 1 K-family).
- 24 conformance harnesses.
- 24 SHA-pinned base fixtures.

Coverage and hash gates report clean at these counts.  The
`scripts/check-security-coverage.sh` find list now includes
`Unicode/Security/Crypto/`.

### Documentation

- README updated: family count bumped 23 → 24; the Layer table
  gains a Layer-6 row showing K1 shipped; the Layer-6 reserved
  paragraph rewritten to "K1 shipped; K2 / K3 reserved".
- Internal docs under `docs/specs/security/` (gitignored
  planning materials) gain a per-family K1 spec doc and the
  Phase 0 checkbox flips for K1.

## v0.12.0 — 2026-05-11

The "v1.5 retraction" release.  Removes the entire language-aware
region-filtering surface added in v0.11.0 because it embedded a
threat-model error that the broader ecosystem evidence
contradicts.

### Threat-model correction

v0.11.0 introduced a `Language` parameter on D1 / D3 `detect`
functions that filtered detector hits by source-region grammar:
hits inside string literals, line comments, and block comments
under `Language.rust` / `.python` / `.typescript` were treated
as "data or documentation, not display deception in code" and
suppressed from the verdict.

That filtering is wrong for our threat model.  Source bytes are
uniformly suspect regardless of which source-region a tokenizer
would assign them to.  The evidence:

- **tj-actions/changed-files supply-chain attack, March 2025** —
  malicious payload hidden in source that downstream GitHub
  Actions consumed without distinguishing source regions.
- **CVE-2025-29927 Next.js middleware bypass** — framework
  parsing logic that treated certain source regions as
  "trusted" got exploited by payloads not respecting that
  boundary.
- **McKinsey Lilli / internal-AI prompt injection** — LLM code
  assistants read comments and docstrings as instructions.
  Bidi or hidden bytes in comments become prompt-injection
  vectors when an agent processes the source.
- **General npm / React / Python / CSS / JS ecosystem
  surface** — strings get `eval`'d, rendered into HTML via
  `innerHTML`, interpolated into SQL/shell, serialized as
  package metadata.  Comments are read by JSDoc generators,
  ESLint pragma parsers, IDE renderers, CI grep matchers,
  AI assistants.  None of these treat one source region as
  "safer" than another.

### Removed

- `Unicode.Security.Display.SourceCodeTokenize` module —
  entirely deleted.  Its state-machine region tokenization was
  only used by the filtering surface that is being retracted.
- `Language` parameter on `Unicode.Security.Display.SourceDisplayDivergence.detect`
  and `Unicode.Security.Display.RtlInjection.detect`.  Both
  functions revert to `(input : Array Nat) → <F>Verdict`.
- Six tokenized fixtures and their conformance harnesses:
  `SourceDisplayDivergenceTokenizedTest`,
  `SourceDisplayDivergencePythonTest`,
  `SourceDisplayDivergenceTypeScriptTest`,
  `RtlInjectionTokenizedTest`,
  `RtlInjectionPythonTest`,
  `RtlInjectionTypeScriptTest`.  Their behaviour was wrong by
  construction; the v1 conformance harnesses cover the same
  inputs without filtering.

### Behaviour

Every D1 and D3 sub-detector hit now fires unconditionally
regardless of source region.  Bidi in strings fires.  Bidi in
comments fires.  VS payloads in string literals fire.  Tag-block
chars in JSDoc fire.  The v1 conformance harnesses
(`SourceDisplayDivergenceTest.lean`, `RtlInjectionTest.lean`)
are unchanged in shape but the underlying detector is now
v1-equivalent on every input.

### Module / fixture / harness counts (post-retraction)

- 23 detector modules.
- 23 conformance harnesses.
- 23 SHA-pinned base fixtures.

Coverage and hash gates report clean at these counts.

### Documentation

- README's Security Conformance Layer section adds a
  "Region-agnosticism" paragraph documenting the retraction
  with the threat-model rationale.
- README's `Unicode.Security.Level` introduction stays — that
  module is unchanged.  Its monotone admission contract was
  always correct; the underlying detectors were the issue.

## v0.11.0 — 2026-05-11

The "v1.5 grammar coverage + admission predicate" release.
Three additive surfaces, no behavioural change to anything
v0.10.0 already pinned.

### Added — D3 v1.5 region-aware tokenization

`Unicode.Security.Display.RtlInjection.detect` gains an
optional `Language` parameter, mirroring v0.9.0's D1 v1.5
refactor.  Sub-detector hits whose position sits inside a
string literal, line comment, or block comment under the
supplied language grammar are filtered out.  Under
`Language.none` (the default) the whole input is treated as
one code region, so v1 behaviour is preserved exactly — the
existing `RtlInjectionTest.lean` conformance harness closes
unchanged.

The Phase-1 (RloInLTRField), Phase-2 (FieldTakeover), and
Phase-3 (StrongRTLInLTR / MixedOverflow) scans are all
re-routed through the shared `positionInCode` predicate.  A
5-character Hebrew run inside a Rust string literal no longer
trips MixedOverflow under `Language.rust`.  Aggregate counters
(`strongRTLCount`, `strongLTRCount`, `bidiControlCount`,
`longestRtlRunLen`) intentionally stay region-unaware — they
describe what the input contains, not what the detector fired
on.

Companion fixture `Ucd/Security/RtlInjectionTokenizedTest.txt`
(16 rows, 7 clear / 7 hazard) folded by a new conformance
harness `RtlInjectionTokenizedTest.lean`.  Pins a pedagogical
post-string-Hebrew row that documents the whole-input
first-strong-in-code semantics.

### Added — wider D1 v1.5 language coverage (Python, TypeScript)

`Unicode.Security.Display.SourceCodeTokenize.Language` gains
two new constructors:

- `python` — `"..."` / `'...'` newline-bounded strings;
  triple-quoted `"""..."""` and `'''..."''` spanning newlines;
  `#` line comments; no block comments.  Prefixed literals
  (r/b/f/rb/...) tokenize the leading letter as code with the
  contents staying a single string region regardless of
  prefix.
- `typescript` — `cStyleGeneric` plus template literals
  `` `...` ``.  Block comments are non-nestable (matches the
  ECMAScript/TypeScript specs, distinct from Rust).
  Template-literal interpolation `${...}` is intentionally
  NOT tracked — the entire template literal stays a single
  string region.  Conservative direction: a bidi codepoint
  inside `${expr}` is filtered out as in-string.

`ScanState` surface gains `inTripleString delim` and
`inTemplateLit`.  Both flow safely through the existing
`stepCStyle` / `stepRust` paths.

Two new D1 conformance fixtures with paired harnesses:

- `SourceDisplayDivergencePythonTest.txt` (13 rows) and
  `SourceDisplayDivergencePythonTest.lean`.
- `SourceDisplayDivergenceTypeScriptTest.txt` (13 rows) and
  `SourceDisplayDivergenceTypeScriptTest.lean`.

Together with the existing Rust-grammar fixture, D1 now has
end-to-end conformance under three concrete language
grammars (Rust, Python, TypeScript) plus `Language.none`.

### Added — `Unicode.Security.Level` admission predicate

UTS #39 §5-style monotone strictness levels lifted to the
23-family detector layer.  Three totally-ordered levels
(`restrictive ⊑ moderate ⊑ minimal`); each defines an
admission predicate `admissibleAt : Level → Array Nat → Bool`
that callers use to gate input acceptance for their
specific context.

Key non-negotiable design properties:

* No detector is ever suppressed.  `runAll` runs all 23
  families on every input; every hazard reported by `runAll`
  remains in the result regardless of the declared level.
* `admissibleAt` is purely an admission predicate over the
  whole `runAll` result.  It answers "is this input
  acceptable at the declared strictness?", not "which
  detectors should I run?".
* Levels are totally ordered.  Rejection sets nest:
  `minimal.rejectionSet ⊆ moderate.rejectionSet ⊆
  restrictive.rejectionSet`.  Admission is monotone in the
  laxer direction.

Per-level rejection sets:

* `restrictive` — all 23 families.  Any hazard rejects.
* `moderate`    — drops F1 / D3 / D4 / I3 (the heuristic /
                  high-FP-risk detectors).  Keeps every
                  targeted-attack detector.
* `minimal`     — only C5 (Trojan Source class) and F2 (UAX
                  #15 §13 stream-safe DoS class).  Outer
                  network-edge floor.

C4 SurrogateReassembly is documented as intentionally absent
from every rejection set because `runAll` feeds codepoint
arrays and C4's predicate treats each codepoint as a byte —
giving spurious hits on any input with a codepoint > 0xFF.

Theorems pin rejection-set sizes (23 / 19 / 2), rejection-set
nesting, and admission witnesses across six canonical attack
vectors (pure ASCII, lone RLO, Nethereum Cyrillic typosquat,
Math Italic admin, Greek polytonic, FDFA normalization
bomb).

Mirrors UTS #39 §5 in tone and contract: declare-which-level,
detectors-stay-on, monotone-superset-relation.  No
suppression knob; no way for the API to silence a real
hazard.

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
