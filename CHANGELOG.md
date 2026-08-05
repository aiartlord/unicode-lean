# Changelog

All notable changes to `unicode-lean` are recorded here.  Each
released version is a tag in `git tag -l`; releases follow
semantic versioning at the level of headline-theorem signatures
on the public surface (a major-version bump signals that a
theorem name or statement changed in a way downstream consumers
might depend on).

## Unreleased

### Added

- `scripts/check-axiom-footprint.sh` — an artifact-level axiom gate. It
  imports the built `Unicode` modules and verifies that every declaration's
  transitive axiom footprint is contained in the Lean-core `propext`,
  `Quot.sound`, and `Classical.choice`, so `sorryAx`, `Lean.ofReduceBool`,
  `Lean.trustCompiler`, and project-local axioms are rejected at the
  artifact level even when a source-text scan cannot see them. The gate
  runs in the `ci / build` job and in the release-evidence workflow, and
  is part of the local pull-request checklist.
- `scripts/check-olean-recheck.sh` — the independent kernel re-check the
  trusted-computing-base document names, now integrated. It builds the
  `lean4checker` proof checker from a commit-pinned checkout under the
  repository's own toolchain pin and replays every declaration in the
  audited root's import closure through the Lean kernel. Runs in the
  `ci / build` job and in the release-evidence workflow.

### Fixed

- `SECURITY.md`, `ASSURANCE.md`, and `CONTRIBUTING.md` reconciled to the
  shipped state: Lean 4.32.0, twenty-seven detector families across six
  layers including the shipped cryptographic-stability layer,
  kernel-checked conformance harnesses, and `detect : List Nat`
  signatures.
- `docs/explanation/tcb.md` records the axiom-footprint gate and the
  CI-integrated independent `lean4checker` re-check.
- Module docstrings and the trusted-computing-base document no longer
  reference external project vocabulary.

## v1.0.0 — 2026-08-03

First stable release. The detector suite is complete across every port: all
twenty-seven Lean-proven security-detector families are implemented and vouched
in all sixteen language ports — 432/432 family × port cells. Each port
implementation is a byte-faithful transliteration of the Lean-proven Rust
reference (the same algorithm, not an output-equivalent substitute), built and
tested under its own toolchain. This 1.0.0 milestone marks suite completion and
API stability across the ports, not a change to the Lean public theorem surface;
the port build-out is verified against the same Lean `detect_*` theorems.

### Added — six additional language ports

- Ruby, Lua, PHP, Elixir, Erlang, and COBOL join the existing ten ports (rust,
  python, cpp, go, jvm, typescript, dotnet, swift, zig, haskell), each carrying
  the full detector suite, grapheme segmentation, the codec layer, and the
  crypto-context detectors, and each self-contained with its own vendored,
  digest-pinned data.

### Added — the detector families that complete the suite, in every port

- `LocaleCaseInversion`, `CaseExpansionMismatch` (full context-sensitive UAX #21
  case mapping — SpecialCasing conditional/locale rows and the
  Cased/Soft_Dotted context predicates), `NfcIdempotenceWitness`,
  `IdentifierFormDrift`, `AdmissibilityFormDrift`, `EmojiZwjIntegrity`,
  `SkinToneVariationForgery`, `FilenameDisguise`, `RendererDivergence`,
  `HashInputStability`, `AiWatermarkDetectability`, and the aggregator
  `SourceDisplayDivergence`, together with the covert, identity, form, and
  boundary families, are implemented and vouched in all sixteen ports against
  their Lean `detect_*` theorems and the shared cross-port fixtures.
- Each port builds the real UAX #31 allowed-identifier predicate
  (`XID_Start`/`XID_Continue` from the bundled `DerivedCoreProperties.txt`) where
  a family requires it, rather than a heuristic.

### Documentation

- `ports/DETECTOR_COVERAGE.md` rewritten from a status table into the detector
  reference: the verdict shape, each of the twenty-seven detectors (what it
  catches and reports), and the per-port build/run/call instructions, with the
  coverage matrix retained.
- `README.md` and `docs/PORTS.md` updated to the completed 27 × 16 suite.

## v0.18.0 — 2026-05-13

Wires two SHA-pinned curated data tables to their detector
consumers and retires every "v1" / future-tense marker from the
security-source surface.

### Changed — HomoglyphConfusable now consumes the curated target table

- `Unicode.Security.Identity.HomoglyphConfusable.canonicalTargets`
  is now derived from `Unicode.Generated.KnownAttackTargets.targets`
  rather than maintained as a hardcoded `#[mkAscii "...", ...]`
  literal.  The SHA-pinned text file is the single maintenance
  surface; adding a target is a one-line edit to
  `Unicode/Ucd/Curated/KnownAttackTargets.txt` followed by a
  `check-curated-hashes` pin refresh.
- `Unicode/Ucd/Curated/KnownAttackTargets.txt` expanded from 48
  to 67 entries (union with the previous hardcoded set;
  case-as-attacked, including capital "Nethereum" for the
  Oct 2025 NuGet typosquat case).  Curation-policy header
  updated to "case preserved as the legitimate package / brand
  publishes it".
- `Unicode.Generated.KnownAttackTargets`: `targets_count`
  updated to `67`; new spot-check theorems `Nethereum_present`,
  `paypal_present`, `openai_present` pin the
  case-sensitivity-preserving rows.  The previous
  `nethereum_present` (lowercase) theorem is renamed to
  `Nethereum_present` — minor-version-bump because a theorem
  identifier changed.

### Added — AiWatermarkDetectability now consumes WatermarkSchemes

- `subThreatCueClass : SubThreat → Option CueClass` maps each
  implementation-level sub-threat onto the conceptual cue class
  drawn from `Unicode.Generated.WatermarkSchemes.CueClass`.
  Marker-encoded sub-threats route to `pseudorandomSeq`,
  vocabulary-bias to `greenListBias`, stylistic-distribution to
  `semanticDrift`, multi-category `unknown` to `none`.
- `every_cueClass_is_probed` proves every cue class published in
  the curated `WatermarkSchemes.txt` table is implicated by at
  least one detector sub-threat — pins the conceptual coverage
  of the publication set against silent regression.
- `Unicode.Generated.WatermarkSchemes` docstring updated:
  retracts "Pre-staging table — no current detector consumes
  it" and names AiWatermarkDetectability as the consumer.
- `Unicode/Ucd/Curated/WatermarkSchemes.txt` header updated:
  drops "deferred K3 detector" framing.

### Cleaned — "v1" / future-tense markers in security source

Six sites that implicitly deferred behaviour to a future version
rewritten to describe the implemented semantic directly:

- `VariationSelectorPayload.ExecutableHint` docstring — drop "at v1"
- `FilenameDisguise` detection strategy — drop "v1 is"
- `RendererDivergence.unknown` constructor — drop "for v1 we treat"
- `NormalizationBomb` detection strategy — drop "v1 detection"
- `AiWatermarkDetectability.detect` wrapper docstring — name the
  default tolerance values inline instead of pointing at "v1"
- `EmojiZwjIntegrityTest.metadataMatches` — drop the `vs_count`
  "placeholder for future emoji variation-selector counts"
  reference (no fixture row or detector field exposes it; the
  remaining `chain_len`, `zwj_count`, `skin_tone_count`, `is_rgi`
  are real keys)

Plus: `AdmissibilityFormDrift` / `IdentifierFormDrift` /
`StreamSafeViolation` "(v1, single)" sub-threat framing dropped;
`Security.lean` "Layer N — <Category>" import-block section
comments deleted; `Width.lean` `displayWidth` docstring rewritten
to describe `displayWidthClusters` as the UTS #51 / UAX #29
cluster-aware sibling rather than claim the per-codepoint sum
"does not yet" collapse emoji ZWJ sequences (the cluster
function exists and the `dwc_family_zwj` theorem pins it).

### Build / gates

- 200/200 jobs clean under `lake build`.
- `check-security-hashes`, `check-security-coverage`,
  `check-sorry`, `check-no-axiom`, `check-orphan-files`,
  `check-ucd-hashes`, `check-curated-hashes` all green.

## v0.17.0 — 2026-05-13

Productionization pass over the Layer-6 (Cryptographic
Stability) detectors.  Expands the AI-favored vocabulary
catalog, adds three new RFC profiles to
HashInputStability's signed-message-rule probe, and
introduces an AiWatermarkDetectability `Context` type
carrying tolerance parameters for the modulo probes.

### Added — AiWatermarkDetectability

- `Context` structure with two tolerance fields:
  `zwspModuloTolerance` (parameter for the
  `gpt5ZwspModulo` probe — accepts position-gap jitter within
  ±k of the first gap) and `adversarialTolerance` (same
  semantic for the `adversarial` probe's NNBSP positions).
  Defaults of `0` reproduce the exact-arithmetic behaviour.
- `detectWithContext (ctx : Context) (input : Array Nat) :
  Verdict` entry point.  The bare `detect input` is
  definitionally `detectWithContext {} input`; `runAll` uses
  the bare entry point so every downstream consumer sees the
  same priority order.
- `positionsAreArithmeticWithin (positions : Array Nat)
  (tolerance : Nat) : Bool` — generalised arithmetic-
  progression check.  `positionsAreArithmetic` becomes a thin
  wrapper at `tolerance = 0`.
- Three spot-check theorems pin the tolerance behaviour:
  jittered ZWSP positions stay clear under exact arithmetic
  but fire `Gpt5ZwspModulo` under `tolerance = 1`, and the
  empty-context wrapper agrees with the bare `detect`.
- `aiFavoredVocabulary` expanded from 3 entries to ~50,
  organised into four signal tiers (very high / high /
  medium / phrase-fragment) with curation notes in the data
  file.

### Added — HashInputStability

- Three new RFC profiles in `RfcRule`:
  `rfc7515JwsBase64Url` (JWS compact-serialisation alphabet
  `[A-Za-z0-9_-]`), `rfc6376DkimRelaxed` (DKIM relaxed body
  canonicalisation — multi-codepoint internal whitespace
  runs), `rfc5751SmimeLineEnding` (S/MIME canonical text;
  bare LF / CR violates).
- Three new violation probes wired into `rfcRuleViolation`:
  `rfc7515Violation`, `rfc6376Violation`, `rfc5751Violation`.
  `rfcRuleViolation` is now exhaustive over all seven
  `RfcRule` constructors.
- Five spot-check theorems pin the new probes — positive
  case (violation) and negative case (clean input) for each
  rule where applicable.

### Module header

HashInputStability header updated to list seven RFC rules
(not four).  AiWatermarkDetectability header is unchanged
from v0.16.1 — the new `Context` is appended without
disturbing the existing probe inventory.

Full repo build: 200/200 jobs.  All six gates clean.

## v0.16.1 — 2026-05-13

Tightening pass over v0.16.0 — no breaking API changes, no
behavioural regression, all six gates clean.

### Added

- `theorem admissibleAt_factors` in `Unicode/Security/Level.lean`
  — explicitly documents that
  `admissibleAt level ctx input
    = levelAdmissible level input && cryptoAdmissible ctx input`.
  Closes by `rfl`; spells out the architectural invariant on the
  public surface.
- `theorem every_subthreat_has_fixture_row` in both
  HashInputStability and AiWatermarkDetectability conformance
  harnesses — checks at build time that every declared
  `SubThreat` constructor has at least one fixture row
  exercising its emission path.  Catches the "structurally
  reachable but no fixture" failure mode that prompted the
  AiWatermarkDetectability `unknown` redefinition in v0.16.0.
- `Unicode/Ucd/Security/AiFavoredVocabulary.txt` — extracts
  the `statisticalTokenChoice` catalog from a hardcoded
  array into a hash-pinned data file (3 entries: "delve",
  "tapestry", "moreover").  Loaded via `include_str`;
  SHA-256 pinned in the Security manifest.  Establishes the
  maintenance path the module docstring already names.

### Changed

- HashInputStability's `encodingMismatch` probe now does a
  real Unicode-scalar validity check.  When the input
  contains a codepoint that is not a valid scalar (out-of-
  range or surrogate), the probe fires with
  `detectedEnc = "invalid"` and the position of the first
  invalid scalar — regardless of the declared encoding.
  Two new spot-check theorems pin the new firing path:
  `detect_encoding_invalid_surrogate` (U+D800 in input) and
  `detect_encoding_invalid_out_of_range` (U+110000 in input).
  Existing tests still pass (the label-drift firing path is
  unchanged for valid Unicode inputs).
- `scripts/check-security-hashes.sh` label tweaked from
  "Security fixture(s)" to "Security UCD-pinned file(s)" —
  reflects that the manifest now covers both `*Test.txt`
  fixtures (26) and the new vocabulary catalog (1) for 27
  total pinned files.

### Documentation (gitignored, internal)

- Per-family submission docs renamed to drop the project-
  internal layer-letter prefixes from the filenames.  Index
  README updated accordingly with explanatory paragraph.
- HashInputStability and AiWatermarkDetectability per-family
  specs retract their "deferred to v2" framing; the variant
  tables now reflect v0.16.0 firing paths.
- `cryptographic-stability.md` code blocks updated to use
  `<Family>.Classification` / `<Family>.SubThreat` /
  `<Family>.Verdict` (namespace-qualified long names) instead
  of the prefixed short forms.

## v0.16.0 — 2026-05-13

The "no deferred variants" release.  Retracts the "deferred to
v2" framing of v0.14.0 (HashInputStability's four context-
bearing variants) and v0.15.0 (AiWatermarkDetectability's six
refinement variants); both sets are now implemented and emit
on real inputs.  Drops the project-internal layer-letter +
ordinal short-code taxonomy from the public surface: types,
FamilyResult fields, rejectionSet entries, and the Family
inductive constructors all use long descriptive names
exclusively.  README adds an explicit disclaimer that the
short codes were project-internal, never Unicode-standard
nomenclature.

### Breaking API changes

The detector type names lose their letter-prefix.  For
example:

  Before                          After
  ------------------------------  ------------------------
  TagBlockPayload.C1Verdict       TagBlockPayload.Verdict
  TagBlockPayload.C1Classification TagBlockPayload.Classification
  TagBlockPayload.C1SubThreat     TagBlockPayload.SubThreat

(Every detector module in `Unicode/Security/*` follows the
same shape — the prefix is dropped uniformly.)

Calculus.Family inductive constructors rename to long-form
lowerCamelCase.  Examples:

  Before        After
  ------------  -----------------------------
  .C1           .tagBlockPayload
  .C2           .variationSelectorPayload
  .K1           .bip39Canonical
  .K2           .hashInputStability
  .K3           .aiWatermarkDetectability

RunAll.FamilyResult drops the short-code `family : String`
field; the previous `fullName : String` is renamed to
`family : String` (the long name is now the canonical
identifier).  mkResult signature drops one argument.

Level.rejectionSet arrays now hold long names ("TagBlockPayload",
"NfcIdempotenceWitness", "BidiControlBalance", etc.).
CryptoContext.toFamilies returns long names ("Bip39Canonical",
"HashInputStability", "AiWatermarkDetectability").

### Implemented — HashInputStability's four previously-deferred variants

New `Context` + `RfcRule` types and a `detectWithContext` entry
point.  The bare `detect input` wrapper is preserved; calling
`detectWithContext ctx input` opts in to the new probes.

Probes that fire when context fields are set:

  encodingMismatch         — ctx.declaredEncoding non-utf-8
  signedMessageRule        — ctx.rfcRule = one of four RFC profiles
                              (PGP 4880 / PGP 9580 / RFC 8785 /
                              RFC 8259)
  auditLogReinterpretation — ctx.asWritten ≠ input
  webhookSignatureDrift    — ctx.serverBytes ≠ input

Priority: context-specific probes outrank the generic
trailingWhitespace / normalizationDrift.

HashInputStabilityTest.txt: 16 → 26 rows.  Four new
coverage gates.

### Implemented — AiWatermarkDetectability's six previously-deferred variants

All six implementable at the character level — no token-stream
API, no statistical baseline required.

New probes (priority order):

  adversarial             — NNBSP count ≥ 3 AND positions form
                            an arithmetic progression (over-
                            regular placement)
  gpt5ZwspModulo          — ZWSP count ≥ 3 AND positions form
                            an arithmetic progression
  unknown                 — invisible markers from ≥ 2 distinct
                            categories (NNBSP / VS / ZWJ /
                            residual-DI) co-occur — single-
                            scheme attribution fails
  smartQuoteAlternation   — paired curly quotes (≥ 2) AND no
                            ASCII straight quotes
  emDashPattern           — em-dashes (≥ 2) AND no ASCII
                            hyphen-minus
  statisticalTokenChoice  — input contains an AI-favored
                            lexical pattern from a small
                            built-in vocabulary ("delve",
                            "tapestry", "moreover")

AiWatermarkDetectabilityTest.txt: 16 → 27 rows.  Six new
coverage gates.  Multi-category mixing fixture rows pin the
new `unknown` priority above single-category probes.

### Behaviour — Level admissibleAt factored

`admissibleAt` is now defined as `levelAdmissible level input
&& cryptoAdmissible cryptoCtx input` — two orthogonal
predicates.  This makes a cryptographic-context detector's
distinguishing contribution directly observable as a
difference in `cryptoAdmissible`, even on inputs that the
Covert / Identity / Display / Form / Boundary detectors already
reject.  Mathematically equivalent
to the prior union-based form; all existing native_decide
theorems close unchanged.

### README — family naming disclaimer

New "A note on family naming" subsection: the layer-letter +
ordinal short codes are project-internal taxonomy invented to
organise the 26-family layered roadmap, not Unicode-standard
nomenclature.  UAX/UTS uses sequential document numbers (UAX
#9, UTS #39) plus spelled-out property names.  Any upstream
submission of this material to the Unicode Consortium would
land under the long-form names only.

### Module / fixture / harness counts (unchanged)

- 26 detector modules.
- 26 conformance harnesses.
- 26 SHA-pinned base fixtures.

HashInputStability fixture: 16 → 26 rows.
AiWatermarkDetectability fixture: 16 → 27 rows.  All other
fixtures unchanged.

All six gates clean.  Full repo: 200/200 jobs.

### Migration

The migration shape for downstream consumers is purely a
type-name rename.  Where prior code held a string short code
or a short-prefixed type, the new code holds the long-form
module name.  Examples:

  Before                  After
  ----------------------  -----------------------------------
  r.family = "K1"         r.family = .bip39Canonical
                          (the field is now an enum, not a String)
  Family.K3               Family.aiWatermarkDetectability
  HashInputStability.K2Verdict  HashInputStability.Verdict
  AiWatermarkDetectability.K3Classification
                          AiWatermarkDetectability.Classification

The bare `Bip39Canonical.detect input`,
`HashInputStability.detect input`, and
`AiWatermarkDetectability.detect input` entry-point names are
unchanged in shape; only the qualified TYPE names lose the
prefix.  HashInputStability's extended surface adds
`detectWithContext` as a new entry point.

## v0.15.0 — 2026-05-12

The "AiWatermarkDetectability" release.  Third and final
family in the 26-family roadmap; ships the character-level
AI-watermark detector under
`Unicode.Security.Crypto.AiWatermarkDetectability` and moves
the Security Conformance Layer from 25/26 to **26/26**
families — the character-level Unicode security scope is now
complete.

### Added — AiWatermarkDetectability (character-level)

- `Unicode.Security.Crypto.AiWatermarkDetectability` detector
  module.  Implements four priority-ordered codepoint probes
  for AI-watermark scheme detection at the character level:
  1. `nnbspBoundary`            — any U+202F NNBSP.
  2. `variationSelectorCarrier` — VS (U+FE00..U+FE0F or
     U+E0100..U+E01EF) NOT adjacent to an emoji codepoint.
  3. `zwjNonEmoji`              — U+200D ZWJ NOT adjacent to
     an emoji codepoint.
  4. `defaultIgnorableCarrier`  — residual Default_Ignorable_
     Code_Point not classified by the three probes above.
- Six additional spec sub-threats (`gpt5ZwspModulo`,
  `emDashPattern`, `smartQuoteAlternation`,
  `statisticalTokenChoice`, `adversarial`, `unknown`) are
  declared in `SubThreat` for spec consistency with
  `cryptographic-stability.md` but require analytical
  context the codepoint-only detector cannot supply (per-
  provider modulo schedule, statistical regularity over the
  document, externally-trained classifier).  v1 never emits
  them.  (They are implemented in v0.16.0.)
- `Unicode/Ucd/Security/AiWatermarkDetectabilityTest.txt` —
  16 hand-curated rows across 5 sub-threat sections.
- `Unicode.Conformance.Security.AiWatermarkDetectabilityTest`
  — `theorem all_rows_pass : rows.all verifyRow = true := by
  native_decide` plus five per-section coverage gates.

### Threat model

AI providers deposit invisible markers (NNBSP at word
boundaries, Variation Selectors in plain text, default-
ignorable carriers) for downstream provenance attribution.
Attackers may strip the markers via normalisation, or
adversarially inject fake markers to discredit human-written
text.  A character-level detector cannot distinguish a
genuine provenance marker from an adversarial injection
without statistical protocol-consistency analysis (deferred
at this release), so v1 emits `suspectedWatermark` for both
shapes and leaves the genuine-vs-adversarial decision to
downstream provider-specific verification.

### v1 scope explicitly deferred to v2

- **Statistical / token-distribution watermarks** —
  distribution-based markers require token-stream access and a
  per-provider distribution baseline.  Not a character-level
  test.
- **Per-segment integrity** — multi-paragraph text with per-
  segment markers introduces segment-boundary ambiguity.
  v1 is whole-input only.
- **Genuine-vs-adversarial distinction** — requires
  statistical protocol-consistency.  v1 reports the matched
  scheme without authentication.

### Behaviour — RunAll aggregator

- `runAll` now returns 26 entries; AiWatermarkDetectability is
  at index 25, layer 6.
- `runAll_size` bumped 25 → 26.
- `runAll_layer_6_count = 3` (Bip39Canonical,
  HashInputStability, AiWatermarkDetectability).

### Behaviour — Level admission predicate

This release **factors `admissibleAt` into two orthogonal
predicates** to fix an architectural defect identified during
AiWatermarkDetectability design.  The fix lands one commit
before the family ships.

- New `levelAdmissible : Level → Array Nat → Bool` — Level-only
  admission, independent of CryptoContext.
- New `cryptoAdmissible : CryptoContext → Array Nat → Bool` —
  Crypto-only admission, independent of Level.
- `admissibleAt level ctx input` is now defined as
  `levelAdmissible level input && cryptoAdmissible ctx input`.
  Mathematical equivalence to the prior union-based form is
  immediate by distribution of `any` over disjunction; all
  existing `native_decide` theorems close unchanged.
- Why: the prior union-based shape masked a cryptographic-
  context detector's contribution whenever a Covert /
  Identity / Display / Form / Boundary detector also
  rejected the same input.  E.g.
  NfcIdempotenceWitness rejects every non-NFC input at
  `.restrictive`/`.moderate`, so the HashInputStability
  `.hashInput` gating demonstration was forced to `.minimal`.
  The same shadowing would have made AiWatermarkDetectability's
  `.aiAttribution` gating invisible at `.restrictive` (where
  ZeroWidthPayload / MixedScriptAdmissibility /
  SourceDisplayDivergence / NfcIdempotenceWitness /
  Bip39Canonical all flag U+202F).  Factoring the predicate
  exposes the cryptographic-context distinguishing
  contribution at every Level.

- New `CryptoContext` constructor `aiAttribution`.  Family
  map: `nonCrypto → ∅`, `bip39Mnemonic → {Bip39Canonical}`,
  `hashInput → {HashInputStability}`,
  `aiAttribution → {AiWatermarkDetectability}`.
- New theorem `crypto_admissible_gates_nnbsp_under_aiAttribution`
  demonstrates AiWatermarkDetectability's context-gating:
  `#[0x61, 0x202F, 0x62]` ("a NNBSP b") admits under
  `cryptoAdmissible .nonCrypto` and rejects under
  `cryptoAdmissible .aiAttribution`, Level-independent.
  Companion `level_admissible_rejects_nnbsp_at_restrictive`
  pins that the Covert / Identity / Display / Form /
  Boundary set also rejects the same input at
  `.restrictive`, documenting the masking effect on the
  composite surface.
- HashInputStability's gating demonstration upgraded
  analogously: `crypto_admissible_gates_decomposed_e_acute`
  is the new level-independent primary witness; the previous
  `.minimal`-only `admissibleAt`-based shape is retained as
  `crypto_ctx_gates_decomposed_e_acute_at_minimal` for the
  composite-form co-witness.

### Module / fixture / harness counts

- 26 detector modules (23 Unicode + 3 cryptographic-stability).
- 26 conformance harnesses.
- 26 SHA-pinned base fixtures.

All six gates clean.

## v0.14.0 — 2026-05-12

The "HashInputStability" release.  Second family under
Cryptographic Stability.  Moves the Security Conformance Layer
from 24 to 25 of the 26 planned families.

### Added — HashInputStability

- `Unicode.Security.Crypto.HashInputStability` detector module.
  Implements the canonical hash-input form:
  `hashStable input = trimTrailing (NFC input)`, where
  `trimTrailing` strips ASCII whitespace
  `{U+0020 SPACE, U+0009 TAB, U+000A LF, U+000D CR}`.  Unicode
  whitespace (`U+00A0`, `U+3000`, etc.) is content, not framing,
  and NOT stripped — distinguishes this detector's ASCII-only
  trim from Bip39Canonical's BIP-39 `{U+0020, U+3000}`
  inventory.
- Six sub-threats, two emitted by the bare-input detector:
  `trailingWhitespace` (priority 1) and `normalizationDrift`
  (priority 2).  The other four (`encodingMismatch`,
  `signedMessageRule`, `auditLogReinterpretation`,
  `webhookSignatureDrift`) require context the codepoint-only
  detector cannot access; declared in `SubThreat` for spec
  consistency, not emitted at this release.  (They become
  emittable in v0.16.0.)
- `Unicode/Ucd/Security/HashInputStabilityTest.txt` — 16 hand-
  curated rows across 4 sections (Clear: empty / ASCII / NFC-
  é / 中文 / mixed / internal-space / trailing-U+3000;
  TrailingWhitespace: SPACE / TAB / LF / CRLF; NormalizationDrift:
  decomposed é / decomposed á / Hangul jamos / mid-string;
  priority pin: NFC drift + trailing space → TrailingWhitespace
  wins).
- `Unicode.Conformance.Security.HashInputStabilityTest` —
  `theorem all_rows_pass : rows.all verifyRow = true := by
  native_decide` plus three per-section coverage gates.

### Threat model

PGP signed messages (RFC 4880 / 9580), RFC 8785 JSON
canonicalization, audit-log entries read after disk write, and
webhook signatures all hash an input that the signer thinks is
canonical and the verifier independently re-canonicalises.  If
the two sides pick different conventions (NFC vs NFD, trim
convention, line-ending) the hashes diverge silently.
HashInputStability is the witness that an input satisfies the
hash-input canonical-form contract.

### Behaviour — RunAll aggregator

- `runAll` now returns 25 entries; HashInputStability is at
  index 24, layer 6.
- `runAll_size` bumped 24 → 25.
- `runAll_layer_6_count = 2` (Bip39Canonical and
  HashInputStability).

### Behaviour — Level admission predicate

- `CryptoContext` extended with `hashInput` constructor.
  `toFamilies .hashInput = #["HashInputStability"]`.  A fourth
  constructor (`aiAttribution`) lands in v0.15.0 alongside
  AiWatermarkDetectability.
- New theorem `crypto_ctx_gates_decomposed_e_acute` demonstrates
  HashInputStability's context-gating: decomposed é admits at
  `.minimal` `.nonCrypto` (no structural-violation family
  fires) but rejects at `.minimal` `.hashInput` (the detector
  fires `normalizationDrift`).  The demonstration drops to
  `.minimal` rather than `.restrictive` because
  NfcIdempotenceWitness sits in both restrictive's and
  moderate's rejection sets — context-gating's distinguishing
  contribution is only visible at the level where
  NfcIdempotenceWitness isn't already rejecting the input.
  (v0.15.0 factors `admissibleAt` to make the contribution
  visible at every Level.)

### Module / fixture / harness counts

- 25 detector modules (23 Unicode + 2 cryptographic-stability).
- 25 conformance harnesses.
- 25 SHA-pinned base fixtures.

All six gates clean.

### Documentation

- README: family count 24 → 25; Layer-6 row gains
  HashInputStability; pin bumps to v0.14.0.
- Internal per-family submission doc written (gitignored).

## v0.13.0 — 2026-05-12

The "Bip39Canonical" release.  First family under
Cryptographic Stability.  Moves the Security Conformance
Layer from 23 to 24 of the 26 planned families.

### Added — Bip39Canonical

- `Unicode.Security.Crypto.Bip39Canonical` detector module.
  Implements the BIP-39 canonical-form check: input is passed
  through `NFKD → toLower (default locale) → collapse U+0020
  + U+3000 whitespace runs → trim leading/trailing U+0020`,
  then each canonical word is looked up against the ten
  pinned BIP-39 wordlists in `Unicode.Generated.BIP39`.
- Seven sub-threats, fired in priority order:
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
wallet.  Bip39Canonical is the witness that an input satisfies
BIP-39's canonical-form contract.

### Behaviour — RunAll aggregator

- `Unicode.Security.RunAll.runAll` now returns 24 entries;
  Bip39Canonical is the 24th, at layer 6.
- `runAll_size` theorem bumped 23 → 24.
- `runAll_layer_6_count = 1` added.
- The pure-ASCII baseline theorem was reformulated:
  `ascii_hello_no_hazards` → `ascii_hello_no_unicode_hazards`
  filtered to `layer ≤ 5`.  Bip39Canonical (correctly) fires
  `mixedCase` on the capital H in "Hello"; the renamed theorem
  makes explicit that the baseline is "no Unicode-layer
  detector fires", not "no detector fires anywhere".

### Behaviour — Level admission predicate (BREAKING CHANGE)

- `admissibleAt` now takes a `CryptoContext` parameter:
  ```
  def admissibleAt
    (level : Level) (cryptoCtx : CryptoContext) (input : Array Nat) : Bool
  ```
  The `CryptoContext` inductive has two constructors at this
  release: `nonCrypto` (general Unicode admission; Layer-6
  detectors ignored) and `bip39Mnemonic` (adds Bip39Canonical
  to the effective rejection set).  The remaining Layer-6
  constructors land alongside HashInputStability (v0.14.0
  adds `hashInput`) and AiWatermarkDetectability (v0.15.0
  adds `aiAttribution`).
- Existing callers must pass `.nonCrypto` to preserve v0.12.0
  semantics: `admissibleAt .restrictive #[..]` → `admissibleAt
  .restrictive .nonCrypto #[..]`.
- Rationale (per `cryptographic-stability.md`): the
  cryptographic-stability detectors are highly context-
  dependent — applicable only when the input is
  declared as a crypto-shaped input.  Without the context
  parameter, callers had two bad options: include
  Bip39Canonical in rejection sets (constant-rejects general
  Unicode input that isn't BIP-39 vocabulary) OR silently
  exclude it (footgun for callers actually verifying
  mnemonics).  The parameter makes the choice explicit at
  the call site.
- The seven existing monotonicity theorems
  (`monotone_ascii_hello`, `monotone_lone_rlo`,
  `monotone_nethereum`, `monotone_math_italic_admin`,
  `monotone_greek_polytonic`, `monotone_fdfa`,
  `monotone_modified_utf8_nul`,
  `monotone_mixed_high_codepoint`) all close unchanged after
  threading `.nonCrypto` through.
- Two new theorems pin the context-gating behaviour:
  `crypto_ctx_gates_mixed_case` shows "Hello" admits under
  `nonCrypto` but rejects under `bip39Mnemonic`
  (Bip39Canonical's `mixedCase` fires on the capital H);
  `crypto_ctx_single_word_passes_both` shows that a single
  canonical-form BIP-39 word "abandon" admits under both
  contexts.
- File-level `set_option maxHeartbeats 4000000` added to
  `Level.lean` — `native_decide` on `admissibleAt` now
  elaborates against Bip39Canonical's 10 × 2,048-word
  wordlist tables, pushing isDefEq past the default
  heartbeat budget.

### Module / fixture / harness counts

- 24 detector modules (23 Unicode + 1 cryptographic-stability).
- 24 conformance harnesses.
- 24 SHA-pinned base fixtures.

Coverage and hash gates report clean at these counts.  The
`scripts/check-security-coverage.sh` find list now includes
`Unicode/Security/Crypto/`.

### Documentation

- README updated: family count bumped 23 → 24; the Layer
  table gains a Layer-6 row showing Bip39Canonical shipped;
  the Layer-6 reserved paragraph rewritten to "Bip39Canonical
  shipped; HashInputStability and AiWatermarkDetectability
  reserved".
- Internal docs under `docs/specs/security/` (gitignored
  planning materials) gain a per-family Bip39Canonical spec
  doc and the Phase 0 checkbox flips.

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

Layer 6 (Cryptographic Stability — K1..K3) is reserved at this
release.  Its three families ship in v1.0.0.

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
