# Threat model

The security engine defends against Unicode-level attacks on text: cases where a
string's rendered appearance, its logical content, and its byte representation
disagree, and an adversary exploits the gap. The Unicode Standard specifies how
text is processed; it does not classify these divergences as security hazards.
This engine does.

## Adversary and assets

The adversary submits text that will be displayed to a human, matched against a
trusted value, executed, hashed, or routed. The asset is the integrity of that
downstream decision: what the reviewer sees, what the machine runs, which
identity a name resolves to, which wallet a mnemonic recovers, which bytes a
signature covers.

The engine sits at a trust boundary and classifies each payload before it is
trusted. It does not rewrite text; it returns a verdict and lets policy decide.

## Hazard classes

The twenty-seven detector families group by the concern each guards. The full
per-detector reference is
[`../../ports/DETECTOR_COVERAGE.md`](../../ports/DETECTOR_COVERAGE.md).

- **Covert channels.** Information smuggled through a codepoint stream that renders
  as innocuous text: tag characters, variation selectors, zero-width runs,
  surrogate misuse, unbalanced bidirectional controls, and noncharacters.
- **Identity spoofing.** Text engineered to be mistaken for a trusted identity:
  homoglyph substitution, disallowed mixed-script identifiers, and forged emoji
  sequences.
- **Display integrity.** A reviewer seeing something different from what the
  machine reads: source-display divergence, disguised filenames, right-to-left
  injection, and renderer-dependent text.
- **Form stability.** Hazards from normalization and case behavior: normalization
  bombs, Stream-Safe violations, locale-dependent case inversion, case-mapping
  length changes, width confusion, and normalization instability.
- **Cross-layer boundary.** Hazards visible only when two layers combine:
  admissibility that changes under normalization, and compound covert-plus-display
  or confusable-plus-bidi signals.
- **Cryptographic stability.** Representation drift that changes a cryptographic
  input: non-canonical mnemonics, hash-input instability, and machine-generated
  watermark patterns.

## Position in the pipeline

Real incidents combine hazards in one payload and cross trust boundaries through
code review, package metadata, identifiers, and message bodies. The engine treats
source bytes as uniformly suspect regardless of which region a language tokenizer
would assign them to, because where a parser places bytes does not change whether
they are an attack surface. It runs inline at ingress so a single payload is
classified once, at the boundary, and the verdict travels with it.

## Guarantees per detection class

A buyer reads the boundary before the proofs. Each class below names the
strongest statement the tree carries for it, and says which tier that is:
**theorem** (machine-checked over every input, axiom footprint `propext`,
`Quot.sound`, `Classical.choice` only — see `scripts/print-load-bearing-axioms.lean`),
**conformance** (the published Unicode test file, every row judged, zero
skipped — see `dist/CONFORMANCE-RUN.txt`), **coverage** (exact with respect to
the Unicode data it reads, which has no official pass/fail file), or
**vectors** (curated attack and control cases, each a build-gated check).
A class marked coverage or vectors is shippable; a class marked as proven
when it is not is what would kill the product, so the tiers are stated
exactly.

| Class | Detector families | Strongest statement | Tier |
|---|---|---|---|
| D1 bidi rendering divergence | `bidiControlBalance`, `sourceDisplayDivergence`, `rtlInjection` | Every bidi control imbalance is reported, for every input: `Unicode.Security.Covert.BidiControlBalance.runWalk_depthAccounted`, `runWalk_stackConsistent`, `Unicode.TrojanSource.balanced_of_no_bidi_control`, `Unicode.TrojanSource.safeForCodeContext_balanced`. Display order equals logical order whenever no odd embedding level occurs: `Unicode.Bidi.Algorithm.applyL2_id_of_all_even` — a divergence can only originate at a bidi control. Which controls are reported is decided by purpose, not presence (`Unicode.Security.Display.BidiControlPurpose`): a span is purposeful only when its direct content is exactly its own direction and carries no ASCII code syntax — a right-to-left span around right-to-left text, a left-to-right span in right-to-left context around left-to-right text — and everything else fires wherever it sits, code, literal or comment: every unbalanced control, every balanced span with nothing of its own direction inside (`purposeless_balanced_empty_isolate`, `purposeless_lro_around_latin`, `purposeless_lri_around_latin`), every span mixing directions (`purposeless_rle_planted_letter`) and every span swallowing a quote or a bracket (`purposeless_rle_with_syntax`). A balanced embedding around a pure Arabic literal does not fire (`purposeful_rle_around_arabic`), nor does a Latin acronym isolated inside it (`purposeful_nested_acronym`). This is a property of the control span, never of the source region. The algorithm itself passes `BidiTest.txt` and `BidiCharacterTest.txt` in full. | theorem + conformance. The full Trojan Source property (rendered order equals lexical order or the scanner reports it) is not one closed theorem yet: the purposeless-but-balanced case is carried by the `BidiControlPurpose` spot checks and the `sourceDisplayDivergence` vectors, and that is stated here rather than implied. What remains outside the rule is a pure right-to-left span placed so that its own text lands somewhere misleading; it moves no code and no syntax, and the text is visible to the reviewer. |
| D2 invisible and format characters | `zeroWidthPayload`, `tagBlockPayload`, `variationSelectorPayload` | The codepoint set is the UCD `Default_Ignorable_Code_Point` property (`Unicode.Generated.DerivedCoreProperties`), not a hand list. Orthographic joiners stay clear and a spliced joiner reports, over the stated inputs: `Unicode.Security.Covert.ZeroWidthPayload.detect_devanagari_zwnj_clear`, `detect_persian_zwnj_clear`, `detect_zwnj_in_latin_hazard`. | coverage (property-derived set) + theorem (the joiner sanction) |
| D3 mixed-script confusables | `homoglyphConfusable`, `mixedScriptAdmissibility` | Sound with respect to `confusables.txt`: the skeleton mapping converges within a bounded chain and expansion, `Unicode.Confusables.confusable_chain_within_bound`, `Unicode.Confusables.mappingsList_expansion_under_bound`. An identifier that is not ASCII but whose case-preserving skeleton is all ASCII is reported as confusable with the ASCII name its skeleton spells, with no target list (`asciiConfusable`: `detect_dotless_i_admin` for `admın`; `detect_sharp_s_clear` pins that `straße` is not folded to `strasse`). Completeness is bounded by Unicode's own data, which has no pass/fail file. | coverage + theorem (chain and expansion bounds) |
| D4 normalization instability | `identifierFormDrift`, `nfcIdempotenceWitness`, `admissibilityFormDrift` | `s ≠ normalize(s)` is decided, not sampled: `Unicode.Conformance.NormalizationTest.nfc_stable`, `nfd_stable`, `nfd_of_nfc` hold for every input; all four forms pass `NormalizationTest.txt` in full. | theorem + conformance |
| D5 normalization expansion | `normalizationBomb` | The detector bounds expansion per input; the tree carries no closed theorem giving a universal expansion factor for NFKC/NFKD. | vectors |
| D6 IDNA and domain confusables | `homoglyphConfusable` over registrable names, UTS #46 processing | UTS #46 processing judged against the whole of `IdnaTestV2.txt`: every published row on all three result columns (toUnicode, toAsciiN, toAsciiT), zero skipped, recorded in `fixtures/conformance/executed-runs.json` and restated by the conformance report; confusable resolution as in D3. | conformance + coverage |
| D7 filename direction spoofing | `filenameDisguise` | The same bidi-balance theorems as D1 apply to the filename, and the bidi rung reads purpose as D1 does; the disguise verdict itself is vector-gated. | theorem (balance) + vectors |

What a detector is asked depends on the kind of field it is handed
(`Unicode.Security.RunAll.Context`, set per profile by
`Unicode.Security.Policy.scan`). A username, a domain and a DNS label are one
identifier: every rung runs over the whole value. A display name, a chat message
and a source file are running text, and the identifier detectors read them per
identifier-shaped token (`Unicode.Security.Identity.IdentifierTokens`, the
maximal `XID_Continue` runs): `scоpe` with a Cyrillic о inside a file is a
mixed-script token and fires (`detectWithContext_token_cyrillic_o_scope`),
`admın` is a Latin token posing as `admin` and fires
(`detectWithContext_token_dotless_i_admin`), while `مرحبا`, `δ`, `α` and `β`
are single-script tokens and do not (`detectWithContext_token_greek_alpha_clear`).
The rungs that only make sense of one value — mixed direction, case expansion,
locale case inversion, file extension shape, and the declared-left-to-right
premise of `rtlInjection` — do not run on running text, because a bilingual
file, an Arabic literal and a capital I are content there. The covert payloads,
purposeless bidi controls, form drift and presentation rungs hold of any field
and run on all of them. A finding is therefore never suppressed by the field; it
is only ever asked of a field, or a token, it is specified for.
