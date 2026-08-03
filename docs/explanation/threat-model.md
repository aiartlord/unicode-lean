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
