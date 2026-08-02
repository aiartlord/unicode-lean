package security

import "strings"

// hash-input-stability: detection of inputs that are not in canonical
// hash-input form. Per UTS #39 §6.1 + RFC 4880 / 9580 + RFC 8785, an input
// hashed by a signer must be byte-identical to the input hashed by the
// verifier; if the two ends pick different canonical forms (NFC vs NFD, trim
// policy, line-ending convention) the resulting hashes diverge silently while
// both sides believe they signed the same content.
//
// Direct port of Unicode.Security.Crypto.HashInputStability (mirroring the
// verified Rust port security/crypto/hash_input_stability.rs). The canonical
// (hash-stable) form is trim_trailing(to_nfc(input)), where trim_trailing
// strips only ASCII whitespace {U+0020, U+0009, U+000A, U+000D}; Unicode
// whitespace (U+00A0, U+2000..U+200A, U+3000) is content and is not stripped.
// NFC is the port's own toNFC, never a host normalizer.
//
// Six probes run in strict priority order (first hit wins):
//
//	1. encodingMismatch         (context: declaredEncoding)
//	2. webhookSignatureDrift    (context: serverBytes)
//	3. auditLogReinterpretation (context: asWritten)
//	4. signedMessageRule        (context: rfcRule)
//	5. trailingWhitespace       (bare input)
//	6. normalizationDrift       (bare input)
//	7. clear
//
// Context-specific probes fire first because they carry more precise threat
// information than the generic probes. hisDetect is the convenience wrapper
// hisDetectWithContext(hisContext{}, input) that leaves the four
// context-bearing probes silent.

// ─────────────────────────────────────────────────────────────────────
// §1 Types
// ─────────────────────────────────────────────────────────────────────

// hisRfcRule names the RFC canonicalisation profiles that the signedMessageRule
// probe checks against. Each variant names a specific canonicalisation rule
// from a published RFC; callers pass one as hisContext.rfcRule to opt in.
type hisRfcRule int

const (
	// hisPgp4880TrailingWhitespace — RFC 4880 §5.2.4: detached signatures
	// normalise trailing whitespace; trailing whitespace in the body causes
	// signature mismatch.
	hisPgp4880TrailingWhitespace hisRfcRule = iota
	// hisPgp9580LineEnding — RFC 9580 (current OpenPGP): line-endings normalise
	// to CRLF before signing; a bare LF or bare CR violates.
	hisPgp9580LineEnding
	// hisRfc8785NfcRequirement — RFC 8785 §3.2.5: JSON Canonicalization Scheme
	// requires strings to be in NFC before serialisation.
	hisRfc8785NfcRequirement
	// hisRfc8259ControlChar — RFC 8259 §7: JSON strings must escape control
	// characters (U+0000..U+001F); unescaped control bytes violate.
	hisRfc8259ControlChar
	// hisRfc7515JwsBase64Url — RFC 7515 §2: JWS Base64URL encoding; any
	// character outside [A-Za-z0-9_-] is a canonicalisation violation.
	hisRfc7515JwsBase64Url
	// hisRfc6376DkimRelaxed — RFC 6376 §3.4.4: DKIM relaxed body canonicalization
	// collapses internal whitespace runs to a single SP; a multi-char internal
	// whitespace run indicates the canonicalisation has not been applied.
	hisRfc6376DkimRelaxed
	// hisRfc5751SmimeLineEnding — RFC 5751 §3.1.1: S/MIME canonical text; like
	// PGP 9580, a bare LF or bare CR violates.
	hisRfc5751SmimeLineEnding
)

// tag is the fixture-string identifier for a hisRfcRule — used by the
// conformance harness's attribution parser to round-trip rule selections.
func (r hisRfcRule) tag() string {
	switch r {
	case hisPgp4880TrailingWhitespace:
		return "pgp4880TrailingWhitespace"
	case hisPgp9580LineEnding:
		return "pgp9580LineEnding"
	case hisRfc8785NfcRequirement:
		return "rfc8785NfcRequirement"
	case hisRfc8259ControlChar:
		return "rfc8259ControlChar"
	case hisRfc7515JwsBase64Url:
		return "rfc7515JwsBase64Url"
	case hisRfc6376DkimRelaxed:
		return "rfc6376DkimRelaxed"
	case hisRfc5751SmimeLineEnding:
		return "rfc5751SmimeLineEnding"
	}
	return ""
}

// hisRfcRuleFromTag is the inverse of tag. The second result is false for
// unrecognised strings.
func hisRfcRuleFromTag(tag string) (hisRfcRule, bool) {
	switch tag {
	case "pgp4880TrailingWhitespace":
		return hisPgp4880TrailingWhitespace, true
	case "pgp9580LineEnding":
		return hisPgp9580LineEnding, true
	case "rfc8785NfcRequirement":
		return hisRfc8785NfcRequirement, true
	case "rfc8259ControlChar":
		return hisRfc8259ControlChar, true
	case "rfc7515JwsBase64Url":
		return hisRfc7515JwsBase64Url, true
	case "rfc6376DkimRelaxed":
		return hisRfc6376DkimRelaxed, true
	case "rfc5751SmimeLineEnding":
		return hisRfc5751SmimeLineEnding, true
	}
	return 0, false
}

// hisSubThreat is the sub-threat this detector fired. tag is the human-facing
// classification tag; the remaining fields carry the sub-threat's data (only
// those relevant to the fired tag are meaningful). The tag values, in the spec's
// declaration order, are: NormalizationDrift, TrailingWhitespace,
// EncodingMismatch, SignedMessageRule, AuditLogReinterpretation,
// WebhookSignatureDrift.
type hisSubThreat struct {
	tag string
	// firstDivergentPos — NormalizationDrift, AuditLogReinterpretation.
	firstDivergentPos int
	// count — TrailingWhitespace.
	count int
	// declaredEnc, detectedEnc — EncodingMismatch.
	declaredEnc string
	detectedEnc string
	// rfcRule — SignedMessageRule (fixture tag of the violated rule).
	rfcRule string
	// firstPos — SignedMessageRule, WebhookSignatureDrift.
	firstPos int
}

// hisContext enables the four context-bearing probes. Each field is nil by
// default — the empty context is the identity case:
// hisDetectWithContext(hisContext{}, input) equals hisDetect(input).
type hisContext struct {
	// declaredEncoding — the encoding label the caller claims. When set and not
	// (case-insensitively) UTF-8, fires encodingMismatch immediately.
	declaredEncoding *string
	// rfcRule — the RFC canonicalisation rule the caller is operating under.
	// When set, scans input for violations and fires signedMessageRule.
	rfcRule *hisRfcRule
	// asWritten — the original "as-written" form of an audit-log entry whose
	// re-read is input. When set, fires auditLogReinterpretation on first
	// divergence.
	asWritten *[]uint32
	// serverBytes — the server-side recomputed bytes for a webhook signature.
	// When set, fires webhookSignatureDrift on first divergence against input.
	serverBytes *[]uint32
}

// hisClassification is the top-level classification. When clear is true the
// input is hash-stable under every enabled probe; otherwise sub names the
// sub-threat and positions holds the implicated codepoint positions.
type hisClassification struct {
	clear     bool
	sub       hisSubThreat
	positions []int
}

// tag is the human-facing tag for a hazard; the second result is false when
// clear.
func (c hisClassification) tag() (string, bool) {
	if c.clear {
		return "", false
	}
	return c.sub.tag, true
}

// hisVerdict is the structured output of hisDetect. stableSize is the codepoint
// count of the hash-stable canonical form; downstream callers compare it against
// len(input) to size the byte-drift their hash sees.
type hisVerdict struct {
	input      []uint32
	classify   hisClassification
	stableForm []uint32
	stableSize int
}

// ─────────────────────────────────────────────────────────────────────
// §3 Canonicalisation pipeline
// ─────────────────────────────────────────────────────────────────────

// hisIsASCIIWhitespace reports whether cp is an ASCII whitespace codepoint that
// line-oriented hash-input protocols treat as framing rather than content:
// U+0020 SPACE, U+0009 TAB, U+000A LF, U+000D CR.
func hisIsASCIIWhitespace(cp uint32) bool {
	return cp == 0x0020 || cp == 0x0009 || cp == 0x000A || cp == 0x000D
}

// hisCountTrailingWhitespace counts the trailing ASCII whitespace codepoints in
// input.
func hisCountTrailingWhitespace(input []uint32) int {
	count := 0
	for i := len(input) - 1; i >= 0; i-- {
		if hisIsASCIIWhitespace(input[i]) {
			count++
		} else {
			break
		}
	}
	return count
}

// hisTrimTrailing strips trailing ASCII whitespace.
func hisTrimTrailing(input []uint32) []uint32 {
	keep := len(input) - hisCountTrailingWhitespace(input)
	out := make([]uint32, keep)
	copy(out, input[:keep])
	return out
}

// hisHashStable is the hash-stable form of an input: NFC then trim, in spec
// order.
func hisHashStable(input []uint32) []uint32 {
	return hisTrimTrailing(toNFC(input))
}

// ─────────────────────────────────────────────────────────────────────
// §6 Context-bearing probes
// ─────────────────────────────────────────────────────────────────────

// hisASCIILower lower-cases an ASCII letter (U+0041..U+005A → U+0061..U+007A).
func hisASCIILower(cp uint32) uint32 {
	if cp >= 0x41 && cp <= 0x5A {
		return cp + 0x20
	}
	return cp
}

// hisIsUTF8Label reports whether label (after ASCII case-fold) names UTF-8:
// accepts "utf-8", "UTF-8", "UTF8", "utf8". Non-ASCII characters pass through
// unchanged.
func hisIsUTF8Label(label string) bool {
	var b strings.Builder
	for _, c := range label {
		b.WriteRune(rune(hisASCIILower(uint32(c))))
	}
	normalised := b.String()
	return normalised == "utf-8" || normalised == "utf8"
}

// hisIsValidScalar reports whether cp is a valid Unicode scalar value: in
// [0, 0x10FFFF] and not a surrogate [0xD800, 0xDFFF].
func hisIsValidScalar(cp uint32) bool {
	return cp <= 0x10FFFF && !(cp >= 0xD800 && cp <= 0xDFFF)
}

// hisFirstInvalidScalar returns the first position in input holding a codepoint
// that is not a valid Unicode scalar; the second result is false when every
// codepoint is valid.
func hisFirstInvalidScalar(input []uint32) (int, bool) {
	for i, cp := range input {
		if !hisIsValidScalar(cp) {
			return i, true
		}
	}
	return 0, false
}

// hisEncHit is the (declared, detected, firstPos) triple returned by the
// encodingMismatch probe when it fires.
type hisEncHit struct {
	declared string
	detected string
	pos      int
}

// hisEncodingMismatchProbe runs the encodingMismatch probe. Validity is
// dispatched first — an invalid scalar fires with detected = "invalid"
// regardless of the declared label; otherwise a non-UTF-8 label fires with
// detected = "utf-8" at position 0. Returns nil when the probe does not fire.
func hisEncodingMismatchProbe(declared string, input []uint32) *hisEncHit {
	if pos, ok := hisFirstInvalidScalar(input); ok {
		return &hisEncHit{declared: declared, detected: "invalid", pos: pos}
	}
	if hisIsUTF8Label(declared) {
		return nil
	}
	return &hisEncHit{declared: declared, detected: "utf-8", pos: 0}
}

// hisPgp4880Violation runs the signedMessageRule probe for
// pgp4880TrailingWhitespace. Same condition as trailingWhitespace; returns the
// first position of the trailing run.
func hisPgp4880Violation(input []uint32) (int, bool) {
	trailing := hisCountTrailingWhitespace(input)
	if trailing > 0 {
		return len(input) - trailing, true
	}
	return 0, false
}

// hisPgp9580Violation runs the signedMessageRule probe for pgp9580LineEnding.
// First bare LF (U+000A not preceded by CR) or bare CR (U+000D not followed by
// LF).
func hisPgp9580Violation(input []uint32) (int, bool) {
	for i, cp := range input {
		if cp == 0x000A {
			// LF: violating iff not preceded by CR.
			precededByCR := i > 0 && input[i-1] == 0x000D
			if !precededByCR {
				return i, true
			}
		} else if cp == 0x000D {
			// CR: violating iff not followed by LF.
			followedByLF := i+1 < len(input) && input[i+1] == 0x000A
			if !followedByLF {
				return i, true
			}
		}
	}
	return 0, false
}

// hisRfc8785Violation runs the signedMessageRule probe for rfc8785NfcRequirement.
// Same condition as normalizationDrift; returns the first NFC divergence
// position.
func hisRfc8785Violation(input []uint32) (int, bool) {
	nfc := toNFC(input)
	if bip39EqualCps(input, nfc) {
		return 0, false
	}
	return bip39FirstArrayDivergence(input, nfc)
}

// hisRfc8259Violation runs the signedMessageRule probe for rfc8259ControlChar.
// First C0 control (U+0000..U+001F) — the JSON-permitted whitespace still
// requires escaping, so it also counts.
func hisRfc8259Violation(input []uint32) (int, bool) {
	for i, cp := range input {
		if cp <= 0x1F {
			return i, true
		}
	}
	return 0, false
}

// hisIsBase64URL reports whether cp is in the JWS Base64URL alphabet
// [A-Za-z0-9_-].
func hisIsBase64URL(cp uint32) bool {
	return (cp >= 0x41 && cp <= 0x5A) || // A-Z
		(cp >= 0x61 && cp <= 0x7A) || // a-z
		(cp >= 0x30 && cp <= 0x39) || // 0-9
		cp == 0x2D || // '-'
		cp == 0x5F // LOW LINE
}

// hisRfc7515Violation runs the signedMessageRule probe for rfc7515JwsBase64Url.
// First codepoint outside [A-Za-z0-9_-].
func hisRfc7515Violation(input []uint32) (int, bool) {
	for i, cp := range input {
		if !hisIsBase64URL(cp) {
			return i, true
		}
	}
	return 0, false
}

// hisIsDkimWhitespace reports whether cp is DKIM whitespace: U+0020 SPACE or
// U+0009 HTAB.
func hisIsDkimWhitespace(cp uint32) bool {
	return cp == 0x20 || cp == 0x09
}

// hisRfc6376Violation runs the signedMessageRule probe for rfc6376DkimRelaxed.
// Position of the second whitespace codepoint in the first internal whitespace
// run longer than one.
func hisRfc6376Violation(input []uint32) (int, bool) {
	for i, cp := range input {
		if hisIsDkimWhitespace(cp) && i > 0 && hisIsDkimWhitespace(input[i-1]) {
			return i, true
		}
	}
	return 0, false
}

// hisRfc5751Violation runs the signedMessageRule probe for rfc5751SmimeLineEnding.
// Reuses the PGP 9580 bare-line-ending rule.
func hisRfc5751Violation(input []uint32) (int, bool) {
	return hisPgp9580Violation(input)
}

// hisRfcRuleViolation dispatches the RFC-rule probe. First violation position;
// the second result is false when clean.
func hisRfcRuleViolation(rule hisRfcRule, input []uint32) (int, bool) {
	switch rule {
	case hisPgp4880TrailingWhitespace:
		return hisPgp4880Violation(input)
	case hisPgp9580LineEnding:
		return hisPgp9580Violation(input)
	case hisRfc8785NfcRequirement:
		return hisRfc8785Violation(input)
	case hisRfc8259ControlChar:
		return hisRfc8259Violation(input)
	case hisRfc7515JwsBase64Url:
		return hisRfc7515Violation(input)
	case hisRfc6376DkimRelaxed:
		return hisRfc6376Violation(input)
	case hisRfc5751SmimeLineEnding:
		return hisRfc5751Violation(input)
	}
	return 0, false
}

// ─────────────────────────────────────────────────────────────────────
// §7 Top-level detection
// ─────────────────────────────────────────────────────────────────────

// hisRfcHit is the (rule, pos) pair returned by the signedMessageRule probe
// when it fires.
type hisRfcHit struct {
	rule hisRfcRule
	pos  int
}

// hisDetectWithContext is the full detection function. It runs all six probes
// in priority order, with the context-bearing probes ahead of the generic ones.
func hisDetectWithContext(ctx hisContext, input []uint32) hisVerdict {
	stable := hisHashStable(input)

	// Probe 1: encodingMismatch.
	var encodingHit *hisEncHit
	if ctx.declaredEncoding != nil {
		encodingHit = hisEncodingMismatchProbe(*ctx.declaredEncoding, input)
	}

	// Probe 2: webhookSignatureDrift.
	var webhookHit *int
	if ctx.serverBytes != nil {
		if pos, ok := bip39FirstArrayDivergence(input, *ctx.serverBytes); ok {
			webhookHit = &pos
		}
	}

	// Probe 3: auditLogReinterpretation.
	var auditHit *int
	if ctx.asWritten != nil {
		if pos, ok := bip39FirstArrayDivergence(*ctx.asWritten, input); ok {
			auditHit = &pos
		}
	}

	// Probe 4: signedMessageRule.
	var rfcHit *hisRfcHit
	if ctx.rfcRule != nil {
		if pos, ok := hisRfcRuleViolation(*ctx.rfcRule, input); ok {
			rfcHit = &hisRfcHit{rule: *ctx.rfcRule, pos: pos}
		}
	}

	// Probe 5: trailingWhitespace.
	trailingCount := hisCountTrailingWhitespace(input)

	// Probe 6: normalizationDrift.
	nfc := toNFC(input)
	var nonNFCPos *int
	if !bip39EqualCps(input, nfc) {
		if pos, ok := bip39FirstArrayDivergence(input, nfc); ok {
			nonNFCPos = &pos
		}
	}

	classification := hisClassify(
		encodingHit,
		webhookHit,
		auditHit,
		rfcHit,
		trailingCount,
		len(input),
		nonNFCPos,
	)

	inputCopy := make([]uint32, len(input))
	copy(inputCopy, input)
	return hisVerdict{
		input:      inputCopy,
		classify:   classification,
		stableForm: stable,
		stableSize: len(stable),
	}
}

// hisClassify is the priority resolver: first hit wins, in the spec's fixed
// order.
func hisClassify(
	encodingHit *hisEncHit,
	webhookHit *int,
	auditHit *int,
	rfcHit *hisRfcHit,
	trailingCount int,
	inputLen int,
	nonNFCPos *int,
) hisClassification {
	if encodingHit != nil {
		return hisClassification{
			sub: hisSubThreat{
				tag:         "EncodingMismatch",
				declaredEnc: encodingHit.declared,
				detectedEnc: encodingHit.detected,
			},
			positions: []int{encodingHit.pos},
		}
	}
	if webhookHit != nil {
		return hisClassification{
			sub:       hisSubThreat{tag: "WebhookSignatureDrift", firstPos: *webhookHit},
			positions: []int{*webhookHit},
		}
	}
	if auditHit != nil {
		return hisClassification{
			sub:       hisSubThreat{tag: "AuditLogReinterpretation", firstDivergentPos: *auditHit},
			positions: []int{*auditHit},
		}
	}
	if rfcHit != nil {
		return hisClassification{
			sub:       hisSubThreat{tag: "SignedMessageRule", rfcRule: rfcHit.rule.tag(), firstPos: rfcHit.pos},
			positions: []int{rfcHit.pos},
		}
	}
	if trailingCount > 0 {
		p := inputLen - trailingCount
		return hisClassification{
			sub:       hisSubThreat{tag: "TrailingWhitespace", count: trailingCount},
			positions: []int{p},
		}
	}
	if nonNFCPos != nil {
		return hisClassification{
			sub:       hisSubThreat{tag: "NormalizationDrift", firstDivergentPos: *nonNFCPos},
			positions: []int{*nonNFCPos},
		}
	}
	return hisClassification{clear: true, positions: []int{}}
}

// hisDetect is the convenience wrapper over hisDetectWithContext with the empty
// context — equivalent to running only the two bare-input probes
// (trailingWhitespace, normalizationDrift).
func hisDetect(input []uint32) hisVerdict {
	return hisDetectWithContext(hisContext{}, input)
}
