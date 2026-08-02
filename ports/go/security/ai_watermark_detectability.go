package security

import (
	_ "embed"
	"strconv"
	"strings"
	"sync"
)

// ai-watermark-detectability — character-level detector for inputs carrying
// codepoint patterns consistent with a known AI watermark scheme. Answers the
// question: does this input contain markers attributable to a watermarking
// protocol?
//
// Direct port of Unicode.Security.Crypto.AiWatermarkDetectability (mirroring the
// verified Rust port security/crypto/ai_watermark_detectability.rs).
//
// Threat model — provenance-attribution attacker. An input either (a) carries
// an AI provider's watermark codepoints (a legitimate provenance marker) or
// (b) carries injected markers that impersonate a provider's scheme to
// discredit the content as AI-generated. Character-level detection alone cannot
// distinguish (a) from (b); the detector reports the matched scheme and leaves
// provider-specific authentication to downstream code.
//
// Probe inventory (priority order, first match wins):
//
//	 1. adversarial              — NNBSP count >= 3 at arithmetic-progression positions.
//	 2. gpt5ZwspModulo           — ZWSP count >= 3 at arithmetic-progression positions.
//	 3. unknown                  — invisible markers from >= 2 distinct categories.
//	 4. nnbspBoundary            — single-category NNBSP.
//	 5. variationSelectorCarrier — VS NOT adjacent to an emoji codepoint.
//	 6. zwjNonEmoji              — ZWJ NOT adjacent to an emoji codepoint.
//	 7. smartQuoteAlternation    — paired curly quotes, no ASCII straight quotes.
//	 8. emDashPattern            — em-dashes, no ASCII hyphen-minus.
//	 9. statisticalTokenChoice   — input contains an AI-favored lexical pattern.
//	10. defaultIgnorableCarrier  — single-category residual Default_Ignorable.
//
// The Emoji property table is bundled in the port's own data/emoji-data.txt
// (UTS #51 17.0, byte-identical to the UCD source the Lean spec cites); the
// adjacency probe parses the Emoji rows from it, never a host emoji library.

// ─────────────────────────────────────────────────────────────────────
// §1 Types
// ─────────────────────────────────────────────────────────────────────

// aiwmCueClass is the conceptual watermark cue class a sub-threat probes for,
// drawn from the fixed vocabulary in
// Unicode.Generated.WatermarkSchemes.CueClass. Ported here because the port
// exposes no generated watermark-schemes module.
type aiwmCueClass int

const (
	// aiwmGreenListBias — a codepoint-frequency bias toward a pinned "green
	// list" of tokens.
	aiwmGreenListBias aiwmCueClass = iota
	// aiwmPseudorandomSeq — a fixed-period or carrier-byte channel surfacing a
	// pseudorandom function.
	aiwmPseudorandomSeq
	// aiwmSemanticDrift — a stylistic-distribution drift away from natural human
	// writing.
	aiwmSemanticDrift
)

// aiwmSubThreat is the sub-threat this detector fired. tag is the human-facing
// classification tag; the remaining fields carry the sub-threat's data (only
// those relevant to the fired tag are meaningful). The tag values, in the spec's
// declaration order, are: NnbspBoundary, VariationSelectorCarrier, ZwjNonEmoji,
// DefaultIgnorableCarrier, Gpt5ZwspModulo, EmDashPattern, SmartQuoteAlternation,
// StatisticalTokenChoice, Adversarial, Unknown.
type aiwmSubThreat struct {
	tag string
	// markerCount — NnbspBoundary, VariationSelectorCarrier, ZwjNonEmoji,
	// DefaultIgnorableCarrier.
	markerCount int
	// firstPos — Gpt5ZwspModulo, EmDashPattern, SmartQuoteAlternation,
	// StatisticalTokenChoice, Adversarial.
	firstPos int
	// impersonatedScheme — Adversarial (the scheme the over-regular placement
	// impersonates).
	impersonatedScheme string
	// anomalyMarker — Unknown (total invisible-marker count across all
	// categories).
	anomalyMarker int
}

// cueClass maps this sub-threat to the conceptual watermark cue class it probes
// for. Marker-encoded sub-threats route to aiwmPseudorandomSeq; vocabulary-bias
// to aiwmGreenListBias; stylistic-distribution to aiwmSemanticDrift; Unknown
// (multi-category mixing) implicates no single scheme, so the second result is
// false.
func (s aiwmSubThreat) cueClass() (aiwmCueClass, bool) {
	switch s.tag {
	case "NnbspBoundary", "VariationSelectorCarrier", "ZwjNonEmoji", "DefaultIgnorableCarrier":
		return aiwmPseudorandomSeq, true
	case "Gpt5ZwspModulo":
		return aiwmPseudorandomSeq, true
	case "EmDashPattern":
		return aiwmSemanticDrift, true
	case "SmartQuoteAlternation":
		return aiwmSemanticDrift, true
	case "StatisticalTokenChoice":
		return aiwmGreenListBias, true
	case "Adversarial":
		return aiwmPseudorandomSeq, true
	case "Unknown":
		return 0, false
	}
	return 0, false
}

// aiwmClassification is the top-level AiWatermarkDetectability classification.
// When clear is true no watermark marker was detected (semantically
// noWatermark); otherwise sub names the fired sub-threat and positions holds the
// implicated codepoint positions.
type aiwmClassification struct {
	clear     bool
	sub       aiwmSubThreat
	positions []int
}

// isClear reports whether no watermark marker was detected.
func (c aiwmClassification) isClear() bool {
	return c.clear
}

// tag is the human-facing tag for a hazard; the second result is false when
// clear.
func (c aiwmClassification) tag() (string, bool) {
	if c.clear {
		return "", false
	}
	return c.sub.tag, true
}

// aiwmVerdict is the structured output of aiwmDetect. markerCount is the count
// of codepoints matching the fired scheme's probe (0 when clear).
type aiwmVerdict struct {
	input      []uint32
	classify   aiwmClassification
	markerCount int
}

// aiwmContext carries the modulo-probe tolerances. Each field controls how
// strictly the corresponding probe checks its arithmetic-progression condition;
// the defaults of 0 require exact equality of consecutive gaps.
type aiwmContext struct {
	// zwspModuloTolerance — ZWSP-modulo tolerance. 0 requires the ZWSP-position
	// arithmetic progression to be exact. k > 0 accepts position gaps within
	// +/- k of the first gap, catching modulo schedules with light jitter.
	zwspModuloTolerance int
	// adversarialTolerance — NNBSP-arithmetic tolerance (the adversarial probe).
	// Same semantic as zwspModuloTolerance but for the NNBSP positions.
	adversarialTolerance int
}

// ─────────────────────────────────────────────────────────────────────
// §2 Emoji property table (bundled data/emoji-data.txt, Emoji rows)
// ─────────────────────────────────────────────────────────────────────

//go:embed data/emoji-data.txt
var aiwmEmojiDataRaw string

type aiwmRange struct {
	lo uint32
	hi uint32
}

var (
	aiwmEmojiRangesOnce  sync.Once
	aiwmEmojiRangesCache []aiwmRange
)

// aiwmParseEmojiRanges parses the Emoji (Emoji=Yes) closed intervals from
// emoji-data.txt. Each non-comment row is "<range> ; <property> # <comment>"; we
// keep only rows whose property is exactly "Emoji".
func aiwmParseEmojiRanges() []aiwmRange {
	out := []aiwmRange{}
	for _, rawLine := range strings.Split(aiwmEmojiDataRaw, "\n") {
		body := rawLine
		if idx := strings.IndexByte(body, '#'); idx >= 0 {
			body = body[:idx]
		}
		stripped := strings.TrimSpace(body)
		if stripped == "" {
			continue
		}
		fields := strings.Split(stripped, ";")
		if len(fields) < 2 {
			continue
		}
		if strings.TrimSpace(fields[1]) != "Emoji" {
			continue
		}
		rangeField := strings.TrimSpace(fields[0])
		if lohi := strings.SplitN(rangeField, "..", 2); len(lohi) == 2 {
			lo, errLo := strconv.ParseUint(strings.TrimSpace(lohi[0]), 16, 32)
			hi, errHi := strconv.ParseUint(strings.TrimSpace(lohi[1]), 16, 32)
			if errLo != nil || errHi != nil {
				continue
			}
			out = append(out, aiwmRange{lo: uint32(lo), hi: uint32(hi)})
		} else {
			single, err := strconv.ParseUint(rangeField, 16, 32)
			if err != nil {
				continue
			}
			out = append(out, aiwmRange{lo: uint32(single), hi: uint32(single)})
		}
	}
	return out
}

func aiwmEmojiRanges() []aiwmRange {
	aiwmEmojiRangesOnce.Do(func() {
		aiwmEmojiRangesCache = aiwmParseEmojiRanges()
	})
	return aiwmEmojiRangesCache
}

// aiwmIsEmoji reports whether cp has the Emoji = Yes property per
// emoji-data.txt.
func aiwmIsEmoji(cp uint32) bool {
	for _, r := range aiwmEmojiRanges() {
		if r.lo <= cp && cp <= r.hi {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────
// §3 Codepoint probes
// ─────────────────────────────────────────────────────────────────────

// aiwmIsNnbsp reports whether cp is U+202F NARROW NO-BREAK SPACE.
func aiwmIsNnbsp(cp uint32) bool {
	return cp == 0x202F
}

// aiwmIsZwj reports whether cp is U+200D ZERO WIDTH JOINER.
func aiwmIsZwj(cp uint32) bool {
	return cp == 0x200D
}

// aiwmIsVariationSelector reports whether cp is a Variation Selector — the basic
// block U+FE00..U+FE0F (VS1..VS16) or the Plane-14 IVS block U+E0100..U+E01EF
// (VS17..VS256).
func aiwmIsVariationSelector(cp uint32) bool {
	return (cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0xE0100 && cp <= 0xE01EF)
}

// aiwmIsDefaultIgnorable reports whether cp is Default_Ignorable_Code_Point.
// Reuses the port's own UCD predicate, never a host normalizer.
func aiwmIsDefaultIgnorable(cp uint32) bool {
	return isDefaultIgnorableCodepoint(cp)
}

// aiwmIsZwsp reports whether cp is U+200B ZERO WIDTH SPACE.
func aiwmIsZwsp(cp uint32) bool {
	return cp == 0x200B
}

// aiwmIsEmDash reports whether cp is U+2014 EM DASH.
func aiwmIsEmDash(cp uint32) bool {
	return cp == 0x2014
}

// aiwmIsHyphenMinus reports whether cp is U+002D HYPHEN-MINUS (ASCII).
func aiwmIsHyphenMinus(cp uint32) bool {
	return cp == 0x002D
}

// aiwmIsCurlyQuote reports whether cp is one of the four "curly" quotation
// marks: U+2018 / U+2019 (single open/close) and U+201C / U+201D (double
// open/close).
func aiwmIsCurlyQuote(cp uint32) bool {
	return cp == 0x2018 || cp == 0x2019 || cp == 0x201C || cp == 0x201D
}

// aiwmIsStraightQuote reports whether cp is an ASCII straight quote — U+0022
// (double) or U+0027 (single / apostrophe).
func aiwmIsStraightQuote(cp uint32) bool {
	return cp == 0x0022 || cp == 0x0027
}

// aiwmIsAdjacentToEmoji reports whether input[i] is adjacent (immediate
// predecessor OR immediate successor) to an emoji codepoint. Two-sided check,
// single pass. Used by the VS and ZWJ probes to exclude legitimate
// emoji-context occurrences.
func aiwmIsAdjacentToEmoji(input []uint32, i int) bool {
	prevIsEmoji := false
	if i > 0 && i-1 < len(input) {
		prevIsEmoji = aiwmIsEmoji(input[i-1])
	}
	nextIsEmoji := false
	if i+1 < len(input) {
		nextIsEmoji = aiwmIsEmoji(input[i+1])
	}
	return prevIsEmoji || nextIsEmoji
}

// aiwmAllPositions returns all positions in input matching predicate p.
func aiwmAllPositions(p func(uint32) bool, input []uint32) []int {
	out := []int{}
	for idx, cp := range input {
		if p(cp) {
			out = append(out, idx)
		}
	}
	return out
}

// aiwmPositionsAreArithmeticWithin reports whether positions forms an arithmetic
// progression with all consecutive gaps within tolerance of the first gap.
// Empty + singleton lists are vacuously arithmetic. positions is assumed
// ascending (produced by aiwmAllPositions), so gaps are non-negative.
func aiwmPositionsAreArithmeticWithin(positions []int, tolerance int) bool {
	if len(positions) < 2 {
		return true
	}
	firstGap := positions[1] - positions[0]
	for i := 0; i < len(positions)-1; i++ {
		gap := positions[i+1] - positions[i]
		if !(gap <= firstGap+tolerance && firstGap <= gap+tolerance) {
			return false
		}
	}
	return true
}

// aiwmContainsSublist returns the first start-position at which pattern appears
// as a contiguous sub-slice of input; the second result is false when absent.
func aiwmContainsSublist(pattern []uint32, input []uint32) (int, bool) {
	if len(pattern) == 0 || len(pattern) > len(input) {
		return 0, false
	}
	maxStart := len(input) - len(pattern)
	for start := 0; start <= maxStart; start++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if input[start+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return start, true
		}
	}
	return 0, false
}

// aiwmAiFavoredVocabulary is the "AI-favored" lexical-pattern catalog (each word
// as its codepoint sequence), transcribed verbatim from the pinned
// aiFavoredVocabulary literal in the Lean spec (parsed from
// Ucd/Security/AiFavoredVocabulary.txt and drift-gated there against a fresh
// parse).
func aiwmAiFavoredVocabulary() [][]uint32 {
	return [][]uint32{
		{100, 101, 108, 118, 101},
		{100, 101, 108, 118, 105, 110, 103},
		{116, 97, 112, 101, 115, 116, 114, 121},
		{105, 110, 116, 114, 105, 99, 97, 116, 101},
		{110, 117, 97, 110, 99, 101, 100},
		{109, 111, 114, 101, 111, 118, 101, 114},
		{102, 117, 114, 116, 104, 101, 114, 109, 111, 114, 101},
		{114, 101, 97, 108, 109},
		{101, 108, 117, 99, 105, 100, 97, 116, 101},
		{115, 104, 111, 119, 99, 97, 115, 105, 110, 103},
		{117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 115},
		{117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 100},
		{112, 105, 118, 111, 116, 97, 108},
		{98, 111, 108, 115, 116, 101, 114},
		{109, 117, 108, 116, 105, 102, 97, 99, 101, 116, 101, 100},
		{116, 101, 115, 116, 97, 109, 101, 110, 116},
		{102, 111, 115, 116, 101, 114},
		{104, 111, 108, 105, 115, 116, 105, 99},
		{112, 97, 114, 97, 100, 105, 103, 109},
		{116, 114, 97, 110, 115, 102, 111, 114, 109, 97, 116, 105, 118, 101},
		{115, 112, 101, 97, 114, 104, 101, 97, 100},
		{109, 101, 116, 105, 99, 117, 108, 111, 117, 115},
		{109, 101, 116, 105, 99, 117, 108, 111, 117, 115, 108, 121},
		{101, 109, 112, 111, 119, 101, 114},
		{101, 109, 112, 111, 119, 101, 114, 105, 110, 103},
		{112, 114, 111, 102, 111, 117, 110, 100},
		{112, 114, 111, 102, 111, 117, 110, 100, 108, 121},
		{99, 111, 109, 112, 101, 108, 108, 105, 110, 103},
		{99, 111, 109, 112, 114, 101, 104, 101, 110, 115, 105, 118, 101},
		{99, 114, 117, 99, 105, 97, 108},
		{100, 97, 117, 110, 116, 105, 110, 103},
		{114, 111, 98, 117, 115, 116},
		{115, 116, 114, 101, 97, 109, 108, 105, 110, 101},
		{101, 110, 114, 105, 99, 104},
		{101, 120, 101, 109, 112, 108, 105, 102, 121},
		{99, 97, 112, 116, 105, 118, 97, 116, 105, 110, 103},
		{100, 105, 115, 99, 101, 114, 110, 105, 110, 103},
		{109, 101, 115, 109, 101, 114, 105, 122, 101},
		{105, 110, 116, 114, 105, 99, 97, 116, 101, 108, 121},
		{105, 109, 98, 117, 101},
		{
			112, 108, 97, 121, 115, 32, 97, 32, 99, 114, 117, 99, 105, 97, 108, 32, 114, 111, 108,
			101,
		},
		{
			112, 108, 97, 121, 115, 32, 97, 32, 112, 105, 118, 111, 116, 97, 108, 32, 114, 111,
			108, 101,
		},
		{
			105, 116, 32, 105, 115, 32, 105, 109, 112, 111, 114, 116, 97, 110, 116, 32, 116, 111,
			32, 110, 111, 116, 101,
		},
		{
			105, 116, 32, 105, 115, 32, 119, 111, 114, 116, 104, 32, 110, 111, 116, 105, 110, 103,
		},
		{105, 110, 32, 99, 111, 110, 99, 108, 117, 115, 105, 111, 110},
		{105, 110, 32, 101, 115, 115, 101, 110, 99, 101},
		{100, 101, 108, 118, 101, 32, 105, 110, 116, 111},
		{100, 101, 108, 118, 105, 110, 103, 32, 105, 110, 116, 111},
		{116, 97, 112, 101, 115, 116, 114, 121, 32, 111, 102},
		{114, 101, 97, 108, 109, 32, 111, 102},
	}
}

// ─────────────────────────────────────────────────────────────────────
// §4 Top-level detection
// ─────────────────────────────────────────────────────────────────────

// aiwmDetectWithContext is the detection function. It runs every probe in the
// fixed priority order (most-specific first); the first hit wins. See the module
// header for the probe inventory and the ordering rationale.
func aiwmDetectWithContext(ctx aiwmContext, input []uint32) aiwmVerdict {
	nnbspPositions := aiwmAllPositions(aiwmIsNnbsp, input)
	nnbspCount := len(nnbspPositions)

	// Probe 1: adversarial — NNBSP too-regular.
	adversarialFires := nnbspCount >= 3 &&
		aiwmPositionsAreArithmeticWithin(nnbspPositions, ctx.adversarialTolerance)

	// Probe 2: gpt5ZwspModulo — ZWSP arithmetic progression.
	zwspPositions := aiwmAllPositions(aiwmIsZwsp, input)
	zwspCount := len(zwspPositions)
	zwspModuloFires := zwspCount >= 3 &&
		aiwmPositionsAreArithmeticWithin(zwspPositions, ctx.zwspModuloTolerance)

	vsAllPos := aiwmAllPositions(aiwmIsVariationSelector, input)
	vsNonEmojiPos := []int{}
	for _, i := range vsAllPos {
		if !aiwmIsAdjacentToEmoji(input, i) {
			vsNonEmojiPos = append(vsNonEmojiPos, i)
		}
	}
	vsNonEmojiCount := len(vsNonEmojiPos)

	zwjAllPos := aiwmAllPositions(aiwmIsZwj, input)
	zwjNonEmojiPos := []int{}
	for _, i := range zwjAllPos {
		if !aiwmIsAdjacentToEmoji(input, i) {
			zwjNonEmojiPos = append(zwjNonEmojiPos, i)
		}
	}
	zwjNonEmojiCount := len(zwjNonEmojiPos)

	// Probe 7: smartQuoteAlternation — curly quotes only.
	curlyPositions := aiwmAllPositions(aiwmIsCurlyQuote, input)
	curlyCount := len(curlyPositions)
	hasStraightQuote := false
	for _, cp := range input {
		if aiwmIsStraightQuote(cp) {
			hasStraightQuote = true
			break
		}
	}
	smartQuoteFires := curlyCount >= 2 && !hasStraightQuote

	// Probe 8: emDashPattern — em-dashes without hyphen-minus.
	emDashPositions := aiwmAllPositions(aiwmIsEmDash, input)
	emDashCount := len(emDashPositions)
	hasHyphenMinus := false
	for _, cp := range input {
		if aiwmIsHyphenMinus(cp) {
			hasHyphenMinus = true
			break
		}
	}
	emDashFires := emDashCount >= 2 && !hasHyphenMinus

	// Probe 9: statisticalTokenChoice — scan the pinned vocabulary. Each word is
	// compared as a contiguous sub-slice of the input.
	vocabPos := 0
	vocabHit := false
	for _, pattern := range aiwmAiFavoredVocabulary() {
		if pos, ok := aiwmContainsSublist(pattern, input); ok {
			vocabPos = pos
			vocabHit = true
			break
		}
	}

	// Residual default-ignorables (excluding VS and ZWJ, handled above).
	isResidualDI := func(cp uint32) bool {
		return aiwmIsDefaultIgnorable(cp) && !aiwmIsVariationSelector(cp) && !aiwmIsZwj(cp)
	}
	diPositions := aiwmAllPositions(isResidualDI, input)
	diCount := len(diPositions)

	// Probe 3: unknown — invisible markers from >= 2 distinct categories.
	categoryCount := boolToInt(nnbspCount > 0) +
		boolToInt(vsNonEmojiCount > 0) +
		boolToInt(zwjNonEmojiCount > 0) +
		boolToInt(diCount > 0)
	unknownFires := categoryCount >= 2
	totalInvisibleCount := nnbspCount + vsNonEmojiCount + zwjNonEmojiCount + diCount

	var classification aiwmClassification
	var firedCount int

	switch {
	case adversarialFires:
		firstPos := 0
		if len(nnbspPositions) > 0 {
			firstPos = nnbspPositions[0]
		}
		classification = aiwmClassification{
			sub: aiwmSubThreat{
				tag:                "Adversarial",
				impersonatedScheme: "nnbspBoundary",
				firstPos:           firstPos,
			},
			positions: nnbspPositions,
		}
		firedCount = nnbspCount
	case zwspModuloFires:
		firstPos := 0
		if len(zwspPositions) > 0 {
			firstPos = zwspPositions[0]
		}
		classification = aiwmClassification{
			sub:       aiwmSubThreat{tag: "Gpt5ZwspModulo", firstPos: firstPos},
			positions: zwspPositions,
		}
		firedCount = zwspCount
	case unknownFires:
		allInvisiblePos := []int{}
		for idx, cp := range input {
			if aiwmIsNnbsp(cp) ||
				aiwmIsVariationSelector(cp) ||
				aiwmIsZwj(cp) ||
				aiwmIsDefaultIgnorable(cp) {
				allInvisiblePos = append(allInvisiblePos, idx)
			}
		}
		classification = aiwmClassification{
			sub:       aiwmSubThreat{tag: "Unknown", anomalyMarker: totalInvisibleCount},
			positions: allInvisiblePos,
		}
		firedCount = totalInvisibleCount
	case nnbspCount > 0:
		classification = aiwmClassification{
			sub:       aiwmSubThreat{tag: "NnbspBoundary", markerCount: nnbspCount},
			positions: nnbspPositions,
		}
		firedCount = nnbspCount
	case vsNonEmojiCount > 0:
		classification = aiwmClassification{
			sub:       aiwmSubThreat{tag: "VariationSelectorCarrier", markerCount: vsNonEmojiCount},
			positions: vsNonEmojiPos,
		}
		firedCount = vsNonEmojiCount
	case zwjNonEmojiCount > 0:
		classification = aiwmClassification{
			sub:       aiwmSubThreat{tag: "ZwjNonEmoji", markerCount: zwjNonEmojiCount},
			positions: zwjNonEmojiPos,
		}
		firedCount = zwjNonEmojiCount
	case smartQuoteFires:
		firstPos := 0
		if len(curlyPositions) > 0 {
			firstPos = curlyPositions[0]
		}
		classification = aiwmClassification{
			sub:       aiwmSubThreat{tag: "SmartQuoteAlternation", firstPos: firstPos},
			positions: curlyPositions,
		}
		firedCount = curlyCount
	case emDashFires:
		firstPos := 0
		if len(emDashPositions) > 0 {
			firstPos = emDashPositions[0]
		}
		classification = aiwmClassification{
			sub:       aiwmSubThreat{tag: "EmDashPattern", firstPos: firstPos},
			positions: emDashPositions,
		}
		firedCount = emDashCount
	case vocabHit:
		classification = aiwmClassification{
			sub:       aiwmSubThreat{tag: "StatisticalTokenChoice", firstPos: vocabPos},
			positions: []int{vocabPos},
		}
		firedCount = 1
	case diCount > 0:
		classification = aiwmClassification{
			sub:       aiwmSubThreat{tag: "DefaultIgnorableCarrier", markerCount: diCount},
			positions: diPositions,
		}
		firedCount = diCount
	default:
		classification = aiwmClassification{clear: true, positions: []int{}}
		firedCount = 0
	}

	inputCopy := make([]uint32, len(input))
	copy(inputCopy, input)
	return aiwmVerdict{
		input:       inputCopy,
		classify:    classification,
		markerCount: firedCount,
	}
}

// aiwmDetect is the convenience wrapper over aiwmDetectWithContext with the
// empty context — exact-arithmetic settings (zwspModuloTolerance = 0,
// adversarialTolerance = 0).
func aiwmDetect(input []uint32) aiwmVerdict {
	return aiwmDetectWithContext(aiwmContext{}, input)
}

// boolToInt maps false to 0 and true to 1, mirroring Rust's usize::from(bool).
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
