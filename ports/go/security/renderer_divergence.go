package security

import "sync"

// renderer-divergence — detection of codepoint/sequence shapes known to render
// differently across font + terminal + browser stacks (the display-layer
// detector, layer D).
//
// Byte-faithful port of Unicode/Security/Display/RendererDivergence.lean,
// mirroring the verified Rust port
// security/display/renderer_divergence.rs.
//
// Threat model. An adversary crafts content that renders one way in the
// auditor's renderer (a benign glyph or an empty span) and a different way in
// the consumer's renderer (a misleading glyph, a wider glyph, or a different
// sequence). This is the "fingerprint stability" family — clear inputs render
// the same across the renderer cohort the Standard documents as stable.
//
// What the detector draws. A heuristic three-value split, surfaced through the
// universal clear/hazard carrier: an input is clear when none of the documented
// variance triggers fire, and otherwise is classified by the first trigger in
// priority order — combining-mark stack overflow, variation-selector presence,
// an unregistered ZWJ shape, fullwidth/halfwidth display, or mixed direction.
// It reuses the port's own tables (the variation-selector predicate
// isVariationSelector, the Grapheme_Extend property from the bundled
// DerivedCoreProperties.txt, the RGI ZWJ registry
// ezwjIsRegisteredZwjSequence, and the strong-bidi predicates
// isStrongLtr / isStrongRtl), never a host rendering or shaping library.
//
// Sub-threats (priority order):
//	1. CombiningStackOverflow    Zalgo-like combining-mark stack >= 4 on a base.
//	2. VariationSelectorVariance any variation selector present.
//	3. UnregisteredZwjVariance   ZWJ-containing input not in the RGI ZWJ set.
//	4. FullwidthVariance         a fullwidth/halfwidth codepoint present.
//	5. MixedDirectionVariance    both strong-LTR and strong-RTL codepoints.

// ─────────────────────────────────────────────────────────────────────
// §1 Constants
// ─────────────────────────────────────────────────────────────────────

// rdMinCombiningStack is the combining-mark stack depth (on a single base) at or
// beyond which the input is treated as a Zalgo-style rendering-variance hazard.
const rdMinCombiningStack = 4

// rdZWJ is the ZERO WIDTH JOINER codepoint.
const rdZWJ uint32 = 0x200D

// ─────────────────────────────────────────────────────────────────────
// §2 Types
// ─────────────────────────────────────────────────────────────────────

// rdSubThreat is the sub-threat this detector fired, in the port's
// struct-with-tag idiom (mirroring ezwjSubThreat). tag is the human-facing
// classification tag; the remaining fields carry the sub-threat's data (only
// those relevant to the fired tag are meaningful). The tag values, in priority
// order, are: CombiningStackOverflow, VariationSelectorVariance,
// UnregisteredZwjVariance, FullwidthVariance, MixedDirectionVariance.
type rdSubThreat struct {
	tag string
	// basePos — CombiningStackOverflow: position of the base the stack sits on.
	basePos int
	// stackLen — CombiningStackOverflow: the stack depth tested (>= rdMinCombiningStack).
	stackLen int
	// firstVsPos — VariationSelectorVariance: position of the first variation selector.
	firstVsPos int
	// firstVsCp — VariationSelectorVariance: codepoint of the first variation selector.
	firstVsCp uint32
	// firstZwjPos — UnregisteredZwjVariance: position of the first ZWJ.
	firstZwjPos int
	// firstFwPos — FullwidthVariance: position of the first fullwidth/halfwidth codepoint.
	firstFwPos int
	// firstFwCp — FullwidthVariance: the fullwidth/halfwidth codepoint.
	firstFwCp uint32
	// ltrCount — MixedDirectionVariance: count of strong-LTR codepoints.
	ltrCount int
	// rtlCount — MixedDirectionVariance: count of strong-RTL codepoints.
	rtlCount int
}

// rdClassification is the top-level RendererDivergence classification. When
// clear is true rendering is consistent across the documented renderer cohort;
// otherwise sub names the fired sub-threat, positions holds the implicated
// codepoint positions, and decoded is the decoded-byte projection (always empty
// here, kept for shape parity with the Lean Classification.hazard).
type rdClassification struct {
	clear     bool
	sub       rdSubThreat
	positions []int
	decoded   []uint8
}

// isClear reports whether the classification is Clear (i.e. stable).
func (c rdClassification) isClear() bool {
	return c.clear
}

// tag is the human-facing tag for a hazard; the second result is false when
// clear.
func (c rdClassification) tag() (string, bool) {
	if c.clear {
		return "", false
	}
	return c.sub.tag, true
}

// posns returns the implicated positions (empty when clear).
func (c rdClassification) posns() []int {
	if c.clear {
		return []int{}
	}
	return c.positions
}

// rdVerdict is the structured output of rendererDivergenceDetect (mirrors the
// Lean Verdict).
type rdVerdict struct {
	input          []uint32
	classify       rdClassification
	vsCount        int
	combiningCount int
	fullwidthCount int
	hasZwj         bool
	strongLtrCount int
	strongRtlCount int
}

// ─────────────────────────────────────────────────────────────────────
// §3 Grapheme_Extend data (reuses the bundled DerivedCoreProperties.txt)
// ─────────────────────────────────────────────────────────────────────

var (
	rdGraphemeExtendOnce   sync.Once
	rdGraphemeExtendRanges [][2]uint32
)

// rdGraphemeExtendProperty reports whether cp carries the Grapheme_Extend core
// property, read from the port's own bundled DerivedCoreProperties.txt via the
// shared parseCasingProperty machinery (no new data file, no host library).
func rdGraphemeExtendProperty(cp uint32) bool {
	rdGraphemeExtendOnce.Do(func() {
		rdGraphemeExtendRanges = parseCasingProperty("Grapheme_Extend")
	})
	return inRanges(rdGraphemeExtendRanges, cp)
}

// ─────────────────────────────────────────────────────────────────────
// §4 Core predicates
// ─────────────────────────────────────────────────────────────────────

// rdIsZwj reports whether cp is the ZWJ codepoint.
func rdIsZwj(cp uint32) bool {
	return cp == rdZWJ
}

// rdIsGraphemeExtend reports whether cp has Grapheme_Cluster_Break = Extend.
//
// The port bundles DerivedCoreProperties.txt (Grapheme_Extend) but not
// GraphemeBreakProperty.txt. The two sets are identical here save for one range:
// the emoji skin-tone modifiers U+1F3FB..U+1F3FF, which have GCB = Extend but
// are not Grapheme_Extend. The port already carries that range as
// ezwjIsEmojiModifier, so their union reproduces the verified Rust reference's
// grapheme::is_grapheme_extend byte-for-byte, using only tables already bundled.
func rdIsGraphemeExtend(cp uint32) bool {
	return rdGraphemeExtendProperty(cp) || ezwjIsEmojiModifier(cp)
}

// ─────────────────────────────────────────────────────────────────────
// §5 Sub-detectors
// ─────────────────────────────────────────────────────────────────────

func rdCountVs(input []uint32) int {
	n := 0
	for _, cp := range input {
		if isVariationSelector(cp) {
			n++
		}
	}
	return n
}

func rdCountCombining(input []uint32) int {
	n := 0
	for _, cp := range input {
		if rdIsGraphemeExtend(cp) {
			n++
		}
	}
	return n
}

func rdCountFullwidth(input []uint32) int {
	n := 0
	for _, cp := range input {
		if isFullwidthHalfwidth(cp) {
			n++
		}
	}
	return n
}

func rdInputHasZwj(input []uint32) bool {
	for _, cp := range input {
		if rdIsZwj(cp) {
			return true
		}
	}
	return false
}

func rdCountStrongLtr(input []uint32) int {
	n := 0
	for _, cp := range input {
		if isStrongLtr(cp) {
			n++
		}
	}
	return n
}

func rdCountStrongRtl(input []uint32) int {
	n := 0
	for _, cp := range input {
		if isStrongRtl(cp) {
			n++
		}
	}
	return n
}

// rdFirstVsPos returns the position and codepoint of the first variation selector.
func rdFirstVsPos(input []uint32) (int, uint32, bool) {
	for idx, cp := range input {
		if isVariationSelector(cp) {
			return idx, cp, true
		}
	}
	return 0, 0, false
}

// rdFirstZwjPos returns the position of the first ZWJ.
func rdFirstZwjPos(input []uint32) (int, bool) {
	for idx, cp := range input {
		if rdIsZwj(cp) {
			return idx, true
		}
	}
	return 0, false
}

// rdFirstFullwidthPos returns the position and codepoint of the first
// fullwidth/halfwidth codepoint.
func rdFirstFullwidthPos(input []uint32) (int, uint32, bool) {
	for idx, cp := range input {
		if isFullwidthHalfwidth(cp) {
			return idx, cp, true
		}
	}
	return 0, 0, false
}

// rdFirstCombiningStack returns the first base position (a non-Extend codepoint)
// immediately followed by at least minStack consecutive Extend codepoints,
// together with minStack, as (basePos, stackLen, found).
func rdFirstCombiningStack(input []uint32, minStack int) (int, int, bool) {
	for idx, cp := range input {
		if rdIsGraphemeExtend(cp) {
			continue
		}
		following := 0
		for offset := idx + 1; offset < len(input) && following < minStack; offset++ {
			if !rdIsGraphemeExtend(input[offset]) {
				break
			}
			following++
		}
		if following == minStack {
			return idx, minStack, true
		}
	}
	return 0, 0, false
}

// ─────────────────────────────────────────────────────────────────────
// §6 Top-level detection
// ─────────────────────────────────────────────────────────────────────

// rendererDivergenceDetect is the RendererDivergence detection function.
func rendererDivergenceDetect(input []uint32) rdVerdict {
	vsCount := rdCountVs(input)
	combiningCount := rdCountCombining(input)
	fullwidthCount := rdCountFullwidth(input)
	hasZwj := rdInputHasZwj(input)
	ltrCount := rdCountStrongLtr(input)
	rtlCount := rdCountStrongRtl(input)

	inputCopy := make([]uint32, len(input))
	copy(inputCopy, input)

	classification := rdClassify(input, hasZwj, ltrCount, rtlCount)

	return rdVerdict{
		input:          inputCopy,
		classify:       classification,
		vsCount:        vsCount,
		combiningCount: combiningCount,
		fullwidthCount: fullwidthCount,
		hasZwj:         hasZwj,
		strongLtrCount: ltrCount,
		strongRtlCount: rtlCount,
	}
}

// rdClassify walks the five variance triggers in priority order, mirroring the
// Rust reference's nested match. Every arm is explicit; the terminal else is the
// documented Clear verdict, not a catch-all default.
func rdClassify(input []uint32, hasZwj bool, ltrCount, rtlCount int) rdClassification {
	// Priority 1: combining-mark stack overflow (Zalgo).
	if basePos, stackLen, ok := rdFirstCombiningStack(input, rdMinCombiningStack); ok {
		return rdClassification{
			sub:       rdSubThreat{tag: "CombiningStackOverflow", basePos: basePos, stackLen: stackLen},
			positions: []int{basePos},
			decoded:   []uint8{},
		}
	}

	// Priority 2: any variation selector triggers presentation variance.
	if pos, cp, ok := rdFirstVsPos(input); ok {
		return rdClassification{
			sub:       rdSubThreat{tag: "VariationSelectorVariance", firstVsPos: pos, firstVsCp: cp},
			positions: []int{pos},
			decoded:   []uint8{},
		}
	}

	// Priority 3: ZWJ-containing input not in the registered RGI set.
	if hasZwj && !ezwjIsRegisteredZwjSequence(input) {
		if pos, ok := rdFirstZwjPos(input); ok {
			return rdClassification{
				sub:       rdSubThreat{tag: "UnregisteredZwjVariance", firstZwjPos: pos},
				positions: []int{pos},
				decoded:   []uint8{},
			}
		}
		return rdClassification{clear: true, positions: []int{}, decoded: []uint8{}}
	}

	// Priority 4: fullwidth/halfwidth.
	if pos, cp, ok := rdFirstFullwidthPos(input); ok {
		return rdClassification{
			sub:       rdSubThreat{tag: "FullwidthVariance", firstFwPos: pos, firstFwCp: cp},
			positions: []int{pos},
			decoded:   []uint8{},
		}
	}

	// Priority 5: mixed direction.
	if ltrCount > 0 && rtlCount > 0 {
		return rdClassification{
			sub:       rdSubThreat{tag: "MixedDirectionVariance", ltrCount: ltrCount, rtlCount: rtlCount},
			positions: []int{},
			decoded:   []uint8{},
		}
	}

	// No documented variance trigger fired: rendering is stable.
	return rdClassification{clear: true, positions: []int{}, decoded: []uint8{}}
}
