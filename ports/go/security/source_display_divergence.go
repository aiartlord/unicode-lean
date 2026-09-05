package security

// source-display-divergence — the aggregate "what a reviewer sees differs from
// what the machine runs" detector (the display-layer aggregator, layer D).
//
// Byte-faithful port of Unicode/Security/Display/SourceDisplayDivergence.lean,
// mirroring the verified Rust port
// security/display/source_display_divergence.rs.
//
// Threat model. Tier D1. A single covert or identity trick may be individually
// benign-looking, but any hit means the rendered source diverges from its
// logical content; two or more is a strong compound signal. This detector runs
// the port's own five constituent detectors on the same codepoint stream and
// aggregates: zero fire → clear, exactly one → pass-through that family's tag,
// two or more → Compound. Every constituent fires region-agnostically — payloads
// inside string literals or comments count.
//
// Constituents reused (this port's own, in canonical aggregation order):
//	1. tag-block-payload          isTagCharacter              → "TagBlock"
//	2. variation-selector-payload variationSelectorFinding    → "VariationSelector"
//	3. zero-width-payload         isZeroWidthPayload          → "ZeroWidth"
//	4. bidi-control-balance       isBidiEmbeddingControl      → "BidiControl"
//	5. homoglyph-confusable       homoglyphConfusableFinding  → "IdentifierHomoglyph"
//
// No new predicate, no new data file, no host library — pure aggregation over
// existing port code. Positions are empty at this layer by the Lean spec (the
// per-family verdicts carry them); this detector carries only the sub-threat.

// sddDetection is one source-display-divergence scan result. When fired is false
// the input is clear; a single constituent hit passes through its family tag,
// two or more yield "Compound". Positions are empty at this layer.
type sddDetection struct {
	sub   string
	fired bool
}

// isClear reports whether the detection is Clear (no constituent fired).
func (d sddDetection) isClear() bool {
	return !d.fired
}

// tag is the human-facing sub-threat tag; the second result is false when clear.
func (d sddDetection) tag() (string, bool) {
	if !d.fired {
		return "", false
	}
	return d.sub, true
}

// sddTagBlockFired reports whether the port's own tag-block-payload constituent
// classifies the input as non-clear. The family fires on any tag character, not
// only the ASCII-bearing span, so a LANGUAGE TAG or a lone CANCEL TAG counts
// here as it does in the family's own verdict.
func sddTagBlockFired(input []uint32) bool {
	return len(positionsWhere(input, isTagCharacter)) > 0
}

// sddVariationSelectorFired reports whether the port's own
// variation-selector-payload constituent classifies the input as non-clear.
func sddVariationSelectorFired(input []uint32) bool {
	_, ok := variationSelectorFinding(input)
	return ok
}

// sddZeroWidthFired reports whether the port's own zero-width-payload constituent
// classifies the input as non-clear. A ZWJ inside a registered emoji sequence
// and a ZWNJ in an RFC 5892 CONTEXTJ-valid position are present but carry
// meaning a reader depends on, so they do not make the constituent fire.
func sddZeroWidthFired(input []uint32) bool {
	positions := positionsWhere(input, isZeroWidthPayload)
	return len(positions) > 0 && hasSuspiciousZeroWidth(input, positions)
}

// sddBidiControlFired reads purpose, not presence (Lean: the C5 constituent is
// BidiControlPurpose.hasPurposelessControl). A Trojan Source payload balances
// its controls, so the balance verdict is blind to it; what every payload
// shares is a control span with nothing right-to-left to manage. A balanced
// embedding around a pure Arabic literal is purposeful and is not a divergence.
func sddBidiControlFired(input []uint32) bool {
	return hasPurposelessControl(input)
}

// sourceDisplayDivergenceDetect reads the input as the identifier its
// constituents assume. Mirrors the Lean detect, which is detectCore with the
// homoglyph family's identifier-reading verdict.
func sourceDisplayDivergenceDetect(input []uint32) sddDetection {
	_, homoglyphFired := homoglyphConfusableFindingCtx(input, homoglyphContext{})
	return sourceDisplayDivergenceDetectCore(input, homoglyphFired)
}

// sourceDisplayDivergenceDetectCore aggregates the five constituent detectors
// into a single D1 verdict with the homoglyph constituent supplied:
// homoglyphFired is whether the homoglyph family fired on this input under
// whatever reading the caller took (whole input, or per identifier token of
// running text). Mirrors the Lean detectCore, which the policy scan calls with
// the same verdict the homoglyph family reports. Constituents are tested in
// canonical aggregation order and each firing tag is collected; the verdict is
// then clear (0), a pass-through of the lone firing tag (1), or Compound (2 or
// more).
func sourceDisplayDivergenceDetectCore(input []uint32, homoglyphFired bool) sddDetection {
	fires := make([]string, 0, 5)
	if sddTagBlockFired(input) {
		fires = append(fires, "TagBlock")
	}
	if sddVariationSelectorFired(input) {
		fires = append(fires, "VariationSelector")
	}
	if sddZeroWidthFired(input) {
		fires = append(fires, "ZeroWidth")
	}
	if sddBidiControlFired(input) {
		fires = append(fires, "BidiControl")
	}
	if homoglyphFired {
		fires = append(fires, "IdentifierHomoglyph")
	}

	if len(fires) == 0 {
		return sddDetection{fired: false}
	}
	if len(fires) == 1 {
		return sddDetection{sub: fires[0], fired: true}
	}
	return sddDetection{sub: "Compound", fired: true}
}
