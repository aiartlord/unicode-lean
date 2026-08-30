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
//	1. tag-block-payload          isTagBlockAsciiPayload      → "TagBlock"
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
// classifies the input as non-clear.
func sddTagBlockFired(input []uint32) bool {
	return len(positionsWhere(input, isTagBlockAsciiPayload)) > 0
}

// sddVariationSelectorFired reports whether the port's own
// variation-selector-payload constituent classifies the input as non-clear.
func sddVariationSelectorFired(input []uint32) bool {
	_, ok := variationSelectorFinding(input)
	return ok
}

// sddZeroWidthFired reports whether the port's own zero-width-payload constituent
// classifies the input as non-clear.
func sddZeroWidthFired(input []uint32) bool {
	return len(positionsWhere(input, isZeroWidthPayload)) > 0
}

// sddBidiControlFired reports whether the input carries any bidi format
// control.
func sddBidiControlFired(input []uint32) bool {
	// Presence, not balance. A Trojan Source payload balances its controls --
	// an unbalanced run breaks the file it is hiding in -- so a constituent
	// built on the balance verdict is blind to the shape the attack takes.
	for _, cp := range input {
		if isBidiFormatControl(cp) {
			return true
		}
	}
	return false
}

// sddHomoglyphFired reports whether the port's own homoglyph-confusable
// constituent classifies the input as non-clear.
func sddHomoglyphFired(input []uint32) bool {
	// The reference runs one homoglyph detector whose priority ladder ends in a
	// CrossScriptMix branch, so a cross-script identifier fires it even though
	// the policy surface reports that case under mixed-script-admissibility.
	// This port splits that ladder across two finding builders, so the
	// constituent has to consult both or it misses every input whose only
	// homoglyph signal is the script mix.
	if _, ok := homoglyphConfusableFinding(input); ok {
		return true
	}
	_, ok := mixedScriptAdmissibilityFinding(input)
	return ok
}

// sourceDisplayDivergenceDetect aggregates the five constituent detectors into a
// single D1 verdict. Constituents are tested in canonical aggregation order and
// each firing tag is collected; the verdict is then clear (0), a pass-through of
// the lone firing tag (1), or Compound (2 or more).
func sourceDisplayDivergenceDetect(input []uint32) sddDetection {
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
	if sddHomoglyphFired(input) {
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
