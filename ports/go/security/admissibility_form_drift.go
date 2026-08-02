package security

import "sync"

// admissibility-form-drift — cross-layer identifier-admissibility × form drift
// (boundary-layer detector, layer X).
//
// Byte-faithful port of Unicode/Security/Boundary/AdmissibilityFormDrift.lean,
// mirroring the verified Rust reference implementation.
//
// Fires on inputs whose UTS #39 whole-string isAllowedIdentifier verdict differs
// between the input and its NFKC form. This is the string-level complement of
// IdentifierFormDrift (which scans Identifier_Status against the per-codepoint
// NFKD head): here the whole-string admissibility predicate is evaluated twice —
// once on the input, once on toNFKC(input). The two are not redundant. In
// particular, a sequence of decomposed Hangul jamos passes the per-codepoint
// scan cleanly (each jamo has identity NFKD and Restricted status on both sides)
// but fires here: the jamo sequence is rejected by isAllowedIdentifier, while its
// NFKC composition into a precomposed Hangul syllable is accepted.
//
// It reuses the port's own UTS #39 admissibility predicate (isAllowedIdentifier =
// UAX #31 default identifier ∧ every codepoint Allowed) and NFKC pipeline
// (toNFKC), never a host normalization or identifier library.
//
// Sub-threat (direction-agnostic):
//	AdmissibilityFormDrift — isAllowedIdentifier(input) !=
//	isAllowedIdentifier(toNFKC(input)). The pair of booleans is carried so the
//	verdict records which direction the drift goes; no position is reported
//	because the predicate is whole-string.

// ─────────────────────────────────────────────────────────────────────
// §1 UAX #31 default identifier + UTS #39 whole-string admissibility
// ─────────────────────────────────────────────────────────────────────
//
// XID_Start / XID_Continue come from the port's own bundled
// DerivedCoreProperties.txt via parseCasingProperty (the same parser that drives
// Cased / Soft_Dotted / Grapheme_Extend). isIdAllowed (from IdentifierFormDrift)
// is the per-codepoint UTS #39 Identifier_Status test.

var (
	xidStartOnce      sync.Once
	xidStartRanges    [][2]uint32
	xidContinueOnce   sync.Once
	xidContinueRanges [][2]uint32
)

// isXidStart reports whether cp carries the XID_Start core property.
func isXidStart(cp uint32) bool {
	xidStartOnce.Do(func() { xidStartRanges = parseCasingProperty("XID_Start") })
	return inRanges(xidStartRanges, cp)
}

// isXidContinue reports whether cp carries the XID_Continue core property.
func isXidContinue(cp uint32) bool {
	xidContinueOnce.Do(func() { xidContinueRanges = parseCasingProperty("XID_Continue") })
	return inRanges(xidContinueRanges, cp)
}

// isDefaultIDStart is the UAX #31 default identifier start: XID_Start or
// U+005F LOW LINE.
func isDefaultIDStart(cp uint32) bool {
	return isXidStart(cp) || cp == 0x005F
}

// isDefaultIDContinue is the UAX #31 default identifier continue: XID_Continue.
func isDefaultIDContinue(cp uint32) bool {
	return isXidContinue(cp)
}

// isDefaultIdentifier reports whether cps is a well-formed UAX #31 default
// identifier: a non-empty sequence whose first codepoint is a default-id start
// and whose remaining codepoints are default-id continues.
func isDefaultIdentifier(cps []uint32) bool {
	if len(cps) == 0 {
		return false
	}
	if !isDefaultIDStart(cps[0]) {
		return false
	}
	for _, cp := range cps[1:] {
		if !isDefaultIDContinue(cp) {
			return false
		}
	}
	return true
}

// isAllowedIdentifier reports whether cps is a well-formed default identifier AND
// every codepoint has Identifier_Status = Allowed per UTS #39 (the whole-string
// admissibility predicate).
func isAllowedIdentifier(cps []uint32) bool {
	if !isDefaultIdentifier(cps) {
		return false
	}
	for _, cp := range cps {
		if !isIdAllowed(cp) {
			return false
		}
	}
	return true
}

// ─────────────────────────────────────────────────────────────────────
// §2 Types
// ─────────────────────────────────────────────────────────────────────

// afdSubThreat is the sub-threat this detector fired, in the port's
// struct-with-tag idiom. tag is the human-facing classification tag (the sole
// value is "AdmissibilityFormDrift"); inputAdmissible and nfkcAdmissible carry
// the two whole-string verdicts so the drift direction is recorded.
type afdSubThreat struct {
	tag             string
	inputAdmissible bool
	nfkcAdmissible  bool
}

// afdClassification is the top-level AdmissibilityFormDrift classification. When
// clear is true the admissibility verdict agrees across forms; otherwise sub
// names the fired sub-threat, positions holds the implicated codepoint positions
// (always empty — the predicate is whole-string), and decoded is the
// decoded-byte projection (always empty here, kept for shape parity with the
// Lean Classification.hazard).
type afdClassification struct {
	clear     bool
	sub       afdSubThreat
	positions []int
	decoded   []uint8
}

// isClear reports whether the classification is Clear.
func (c afdClassification) isClear() bool {
	return c.clear
}

// tag is the human-facing tag for a hazard; the second result is false when
// clear.
func (c afdClassification) tag() (string, bool) {
	if c.clear {
		return "", false
	}
	return c.sub.tag, true
}

// posns returns the implicated positions (always empty — the predicate is
// whole-string).
func (c afdClassification) posns() []int {
	if c.clear {
		return []int{}
	}
	return c.positions
}

// afdVerdict is the structured output of admissibilityFormDriftDetect (mirrors
// the Lean Verdict). inputAdmissible is isAllowedIdentifier(input);
// nfkcAdmissible is isAllowedIdentifier(toNFKC(input)).
type afdVerdict struct {
	input           []uint32
	classify        afdClassification
	inputAdmissible bool
	nfkcAdmissible  bool
}

// ─────────────────────────────────────────────────────────────────────
// §3 Top-level detection
// ─────────────────────────────────────────────────────────────────────

// admissibilityFormDriftDetect is the AdmissibilityFormDrift detection function.
// The sole sub-threat fires when the whole-string admissibility verdict of the
// input differs from that of its NFKC form; the terminal else is the documented
// Clear verdict, not a catch-all default.
func admissibilityFormDriftDetect(input []uint32) afdVerdict {
	inputCopy := make([]uint32, len(input))
	copy(inputCopy, input)

	nfkc := toNFKC(input)
	inOk := isAllowedIdentifier(input)
	nfkcOk := isAllowedIdentifier(nfkc)

	var classification afdClassification
	if inOk == nfkcOk {
		// The admissibility verdict agrees across forms: the input is clear.
		classification = afdClassification{clear: true, positions: []int{}, decoded: []uint8{}}
	} else {
		classification = afdClassification{
			sub: afdSubThreat{
				tag:             "AdmissibilityFormDrift",
				inputAdmissible: inOk,
				nfkcAdmissible:  nfkcOk,
			},
			positions: []int{},
			decoded:   []uint8{},
		}
	}

	return afdVerdict{
		input:           inputCopy,
		classify:        classification,
		inputAdmissible: inOk,
		nfkcAdmissible:  nfkcOk,
	}
}
