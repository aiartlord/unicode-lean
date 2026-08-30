package security

// identifier-form-drift — cross-layer identifier × form drift (boundary-layer
// detector, layer X).
//
// Byte-faithful port of Unicode/Security/Boundary/IdentifierFormDrift.lean,
// mirroring the verified Rust reference implementation.
//
// Threat model. Tier A₂ two-system bypass. An identity validator and a form
// normalizer disagree about a codepoint: stage A runs the UTS #39
// Identifier_Status check before normalisation and rejects, say, U+1D44E
// MATHEMATICAL ITALIC SMALL A (Restricted); stage B normalises first and then
// runs the same check, seeing U+0061 'a' (Allowed) and accepting. The attacker
// controls which stage processes the input and exploits the disagreement. The
// same shape covers fullwidth (U+FF21), circled (U+24B6), ligature (U+FB01),
// and Roman-numeral (U+2163) compatibility forms.
//
// The detector fires on the form transition itself — it reports every input
// position whose Identifier_Status differs from the Identifier_Status of that
// codepoint's NFKD head. This is orthogonal to the single-form
// identity-spoofing detectors and stronger than a form-of-input fold: it asks
// whether the identifier verdict changes, not whether any output bit changes.
//
// Note on Hangul: precomposed syllables are Allowed while their NFKD-head jamos
// are Restricted, so pure Korean text fires; callers intending to accept Korean
// identifiers should apply NFC before evaluating admissibility.
//
// It reuses the port's own UTS #39 Identifier_Status predicate (isIdAllowed) and
// NFKD pipeline (toNFKD), never a host normalization or identifier library.
//
// Sub-threat (direction-agnostic):
//	IdentifierStatusShift — the first input position whose Identifier_Status
//	differs from its NFKD-head's. The verdict carries the total shift count.

// ─────────────────────────────────────────────────────────────────────
// §1 Types
// ─────────────────────────────────────────────────────────────────────

// ifdSubThreat is the sub-threat this detector fired, in the port's
// struct-with-tag idiom. tag is the human-facing classification tag (the sole
// value is "IdentifierStatusShift"); basePos is the position of the
// status-shifting codepoint and cp is that codepoint.
type ifdSubThreat struct {
	tag     string
	basePos int
	cp      uint32
}

// ifdClassification is the top-level IdentifierFormDrift classification. When
// clear is true no status shift fired; otherwise sub names the fired sub-threat,
// positions holds the implicated codepoint positions, and decoded is the
// decoded-byte projection (always empty here, kept for shape parity with the
// Lean Classification.hazard).
type ifdClassification struct {
	clear     bool
	sub       ifdSubThreat
	positions []int
	decoded   []uint8
}

// isClear reports whether the classification is Clear.
func (c ifdClassification) isClear() bool {
	return c.clear
}

// tag is the human-facing tag for a hazard; the second result is false when
// clear.
func (c ifdClassification) tag() (string, bool) {
	if c.clear {
		return "", false
	}
	return c.sub.tag, true
}

// posns returns the implicated positions (empty when clear).
func (c ifdClassification) posns() []int {
	if c.clear {
		return []int{}
	}
	return c.positions
}

// ifdVerdict is the structured output of identifierFormDriftDetect (mirrors the
// Lean Verdict). shiftCount is the total count of positions whose
// Identifier_Status shifts under NFKD.
type ifdVerdict struct {
	input      []uint32
	classify   ifdClassification
	shiftCount int
}

// ─────────────────────────────────────────────────────────────────────
// §2 Core predicates
// ─────────────────────────────────────────────────────────────────────

// nfkdHeadAllowed reports the Identifier_Status = Allowed of the first codepoint
// of cp's NFKD form, or cp's own status when NFKD is empty (defensive — toNFKD
// is total and returns at least [cp]). Reuses the port's own UTS #39 predicate
// (isIdAllowed) and NFKD pipeline (toNFKD).
func nfkdHeadAllowed(cp uint32) bool {
	decomposed := toNFKD([]uint32{cp})
	if len(decomposed) > 0 {
		return isIdAllowed(decomposed[0])
	}
	return isIdAllowed(cp)
}

// ─────────────────────────────────────────────────────────────────────
// §3 Sub-detectors
// ─────────────────────────────────────────────────────────────────────

// ifdFirstStatusShift returns the first input position whose isIdAllowed differs
// from its NFKD-head's, with that codepoint; the third result is false when no
// position shifts.
func ifdFirstStatusShift(input []uint32) (int, uint32, bool) {
	for idx, cp := range input {
		if !isIdAllowed(cp) && nfkdHeadAllowed(cp) {
			return idx, cp, true
		}
	}
	return 0, 0, false
}

// ifdStatusShiftCount counts the input positions where the per-codepoint status
// shifts under NFKD.
func ifdStatusShiftCount(input []uint32) int {
	n := 0
	for _, cp := range input {
		if !isIdAllowed(cp) && nfkdHeadAllowed(cp) {
			n++
		}
	}
	return n
}

// ─────────────────────────────────────────────────────────────────────
// §4 Top-level detection
// ─────────────────────────────────────────────────────────────────────

// identifierFormDriftDetect is the IdentifierFormDrift detection function. The
// sole sub-threat fires on the first status-shifting position; the terminal
// else is the documented Clear verdict, not a catch-all default.
func identifierFormDriftDetect(input []uint32) ifdVerdict {
	inputCopy := make([]uint32, len(input))
	copy(inputCopy, input)

	classification := ifdClassify(input)

	return ifdVerdict{
		input:      inputCopy,
		classify:   classification,
		shiftCount: ifdStatusShiftCount(input),
	}
}

// ifdClassify emits the sole IdentifierStatusShift sub-threat when a status
// shift is present, else the documented Clear verdict.
func ifdClassify(input []uint32) ifdClassification {
	if pos, cp, ok := ifdFirstStatusShift(input); ok {
		return ifdClassification{
			sub:       ifdSubThreat{tag: "IdentifierStatusShift", basePos: pos, cp: cp},
			positions: []int{pos},
			decoded:   []uint8{},
		}
	}

	// No status shift fired: the input is clear.
	return ifdClassification{clear: true, positions: []int{}, decoded: []uint8{}}
}
