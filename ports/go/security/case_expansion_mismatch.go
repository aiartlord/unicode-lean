package security

// case-expansion-mismatch — codepoints whose UAX #21 default-locale case mapping
// changes the codepoint count (the form-layer detector, layer F).
//
// Byte-faithful port of Unicode/Security/Form/CaseExpansionMismatch.lean,
// mirroring the verified Rust reference implementation.
//
// Threat model. Tier A1..A2. An attacker submits text whose case-mapped form has
// a different codepoint count than the input. A receiver that fixes a 16-byte
// username column and stores toUpper(username) overflows when the user picks
// "ßßßßßßßß" (8 in → 16 stored); a receiver that checks len(stored) == len(input)
// rejects valid case-insensitive logins whose names expand under folding.
// Examples: U+00DF ß → "SS", U+FB01 ﬁ → "FI", U+0130 İ → toLower "i̇" (i + U+0307).
//
// Distinct from locale-case-inversion (case mapping that changes ACROSS locales):
// this fires on shapes whose mapping is locale-stable but length-changing under
// the default locale itself.
//
// It reuses the port's own UAX #21 case mapping (upperCodepoint / lowerCodepoint,
// which evaluate the SpecialCasing context predicates), never a host casing
// library.
//
// Sub-threats (priority order):
//	1. UpperExpansion — first position whose default upperCodepoint yields > 1 cp.
//	2. LowerExpansion — first position whose default lowerCodepoint yields > 1 cp
//	   (reached only when no upper expansion fires first).

// ─────────────────────────────────────────────────────────────────────
// §1 upperCodepoint — the additive mirror of lowerCodepoint
// ─────────────────────────────────────────────────────────────────────

// upperCodepoint uppercases a single codepoint in its full input context (UAX
// #21): the SpecialCasing row whose conditions hold (its uppercase column), else
// the simple uppercase mapping. revPrefix is the preceding codepoints
// nearest-first; suffix the strictly-following ones. Mirrors lowerCodepoint
// exactly, reusing the port's own findSpecialRow + conditionsHold machinery, and
// returns the row's upper column instead of its lower one.
func upperCodepoint(locale casingLocale, revPrefix, suffix []uint32, cp uint32) []uint32 {
	if row, ok := findSpecialRow(locale, revPrefix, suffix, cp); ok {
		return row.upper
	}
	return []uint32{simpleUppercase(cp)}
}

// ─────────────────────────────────────────────────────────────────────
// §2 Types
// ─────────────────────────────────────────────────────────────────────

// cemSubThreat is the sub-threat this detector fired, in the port's
// struct-with-tag idiom. tag is the human-facing classification tag; the
// remaining fields carry the sub-threat's data. The tag values, in priority
// order, are: UpperExpansion, LowerExpansion.
type cemSubThreat struct {
	tag string
	// basePos — position of the expanding codepoint.
	basePos int
	// cp — the expanding codepoint.
	cp uint32
	// expansionLen — length of the case-mapped expansion (> 1).
	expansionLen int
}

// cemClassification is the top-level CaseExpansionMismatch classification. When
// clear is true no expansion fired; otherwise sub names the fired sub-threat,
// positions holds the implicated codepoint positions, and decoded is the
// decoded-byte projection (always empty here, kept for shape parity with the
// Lean Classification.hazard).
type cemClassification struct {
	clear     bool
	sub       cemSubThreat
	positions []int
	decoded   []uint8
}

// isClear reports whether the classification is Clear.
func (c cemClassification) isClear() bool {
	return c.clear
}

// tag is the human-facing tag for a hazard; the second result is false when
// clear.
func (c cemClassification) tag() (string, bool) {
	if c.clear {
		return "", false
	}
	return c.sub.tag, true
}

// posns returns the implicated positions (empty when clear).
func (c cemClassification) posns() []int {
	if c.clear {
		return []int{}
	}
	return c.positions
}

// cemVerdict is the structured output of caseExpansionMismatchDetect (mirrors the
// Lean Verdict).
type cemVerdict struct {
	input               []uint32
	classify            cemClassification
	upperExpansionCount int
	lowerExpansionCount int
	maxExpansionLen     int
}

// ─────────────────────────────────────────────────────────────────────
// §3 Per-position expansion scan
// ─────────────────────────────────────────────────────────────────────

// cemRevPrefix returns input[..i] reversed (the preceding codepoints
// nearest-first, as the SpecialCasing context predicates expect).
func cemRevPrefix(input []uint32, i int) []uint32 {
	revPrefix := make([]uint32, 0, i)
	for j := i - 1; j >= 0; j-- {
		revPrefix = append(revPrefix, input[j])
	}
	return revPrefix
}

// cemUpperLenAt is the default-locale uppercase expansion length at position i,
// evaluating the SpecialCasing context.
func cemUpperLenAt(input []uint32, i int) int {
	revPrefix := cemRevPrefix(input, i)
	suffix := input[i+1:]
	return len(upperCodepoint(localeDefault, revPrefix, suffix, input[i]))
}

// cemLowerLenAt is the default-locale lowercase expansion length at position i.
func cemLowerLenAt(input []uint32, i int) int {
	revPrefix := cemRevPrefix(input, i)
	suffix := input[i+1:]
	return len(lowerCodepoint(localeDefault, revPrefix, suffix, input[i]))
}

// cemFirstUpperExpansion returns the first position whose default uppercase
// mapping expands to > 1 codepoint.
func cemFirstUpperExpansion(input []uint32) (int, uint32, int, bool) {
	for i := range input {
		if length := cemUpperLenAt(input, i); length > 1 {
			return i, input[i], length, true
		}
	}
	return 0, 0, 0, false
}

// cemFirstLowerExpansion returns the first position whose default lowercase
// mapping expands to > 1 codepoint.
func cemFirstLowerExpansion(input []uint32) (int, uint32, int, bool) {
	for i := range input {
		if length := cemLowerLenAt(input, i); length > 1 {
			return i, input[i], length, true
		}
	}
	return 0, 0, 0, false
}

// cemUpperExpansionCount counts positions whose default uppercase mapping
// expands.
func cemUpperExpansionCount(input []uint32) int {
	n := 0
	for i := range input {
		if cemUpperLenAt(input, i) > 1 {
			n++
		}
	}
	return n
}

// cemLowerExpansionCount counts positions whose default lowercase mapping
// expands.
func cemLowerExpansionCount(input []uint32) int {
	n := 0
	for i := range input {
		if cemLowerLenAt(input, i) > 1 {
			n++
		}
	}
	return n
}

// cemMaxExpansionLen is the maximum case-mapped expansion length across all
// positions (upper or lower); 0 for empty input.
func cemMaxExpansionLen(input []uint32) int {
	maxLen := 0
	for i := range input {
		upper := cemUpperLenAt(input, i)
		lower := cemLowerLenAt(input, i)
		positionMax := upper
		if lower > positionMax {
			positionMax = lower
		}
		if positionMax > maxLen {
			maxLen = positionMax
		}
	}
	return maxLen
}

// ─────────────────────────────────────────────────────────────────────
// §4 Top-level detection
// ─────────────────────────────────────────────────────────────────────

// cemClassify walks the two expansion triggers in priority order, mirroring the
// Rust reference's nested match. Every arm is explicit; the terminal else is the
// documented Clear verdict, not a catch-all default.
func cemClassify(input []uint32) cemClassification {
	// Priority 1: an uppercase expansion.
	if pos, cp, length, ok := cemFirstUpperExpansion(input); ok {
		return cemClassification{
			sub:       cemSubThreat{tag: "UpperExpansion", basePos: pos, cp: cp, expansionLen: length},
			positions: []int{pos},
			decoded:   []uint8{},
		}
	}

	// Priority 2: a lowercase expansion (reached only when no upper fired).
	if pos, cp, length, ok := cemFirstLowerExpansion(input); ok {
		return cemClassification{
			sub:       cemSubThreat{tag: "LowerExpansion", basePos: pos, cp: cp, expansionLen: length},
			positions: []int{pos},
			decoded:   []uint8{},
		}
	}

	// No expansion fired: the input is clear.
	return cemClassification{clear: true, positions: []int{}, decoded: []uint8{}}
}

// caseExpansionMismatchDetect is the CaseExpansionMismatch detection function.
func caseExpansionMismatchDetect(input []uint32) cemVerdict {
	inputCopy := make([]uint32, len(input))
	copy(inputCopy, input)

	return cemVerdict{
		input:               inputCopy,
		classify:            cemClassify(input),
		upperExpansionCount: cemUpperExpansionCount(input),
		lowerExpansionCount: cemLowerExpansionCount(input),
		maxExpansionLen:     cemMaxExpansionLen(input),
	}
}
