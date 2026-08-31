package security

// Right-to-left injection detection for left-to-right-declared fields.
//
// Threat model. Tier A1. An adversary places strong-RTL codepoints
// (Hebrew, Arabic, ...) or bidi format-controls (RLO, LRO, PDF, the
// isolates) into a field the surrounding UI declares left-to-right — a
// username box, a filename, a source-code token. A bidi-aware renderer
// reorders the visible glyphs, so what the reviewer reads differs from
// the logical byte order the machine acts on.
//
// Direct port of Unicode/Security/Display/RtlInjection.lean. The four
// sub-threats, their priority, and the reported positions match that
// module's detect exactly; the strong-RTL / strong-LTR predicates read
// Bidi_Class from the bundled DerivedBidiClass.txt (isStrongRtl /
// isStrongLtr in bidi.go), mirroring Unicode.Generated.DerivedBidiClass.lookup.

// isBidiFormatControl reports whether cp is a bidi format-control: an
// embedding/override (LRE, RLE, LRO, RLO), PDF, an isolate initiator
// (LRI, RLI, FSI), or PDI.
func isBidiFormatControl(cp uint32) bool {
	switch cp {
	case 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
		0x2066, 0x2067, 0x2068, 0x2069:
		return true
	default:
		return false
	}
}

func countStrongRtl(input []uint32) int {
	n := 0
	for _, cp := range input {
		if isStrongRtl(cp) {
			n++
		}
	}
	return n
}

func firstBidiControlPos(input []uint32) (int, bool) {
	for index, cp := range input {
		if isBidiFormatControl(cp) {
			return index, true
		}
	}
	return 0, false
}

// firstStrongChar returns the position of the first strong (L, R, or AL)
// codepoint and whether it is strong-RTL.
func firstStrongChar(input []uint32) (int, bool, bool) {
	for index, cp := range input {
		if isStrongRtl(cp) {
			return index, true, true
		}
		if isStrongLtr(cp) {
			return index, false, true
		}
	}
	return 0, false, false
}

func firstStrongRtlPos(input []uint32) (int, bool) {
	for index, cp := range input {
		if isStrongRtl(cp) {
			return index, true
		}
	}
	return 0, false
}

// longestRtlRun returns the length of the longest consecutive run of
// strong-RTL codepoints together with that run's starting position;
// (0, 0) when there are none.
func longestRtlRun(input []uint32) (int, int) {
	longest := 0
	longestStart := 0
	current := 0
	currentStart := 0
	for index, cp := range input {
		if isStrongRtl(cp) {
			newStart := currentStart
			if current == 0 {
				newStart = index
			}
			current++
			currentStart = newStart
			if current > longest {
				longest = current
				longestStart = newStart
			}
		} else {
			current = 0
		}
	}
	return longest, longestStart
}

func rtlInjectionPhase3(input []uint32, strongRtl, runLen, runStart int) (string, []int, bool) {
	if strongRtl == 0 {
		return "", nil, false
	}
	if runLen >= 4 {
		return "MixedOverflow", []int{runStart}, true
	}
	if pos, ok := firstStrongRtlPos(input); ok {
		return "StrongRTLInLTR", []int{pos}, true
	}
	// Unreachable when strongRtl > 0.
	return "", nil, false
}

// FieldDirection is the declared display direction of the field holding an
// input.
//
// A caller handling Hebrew, Arabic or Persian UI text declares its field
// right-to-left. Every other reading treats the input as a declared-LTR
// string, under which right-to-left content is itself the hazard.
//
// Mirrors FieldDirection in Unicode/Security/Display/RtlInjection.lean, that
// spec's alias for the UAX #9 paragraph-direction vocabulary.
type FieldDirection uint8

const (
	// FieldLTR is the reading the module scope note fixes for an undeclared
	// field.
	FieldLTR FieldDirection = iota
	FieldRTL
)

// rtlInjectionDetectWithContext detects right-to-left injection in a field
// whose declared display direction is direction.
//
// A bidi format control reorders what a reviewer sees whichever way the field
// runs, so Phase 1 holds unconditionally and trumps all.
//
// Phases 2 and 3 ask whether right-to-left text has taken over or been spliced
// into a left-to-right field. That question has no premise in a right-to-left
// field, where right-to-left text is the content. The mirror-image hazard,
// strong-LTR injection into a right-to-left field, belongs to the separate
// detector the scope note assigns it to.
//
// Within a left-to-right field: (1) any bidi format-control anywhere fires
// BidiControlInLTRField; otherwise (2) a leading strong-RTL codepoint fires
// FieldTakeover; otherwise (3) mid-stream strong-RTL is classified by run
// length. It returns the sub-threat tag, the offending positions, and whether
// a hazard fired.
func rtlInjectionDetectWithContext(direction FieldDirection, input []uint32) (string, []int, bool) {
	strongRtl := countStrongRtl(input)
	runLen, runStart := longestRtlRun(input)

	// Phase 1: bidi format-control trumps all, in either direction.
	if pos, ok := firstBidiControlPos(input); ok {
		return "BidiControlInLTRField", []int{pos}, true
	}

	// A right-to-left field carrying right-to-left text carries its content.
	if direction == FieldRTL {
		return "", nil, false
	}

	if pos, isRtl, ok := firstStrongChar(input); ok && isRtl {
		return "FieldTakeover", []int{pos}, true
	}
	return rtlInjectionPhase3(input, strongRtl, runLen, runStart)
}

// rtlInjectionDetect detects right-to-left injection in a field declared
// left-to-right, the reading the module scope note fixes for an undeclared
// field.
func rtlInjectionDetect(input []uint32) (string, []int, bool) {
	return rtlInjectionDetectWithContext(FieldLTR, input)
}

func rtlInjectionFinding(input []uint32) (Finding, bool) {
	subThreat, positions, ok := rtlInjectionDetect(input)
	if !ok {
		return Finding{}, false
	}
	return Finding{
		Code:      reasonCode(FamilyRtlInjection, subThreat),
		Family:    FamilyRtlInjection,
		Severity:  2,
		Positions: positions,
		SubThreat: subThreat,
		Detail:    string(FamilyRtlInjection),
	}, true
}
