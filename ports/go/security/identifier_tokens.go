package security

// The identifier-shaped tokens of running text.
//
// Direct port of Unicode/Security/Identity/IdentifierTokens.lean. A source
// file or a message is not one identifier, and the identifier detectors judge
// a whole document wrongly when handed one; switching them off for running
// text is wrong the other way, because scоpe with a Cyrillic о inside a
// source file is exactly the homograph they exist to catch. The reading that
// is right for both is per token: a maximal run of codepoints with the UAX #31
// XID_Continue property, judged as the identifier it is. No language is
// assumed and no region is exempt.

// identifierToken mirrors Token: where it starts in the input, and its
// codepoints.
type identifierToken struct {
	start int
	cps   []uint32
}

// isIdentifierTokenChar mirrors isTokenChar: UAX #31 XID_Continue.
func isIdentifierTokenChar(cp uint32) bool {
	return isXidContinue(cp)
}

// identifierTokens mirrors tokens: the identifier-shaped tokens of input, in
// input order — maximal runs of XID_Continue codepoints, each with the
// position it starts at.
func identifierTokens(input []uint32) []identifierToken {
	out := make([]identifierToken, 0, 4)
	start := -1
	for idx, cp := range input {
		if isIdentifierTokenChar(cp) {
			if start < 0 {
				start = idx
			}
			continue
		}
		if start >= 0 {
			out = append(out, identifierToken{start: start, cps: append([]uint32(nil), input[start:idx]...)})
			start = -1
		}
	}
	if start >= 0 {
		out = append(out, identifierToken{start: start, cps: append([]uint32(nil), input[start:]...)})
	}
	return out
}

// shiftPositions mirrors shiftPositions: token-relative to input-relative.
func shiftPositions(start int, positions []int) []int {
	out := make([]int, len(positions))
	for i, p := range positions {
		out[i] = p + start
	}
	return out
}
