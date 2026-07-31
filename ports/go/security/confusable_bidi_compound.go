package security

// Confusable-in-bidi-context compound detector (CVE-2021-42574 class).
//
// Threat model. Compound tier. A confusable (homoglyph) codepoint co-located
// with a bidi format-control is materially more dangerous than either alone:
// the homoglyph disguises an identifier while the bidi control reorders how a
// reviewer reads it. This detector fires only when both are present.
//
// Direct port of Unicode/Security/Boundary/ConfusableBidiCompound.lean. The
// confusable-source predicate reads confusables.txt (via the shared
// confusablesMap in homoglyph.go); the bidi predicates split the
// format-controls into the override class (LRE/RLE/LRO/RLO/PDF) and the
// isolate class (LRI/RLI/FSI/PDI), matching Unicode.TrojanSource.

// isConfusableSource reports whether cp is a confusable source per UTS #39 §4 —
// i.e. it has a row in confusables.txt mapping it to a different skeleton
// sequence. Plain ASCII letters return false; only homoglyph forms (Cyrillic а,
// Greek ο, mathematical-italic letters, etc.) return true. It reuses the shared
// confusables map that homoglyph.go builds.
func isConfusableSource(cp uint32) bool {
	_, ok := confusablesMap()[cp]
	return ok
}

// isConfusableBidiIsolate reports whether cp is an isolate-class bidi control
// (LRI, RLI, FSI, PDI). The override-class controls (LRE, RLE, LRO, RLO, PDF)
// are covered by the shared isBidiEmbeddingControl predicate.
func isConfusableBidiIsolate(cp uint32) bool {
	return cp >= 0x2066 && cp <= 0x2069
}

// firstPosWhere returns the position of the first codepoint satisfying pred.
func firstPosWhere(input []uint32, pred func(uint32) bool) (int, bool) {
	for index, cp := range input {
		if pred(cp) {
			return index, true
		}
	}
	return 0, false
}

// confusableBidiCompoundDetect detects a confusable codepoint sharing the input
// with a bidi control. Priority mirrors the spec: with a confusable present, an
// override-class control fires ConfusableInOverride; otherwise an isolate-class
// control fires ConfusableInIsolate; otherwise clear. Reported positions are
// [confusablePos, bidiPos].
func confusableBidiCompoundDetect(input []uint32) (string, []int, bool) {
	confusablePos, ok := firstPosWhere(input, isConfusableSource)
	if !ok {
		return "", nil, false
	}
	if bidiPos, ok := firstPosWhere(input, isBidiEmbeddingControl); ok {
		return "ConfusableInOverride", []int{confusablePos, bidiPos}, true
	}
	if bidiPos, ok := firstPosWhere(input, isConfusableBidiIsolate); ok {
		return "ConfusableInIsolate", []int{confusablePos, bidiPos}, true
	}
	return "", nil, false
}

func confusableBidiCompoundFinding(input []uint32) (Finding, bool) {
	subThreat, positions, ok := confusableBidiCompoundDetect(input)
	if !ok {
		return Finding{}, false
	}
	return Finding{
		Code:      reasonCode(FamilyConfusableBidiCompound, subThreat),
		Family:    FamilyConfusableBidiCompound,
		Severity:  2,
		Positions: positions,
		SubThreat: subThreat,
		Detail:    string(FamilyConfusableBidiCompound),
	}, true
}
