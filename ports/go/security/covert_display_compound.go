package security

// Covert-display compound detector (bidi control co-located with a hidden
// covert channel).
//
// Threat model. Tier compound. A bidi format-control that reorders the
// visible glyphs is materially more dangerous when the same input also
// carries a covert channel — an unregistered variation selector or a
// tag-block character — because the reorder hides where the covert payload
// sits. This detector fires only when a bidi control coincides with one of
// those covert classes.
//
// Direct port of Unicode/Security/Boundary/CovertDisplayCompound.lean, mirrored
// from the verified Rust port
// ports/rust/src/security/boundary/covert_display_compound.rs. A "suspicious
// VS" is a variation selector that does not form a registered (base, VS) pair
// (StandardizedVariants / emoji-variation-sequences), the .suspicious case of
// the variation-selector classifier. The bidi predicate (isBidiFormatControl in
// rtl_injection.go) and the VS predicates (isVariationSelector /
// isRegisteredVariationPosition in policy.go) are reused unchanged.

// isTagBlockChar reports whether cp is in the tag-block range U+E0000..U+E007F.
func isTagBlockChar(cp uint32) bool {
	return cp >= 0xE0000 && cp <= 0xE007F
}

// firstSuspiciousVsPos returns the first position holding a suspicious
// variation selector — a VS that does not form a registered (base, VS) pair
// with its predecessor. Mirrors the .suspicious case of the Lean
// classifyPositions.
func firstSuspiciousVsPos(input []uint32) (int, bool) {
	for i, cp := range input {
		if isVariationSelector(cp) && !isRegisteredVariationPosition(input, i) {
			return i, true
		}
	}
	return 0, false
}

// covertDisplayCompoundDetect detects a bidi control co-located with a covert
// channel. Priority mirrors the spec: a bidi control must be present; then a
// suspicious VS fires BidiPlusUnregisteredVs; otherwise a tag-block character
// fires BidiPlusTagBlock; otherwise clear. Reported positions are
// [bidiPos, covertPos].
func covertDisplayCompoundDetect(input []uint32) (string, []int, bool) {
	bidiPos, ok := firstPosWhere(input, isBidiFormatControl)
	if !ok {
		return "", nil, false
	}
	if vsPos, ok := firstSuspiciousVsPos(input); ok {
		return "BidiPlusUnregisteredVs", []int{bidiPos, vsPos}, true
	}
	if tagPos, ok := firstPosWhere(input, isTagBlockChar); ok {
		return "BidiPlusTagBlock", []int{bidiPos, tagPos}, true
	}
	return "", nil, false
}

func covertDisplayCompoundFinding(input []uint32) (Finding, bool) {
	subThreat, positions, ok := covertDisplayCompoundDetect(input)
	if !ok {
		return Finding{}, false
	}
	return Finding{
		Code:      reasonCode(FamilyCovertDisplayCompound, subThreat),
		Family:    FamilyCovertDisplayCompound,
		Severity:  2,
		Positions: positions,
		SubThreat: subThreat,
		Detail:    string(FamilyCovertDisplayCompound),
	}, true
}
