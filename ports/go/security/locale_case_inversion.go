package security

import "slices"

// Locale-case-inversion detector (UAX #21 / Tier A2) — inputs whose lowercase
// fold inverts across locales, the homograph-via-locale attack (CVE-2007-6692,
// CVE-2021-30245, the Spotify "İSTANBUL" / "iSTANBUL" incident class). Mirrors
// Unicode.Security.Form.LocaleCaseInversion.
//
// Detection compares per-position lowerCodepoint under each locale against the
// default, rather than diffing whole-string toLower, because lowerCodepoint
// evaluates the SpecialCasing context predicates with full surrounding context.
// Turkish divergence takes priority over Lithuanian (SpecialCasing has no
// az-only codepoint, so Turkish covers Azeri).

// lowerCodepoint lowercases a single codepoint in its full input context: the
// SpecialCasing row whose conditions hold, else the simple lowercase mapping.
func lowerCodepoint(locale casingLocale, revPrefix, suffix []uint32, cp uint32) []uint32 {
	if row, ok := findSpecialRow(locale, revPrefix, suffix, cp); ok {
		return row.lower
	}
	return []uint32{simpleLowercase(cp)}
}

// firstLocaleDivergence returns the first input position whose lowerCodepoint
// under locale differs from the default-locale result.
func firstLocaleDivergence(locale casingLocale, input []uint32) (int, bool) {
	revPrefix := []uint32{}
	for i, cp := range input {
		suffix := input[i+1:]
		defaultLower := lowerCodepoint(localeDefault, revPrefix, suffix, cp)
		localeLower := lowerCodepoint(locale, revPrefix, suffix, cp)
		if !slices.Equal(defaultLower, localeLower) {
			return i, true
		}
		revPrefix = append([]uint32{cp}, revPrefix...)
	}
	return 0, false
}

// localeCaseInversionDetect reports the divergent-locale sub-threat and the
// first divergent position. Turkish divergence takes priority; Lithuanian is
// reached only when no Turkish divergence is found.
func localeCaseInversionDetect(input []uint32) (string, []int, bool) {
	if pos, ok := firstLocaleDivergence(localeTurkish, input); ok {
		return "TurkishCaseDivergence", []int{pos}, true
	}
	if pos, ok := firstLocaleDivergence(localeLithuanian, input); ok {
		return "LithuanianCaseDivergence", []int{pos}, true
	}
	return "", nil, false
}
