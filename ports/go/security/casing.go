package security

import (
	_ "embed"
	"strings"
	"sync"
)

// UAX #21 case mapping (toLower), mirroring Unicode.Casing. Full case mappings
// from SpecialCasing.txt over the simple lowercase in UnicodeData.txt field 13,
// with the context predicates (Final_Sigma, After_Soft_Dotted, More_Above,
// Not_Before_Dot, After_I) driven by CCC and the Cased / Soft_Dotted properties
// from DerivedCoreProperties.txt. Keystone for bip39-canonical's default-locale
// canonicalisation; computed from the pinned UCD tables, not the runtime.

//go:embed data/SpecialCasing.txt
var specialCasingRaw string

//go:embed data/DerivedCoreProperties.txt
var derivedCorePropertiesRaw string

// casingLocale selects the SpecialCasing locale rules; localeDefault covers
// everything not tagged Turkish / Azeri / Lithuanian.
type casingLocale uint8

const (
	localeDefault casingLocale = iota
	localeTurkish
	localeAzeri
	localeLithuanian
)

type casingRow struct {
	lower      []uint32
	conditions []string
}

var (
	specialCasingOnce  sync.Once
	specialCasingTable map[uint32][]casingRow
	simpleLowerOnce    sync.Once
	simpleLowerTable   map[uint32]uint32
	casedOnce          sync.Once
	casedRanges        [][2]uint32
	softDottedOnce     sync.Once
	softDottedRanges   [][2]uint32
)

func parseCodepointList(field string) []uint32 {
	out := []uint32{}
	for _, tok := range strings.Fields(field) {
		if cp, ok := parseHexUint32(tok); ok {
			out = append(out, cp)
		}
	}
	return out
}

func parseRangeField(field string) (uint32, uint32, bool) {
	if idx := strings.Index(field, ".."); idx >= 0 {
		lo, ok1 := parseHexUint32(strings.TrimSpace(field[:idx]))
		hi, ok2 := parseHexUint32(strings.TrimSpace(field[idx+2:]))
		return lo, hi, ok1 && ok2
	}
	cp, ok := parseHexUint32(strings.TrimSpace(field))
	return cp, cp, ok
}

func parseSpecialCasing() map[uint32][]casingRow {
	table := map[uint32][]casingRow{}
	for _, rawLine := range strings.Split(specialCasingRaw, "\n") {
		body, _, _ := strings.Cut(rawLine, "#")
		body = strings.TrimSpace(body)
		if body == "" {
			continue
		}
		fields := strings.Split(body, ";")
		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}
		if len(fields) < 4 {
			continue
		}
		code, ok := parseHexUint32(fields[0])
		if !ok {
			continue
		}
		var conditions []string
		if len(fields) > 4 && fields[4] != "" {
			conditions = strings.Fields(fields[4])
		}
		table[code] = append(table[code], casingRow{
			lower:      parseCodepointList(fields[1]),
			conditions: conditions,
		})
	}
	return table
}

func getSpecialCasing() map[uint32][]casingRow {
	specialCasingOnce.Do(func() { specialCasingTable = parseSpecialCasing() })
	return specialCasingTable
}

func parseSimpleLowercase() map[uint32]uint32 {
	lower := map[uint32]uint32{}
	for _, line := range strings.Split(unicodeDataRaw, "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ";")
		if len(fields) < 15 {
			continue
		}
		cp, ok := parseHexUint32(fields[0])
		if !ok {
			continue
		}
		if fields[13] != "" {
			if l, ok := parseHexUint32(fields[13]); ok {
				lower[cp] = l
			}
		}
	}
	return lower
}

func simpleLowercase(cp uint32) uint32 {
	simpleLowerOnce.Do(func() { simpleLowerTable = parseSimpleLowercase() })
	if l, ok := simpleLowerTable[cp]; ok {
		return l
	}
	return cp
}

func parseCasingProperty(name string) [][2]uint32 {
	out := [][2]uint32{}
	for _, rawLine := range strings.Split(derivedCorePropertiesRaw, "\n") {
		body, _, _ := strings.Cut(rawLine, "#")
		body = strings.TrimSpace(body)
		if body == "" {
			continue
		}
		parts := strings.SplitN(body, ";", 2)
		if len(parts) < 2 || strings.TrimSpace(parts[1]) != name {
			continue
		}
		if lo, hi, ok := parseRangeField(parts[0]); ok {
			out = append(out, [2]uint32{lo, hi})
		}
	}
	return out
}

func inRanges(ranges [][2]uint32, cp uint32) bool {
	for _, r := range ranges {
		if r[0] <= cp && cp <= r[1] {
			return true
		}
	}
	return false
}

func isCased(cp uint32) bool {
	casedOnce.Do(func() { casedRanges = parseCasingProperty("Cased") })
	return inRanges(casedRanges, cp)
}

func isSoftDotted(cp uint32) bool {
	softDottedOnce.Do(func() { softDottedRanges = parseCasingProperty("Soft_Dotted") })
	return inRanges(softDottedRanges, cp)
}

// Context predicates (UAX #21). revPrefix is the preceding codepoints
// nearest-first; suffix the strictly-following ones.

func moreAboveAfter(suffix []uint32) bool {
	for _, cp := range suffix {
		c := canonicalCombiningClass(cp)
		if c == 230 {
			return true
		}
		if c == 0 {
			return false
		}
	}
	return false
}

func afterSoftDotted(revPrefix []uint32) bool {
	for _, cp := range revPrefix {
		if isSoftDotted(cp) {
			return true
		}
		c := canonicalCombiningClass(cp)
		if c == 0 || c == 230 {
			return false
		}
	}
	return false
}

func afterI(revPrefix []uint32) bool {
	for _, cp := range revPrefix {
		if cp == 0x0049 {
			return true
		}
		c := canonicalCombiningClass(cp)
		if c == 0 || c == 230 {
			return false
		}
	}
	return false
}

func beforeDot(suffix []uint32) bool {
	for _, cp := range suffix {
		if cp == 0x0307 {
			return true
		}
		if canonicalCombiningClass(cp) == 0 {
			return false
		}
	}
	return false
}

func hasCasedBefore(revPrefix []uint32) bool {
	for _, cp := range revPrefix {
		if isCased(cp) {
			return true
		}
		if canonicalCombiningClass(cp) == 0 {
			return false
		}
	}
	return false
}

func hasCasedAfter(suffix []uint32) bool {
	for _, cp := range suffix {
		if isCased(cp) {
			return true
		}
		if canonicalCombiningClass(cp) == 0 {
			return false
		}
	}
	return false
}

func finalSigma(revPrefix, suffix []uint32) bool {
	return hasCasedBefore(revPrefix) && !hasCasedAfter(suffix)
}

func isLocaleCondition(condition string) bool {
	return condition == "tr" || condition == "az" || condition == "lt"
}

func localeMatches(locale casingLocale, conditions []string) bool {
	hasLocale := false
	for _, c := range conditions {
		if isLocaleCondition(c) {
			hasLocale = true
			break
		}
	}
	if !hasLocale {
		return true
	}
	for _, c := range conditions {
		if (c == "tr" && locale == localeTurkish) ||
			(c == "az" && locale == localeAzeri) ||
			(c == "lt" && locale == localeLithuanian) {
			return true
		}
	}
	return false
}

func conditionsHold(locale casingLocale, revPrefix, suffix []uint32, conditions []string) bool {
	if !localeMatches(locale, conditions) {
		return false
	}
	for _, c := range conditions {
		if isLocaleCondition(c) {
			continue
		}
		var ok bool
		switch c {
		case "Final_Sigma":
			ok = finalSigma(revPrefix, suffix)
		case "Not_Final_Sigma":
			ok = !finalSigma(revPrefix, suffix)
		case "After_Soft_Dotted":
			ok = afterSoftDotted(revPrefix)
		case "More_Above":
			ok = moreAboveAfter(suffix)
		case "Not_Before_Dot":
			ok = !beforeDot(suffix)
		case "After_I":
			ok = afterI(revPrefix)
		default:
			ok = false
		}
		if !ok {
			return false
		}
	}
	return true
}

func findSpecialRow(locale casingLocale, revPrefix, suffix []uint32, cp uint32) (casingRow, bool) {
	candidates, ok := getSpecialCasing()[cp]
	if !ok {
		return casingRow{}, false
	}
	for _, row := range candidates {
		if len(row.conditions) > 0 && conditionsHold(locale, revPrefix, suffix, row.conditions) {
			return row, true
		}
	}
	for _, row := range candidates {
		if len(row.conditions) == 0 {
			return row, true
		}
	}
	return casingRow{}, false
}

// toLower lowercases a codepoint sequence under locale (UAX #21 full mapping):
// SpecialCasing rows where their conditions hold, else the simple lowercase.
func toLower(locale casingLocale, cps []uint32) []uint32 {
	out := []uint32{}
	revPrefix := []uint32{}
	for i, cp := range cps {
		suffix := cps[i+1:]
		if row, ok := findSpecialRow(locale, revPrefix, suffix, cp); ok {
			out = append(out, row.lower...)
		} else {
			out = append(out, simpleLowercase(cp))
		}
		revPrefix = append([]uint32{cp}, revPrefix...)
	}
	return out
}
