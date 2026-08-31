package security

import (
	_ "embed"
	"sort"
	"strings"
	"sync"
)

// UTS #39 §5.1 restriction levels.
//
// Direct mirror of Unicode/Restriction.lean. A string's restriction level is
// the strictest level it satisfies, and the ladder is decided over the string's
// resolved script set: the Script_Extensions of each codepoint where the file
// gives one, otherwise the codepoint's Script property. Common and Inherited
// codepoints are ignored when intersecting, per UTS #39 §5.1.
//
// The abbreviation vocabulary is exactly the set occurring in
// ScriptExtensions.txt, which is what Unicode/ResolvedScripts.lean models as
// its ScriptAbbrev enum. A primary script outside that set resolves to no
// abbreviation on both sides; returning a singleton instead would make every
// unknown-script codepoint look Single-Script, putting restrictionLevel one
// rung too strict and hiding RestrictionLow.

//go:embed data/Scripts.txt
var scriptsRaw string

//go:embed data/ScriptExtensions.txt
var scriptExtensionsRaw string

//go:embed data/PropertyValueAliases.txt
var propertyValueAliasesRaw string

// RestrictionLevel is the UTS #39 §5.1 restriction level of a string.
type RestrictionLevel string

const (
	RestrictionASCIIOnly             RestrictionLevel = "ASCIIOnly"
	RestrictionSingleScript          RestrictionLevel = "SingleScript"
	RestrictionHighlyRestrictive     RestrictionLevel = "HighlyRestrictive"
	RestrictionModeratelyRestrictive RestrictionLevel = "ModeratelyRestrictive"
	RestrictionMinimallyRestrictive  RestrictionLevel = "MinimallyRestrictive"
	RestrictionUnrestricted          RestrictionLevel = "Unrestricted"
)

// scriptRange is a closed codepoint range carrying one script value: a long
// name for Scripts.txt rows, abbreviations for ScriptExtensions.txt rows.
type scriptRange struct {
	lo    uint32
	hi    uint32
	value []string
}

var (
	scriptsOnce      sync.Once
	scriptRanges     []scriptRange
	scriptExtOnce    sync.Once
	scriptExtRanges  []scriptRange
	scriptExtAbbrevs map[string]bool
	aliasOnce        sync.Once
	scriptLongToAbbr map[string]string
)

// parseScriptRanges parses a "RANGE ; VALUE" file into ascending ranges. The
// value field is split on whitespace, so a Scripts.txt row yields one long
// name and a ScriptExtensions.txt row yields its abbreviation list.
func parseScriptRanges(raw string) []scriptRange {
	var ranges []scriptRange
	for _, rawLine := range strings.Split(raw, "\n") {
		body, _, _ := strings.Cut(rawLine, "#")
		body = strings.TrimSpace(body)
		if body == "" {
			continue
		}
		rangeField, valueField, ok := strings.Cut(body, ";")
		if !ok {
			continue
		}
		value := strings.Fields(valueField)
		if len(value) == 0 {
			continue
		}
		lo, hi, ok := parseIdStatusRangeField(rangeField)
		if !ok {
			continue
		}
		ranges = append(ranges, scriptRange{lo: lo, hi: hi, value: value})
	}
	sort.SliceStable(ranges, func(i, j int) bool { return ranges[i].lo < ranges[j].lo })
	return ranges
}

// findScriptRange returns the range containing cp, or nil.
func findScriptRange(ranges []scriptRange, cp uint32) *scriptRange {
	idx := sort.Search(len(ranges), func(i int) bool { return ranges[i].lo > cp })
	if idx == 0 {
		return nil
	}
	entry := &ranges[idx-1]
	if cp <= entry.hi {
		return entry
	}
	return nil
}

func scriptsTable() []scriptRange {
	scriptsOnce.Do(func() { scriptRanges = parseScriptRanges(scriptsRaw) })
	return scriptRanges
}

func scriptExtensionsTable() []scriptRange {
	scriptExtOnce.Do(func() {
		scriptExtRanges = parseScriptRanges(scriptExtensionsRaw)
		scriptExtAbbrevs = map[string]bool{}
		for _, row := range scriptExtRanges {
			for _, abbrev := range row.value {
				scriptExtAbbrevs[abbrev] = true
			}
		}
	})
	return scriptExtRanges
}

// scriptLongToAbbrev maps a Script long name to its four-letter abbreviation,
// parsed from the "sc" rows of PropertyValueAliases.txt.
func scriptLongToAbbrev() map[string]string {
	aliasOnce.Do(func() {
		scriptLongToAbbr = map[string]string{}
		for _, rawLine := range strings.Split(propertyValueAliasesRaw, "\n") {
			body, _, _ := strings.Cut(rawLine, "#")
			fields := strings.Split(body, ";")
			if len(fields) < 3 || strings.TrimSpace(fields[0]) != "sc" {
				continue
			}
			abbrev := strings.TrimSpace(fields[1])
			long := strings.TrimSpace(fields[2])
			if abbrev != "" && long != "" {
				scriptLongToAbbr[long] = abbrev
			}
		}
	})
	return scriptLongToAbbr
}

// scriptOf returns cp's Script long name, "Unknown" when the file lists none.
func scriptOf(cp uint32) string {
	if entry := findScriptRange(scriptsTable(), cp); entry != nil {
		return entry.value[0]
	}
	return "Unknown"
}

// resolveScripts returns cp's resolved script abbreviations: its
// Script_Extensions when the file gives one, otherwise the abbreviation of its
// primary Script, or none when that script has no abbreviation in the
// resolver's vocabulary.
func resolveScripts(cp uint32) []string {
	if entry := findScriptRange(scriptExtensionsTable(), cp); entry != nil {
		return entry.value
	}
	scriptExtensionsTable()
	abbrev, ok := scriptLongToAbbrev()[scriptOf(cp)]
	if !ok || !scriptExtAbbrevs[abbrev] {
		return nil
	}
	return []string{abbrev}
}

func isCommonScript(cp uint32) bool    { return scriptOf(cp) == "Common" }
func isInheritedScript(cp uint32) bool { return scriptOf(cp) == "Inherited" }

// isIgnoredForIntersection reports whether cp is Common or Inherited, which
// UTS #39 §5.1 excludes from the resolved-scripts intersection.
func isIgnoredForIntersection(cp uint32) bool {
	return isCommonScript(cp) || isInheritedScript(cp)
}

func intersectsScripts(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

// stringResolvedScripts is the intersection of resolveScripts across every
// non-ignored codepoint, empty when the string has none in common.
func stringResolvedScripts(cps []uint32) []string {
	var acc []string
	first := true
	for _, cp := range cps {
		if isIgnoredForIntersection(cp) {
			continue
		}
		resolved := resolveScripts(cp)
		if first {
			acc = append([]string(nil), resolved...)
			first = false
			continue
		}
		var next []string
		for _, s := range acc {
			for _, t := range resolved {
				if s == t {
					next = append(next, s)
					break
				}
			}
		}
		acc = next
	}
	if first {
		return nil
	}
	return acc
}

// stringScriptUnion is the union of resolveScripts across every non-ignored
// codepoint.
func stringScriptUnion(cps []uint32) []string {
	var union []string
	seen := map[string]bool{}
	for _, cp := range cps {
		if isIgnoredForIntersection(cp) {
			continue
		}
		for _, s := range resolveScripts(cp) {
			if !seen[s] {
				seen[s] = true
				union = append(union, s)
			}
		}
	}
	return union
}

func isASCIIOnly(cps []uint32) bool {
	for _, cp := range cps {
		if cp >= 0x80 {
			return false
		}
	}
	return true
}

// isSingleScript reports UTS #39 §5.1.2 Single-Script: not ASCII-only, and the
// resolved-scripts intersection is non-empty.
func isSingleScript(cps []uint32) bool {
	return !isASCIIOnly(cps) && len(stringResolvedScripts(cps)) > 0
}

var (
	coveredJapanese = []string{"Latn", "Hani", "Hira", "Kana"}
	coveredChinese  = []string{"Latn", "Hani", "Bopo"}
	coveredKorean   = []string{"Latn", "Hani", "Hang"}
)

// allWithinCovered reports whether every non-ignored codepoint resolves into
// the given covered set.
func allWithinCovered(cps []uint32, covered []string) bool {
	for _, cp := range cps {
		if isIgnoredForIntersection(cp) {
			continue
		}
		resolved := resolveScripts(cp)
		if len(resolved) == 0 || !intersectsScripts(resolved, covered) {
			return false
		}
	}
	return true
}

// isCoveredCJK reports whether the string stays inside one of the three CJK
// covered sets: Japanese, Chinese, or Korean.
func isCoveredCJK(cps []uint32) bool {
	return allWithinCovered(cps, coveredJapanese) ||
		allWithinCovered(cps, coveredChinese) ||
		allWithinCovered(cps, coveredKorean)
}

// isHighlyRestrictive reports UTS #39 Highly Restrictive: Single-Script or one
// of the CJK covered combinations.
func isHighlyRestrictive(cps []uint32) bool {
	return isSingleScript(cps) || isCoveredCJK(cps)
}

// isModeratelyRestrictiveShape reports the Moderately Restrictive shape: every
// codepoint resolves to Latin or to one fixed other Recommended script, with
// that other script neither Cyrillic nor Greek.
func isModeratelyRestrictiveShape(cps []uint32) bool {
	other := ""
	for _, cp := range cps {
		if isIgnoredForIntersection(cp) {
			continue
		}
		resolved := resolveScripts(cp)
		if len(resolved) == 0 {
			return false
		}
		if intersectsScripts(resolved, []string{"Latn"}) {
			continue
		}
		s := resolved[0]
		if s == "Cyrl" || s == "Grek" {
			return false
		}
		if other == "" {
			other = s
			continue
		}
		if s != other {
			return false
		}
	}
	return other != ""
}

// isMinimallyRestrictive reports whether every codepoint is Identifier_Status
// = Allowed.
func isMinimallyRestrictive(cps []uint32) bool {
	for _, cp := range cps {
		if !isIdAllowed(cp) {
			return false
		}
	}
	return true
}

// restrictionLevel returns the strictest UTS #39 §5.1 level the string
// satisfies, Unrestricted when it satisfies none.
func restrictionLevel(cps []uint32) RestrictionLevel {
	switch {
	case isASCIIOnly(cps):
		return RestrictionASCIIOnly
	case isSingleScript(cps):
		return RestrictionSingleScript
	case isHighlyRestrictive(cps):
		return RestrictionHighlyRestrictive
	case isModeratelyRestrictiveShape(cps):
		return RestrictionModeratelyRestrictive
	case isMinimallyRestrictive(cps):
		return RestrictionMinimallyRestrictive
	default:
		return RestrictionUnrestricted
	}
}
