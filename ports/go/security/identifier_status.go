package security

import (
	_ "embed"
	"strings"
	"sync"
)

// UTS #39 Identifier_Status lookup — the General-Security-Profile "Allowed"
// set backing identifier-admissibility reasoning.
//
// Direct mirror of the vendored UTS #39 IdentifierStatus.txt: every DATA line
// carries a codepoint (or "LO..HI" range) and its Identifier_Status value, one
// of Allowed or Restricted. Only the Allowed ranges are retained; a codepoint
// is Allowed iff it falls inside one of them, Restricted otherwise. The ranges
// are sorted by lower bound so isIdAllowed can binary-search them.

//go:embed data/IdentifierStatus.txt
var identifierStatusRaw string

// idStatusRange is a closed codepoint range [lo, hi] whose members are all
// Identifier_Status = Allowed.
type idStatusRange struct {
	lo uint32
	hi uint32
}

var (
	idStatusOnce    sync.Once
	idAllowedRanges []idStatusRange
)

// parseIdentifierStatus parses IdentifierStatus.txt into the ascending list of
// Allowed ranges. Restricted rows are dropped; comment and blank lines are
// skipped. Each DATA line is "CP ; Status" or "LO..HI ; Status".
func parseIdentifierStatus(raw string) []idStatusRange {
	var allowed []idStatusRange
	for _, rawLine := range strings.Split(raw, "\n") {
		body, _, _ := strings.Cut(rawLine, "#")
		body = strings.TrimSpace(body)
		if body == "" {
			continue
		}
		rangeField, status, ok := strings.Cut(body, ";")
		if !ok {
			continue
		}
		if strings.TrimSpace(status) != "Allowed" {
			continue
		}
		lo, hi, ok := parseIdStatusRangeField(rangeField)
		if !ok {
			continue
		}
		allowed = append(allowed, idStatusRange{lo: lo, hi: hi})
	}
	sortIdStatusRangesByLo(allowed)
	return allowed
}

// parseIdStatusRangeField parses a "LO..HI" or single "CP" range field.
func parseIdStatusRangeField(field string) (uint32, uint32, bool) {
	field = strings.TrimSpace(field)
	if idx := strings.Index(field, ".."); idx >= 0 {
		lo, ok := parseHexUint32(field[:idx])
		if !ok {
			return 0, 0, false
		}
		hi, ok := parseHexUint32(field[idx+2:])
		if !ok {
			return 0, 0, false
		}
		return lo, hi, true
	}
	cp, ok := parseHexUint32(field)
	if !ok {
		return 0, 0, false
	}
	return cp, cp, true
}

// sortIdStatusRangesByLo insertion-sorts ranges by lower bound. The DATA lines
// are already ascending in the file, so this is a cheap stabilizing pass.
func sortIdStatusRangesByLo(ranges []idStatusRange) {
	for i := 1; i < len(ranges); i++ {
		key := ranges[i]
		j := i - 1
		for j >= 0 && ranges[j].lo > key.lo {
			ranges[j+1] = ranges[j]
			j--
		}
		ranges[j+1] = key
	}
}

// identifierAllowedRanges lazily parses the embedded IdentifierStatus.txt.
func identifierAllowedRanges() []idStatusRange {
	idStatusOnce.Do(func() {
		idAllowedRanges = parseIdentifierStatus(identifierStatusRaw)
	})
	return idAllowedRanges
}

// isIdAllowed reports whether cp has UTS #39 Identifier_Status = Allowed.
func isIdAllowed(cp uint32) bool {
	ranges := identifierAllowedRanges()

	// Binary-search the sorted Allowed ranges: find the last range whose lower
	// bound is <= cp and test whether cp is within its upper bound.
	lo, hi := 0, len(ranges)
	for lo < hi {
		mid := lo + (hi-lo)/2
		if ranges[mid].lo <= cp {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo > 0 {
		entry := ranges[lo-1]
		if cp <= entry.hi {
			return true
		}
	}
	return false
}
