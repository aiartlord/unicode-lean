package security

import (
	_ "embed"
	"strings"
	"sync"
)

// Strong Bidi_Class lookup backing the rtl-injection detector.
//
// Direct mirror of Unicode.Generated.DerivedBidiClass.lookup: the vendored
// DerivedBidiClass.txt is parsed into two range lists — explicit ranges from
// the DATA lines (sorted by lower bound) and @missing default ranges from the
// comment lines (kept in file order). A lookup binary-searches the explicit
// ranges first; on a miss it scans the defaults in order with last-match-wins;
// on a total miss it returns L. Only the strong distinction the display layer
// needs is retained — every non-strong Bidi_Class collapses to Other.

//go:embed data/DerivedBidiClass.txt
var derivedBidiClassRaw string

// bidiStrong is the strong Bidi_Class distinction: R, AL, L, or Other.
type bidiStrong uint8

const (
	bidiOther bidiStrong = iota
	bidiR
	bidiAL
	bidiL
)

// bidiRange is a closed codepoint range [lo, hi] with its strong class.
type bidiRange struct {
	lo  uint32
	hi  uint32
	cls bidiStrong
}

var (
	bidiOnce     sync.Once
	bidiExplicit []bidiRange
	bidiDefaults []bidiRange
)

// strongOfShort maps a DATA-line short Bidi_Class token to its strong class.
// R→R, AL→AL, L→L; every other class collapses to Other.
func strongOfShort(token string) bidiStrong {
	switch token {
	case "R":
		return bidiR
	case "AL":
		return bidiAL
	case "L":
		return bidiL
	default:
		return bidiOther
	}
}

// strongOfLong maps an @missing-line long Bidi_Class name to its strong class.
// Right_To_Left→R, Arabic_Letter→AL, Left_To_Right→L; else Other.
func strongOfLong(token string) bidiStrong {
	switch token {
	case "Right_To_Left":
		return bidiR
	case "Arabic_Letter":
		return bidiAL
	case "Left_To_Right":
		return bidiL
	default:
		return bidiOther
	}
}

// parseBidiRangeField parses a "LO..HI" or single "CP" range field.
func parseBidiRangeField(field string) (uint32, uint32, bool) {
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

// parseDerivedBidiClass parses DerivedBidiClass.txt into the explicit range
// list (sorted by lower bound) and the @missing default list (file order).
func parseDerivedBidiClass(raw string) ([]bidiRange, []bidiRange) {
	var explicit []bidiRange
	var defaults []bidiRange
	for _, rawLine := range strings.Split(raw, "\n") {
		if rest, ok := strings.CutPrefix(rawLine, "# @missing:"); ok {
			// "# @missing: LO..HI; Long_Class_Name"
			rangeField, cls, ok := strings.Cut(rest, ";")
			if !ok {
				continue
			}
			lo, hi, ok := parseBidiRangeField(rangeField)
			if !ok {
				continue
			}
			defaults = append(defaults, bidiRange{lo: lo, hi: hi, cls: strongOfLong(strings.TrimSpace(cls))})
			continue
		}
		body, _, _ := strings.Cut(rawLine, "#")
		body = strings.TrimSpace(body)
		if body == "" {
			continue
		}
		// "LO..HI ; SHORT" or "CP ; SHORT"
		rangeField, cls, ok := strings.Cut(body, ";")
		if !ok {
			continue
		}
		lo, hi, ok := parseBidiRangeField(rangeField)
		if !ok {
			continue
		}
		explicit = append(explicit, bidiRange{lo: lo, hi: hi, cls: strongOfShort(strings.TrimSpace(cls))})
	}
	sortBidiRangesByLo(explicit)
	return explicit, defaults
}

// sortBidiRangesByLo insertion-sorts ranges by lower bound. The explicit
// DATA lines are already in ascending order in the file, so this is a cheap
// stabilizing pass rather than a hot path.
func sortBidiRangesByLo(ranges []bidiRange) {
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

// bidiTables lazily parses the embedded DerivedBidiClass.txt on first use.
func bidiTables() ([]bidiRange, []bidiRange) {
	bidiOnce.Do(func() {
		bidiExplicit, bidiDefaults = parseDerivedBidiClass(derivedBidiClassRaw)
	})
	return bidiExplicit, bidiDefaults
}

// bidiLookup returns the strong Bidi_Class of cp: the explicit range wins;
// otherwise the last matching @missing default wins; otherwise L. Mirrors
// Unicode.Generated.DerivedBidiClass.lookup collapsed to the strong classes.
func bidiLookup(cp uint32) bidiStrong {
	explicit, defaults := bidiTables()

	// (1) Binary-search the sorted explicit ranges.
	lo, hi := 0, len(explicit)
	for lo < hi {
		mid := lo + (hi-lo)/2
		row := explicit[mid]
		switch {
		case cp < row.lo:
			hi = mid
		case cp > row.hi:
			lo = mid + 1
		default:
			return row.cls
		}
	}

	// (2) No explicit row: last matching @missing default wins, else (3) L.
	result := bidiL
	for _, row := range defaults {
		if row.lo <= cp && cp <= row.hi {
			result = row.cls
		}
	}
	return result
}

// isStrongRtl reports whether cp has Bidi_Class R or AL (strong RTL).
func isStrongRtl(cp uint32) bool {
	cls := bidiLookup(cp)
	return cls == bidiR || cls == bidiAL
}

// isStrongLtr reports whether cp has Bidi_Class L (strong LTR).
func isStrongLtr(cp uint32) bool {
	return bidiLookup(cp) == bidiL
}
