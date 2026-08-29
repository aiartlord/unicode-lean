package security

// Width-class-confusion detection — UAX #11 East Asian Width class confusion.
// An input containing a Fullwidth (EAW = F) or Halfwidth (EAW = H) codepoint
// whose NFKD form carries a different EAW class is a compatibility-fold
// homograph. The canonical shapes:
//
//	U+FF21 'Ａ' (F)  ->  U+0041 'A' (Na)
//	U+FF11 '１' (F)  ->  U+0031 '1' (Na)
//	U+FF71 'ｱ' (H)  ->  U+30A2 'ア' (W)
//
// The two-system bypass this detects: a validator that whitelists ASCII
// rejects Ａ, while a downstream NFKC step at storage or comparison time folds
// it to plain A. The attacker claims the username ADMIN with ＡＤＭＩＮ
// against a system that did not normalise before whitelisting.
//
// Distinct from rendererDivergence's FullwidthVariance, which fires on F-class
// codepoints for renderer-cohort reasons; this is the NFKC-fold verdict, and
// both can fire on one input independently.
//
// Detection is per input position and uses NFKD, because every compatibility
// decomposition path goes through it. Hangul syllables decompose to jamos that
// are still W class, so pure Hangul stays clear.
//
// Direct port of Unicode/Security/Form/WidthClassConfusion.lean, transliterated
// from the Rust reference security/form/width_class_confusion.rs. The East
// Asian Width table is read from the port's own bundled
// data/EastAsianWidth.txt, never a host library.

import (
	_ "embed"
	"strings"
	"sync"
)

//go:embed data/EastAsianWidth.txt
var eastAsianWidthRaw string

// eastAsianWidthClass is the UAX #11 East_Asian_Width class.
type eastAsianWidthClass uint8

const (
	eawN eastAsianWidthClass = iota
	eawA
	eawF
	eawH
	eawNa
	eawW
)

type eawRange struct {
	lo    uint32
	hi    uint32
	class eastAsianWidthClass
}

func eastAsianWidthOfToken(token string) eastAsianWidthClass {
	switch token {
	case "A":
		return eawA
	case "F":
		return eawF
	case "H":
		return eawH
	case "Na":
		return eawNa
	case "W":
		return eawW
	default:
		return eawN
	}
}

// parseEastAsianWidth parses EastAsianWidth.txt into ranges sorted by lower
// bound. The file's @missing line declares N over the whole space, so an
// unlisted codepoint is Neutral and needs no explicit default list.
func parseEastAsianWidth(raw string) []eawRange {
	var ranges []eawRange
	for _, line := range strings.Split(raw, "\n") {
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		body := strings.TrimSpace(line)
		if body == "" {
			continue
		}
		semi := strings.IndexByte(body, ';')
		if semi < 0 {
			continue
		}
		lo, hi, ok := parseBidiRangeField(body[:semi])
		if !ok {
			continue
		}
		ranges = append(ranges, eawRange{
			lo:    lo,
			hi:    hi,
			class: eastAsianWidthOfToken(strings.TrimSpace(body[semi+1:])),
		})
	}
	for i := 1; i < len(ranges); i++ {
		entry := ranges[i]
		j := i - 1
		for j >= 0 && ranges[j].lo > entry.lo {
			ranges[j+1] = ranges[j]
			j--
		}
		ranges[j+1] = entry
	}
	return ranges
}

var (
	eawOnce   sync.Once
	eawSorted []eawRange
)

func eastAsianWidthTable() []eawRange {
	eawOnce.Do(func() {
		eawSorted = parseEastAsianWidth(eastAsianWidthRaw)
	})
	return eawSorted
}

// eastAsianWidth returns the East_Asian_Width class of one codepoint.
func eastAsianWidth(cp uint32) eastAsianWidthClass {
	table := eastAsianWidthTable()
	lo, hi := 0, len(table)
	for lo < hi {
		mid := lo + (hi-lo)/2
		entry := table[mid]
		switch {
		case cp < entry.lo:
			hi = mid
		case cp > entry.hi:
			lo = mid + 1
		default:
			return entry.class
		}
	}
	return eawN
}

// hasWidthFold reports whether the NFKD head of cp has a different EAW class.
func hasWidthFold(cp uint32) bool {
	folded := toNFKD([]uint32{cp})
	if len(folded) == 0 {
		return false
	}
	return eastAsianWidth(folded[0]) != eastAsianWidth(cp)
}

// firstWidthFold returns the first position whose codepoint has class want and
// folds to a different class.
func firstWidthFold(input []uint32, want eastAsianWidthClass) (int, bool) {
	for i, cp := range input {
		if eastAsianWidth(cp) == want && hasWidthFold(cp) {
			return i, true
		}
	}
	return 0, false
}

func widthFoldCount(input []uint32, want eastAsianWidthClass) int {
	count := 0
	for _, cp := range input {
		if eastAsianWidth(cp) == want && hasWidthFold(cp) {
			count++
		}
	}
	return count
}

// WidthClassDetection is one width-class-confusion scan result. SubThreat is
// empty for a clear input.
type WidthClassDetection struct {
	SubThreat          string
	Positions          []int
	FullwidthFoldCount int
	HalfwidthFoldCount int
}

// DetectWidthClassConfusion classifies a codepoint sequence. A Fullwidth fold
// takes priority over a Halfwidth one, matching the reference's sub-threat
// order.
func DetectWidthClassConfusion(input []uint32) WidthClassDetection {
	result := WidthClassDetection{
		FullwidthFoldCount: widthFoldCount(input, eawF),
		HalfwidthFoldCount: widthFoldCount(input, eawH),
	}
	if pos, ok := firstWidthFold(input, eawF); ok {
		result.SubThreat = "FullwidthFold"
		result.Positions = []int{pos}
		return result
	}
	if pos, ok := firstWidthFold(input, eawH); ok {
		result.SubThreat = "HalfwidthFold"
		result.Positions = []int{pos}
		return result
	}
	return result
}
