package security

import (
	_ "embed"
	"sort"
	"strings"
	"sync"
)

// Joining_Type support for RFC 5892 Appendix A.1.
//
// The rule decides whether a ZERO WIDTH NON-JOINER sits in a position its
// script actually requires, from the Joining_Type of the codepoints around it
// with Transparent characters skipped on both sides. Without this table a port
// reports every ZWNJ as a covert payload and rejects ordinary Devanagari and
// Persian text, which the Lean reference proves clear.

//go:embed data/DerivedJoiningType.txt
var derivedJoiningTypeRaw string

// joiningType is the cursive-joining behaviour a character has in scripts like
// Arabic.
type joiningType uint8

const (
	joiningNonJoining joiningType = iota
	joiningJoinCausing
	joiningDualJoining
	joiningLeftJoining
	joiningRightJoining
	joiningTransparent
)

type joiningTypeRange struct {
	lo    uint32
	hi    uint32
	class joiningType
}

var (
	joiningTypeOnce   sync.Once
	joiningTypeRanges []joiningTypeRange
)

func joiningTypeOfToken(token string) joiningType {
	switch token {
	case "C":
		return joiningJoinCausing
	case "D":
		return joiningDualJoining
	case "L":
		return joiningLeftJoining
	case "R":
		return joiningRightJoining
	case "T":
		return joiningTransparent
	default:
		return joiningNonJoining
	}
}

func parseJoiningTypes() []joiningTypeRange {
	var ranges []joiningTypeRange
	for _, rawLine := range strings.Split(derivedJoiningTypeRaw, "\n") {
		body, _, _ := strings.Cut(rawLine, "#")
		body = strings.TrimSpace(body)
		if body == "" {
			continue
		}
		rangeField, class, ok := strings.Cut(body, ";")
		if !ok {
			continue
		}
		lo, hi, ok := parseIdStatusRangeField(rangeField)
		if !ok {
			continue
		}
		ranges = append(ranges, joiningTypeRange{lo: lo, hi: hi, class: joiningTypeOfToken(strings.TrimSpace(class))})
	}
	sort.SliceStable(ranges, func(i, j int) bool { return ranges[i].lo < ranges[j].lo })
	return ranges
}

// joiningTypeOf returns cp's Joining_Type. The file's @missing line declares
// Non_Joining over the whole space, so an unlisted codepoint is Non_Joining.
func joiningTypeOf(cp uint32) joiningType {
	joiningTypeOnce.Do(func() { joiningTypeRanges = parseJoiningTypes() })
	table := joiningTypeRanges
	idx := sort.Search(len(table), func(i int) bool { return table[i].lo > cp })
	if idx == 0 {
		return joiningNonJoining
	}
	entry := table[idx-1]
	if cp <= entry.hi {
		return entry.class
	}
	return joiningNonJoining
}

// isVirama reports whether cp has Canonical_Combining_Class 9, the Virama used
// to request an explicit conjunct in scripts like Devanagari.
func isVirama(cp uint32) bool {
	return canonicalCombiningClass(cp) == 9
}

// joiningTypeBefore returns the Joining_Type of the first non-Transparent
// codepoint before i, and false when there is none.
func joiningTypeBefore(input []uint32, i int) (joiningType, bool) {
	for j := i; j > 0; {
		j--
		if jt := joiningTypeOf(input[j]); jt != joiningTransparent {
			return jt, true
		}
	}
	return joiningNonJoining, false
}

// joiningTypeAfter returns the Joining_Type of the first non-Transparent
// codepoint after i, and false when there is none.
func joiningTypeAfter(input []uint32, i int) (joiningType, bool) {
	for j := i + 1; j < len(input); j++ {
		if jt := joiningTypeOf(input[j]); jt != joiningTransparent {
			return jt, true
		}
	}
	return joiningNonJoining, false
}

// isLegitimateZwnjContext reports whether the ZWNJ at index i occupies a
// position where it is orthographically required, by RFC 5892 Appendix A.1: it
// follows a Virama, which is how a Devanagari conjunct is suppressed, or it
// sits between a left- or dual-joining character and a right- or dual-joining
// one, skipping Transparent characters on both sides, which is how a Persian
// word boundary is written inside a cursive run.
//
// A ZWNJ outside such a position carries no orthographic duty and stays
// reportable.
func isLegitimateZwnjContext(input []uint32, i int) bool {
	if i > 0 && isVirama(input[i-1]) {
		return true
	}
	left, leftOK := joiningTypeBefore(input, i)
	right, rightOK := joiningTypeAfter(input, i)
	if !leftOK || !rightOK {
		return false
	}
	leftJoins := left == joiningLeftJoining || left == joiningDualJoining
	rightJoins := right == joiningRightJoining || right == joiningDualJoining
	return leftJoins && rightJoins
}

// isLegitimateZwjContext reports whether the ZWJ at index i is flanked by two
// codepoints that both participate in some registered RGI emoji ZWJ sequence.
// The membership predicate is derived from emoji-zwj-sequences.txt itself
// rather than hand-listed, and is strictly narrower than "is an emoji": a
// codepoint carrying the Emoji property but appearing in no registered sequence
// does not sanction a ZWJ beside it. A ZWJ in head or tail position is never
// legitimate.
func isLegitimateZwjContext(input []uint32, i int) bool {
	if i == 0 || i+1 >= len(input) {
		return false
	}
	return ezwjIsEmojiTarget(input[i-1]) && ezwjIsEmojiTarget(input[i+1])
}

// isSanctionedZeroWidth reports whether the zero-width codepoint at index i
// carries meaning a reader depends on, so it is recorded as present but not
// treated as suspicious.
func isSanctionedZeroWidth(input []uint32, i int) bool {
	cp := input[i]
	return (cp == 0x200D && isLegitimateZwjContext(input, i)) ||
		(cp == 0x200C && isLegitimateZwnjContext(input, i))
}

// hasSuspiciousZeroWidth reports whether at least one of the given zero-width
// positions is unsanctioned. Every position stays in the reported finding; only
// whether the family fires depends on this.
func hasSuspiciousZeroWidth(input []uint32, positions []int) bool {
	for _, i := range positions {
		if !isSanctionedZeroWidth(input, i) {
			return true
		}
	}
	return false
}
