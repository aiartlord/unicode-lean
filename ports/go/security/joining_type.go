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

// zeroWidthSubThreat names which zero-width hazard the input carries, in the
// dispatch order of Unicode.Security.Covert.ZeroWidthPayload: an annotation
// outranks a word joiner, which outranks a narrow no-break space run, which
// outranks a binary payload, and a bare occurrence is the fallback once no
// richer class fits.
//
// The classes are counted over the codepoints the family already collected, so
// a caller that has the positions does not walk the input twice.
func zeroWidthSubThreat(input []uint32, positions []int) string {
	var annotation, wordJoiner, nnbsp, zwjZwsp int
	for _, i := range positions {
		switch cp := input[i]; {
		case cp >= 0xFFF9 && cp <= 0xFFFB:
			annotation++
		case cp == 0x2060:
			wordJoiner++
		case cp == 0x202F:
			nnbsp++
		case cp == 0x200B || cp == 0x200D:
			zwjZwsp++
		}
	}
	switch {
	case annotation > 0:
		return "AnnotationMisuse"
	case wordJoiner > 0:
		return "WordJoinerInjection"
	case nnbsp >= 2:
		return "AiWatermarkNNBSP"
	case zwjZwsp >= 2:
		return "BinaryPayload"
	default:
		return "BareZeroWidth"
	}
}

// ── tag-block-payload sub-threat ──────────────────────────────────────────

// isTagCharacter reports whether cp is in the tag block, mirroring
// `isTagCharacter` in Unicode.Security.Covert.TagBlockPayload. The whole block
// counts, not only the ASCII-bearing span: LANGUAGE TAG at U+E0001 and CANCEL
// TAG at U+E007F are tag characters that carry no ASCII, and a run made only of
// those is still a payload.
func isTagCharacter(cp uint32) bool {
	return cp >= 0xE0000 && cp <= 0xE007F
}

// tagToAscii maps a tag character to the ASCII it stands for, and reports
// whether it stands for any. Only U+E0020..U+E007E carry ASCII.
func tagToAscii(cp uint32) (byte, bool) {
	if cp >= 0xE0020 && cp <= 0xE007E {
		return byte(cp - 0xE0000), true
	}
	return 0, false
}

// decodeTagRun recovers the ASCII a tag run stands for, skipping the tag
// characters that carry none.
func decodeTagRun(cps []uint32) string {
	out := make([]byte, 0, len(cps))
	for _, cp := range cps {
		if ascii, ok := tagToAscii(cp); ok {
			out = append(out, ascii)
		}
	}
	return string(out)
}

// tagBlockSubThreat names which tag-block hazard the input carries, in the
// priority order of Unicode.Security.Covert.TagBlockPayload: a LANGUAGE TAG
// followed by at least one further tag character revives the deprecated
// language-tag mechanism; otherwise an all-tag input decoding to at least one
// ASCII character is a direct payload; otherwise a run mixed with ordinary text
// is a mixed block; otherwise the run is tag characters carrying no ASCII, such
// as a CANCEL TAG standing alone.
func tagBlockSubThreat(input []uint32, tagPositions []int) string {
	tags := make([]uint32, 0, len(tagPositions))
	for _, index := range tagPositions {
		tags = append(tags, input[index])
	}
	if len(tags) >= 2 && tags[0] == 0xE0001 {
		return "LanguageTagRevival"
	}
	allTags := len(input) == len(tags)
	if allTags && len(decodeTagRun(tags)) >= 1 {
		return "DirectAscii"
	}
	if len(input) > len(tags) {
		return "MixedBlock"
	}
	return "BareTagPresent"
}

// ── bidi-control-balance sub-threat ───────────────────────────────────────

// uaxDepthLimit is the embedding depth bound of UAX #9 §3.3.2.
const uaxDepthLimit = 125

func opensEmbedding(cp uint32) bool {
	return cp == 0x202A || cp == 0x202B || cp == 0x202D || cp == 0x202E
}

func opensIsolate(cp uint32) bool {
	return cp == 0x2066 || cp == 0x2067 || cp == 0x2068
}

// bidiWalk is the stack-of-stacks accumulator of
// Unicode.Security.Covert.BidiControlBalance: each opener pushes, each popper
// pops or records an orphan position, and maxDepth tracks the peak combined
// height.
type bidiWalk struct {
	embStack, isoStack int
	embOpen, embPop    int
	isoOpen, isoPop    int
	maxDepth           int
	orphans            []int
	positions          []int
}

func runBidiWalk(input []uint32) bidiWalk {
	var st bidiWalk
	for index, cp := range input {
		if !isBidiFormatControl(cp) {
			continue
		}
		st.positions = append(st.positions, index)
		switch {
		case opensEmbedding(cp):
			st.embStack++
			st.embOpen++
			if d := st.embStack + st.isoStack; d > st.maxDepth {
				st.maxDepth = d
			}
		case cp == 0x202C:
			st.embPop++
			if st.embStack > 0 {
				st.embStack--
			} else {
				st.orphans = append(st.orphans, index)
			}
		case opensIsolate(cp):
			st.isoStack++
			st.isoOpen++
			if d := st.embStack + st.isoStack; d > st.maxDepth {
				st.maxDepth = d
			}
		case cp == 0x2069:
			st.isoPop++
			if st.isoStack > 0 {
				st.isoStack--
			} else {
				st.orphans = append(st.orphans, index)
			}
		}
	}
	return st
}

// bidiSubThreat names which bidi hazard the input carries and the positions it
// localises, or reports that the controls are balanced and within depth. The
// priority is the spec's: depth exceeded, then an orphan pop, then an
// unbalanced embedding, then an unbalanced isolate.
//
// Orphan pop localises per stray popper. Depth exceeded is a whole-string
// verdict, so it localises nothing. The unbalanced cases report every bidi
// position, the diagnostic being that something among these controls is missing
// its partner.
func bidiSubThreat(input []uint32) (string, []int, bool) {
	st := runBidiWalk(input)
	if len(st.positions) == 0 {
		return "", nil, false
	}
	switch {
	case st.maxDepth > uaxDepthLimit:
		return "DepthExceeded", []int{}, true
	case len(st.orphans) > 0:
		return "OrphanPop", st.orphans, true
	case st.embStack > 0:
		return "UnbalancedEmbedding", st.positions, true
	case st.isoStack > 0:
		return "UnbalancedIsolate", st.positions, true
	default:
		return "", nil, false
	}
}
