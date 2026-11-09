package segmentation

// UAX #29 default extended grapheme cluster segmentation.
//
// A port of the Lean algorithm Unicode.Segmentation.GraphemeBreak.graphemeBreaks,
// whose graphemeBreaks_eq_spec theorem relates it to the declarative UAX #29
// GB1-GB999 specification. The state fields, rule order and transitions below
// mirror that reference: the first matching rule wins, and the trailing GB999
// breaks every otherwise-unmatched pair.
//
// Where a cluster boundary falls is a property of a sequence rather than of a
// code point, so the entry point returns one flag per boundary position: a
// sequence of n code points yields n + 1 flags, entry 0 the GB1 start-of-text
// break and entry n the GB2 end-of-text break, both always true.
//
// Three pieces of left context carry what the rules read, each a field of
// graphemeState: the previous code point's class, the GB11 emoji-pictograph
// window, and the GB9c Indic-conjunct window, plus the regional-indicator run
// length GB12 and GB13 count parity over. Where the Lean carries an optional
// previous class, this file carries the value beside a presence flag, since Go
// has no option type.
//
// Two of the three properties the rules read come from the generated tables in
// grapheme_tables.go. The third, Extended_Pictographic, is the table LB30b
// already reads: GB11 calls IsExtendedPictographic rather than carrying a
// second copy. So this file takes code points and needs no data directory.

// epicState is the GB11 left-context window: whether the scan has just passed
// an Extended_Pictographic, and whether a ZWJ has followed it.
type epicState uint8

const (
	// epicNone is no relevant prefix.
	epicNone epicState = iota
	// epicAfterEP is an Extended_Pictographic followed by zero or more Extend.
	epicAfterEP
	// epicAfterEPZWJ is an Extended_Pictographic Extend* ZWJ, the prefix GB11
	// fires on.
	epicAfterEPZWJ
)

// incbState is the GB9c left-context window: whether the scan has passed an
// Indic_Conjunct_Break consonant, and whether a linker has followed it.
type incbState uint8

const (
	// incbStateNone is no relevant prefix.
	incbStateNone incbState = iota
	// incbStateConsonant is a Consonant followed by zero or more Extend, with
	// no Linker yet.
	incbStateConsonant
	// incbStateLinker is a Consonant (Extend | Linker)* Linker (Extend |
	// Linker)*, the prefix GB9c fires on.
	incbStateLinker
)

// graphemeState is the running scan state, mirroring the Lean State.
type graphemeState struct {
	// prevClass is the Grapheme_Cluster_Break class of the previous code point.
	// hasPrevClass is false only before the first one is read, which is the
	// condition GB1 tests.
	prevClass    Gcb
	hasPrevClass bool

	// epic is the GB11 window and incb the GB9c window.
	epic epicState
	incb incbState

	// riRun is the length of the current regional-indicator run, whose parity
	// GB12 and GB13 read.
	riRun uint32
}

// shouldBreakBeforeCluster reports whether a cluster boundary falls immediately
// before cp, given the running state. UAX #29 GB1 through GB999 in canonical
// order.
func shouldBreakBeforeCluster(cp uint32, s graphemeState) bool {
	if !s.hasPrevClass {
		return true // GB1: start of text
	}
	bc := GcbOf(cp)
	incb := IncbOf(cp)
	isEP := IsExtendedPictographic(cp)
	pc := s.prevClass

	// GB3
	if pc == GcbCR && bc == GcbLF {
		return false
	}
	// GB4
	if pc == GcbControl || pc == GcbCR || pc == GcbLF {
		return true
	}
	// GB5
	if bc == GcbControl || bc == GcbCR || bc == GcbLF {
		return true
	}
	// GB6
	if pc == GcbL && (bc == GcbL || bc == GcbV || bc == GcbLV || bc == GcbLVT) {
		return false
	}
	// GB7
	if (pc == GcbLV || pc == GcbV) && (bc == GcbV || bc == GcbT) {
		return false
	}
	// GB8
	if (pc == GcbLVT || pc == GcbT) && bc == GcbT {
		return false
	}
	// GB9
	if bc == GcbExtend || bc == GcbZWJ {
		return false
	}
	// GB9a
	if bc == GcbSpacingMark {
		return false
	}
	// GB9b
	if pc == GcbPrepend {
		return false
	}
	// GB9c: Consonant (Extend | Linker)* Linker (Extend | Linker)* x Consonant
	if s.incb == incbStateLinker && incb == IncbConsonant {
		return false
	}
	// GB11: ExtPict Extend* ZWJ x ExtPict
	if s.epic == epicAfterEPZWJ && isEP {
		return false
	}
	// GB12 / GB13: an odd-parity regional-indicator run extends
	if bc == GcbRegionalIndicator && s.riRun%2 == 1 {
		return false
	}
	// GB999
	return true
}

// advanceCluster folds one code point into the context. Mirrors the Lean
// advance, which computes the update independently of the break decision so
// the caller records the break and moves on.
func advanceCluster(cp uint32, s graphemeState) graphemeState {
	bc := GcbOf(cp)
	incb := IncbOf(cp)
	isEP := IsExtendedPictographic(cp)

	epic := epicNone
	switch {
	case isEP:
		epic = epicAfterEP
	case s.epic == epicAfterEP && bc == GcbExtend:
		epic = epicAfterEP
	case s.epic == epicAfterEP && bc == GcbZWJ:
		epic = epicAfterEPZWJ
	}

	conjunct := incbStateNone
	switch {
	case incb == IncbConsonant:
		conjunct = incbStateConsonant
	case s.incb == incbStateConsonant && incb == IncbLinker:
		conjunct = incbStateLinker
	case s.incb == incbStateConsonant && incb == IncbExtend:
		conjunct = incbStateConsonant
	case s.incb == incbStateLinker && incb == IncbLinker:
		conjunct = incbStateLinker
	case s.incb == incbStateLinker && incb == IncbExtend:
		conjunct = incbStateLinker
	}

	riRun := uint32(0)
	if bc == GcbRegionalIndicator {
		riRun = s.riRun + 1
	}

	return graphemeState{
		prevClass:    bc,
		hasPrevClass: true,
		epic:         epic,
		incb:         conjunct,
		riRun:        riRun,
	}
}

// GraphemeBreaks returns one cluster-boundary flag per boundary of the code
// point sequence, so a sequence of n code points yields n + 1 flags.
//
// Entry 0 is the GB1 start-of-text break and entry n the GB2 end-of-text
// break, both always true.
func GraphemeBreaks(cps []uint32) []bool {
	out := make([]bool, 0, len(cps)+1)
	s := graphemeState{}
	for _, cp := range cps {
		out = append(out, shouldBreakBeforeCluster(cp, s))
		s = advanceCluster(cp, s)
	}
	out = append(out, true) // GB2
	return out
}

// GraphemeClusters returns the code points between consecutive boundaries —
// the clusters a renderer treats as single user-perceived characters.
func GraphemeClusters(cps []uint32) [][]uint32 {
	breaks := GraphemeBreaks(cps)
	var out [][]uint32
	var current []uint32
	for i, cp := range cps {
		if breaks[i] && len(current) > 0 {
			out = append(out, current)
			current = nil
		}
		current = append(current, cp)
	}
	if len(current) > 0 {
		out = append(out, current)
	}
	return out
}
