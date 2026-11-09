// Package segmentation implements UAX #14 default line breaking over code
// point sequences.
//
// A port of the Lean algorithm Unicode.Segmentation.LineBreak.lineBreaks, whose
// lineBreaks_length theorem fixes the output shape: one break-opportunity flag
// per boundary position. The rule order, rule bodies, and snapshot fields below
// mirror that reference — LB2 through LB31 in UAX #14 R7's canonical order,
// first match winning, the trailing LB31 breaking every otherwise-unmatched
// pair.
//
// Where a line may break is a property of a sequence rather than of a code
// point, so the entry point returns a flag per boundary instead of a predicate
// over code points.
//
// Three mechanisms carry the context the rules read:
//
//   - LB1 is applied at lookup time by ResolvedClass, which folds the
//     tailorable AI, CJ, SA, SG and XX into the algorithm's working alphabet.
//     SA needs General_Category to choose between CM and AL.
//   - LB9 — treat X CM* / X ZWJ* as X — is realised through snapshot, whose
//     fields hold the most recent class that was not CM or ZWJ. LB10, treating
//     a leftover CM or ZWJ as AL, is the fallback taken when no such class
//     exists.
//   - The rules naming a third character — LB15b, LB15c, the LB25 bracket and
//     the fourth LB28a sub-rule — read forward from the position being decided.
//
// Two departures from the Lean. Its positional reads are lits[i]! and cps[i]!,
// panicking accessors; here every read is bounded by the slice length the
// caller already holds, so no access can leave the sequence. And its
// spSinceNoSp snapshot field is written by its fold and read by no rule, so
// this port omits it.
//
// Where the Lean carries an optional neighbour, this package carries the value
// beside a presence flag, since Go has no option type. A class and the code
// point it came from are set together, so one flag covers the pair.
//
// The two properties UAX #14 needs beyond the Line_Break class —
// General_Category for LB1's SA resolution, the Pi/Pf quote refinement and
// LB30b, and East_Asian_Width for LB19a, LB25 and LB30 — come from the
// generated tables in line_break_tables.go, so this package takes code points
// and needs no data directory.
package segmentation

// classified is one character as the algorithm reads it: its code point and its
// LB1-resolved class.
type classified struct {
	cp    uint32
	class Lb
}

// ResolvedClass returns the Line_Break class cp carries once LB1 has tailored
// it.
//
// AI, SG and XX resolve to AL; CJ to NS; SA to CM when the code point is a
// non-spacing or spacing combining mark and to AL otherwise. Every other class
// is already in the working alphabet.
func ResolvedClass(cp uint32) Lb {
	switch raw := RawClass(cp); raw {
	case LbAI, LbSG, LbXX:
		return LbAL
	case LbCJ:
		return LbNS
	case LbSA:
		// LB1 reads only the two combining-mark categories here; an enclosing
		// mark is not among them.
		if gc := CategoryOf(cp); gc == GcMn || gc == GcMc {
			return LbCM
		}
		return LbAL
	default:
		return raw
	}
}

// isCmZwj reports whether LB9 absorbs this class into the character before it.
func isCmZwj(cls Lb) bool {
	return cls == LbCM || cls == LbZWJ
}

// blocksAbsorb reports whether a preceding class blocks LB9's absorption, so a
// following CM or ZWJ stands on its own and LB10 reads it as AL.
func blocksAbsorb(cls Lb) bool {
	return cls == LbBK || cls == LbCR || cls == LbLF || cls == LbNL ||
		cls == LbSP || cls == LbZW
}

// isPiQuote reports whether the class is QU and the code point is initial
// punctuation, the refinement LB15a reads.
func isPiQuote(cp uint32, cls Lb) bool {
	return cls == LbQU && CategoryOf(cp) == GcPi
}

// isPfQuote reports whether the class is QU and the code point is final
// punctuation, the refinement LB15b reads.
func isPfQuote(cp uint32, cls Lb) bool {
	return cls == LbQU && CategoryOf(cp) == GcPf
}

// hyphenU2010 is U+2010 HYPHEN, which LB20a and LB21a name explicitly because
// UCD 17.0 moved it from class HY to class HH.
const hyphenU2010 uint32 = 0x2010

// dottedCircle is U+25CC DOTTED CIRCLE, which LB28a reads as a stand-in cluster
// base.
const dottedCircle uint32 = 0x25CC

// isEastAsianFullWide reports whether cp is East_Asian_Width F, W or H, the set
// LB25 and LB30 read.
func isEastAsianFullWide(cp uint32) bool {
	w := WidthOf(cp)
	return w == EawF || w == EawW || w == EawH
}

// isEastAsianOrAmbiguous reports whether cp counts as East Asian for LB19a's
// tailoring, which treats Ambiguous as East Asian alongside Fullwidth, Wide and
// Halfwidth. Wider than isEastAsianFullWide.
func isEastAsianOrAmbiguous(cp uint32) bool {
	w := WidthOf(cp)
	return w == EawF || w == EawW || w == EawH || w == EawA
}

// effIn reports whether the effective class is present and among classes.
func effIn(effective Lb, present bool, classes ...Lb) bool {
	if !present {
		return false
	}
	for _, cls := range classes {
		if effective == cls {
			return true
		}
	}
	return false
}

// snapshot is the left-hand context a boundary decision reads: the classes and
// code points of the most recent characters LB9 did not absorb, plus the
// running counters the rules keep. Mirrors the Lean EffSnapshot.
type snapshot struct {
	// effPrev is the class of the most recent character that was not CM or ZWJ,
	// and effPrevCP its code point — LB20a, LB21a and LB28a name U+2010 and
	// U+25CC. hasEffPrev covers both, since advance sets them together.
	effPrev    Lb
	effPrevCP  uint32
	hasEffPrev bool

	// effPrevNoSP is the class of the most recent character that was not CM,
	// ZWJ or SP.
	effPrevNoSP    Lb
	hasEffPrevNoSP bool

	// effPrevPrev is the class of the second most recent such character and
	// effPrevPrevCP its code point.
	effPrevPrev    Lb
	effPrevPrevCP  uint32
	hasEffPrevPrev bool

	// inPiQuoteWindow records whether an LB15a initial-punctuation quote window
	// is open.
	inPiQuoteWindow bool
	// riRun is the length of the current regional-indicator run, for LB30a.
	riRun uint32
	// inNuChain records whether an LB25 numeric chain is open.
	inNuChain bool
}

// effectiveClass returns the class a CM or ZWJ takes from what it attaches to
// under LB9, or AL under LB10 when nothing absorbs it.
func effectiveClass(cls Lb, effPrev Lb, hasEffPrev bool) Lb {
	if !isCmZwj(cls) {
		return cls
	}
	if !hasEffPrev {
		return LbAL
	}
	if blocksAbsorb(effPrev) {
		return LbAL
	}
	return cls
}

// advance folds one character into the context. A character LB9 absorbs leaves
// the context untouched, which is what makes the neighbours it records
// effective rather than literal. Mirrors the Lean buildSnapshots step.
func advance(s snapshot, cp uint32, cls Lb) snapshot {
	effective := effectiveClass(cls, s.effPrev, s.hasEffPrev)
	if isCmZwj(effective) {
		return s
	}

	// LB15a opens its window only where an initial-punctuation quote stands
	// outside a word; a space carries an open window forward.
	leftContextOpens := !s.hasEffPrev ||
		effIn(s.effPrev, s.hasEffPrev, LbBK, LbCR, LbLF, LbNL, LbOP, LbQU,
			LbGL, LbSP, LbZW)
	inPiQuoteWindow := false
	switch {
	case isPiQuote(cp, effective) && leftContextOpens:
		inPiQuoteWindow = true
	case effective == LbSP:
		inPiQuoteWindow = s.inPiQuoteWindow
	}

	inNuChain := false
	switch {
	case effective == LbNU:
		inNuChain = true
	case s.inNuChain:
		inNuChain = effective == LbSY || effective == LbIS ||
			effective == LbCL || effective == LbCP || effective == LbPR
	}

	out := snapshot{
		effPrev:         effective,
		effPrevCP:       cp,
		hasEffPrev:      true,
		effPrevPrev:     s.effPrev,
		effPrevPrevCP:   s.effPrevCP,
		hasEffPrevPrev:  s.hasEffPrev,
		inPiQuoteWindow: inPiQuoteWindow,
		inNuChain:       inNuChain,
	}
	if effective == LbSP {
		out.effPrevNoSP = s.effPrevNoSP
		out.hasEffPrevNoSP = s.hasEffPrevNoSP
	} else {
		out.effPrevNoSP = effective
		out.hasEffPrevNoSP = true
	}
	if effective == LbRI {
		out.riRun = s.riRun + 1
	}
	return out
}

// finalQuoteCloses reports whether LB15b holds: the final quote is last, or
// what follows it cannot itself open a line.
func finalQuoteCloses(ahead []classified) bool {
	if len(ahead) == 0 {
		return true
	}
	switch ahead[0].class {
	case LbSP, LbGL, LbWJ, LbCL, LbQU, LbCP, LbEX, LbIS, LbSY, LbBK, LbCR,
		LbLF, LbNL, LbZW:
		return true
	default:
		return false
	}
}

// nextSignificantIsVF reports what the fourth LB28a sub-rule tests: it looks
// past any CM or ZWJ the cluster absorbs, so the character it reads is the
// first significant one ahead.
func nextSignificantIsVF(ahead []classified) bool {
	for _, entry := range ahead {
		if !isCmZwj(entry.class) {
			return entry.class == LbVF
		}
	}
	return false
}

// headClass returns the class at the head of a suffix and whether the suffix
// has one.
func headClass(ahead []classified) (Lb, bool) {
	if len(ahead) == 0 {
		return LbAI, false
	}
	return ahead[0].class, true
}

// breaksBefore reports whether a line break opportunity falls immediately
// before the head of suffix, given the character before it and the context
// accumulated from everything earlier.
//
// suffix begins at the position being decided, so its head is the current
// character and its tail supplies every lookahead the rules take.
func breaksBefore(prev classified, suffix []classified, s snapshot) bool {
	if len(suffix) == 0 {
		return true // LB3
	}
	prevCP, prevClass := prev.cp, prev.class
	currentCP, currentClass := suffix[0].cp, suffix[0].class
	ahead := suffix[1:]

	eff := effectiveClass(currentClass, s.effPrev, s.hasEffPrev)
	left, hasLeft := prevClass, true
	if isCmZwj(prevClass) {
		left, hasLeft = s.effPrev, s.hasEffPrev
	}

	// LB4
	if prevClass == LbBK {
		return true
	}
	// LB5
	if prevClass == LbCR && currentClass == LbLF {
		return false
	}
	if prevClass == LbCR || prevClass == LbLF || prevClass == LbNL {
		return true
	}
	// LB6
	if currentClass == LbBK || currentClass == LbCR || currentClass == LbLF ||
		currentClass == LbNL {
		return false
	}
	// LB7
	if currentClass == LbSP || currentClass == LbZW {
		return false
	}
	// LB8
	if s.hasEffPrevNoSP && s.effPrevNoSP == LbZW {
		return true
	}
	// LB8a
	if prevClass == LbZWJ {
		return false
	}
	// LB9
	if isCmZwj(currentClass) && s.hasEffPrev && !blocksAbsorb(s.effPrev) {
		return false
	}
	// LB11
	if eff == LbWJ || effIn(left, hasLeft, LbWJ) {
		return false
	}
	// LB12
	if effIn(left, hasLeft, LbGL) {
		return false
	}
	// LB12a
	if eff == LbGL && !effIn(left, hasLeft, LbSP, LbBA, LbHY, LbHH) {
		return false
	}
	// LB15c, which UCD 17.0 orders above LB13 and LB15d: break before an IS
	// that opens a number and follows a space, as in "equals .35".
	if head, ok := headClass(ahead); prevClass == LbSP && eff == LbIS && ok &&
		head == LbNU {
		return true
	}
	// LB13
	if eff == LbCL || eff == LbCP || eff == LbEX || eff == LbIS ||
		eff == LbSY {
		return false
	}
	// LB14
	if s.hasEffPrevNoSP && s.effPrevNoSP == LbOP {
		return false
	}
	// LB15a
	if s.inPiQuoteWindow {
		return false
	}
	// LB15b
	if isPfQuote(currentCP, eff) && finalQuoteCloses(ahead) {
		return false
	}
	// LB15d
	if eff == LbIS {
		return false
	}
	// LB16
	if eff == LbNS && s.hasEffPrevNoSP &&
		(s.effPrevNoSP == LbCL || s.effPrevNoSP == LbCP) {
		return false
	}
	// LB17
	if eff == LbB2 && s.hasEffPrevNoSP && s.effPrevNoSP == LbB2 {
		return false
	}
	// LB18
	if prevClass == LbSP {
		return true
	}
	// LB19 and LB19a. A quote neither breaks before nor after, except on the
	// OUTER side of an initial or final punctuation quote standing in
	// contiguous East Asian content — there the default break applies, so a
	// line may break at the quote boundary. The inner side stays unbroken,
	// being the boundary inside the quote's own scope.
	if eff == LbQU {
		nextEastAsian := len(ahead) > 0 && isEastAsianOrAmbiguous(ahead[0].cp)
		openQuoteInEastAsian := isPiQuote(currentCP, eff) &&
			isEastAsianOrAmbiguous(prevCP) &&
			isEastAsianOrAmbiguous(currentCP) && nextEastAsian
		if !openQuoteInEastAsian {
			return false
		}
	}
	if effIn(left, hasLeft, LbQU) {
		closeQuoteInEastAsian := false
		if s.hasEffPrev {
			quoteCP := s.effPrevCP
			closeQuoteInEastAsian = isPfQuote(quoteCP, LbQU) &&
				s.hasEffPrevPrev &&
				isEastAsianOrAmbiguous(s.effPrevPrevCP) &&
				isEastAsianOrAmbiguous(quoteCP) &&
				isEastAsianOrAmbiguous(currentCP)
		}
		if !closeQuoteInEastAsian {
			return false
		}
	}
	// LB20
	if eff == LbCB || effIn(left, hasLeft, LbCB) {
		return true
	}

	// LB20.1 and LB20a both require the hyphen's own left context to be outside
	// a word, the same start-of-segment set.
	hyphenLeftContextOpens := !s.hasEffPrevPrev ||
		effIn(s.effPrevPrev, s.hasEffPrevPrev, LbBK, LbCR, LbLF, LbNL, LbSP,
			LbZW, LbCB, LbGL)
	// LB20.1, UCD 17.0: an explicit hyphen joins a following letter only where
	// its own left context is outside a word. A mid-word HH falls through to
	// LB31.
	if effIn(left, hasLeft, LbHH) && (eff == LbAL || eff == LbHL) &&
		hyphenLeftContextOpens {
		return false
	}
	// LB20a, with UCD 17.0's right side broadened to HL beside AL.
	if eff == LbAL || eff == LbHL {
		hyphenCarriesLeft := s.hasEffPrev &&
			(s.effPrev == LbHY || s.effPrev == LbHH ||
				s.effPrevCP == hyphenU2010)
		if hyphenCarriesLeft && hyphenLeftContextOpens {
			return false
		}
	}
	// LB21
	if eff == LbBA || eff == LbHY || eff == LbHH || eff == LbNS {
		return false
	}
	if effIn(left, hasLeft, LbBB) {
		return false
	}
	// LB21a: an HL letter followed by an HY hyphen or U+2010 glues to what comes
	// next unless that is itself HL. A BA does not glue here.
	if s.hasEffPrevPrev && s.effPrevPrev == LbHL && eff != LbHL {
		hyphenIsHyOr2010 := s.hasEffPrev &&
			(s.effPrev == LbHY || s.effPrevCP == hyphenU2010)
		if hyphenIsHyOr2010 {
			return false
		}
	}
	// LB21b
	if eff == LbHL && effIn(left, hasLeft, LbSY) {
		return false
	}
	// LB22
	if eff == LbIN {
		return false
	}
	// LB23
	if eff == LbNU && effIn(left, hasLeft, LbAL, LbHL) {
		return false
	}
	if (eff == LbAL || eff == LbHL) && effIn(left, hasLeft, LbNU) {
		return false
	}
	// LB23a
	if (eff == LbID || eff == LbEB || eff == LbEM) &&
		effIn(left, hasLeft, LbPR) {
		return false
	}
	if eff == LbPO && effIn(left, hasLeft, LbID, LbEB, LbEM) {
		return false
	}
	// LB24
	if (eff == LbAL || eff == LbHL) && effIn(left, hasLeft, LbPR, LbPO) {
		return false
	}
	if (eff == LbPR || eff == LbPO) && effIn(left, hasLeft, LbAL, LbHL) {
		return false
	}
	// LB25, closing an open numeric chain with a CL or CP suffix and a following
	// PO or PR.
	if s.inNuChain && (eff == LbCL || eff == LbCP || eff == LbPO ||
		eff == LbPR) {
		return false
	}
	// LB25, opening a chain
	if eff == LbNU && effIn(left, hasLeft, LbPR, LbPO, LbHY, LbOP, LbIS) {
		return false
	}
	// LB25, chain body
	if eff == LbNU && effIn(left, hasLeft, LbNU) {
		return false
	}
	// LB25, extending an open chain across a SY
	if eff == LbNU && effIn(left, hasLeft, LbSY) && s.inNuChain {
		return false
	}
	// LB25, bracketed prefix: a PR joins an OP only when the OP itself opens a
	// number, and neither is East Asian Fullwidth, Wide or Halfwidth.
	if head, ok := headClass(ahead); eff == LbOP &&
		effIn(left, hasLeft, LbPR) && !isEastAsianFullWide(currentCP) &&
		s.hasEffPrev && !isEastAsianFullWide(s.effPrevCP) && ok &&
		head == LbNU {
		return false
	}
	// LB26
	if effIn(left, hasLeft, LbJL) &&
		(eff == LbJL || eff == LbJV || eff == LbH2 || eff == LbH3) {
		return false
	}
	if effIn(left, hasLeft, LbJV, LbH2) && (eff == LbJV || eff == LbJT) {
		return false
	}
	if effIn(left, hasLeft, LbJT, LbH3) && eff == LbJT {
		return false
	}
	// LB27
	if effIn(left, hasLeft, LbJL, LbJV, LbJT, LbH2, LbH3) &&
		(eff == LbIN || eff == LbPO) {
		return false
	}
	if effIn(left, hasLeft, LbPR) &&
		(eff == LbJL || eff == LbJV || eff == LbJT || eff == LbH2 ||
			eff == LbH3) {
		return false
	}
	// LB28
	if (eff == LbAL || eff == LbHL) && effIn(left, hasLeft, LbAL, LbHL) {
		return false
	}

	// LB28a, the aksara cluster rules. U+25CC DOTTED CIRCLE carries class AL and
	// stands in for a cluster base throughout.
	leftIsAksaraBase := effIn(left, hasLeft, LbAK, LbAS) ||
		(s.hasEffPrev && s.effPrevCP == dottedCircle && s.effPrev == LbAL)
	if effIn(left, hasLeft, LbAP) &&
		(eff == LbAK || eff == LbAS || currentCP == dottedCircle) {
		return false
	}
	if leftIsAksaraBase && (eff == LbVF || eff == LbVI) {
		return false
	}
	if s.hasEffPrev && s.effPrev == LbVI &&
		(effIn(s.effPrevPrev, s.hasEffPrevPrev, LbAK, LbAS) ||
			(s.hasEffPrevPrev && s.effPrevPrevCP == dottedCircle)) &&
		(eff == LbAK || currentCP == dottedCircle) {
		return false
	}
	if leftIsAksaraBase &&
		(eff == LbAK || eff == LbAS || currentCP == dottedCircle) &&
		nextSignificantIsVF(ahead) {
		return false
	}
	// LB29
	if (eff == LbAL || eff == LbHL) && effIn(left, hasLeft, LbIS) {
		return false
	}
	// LB30, where the bracket must not be East Asian Fullwidth, Wide or
	// Halfwidth.
	if eff == LbOP && effIn(left, hasLeft, LbAL, LbHL, LbNU) &&
		!isEastAsianFullWide(currentCP) {
		return false
	}
	if (eff == LbAL || eff == LbHL || eff == LbNU) &&
		effIn(left, hasLeft, LbCP) && !isEastAsianFullWide(prevCP) {
		return false
	}
	// LB30a
	if eff == LbRI && s.riRun%2 == 1 {
		return false
	}
	// LB30b
	if eff == LbEM && effIn(left, hasLeft, LbEB) {
		return false
	}
	if eff == LbEM && s.hasEffPrev {
		previous := s.effPrevCP
		if IsExtendedPictographic(previous) && CategoryOf(previous) == GcCn {
			return false
		}
	}
	// LB31
	return true
}

// LineBreaks returns one break-opportunity flag per boundary of the code point
// sequence, so a sequence of n code points yields n + 1 flags — the shape the
// Lean lineBreaks_length theorem fixes.
//
// Entry 0 is false — LB2 forbids a break at the start of text — and entry n is
// true per LB3, which requires one at the end.
func LineBreaks(cps []uint32) []bool {
	pairs := make([]classified, len(cps))
	for i, cp := range cps {
		pairs[i] = classified{cp: cp, class: ResolvedClass(cp)}
	}
	out := make([]bool, 0, len(pairs)+1)
	s := snapshot{}
	for i := range pairs {
		if i == 0 {
			out = append(out, false) // LB2
		} else {
			out = append(out, breaksBefore(pairs[i-1], pairs[i:], s))
		}
		s = advance(s, pairs[i].cp, pairs[i].class)
	}
	out = append(out, true) // LB3
	return out
}

// LineRuns returns the code point sequence split at every break opportunity —
// the runs a renderer may place on separate lines.
func LineRuns(cps []uint32) [][]uint32 {
	breaks := LineBreaks(cps)
	var out [][]uint32
	var current []uint32
	for i, cp := range cps {
		current = append(current, cp)
		if breaks[i+1] {
			out = append(out, current)
			current = nil
		}
	}
	if len(current) > 0 {
		out = append(out, current)
	}
	return out
}
