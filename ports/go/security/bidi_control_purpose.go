package security

// Which bidi format controls in an input serve a purpose, and which do not.
//
// Direct port of Unicode/Security/Display/BidiControlPurpose.lean. The nine
// UAX #9 format controls exist to manage right-to-left text: a span is doing
// that job when the text it encloses is right-to-left, or when it forces
// left-to-right text inside a right-to-left context. A span enclosing no
// strong right-to-left character in a left-to-right context manages nothing
// (LRI user PDI around Latin text, LRO return PDF around a keyword), and an
// unbalanced control never manages anything. Every Trojan Source payload is a
// control of that kind; a balanced embedding around an Arabic string literal is
// the opposite case and renders the literal as written.
//
// This is not source-region filtering: the question is asked of every control
// wherever it sits, and it is decided from the codepoints the span encloses,
// never from where a tokenizer would place it.
//
// Rule, as the Lean walk states it:
//
//   - An opener pushes a span: its position, whether it is an isolate (closed by
//     PDI) or an embedding/override (closed by PDF), and whether it is
//     right-to-left in effect (RLE, RLO, RLI, FSI) or left-to-right (LRE, LRO,
//     LRI).
//   - Every other codepoint is recorded against the innermost open span only:
//     strong right-to-left (R or AL), strong left-to-right (L), or ASCII code
//     syntax. A nested span manages its own content.
//   - PDF closes the top span when it is an embedding; against an isolate on
//     top, or an empty stack, it is an orphan. PDI closes down to the innermost
//     isolate, implicitly terminating the embeddings above it, which are thereby
//     unbalanced; with no isolate open it is an orphan.
//   - A closed span is purposeful iff its direct content is exactly its own
//     direction and carries no code syntax; a left-to-right span additionally
//     needs right-to-left context (an enclosing right-to-left span, or a
//     paragraph whose first strong character is right-to-left).
//   - Reported: every orphan, every opener still open at the end, every
//     embedding a PDI terminated implicitly, and both ends of every closed span
//     that was not purposeful.

// bcpOpensRtlKind mirrors opensRtlKind: RLE, RLO, RLI, or FSI (whose direction
// resolves from its content).
func bcpOpensRtlKind(cp uint32) bool {
	return cp == 0x202B || cp == 0x202E || cp == 0x2067 || cp == 0x2068
}

// bcpOpensLtrKind mirrors opensLtrKind: LRE, LRO, LRI.
func bcpOpensLtrKind(cp uint32) bool {
	return cp == 0x202A || cp == 0x202D || cp == 0x2066
}

// bcpOpensIsolateKind mirrors opensIsolateKind: LRI, RLI, FSI.
func bcpOpensIsolateKind(cp uint32) bool {
	return cp == 0x2066 || cp == 0x2067 || cp == 0x2068
}

// bcpIsPDF is U+202C POP DIRECTIONAL FORMATTING.
func bcpIsPDF(cp uint32) bool { return cp == 0x202C }

// bcpIsPDI is U+2069 POP DIRECTIONAL ISOLATE.
func bcpIsPDI(cp uint32) bool { return cp == 0x2069 }

// isCodeSyntax mirrors isCodeSyntax: the ASCII codepoints a Trojan Source
// payload moves — quotes, brackets, comment markers, statement separators,
// operators. Prose punctuation, space and digits are not in the set.
func isCodeSyntax(cp uint32) bool {
	switch cp {
	case 0x22, 0x27, 0x60, 0x28, 0x29, 0x5B, 0x5D, 0x7B, 0x7D, 0x2F, 0x5C, 0x2A,
		0x23, 0x3B, 0x3C, 0x3E, 0x3D, 0x2B, 0x7C, 0x26, 0x25, 0x24, 0x40, 0x5E, 0x7E:
		return true
	default:
		return false
	}
}

// bcpOpenSpan mirrors OpenSpan: where it opened, how it closes, its direction in
// effect, and what has appeared directly inside it.
type bcpOpenSpan struct {
	pos       int
	isolate   bool
	rtlKind   bool
	sawRtl    bool
	sawLtr    bool
	sawSyntax bool
}

func bcpInRtlContext(enclosing []bcpOpenSpan, paragraphRtl bool) bool {
	if paragraphRtl {
		return true
	}
	for _, s := range enclosing {
		if s.rtlKind {
			return true
		}
	}
	return false
}

// bcpSpanPurposeful mirrors spanPurposeful: a closed span is purposeful iff its
// direct content is exactly its own direction and carries no code syntax.
func bcpSpanPurposeful(s bcpOpenSpan, enclosing []bcpOpenSpan, paragraphRtl bool) bool {
	if s.rtlKind {
		return s.sawRtl && !s.sawLtr && !s.sawSyntax
	}
	return bcpInRtlContext(enclosing, paragraphRtl) && s.sawLtr && !s.sawRtl && !s.sawSyntax
}

// paragraphIsRtl mirrors paragraphIsRtl (UAX #9 P2/P3): the paragraph runs
// right-to-left iff its first strong character is right-to-left.
func paragraphIsRtl(input []uint32) bool {
	for _, cp := range input {
		if isStrongRtl(cp) {
			return true
		}
		if isStrongLtr(cp) {
			return false
		}
	}
	return false
}

// purposelessControlPositions mirrors purposelessControlPositions: the positions
// of the purposeless bidi format controls in input, in input order. Empty iff
// every control is balanced and manages right-to-left text.
func purposelessControlPositions(input []uint32) []int {
	paragraphRtl := paragraphIsRtl(input)
	// The stack's top is the slice's last element; the Lean list's head.
	stack := make([]bcpOpenSpan, 0, 4)
	marked := make(map[int]struct{})
	for idx, cp := range input {
		switch {
		case bcpOpensRtlKind(cp) || bcpOpensLtrKind(cp):
			stack = append(stack, bcpOpenSpan{
				pos:     idx,
				isolate: bcpOpensIsolateKind(cp),
				rtlKind: bcpOpensRtlKind(cp),
			})
		case bcpIsPDF(cp):
			if len(stack) == 0 || stack[len(stack)-1].isolate {
				// PDF against an open isolate closes nothing (UAX #9 X7), and
				// against an empty stack it is an orphan.
				marked[idx] = struct{}{}
				continue
			}
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if !bcpSpanPurposeful(top, stack, paragraphRtl) {
				marked[top.pos] = struct{}{}
				marked[idx] = struct{}{}
			}
		case bcpIsPDI(cp):
			isoIndex := -1
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i].isolate {
					isoIndex = i
					break
				}
			}
			if isoIndex < 0 {
				marked[idx] = struct{}{}
				continue
			}
			// Embeddings above the isolate are terminated implicitly.
			for _, dropped := range stack[isoIndex+1:] {
				marked[dropped.pos] = struct{}{}
			}
			iso := stack[isoIndex]
			stack = stack[:isoIndex]
			if !bcpSpanPurposeful(iso, stack, paragraphRtl) {
				marked[iso.pos] = struct{}{}
				marked[idx] = struct{}{}
			}
		default:
			if len(stack) > 0 {
				// Content is recorded against the innermost open span only
				// (Lean markContent).
				top := &stack[len(stack)-1]
				top.sawRtl = top.sawRtl || isStrongRtl(cp)
				top.sawLtr = top.sawLtr || isStrongLtr(cp)
				top.sawSyntax = top.sawSyntax || isCodeSyntax(cp)
			}
		}
	}
	for _, s := range stack {
		marked[s.pos] = struct{}{}
	}
	out := make([]int, 0, len(marked))
	for idx := range input {
		if _, ok := marked[idx]; ok {
			out = append(out, idx)
		}
	}
	return out
}

// hasPurposelessControl mirrors hasPurposelessControl.
func hasPurposelessControl(input []uint32) bool {
	return len(purposelessControlPositions(input)) > 0
}

// firstPurposelessControl mirrors firstPurposelessControl: the position and
// codepoint of the first purposeless control, if any.
func firstPurposelessControl(input []uint32) (int, uint32, bool) {
	positions := purposelessControlPositions(input)
	if len(positions) == 0 {
		return 0, 0, false
	}
	pos := positions[0]
	return pos, input[pos], true
}
