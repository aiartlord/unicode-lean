package security

// filename-disguise — detection of filename/extension disguise attacks where
// the visible extension differs from the byte extension (the display-layer
// detector, layer D).
//
// Byte-faithful port of Unicode/Security/Display/FilenameDisguise.lean,
// mirroring the verified Rust reference implementation.
//
// Threat model. An adversary delivers a file whose rendered name looks like a
// benign type (document.txt) but whose actual byte extension is executable —
// the canonical attack inserts U+202E RIGHT-TO-LEFT OVERRIDE so
// document<RLO>txt.exe renders as document exe.txt.
//
// Detection is presentation- and language-agnostic: it surfaces every codepoint
// that could cause display-vs-byte divergence in the filename — any bidi
// format-control anywhere, and any fullwidth/halfwidth or combining (grapheme
// Extend) codepoint in the extension region (after the last dot). Native-RTL
// names with no bidi controls clear. It reuses the port's own predicates (the
// bidi-format-control set isBidiFormatControl, the grapheme Extend class
// rdIsGraphemeExtend, the fullwidth range isFullwidthHalfwidth), never a host
// filesystem or rendering library.
//
// Sub-threats (priority order):
//	1. RloFlip            any bidi format-control in the input.
//	2. WidthClassExt      a fullwidth/halfwidth codepoint in the extension.
//	3. CombiningInExt     a combining (grapheme Extend) codepoint in the extension.
//	4. MultipleExtensions >= 3 dots (advisory; e.g. legitimate .tar.gz.sig).

// ─────────────────────────────────────────────────────────────────────
// §1 Types
// ─────────────────────────────────────────────────────────────────────

// fdSubThreat is the sub-threat this detector fired, in the port's
// struct-with-tag idiom (mirroring rdSubThreat). tag is the human-facing
// classification tag; the remaining fields carry the sub-threat's data (only
// those relevant to the fired tag are meaningful). The tag values, in priority
// order, are: RloFlip, WidthClassExt, CombiningInExt, MultipleExtensions.
type fdSubThreat struct {
	tag string
	// position — RloFlip / WidthClassExt / CombiningInExt: implicated position.
	position int
	// controlCp — RloFlip: the bidi format-control codepoint.
	controlCp uint32
	// cp — WidthClassExt / CombiningInExt: the implicated codepoint.
	cp uint32
	// dotCount — MultipleExtensions: the number of dot separators.
	dotCount int
}

// fdClassification is the top-level FilenameDisguise classification. When clear
// is true no disguise trigger fired; otherwise sub names the fired sub-threat,
// positions holds the implicated codepoint positions, and decoded is the
// decoded-byte projection (always empty here, kept for shape parity with the
// Lean Classification.hazard).
type fdClassification struct {
	clear     bool
	sub       fdSubThreat
	positions []int
	decoded   []uint8
}

// isClear reports whether the classification is Clear.
func (c fdClassification) isClear() bool {
	return c.clear
}

// tag is the human-facing tag for a hazard; the second result is false when
// clear.
func (c fdClassification) tag() (string, bool) {
	if c.clear {
		return "", false
	}
	return c.sub.tag, true
}

// posns returns the implicated positions (empty when clear).
func (c fdClassification) posns() []int {
	if c.clear {
		return []int{}
	}
	return c.positions
}

// fdVerdict is the structured output of filenameDisguiseDetect (mirrors the
// Lean Verdict). lastDotPos is meaningful only when hasLastDot is true,
// modelling the reference's Option<usize>.
type fdVerdict struct {
	input            []uint32
	classify         fdClassification
	dotPositions     []int
	lastDotPos       int
	hasLastDot       bool
	bidiControlCount int
	fullwidthInExt   int
	combiningInExt   int
}

// ─────────────────────────────────────────────────────────────────────
// §2 Core predicates
// ─────────────────────────────────────────────────────────────────────

// fdIsAsciiDot reports whether cp is U+002E FULL STOP (the extension separator).
func fdIsAsciiDot(cp uint32) bool {
	return cp == 0x002E
}

// ─────────────────────────────────────────────────────────────────────
// §3 Sub-detectors
// ─────────────────────────────────────────────────────────────────────

// fdDotPositions returns the positions of every dot in input.
func fdDotPositions(input []uint32) []int {
	positions := []int{}
	for idx, cp := range input {
		if fdIsAsciiDot(cp) {
			positions = append(positions, idx)
		}
	}
	return positions
}

// fdFirstBidiControl returns the position and codepoint of the first bidi
// format-control (reuses the port's isBidiFormatControl).
func fdFirstBidiControl(input []uint32) (int, uint32, bool) {
	for idx, cp := range input {
		if isBidiFormatControl(cp) {
			return idx, cp, true
		}
	}
	return 0, 0, false
}

// fdFirstFullwidthFrom returns the position and codepoint of the first
// fullwidth/halfwidth codepoint at or after start.
func fdFirstFullwidthFrom(input []uint32, start int) (int, uint32, bool) {
	for idx, cp := range input {
		if idx >= start && isFullwidthHalfwidth(cp) {
			return idx, cp, true
		}
	}
	return 0, 0, false
}

// fdFirstExtendFrom returns the position and codepoint of the first grapheme
// Extend codepoint at or after start (reuses the port's rdIsGraphemeExtend).
func fdFirstExtendFrom(input []uint32, start int) (int, uint32, bool) {
	for idx, cp := range input {
		if idx >= start && rdIsGraphemeExtend(cp) {
			return idx, cp, true
		}
	}
	return 0, 0, false
}

// fdCountFullwidthFrom counts fullwidth/halfwidth codepoints at or after start.
func fdCountFullwidthFrom(input []uint32, start int) int {
	n := 0
	for idx, cp := range input {
		if idx >= start && isFullwidthHalfwidth(cp) {
			n++
		}
	}
	return n
}

// fdCountExtendFrom counts grapheme Extend codepoints at or after start.
func fdCountExtendFrom(input []uint32, start int) int {
	n := 0
	for idx, cp := range input {
		if idx >= start && rdIsGraphemeExtend(cp) {
			n++
		}
	}
	return n
}

// fdCountBidiControl counts bidi format-controls anywhere in input.
func fdCountBidiControl(input []uint32) int {
	n := 0
	for _, cp := range input {
		if isBidiFormatControl(cp) {
			n++
		}
	}
	return n
}

// ─────────────────────────────────────────────────────────────────────
// §4 Top-level detection
// ─────────────────────────────────────────────────────────────────────

// fdMinMultipleExtensions is the dot count at or beyond which the input is
// flagged as a (advisory) multiple-extensions hazard.
const fdMinMultipleExtensions = 3

// filenameDisguiseDetect is the FilenameDisguise detection function.
func filenameDisguiseDetect(input []uint32) fdVerdict {
	dots := fdDotPositions(input)
	lastDotPos := 0
	hasLastDot := false
	if len(dots) > 0 {
		lastDotPos = dots[len(dots)-1]
		hasLastDot = true
	}

	// Extension region begins after the last dot, or at input end if none.
	extStart := len(input)
	if hasLastDot {
		extStart = lastDotPos + 1
	}

	bidiCount := fdCountBidiControl(input)
	fwInExt := fdCountFullwidthFrom(input, extStart)
	extInExt := fdCountExtendFrom(input, extStart)

	inputCopy := make([]uint32, len(input))
	copy(inputCopy, input)

	classification := fdClassify(input, dots, extStart)

	return fdVerdict{
		input:            inputCopy,
		classify:         classification,
		dotPositions:     dots,
		lastDotPos:       lastDotPos,
		hasLastDot:       hasLastDot,
		bidiControlCount: bidiCount,
		fullwidthInExt:   fwInExt,
		combiningInExt:   extInExt,
	}
}

// fdClassify walks the four disguise triggers in priority order, mirroring the
// Rust reference's nested match. Every arm is explicit; the terminal else is the
// documented Clear verdict, not a catch-all default.
func fdClassify(input []uint32, dots []int, extStart int) fdClassification {
	// Priority 1: any bidi format-control anywhere in the input.
	if pos, ctlCp, ok := fdFirstBidiControl(input); ok {
		return fdClassification{
			sub:       fdSubThreat{tag: "RloFlip", position: pos, controlCp: ctlCp},
			positions: []int{pos},
			decoded:   []uint8{},
		}
	}

	// Priority 2: fullwidth/halfwidth in the extension.
	if pos, cp, ok := fdFirstFullwidthFrom(input, extStart); ok {
		return fdClassification{
			sub:       fdSubThreat{tag: "WidthClassExt", position: pos, cp: cp},
			positions: []int{pos},
			decoded:   []uint8{},
		}
	}

	// Priority 3: combining (grapheme Extend) mark in the extension.
	if pos, cp, ok := fdFirstExtendFrom(input, extStart); ok {
		return fdClassification{
			sub:       fdSubThreat{tag: "CombiningInExt", position: pos, cp: cp},
			positions: []int{pos},
			decoded:   []uint8{},
		}
	}

	// Priority 4: three or more extensions (advisory).
	if len(dots) >= fdMinMultipleExtensions {
		positions := make([]int, len(dots))
		copy(positions, dots)
		return fdClassification{
			sub:       fdSubThreat{tag: "MultipleExtensions", dotCount: len(dots)},
			positions: positions,
			decoded:   []uint8{},
		}
	}

	// No disguise trigger fired: the filename is clear.
	return fdClassification{clear: true, positions: []int{}, decoded: []uint8{}}
}
