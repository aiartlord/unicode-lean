package security

// Stream-Safe-Text-Format-violation detection (F2) — inputs whose consecutive
// non-starter run exceeds the UAX #15 §13 streamSafeLimit of 30. Such an input
// (the canonical "Zalgo" shape, a single base codepoint followed by a long
// combining-mark run) forces unbounded combining-mark buffers in receiver-side
// streaming normalization (toNFC / toNFD / toNFKC / toNFKD) and is a known DoS
// vector.
//
// Direct port of Unicode/Security/Form/StreamSafeViolation.lean, transliterated
// from the verified Rust port security/form/stream_safe_violation.rs. UAX #15
// §13 defines Stream-Safe Text Format as the remediation: insert U+034F
// COMBINING GRAPHEME JOINER (a starter) after every 30 consecutive non-starters,
// which bounds the normalization buffer. StreamSafeViolation is the security
// verdict over the same property — distinct from RendererDivergence's
// combiningStackOverflow (the cosmetic 4-mark threshold), this is the
// spec-mandated DoS-prevention bound.
//
// A codepoint is a non-starter iff its Canonical_Combining_Class is non-zero
// (UAX #15 D49). This module reads CCC from the port's own bundled UCD table via
// canonicalCombiningClass, never a host normalizer.
//
// Sub-threat: StreamSafeOverrun(basePos, runLen) — the first non-starter run
// whose length exceeds streamSafeLimit. basePos is the index of that run's first
// non-starter codepoint.

// ─────────────────────────────────────────────────────────────────────
// §1 Run inventory
// ─────────────────────────────────────────────────────────────────────

// streamSafeLimit is the UAX #15 §13 Stream-Safe limit: the maximum number of
// consecutive non-starters permitted before a COMBINING GRAPHEME JOINER must be
// inserted.
const streamSafeLimit = 30

// isNonStarter reports whether cp is a non-starter — a codepoint with non-zero
// Canonical_Combining_Class (UAX #15 D49). Starters have CCC = 0.
func isNonStarter(cp uint32) bool {
	return canonicalCombiningClass(cp) != 0
}

// nonStarterRun is a maximal run of consecutive non-starter codepoints: start is
// the absolute index of the run's first codepoint, length is the run's length.
type nonStarterRun struct {
	start  int
	length int
}

// nonStarterRuns is the inventory of every maximal non-starter run in input.
// Mirrors collectRunsGo: a run opens on the first non-starter, its start index
// is fixed to that codepoint's absolute index, and it closes (emitting its
// (start, length) pair) on the next starter or at end of input.
func nonStarterRuns(input []uint32) []nonStarterRun {
	runs := []nonStarterRun{}
	curStart := -1
	curLen := 0
	for i, cp := range input {
		if isNonStarter(cp) {
			if curStart < 0 {
				curStart = i
			}
			curLen++
		} else {
			if curStart >= 0 {
				runs = append(runs, nonStarterRun{start: curStart, length: curLen})
			}
			curStart = -1
			curLen = 0
		}
	}
	if curStart >= 0 {
		runs = append(runs, nonStarterRun{start: curStart, length: curLen})
	}
	return runs
}

// firstOverrun is the first non-starter run whose length exceeds
// streamSafeLimit; the second result is false when none exists.
func firstOverrun(input []uint32) (nonStarterRun, bool) {
	for _, run := range nonStarterRuns(input) {
		if run.length > streamSafeLimit {
			return run, true
		}
	}
	return nonStarterRun{}, false
}

// maxRunLen is the longest non-starter run length in input.
func maxRunLen(input []uint32) int {
	acc := 0
	for _, run := range nonStarterRuns(input) {
		if run.length > acc {
			acc = run.length
		}
	}
	return acc
}

// overrunCount is the number of distinct non-starter runs that exceed
// streamSafeLimit.
func overrunCount(input []uint32) int {
	acc := 0
	for _, run := range nonStarterRuns(input) {
		if run.length > streamSafeLimit {
			acc++
		}
	}
	return acc
}

// totalNonStarters is the total number of non-starter codepoints in input (the
// sum of all run lengths).
func totalNonStarters(input []uint32) int {
	acc := 0
	for _, run := range nonStarterRuns(input) {
		acc += run.length
	}
	return acc
}

// ─────────────────────────────────────────────────────────────────────
// §2 Types
// ─────────────────────────────────────────────────────────────────────

// streamSafeSubThreat is a sub-threat this detector can fire. tag is the
// human-facing classification tag; basePos is the index of the run's first
// non-starter codepoint and runLen is the length of the overrunning run.
type streamSafeSubThreat struct {
	tag     string
	basePos int
	runLen  int
}

// streamSafeClassification is the top-level F2 classification. When clear is
// true no non-starter run exceeds the Stream-Safe limit; otherwise sub names the
// sub-threat that fired and positions holds the implicated codepoint positions.
type streamSafeClassification struct {
	clear     bool
	sub       streamSafeSubThreat
	positions []int
}

// tag is the human-facing tag for a hazard; the second result is false when
// clear.
func (c streamSafeClassification) tag() (string, bool) {
	if c.clear {
		return "", false
	}
	return c.sub.tag, true
}

// streamSafeVerdict is the structured output of streamSafeViolationDetect. The
// run-inventory summaries (maxRunLen, overrunCount, totalNonStarters) are exposed
// so downstream callers can size the buffer pressure a streaming normalizer would
// see.
type streamSafeVerdict struct {
	input            []uint32
	classify         streamSafeClassification
	maxRunLen        int
	overrunCount     int
	totalNonStarters int
}

// ─────────────────────────────────────────────────────────────────────
// §3 Top-level detection
// ─────────────────────────────────────────────────────────────────────

// streamSafeViolationDetect is the F2 detection function. It fires
// StreamSafeOverrun on the first non-starter run whose length exceeds
// streamSafeLimit.
func streamSafeViolationDetect(input []uint32) streamSafeVerdict {
	var classification streamSafeClassification
	if run, ok := firstOverrun(input); ok {
		classification = streamSafeClassification{
			clear: false,
			sub: streamSafeSubThreat{
				tag:     "StreamSafeOverrun",
				basePos: run.start,
				runLen:  run.length,
			},
			positions: []int{run.start},
		}
	} else {
		classification = streamSafeClassification{clear: true, positions: []int{}}
	}
	return streamSafeVerdict{
		input:            append([]uint32(nil), input...),
		classify:         classification,
		maxRunLen:        maxRunLen(input),
		overrunCount:     overrunCount(input),
		totalNonStarters: totalNonStarters(input),
	}
}
