package security

import (
	"slices"
	"testing"
)

// Ground truth: the detect_* theorems in
// Unicode/Security/Form/StreamSafeViolation.lean, mirrored from the verified
// Rust port security/form/stream_safe_violation.rs. This detector is
// context-free — every fixture vector is expressible in the shared detector
// fixture (fixtures/security/detectors/stream_safe_violation.json).
//
// U+0301 COMBINING ACUTE ACCENT has CCC = 230 (a non-starter); the ASCII letters
// in these vectors have CCC = 0 (starters).

const streamSafeAcute uint32 = 0x0301

// aPlusMarks builds "a" followed by n combining acute accents.
func aPlusMarks(n int) []uint32 {
	v := []uint32{0x61}
	for i := 0; i < n; i++ {
		v = append(v, streamSafeAcute)
	}
	return v
}

// TestStreamSafeViolationFixture runs the shared context-free detector fixture
// through streamSafeViolationDetect, mapping the classification tag onto its
// reason code the way TestDetectorFixtures checks required_findings.
func TestStreamSafeViolationFixture(t *testing.T) {
	var fixture detectorFixture
	loadJSON(t, fixturePath(t, "fixtures", "security", "detectors", "stream_safe_violation.json"), &fixture)
	if fixture.Schema != 1 {
		t.Fatalf("unexpected detector schema: %d", fixture.Schema)
	}
	if fixture.Family != string(FamilyStreamSafeViolation) {
		t.Fatalf("unexpected family: %s", fixture.Family)
	}
	for _, tc := range fixture.Cases {
		verdict := streamSafeViolationDetect(tc.Input)
		findings := []string{}
		if tag, ok := verdict.classify.tag(); ok {
			findings = append(findings, reasonCode(FamilyStreamSafeViolation, tag))
		}
		for _, required := range tc.RequiredFindings {
			if !slices.Contains(findings, required) {
				t.Fatalf("%s: missing finding %q in %#v", tc.Name, required, findings)
			}
		}
		if len(tc.RequiredFindings) == 0 && len(findings) != 0 {
			t.Fatalf("%s: unexpected finding in %#v", tc.Name, findings)
		}
	}
}

// TestStreamSafeViolationReasonCode confirms the F-layer reason code wiring
// resolves to unicode.security.F.stream-safe-violation.StreamSafeOverrun.
func TestStreamSafeViolationReasonCode(t *testing.T) {
	if got := reasonCode(FamilyStreamSafeViolation, "StreamSafeOverrun"); got != "unicode.security.F.stream-safe-violation.StreamSafeOverrun" {
		t.Errorf("reason code = %q", got)
	}
}

// TestStreamSafeViolationBoundary exercises the 30/31 strict-> boundary and the
// detect_* spot checks transcribed from the Rust reference tests.
func TestStreamSafeViolationBoundary(t *testing.T) {
	// detect_empty_clear: empty input is clear.
	v := streamSafeViolationDetect([]uint32{})
	if _, ok := v.classify.tag(); ok {
		t.Errorf("empty: expected clear")
	}
	if v.maxRunLen != 0 || v.overrunCount != 0 || v.totalNonStarters != 0 {
		t.Errorf("empty summaries: %d %d %d", v.maxRunLen, v.overrunCount, v.totalNonStarters)
	}

	// detect_ascii_clear: pure-ASCII "Hello" is clear.
	v = streamSafeViolationDetect([]uint32{0x48, 0x65, 0x6C, 0x6C, 0x6F})
	if _, ok := v.classify.tag(); ok {
		t.Errorf("ascii: expected clear")
	}
	if v.maxRunLen != 0 || v.totalNonStarters != 0 {
		t.Errorf("ascii summaries: %d %d", v.maxRunLen, v.totalNonStarters)
	}

	// detect_one_combine_clear: "a" + one mark is clear.
	v = streamSafeViolationDetect([]uint32{0x61, streamSafeAcute})
	if _, ok := v.classify.tag(); ok {
		t.Errorf("one-combine: expected clear")
	}
	if v.maxRunLen != 1 || v.overrunCount != 0 || v.totalNonStarters != 1 {
		t.Errorf("one-combine summaries: %d %d %d", v.maxRunLen, v.overrunCount, v.totalNonStarters)
	}

	// detect_thirty_marks_clear: exactly 30 marks is the boundary — clear under
	// strict >.
	v = streamSafeViolationDetect(aPlusMarks(30))
	if _, ok := v.classify.tag(); ok {
		t.Errorf("thirty: expected clear")
	}
	if v.maxRunLen != 30 || v.overrunCount != 0 || v.totalNonStarters != 30 {
		t.Errorf("thirty summaries: %d %d %d", v.maxRunLen, v.overrunCount, v.totalNonStarters)
	}

	// detect_thirtyone_marks_hazard: 31 marks fires StreamSafeOverrun with
	// firstOverrun = (1, 31) and positions [1].
	v = streamSafeViolationDetect(aPlusMarks(31))
	tag, ok := v.classify.tag()
	if !ok || tag != "StreamSafeOverrun" {
		t.Errorf("thirtyone tag = %q, %v", tag, ok)
	}
	if !slices.Equal(v.classify.positions, []int{1}) {
		t.Errorf("thirtyone positions = %#v", v.classify.positions)
	}
	if v.classify.sub.basePos != 1 || v.classify.sub.runLen != 31 {
		t.Errorf("thirtyone sub = %+v", v.classify.sub)
	}
	if v.maxRunLen != 31 || v.overrunCount != 1 || v.totalNonStarters != 31 {
		t.Errorf("thirtyone summaries: %d %d %d", v.maxRunLen, v.overrunCount, v.totalNonStarters)
	}
}

// TestStreamSafeViolationRunInventory covers the run-inventory structure checks
// transcribed from the Rust reference (bare run at index 0, two short runs
// summed, first overrun wins).
func TestStreamSafeViolationRunInventory(t *testing.T) {
	// A bare 31-mark run (no leading starter) records its start as 0.
	bare := []uint32{}
	for i := 0; i < 31; i++ {
		bare = append(bare, streamSafeAcute)
	}
	v := streamSafeViolationDetect(bare)
	if tag, ok := v.classify.tag(); !ok || tag != "StreamSafeOverrun" {
		t.Errorf("bare tag = %q, %v", tag, ok)
	}
	if !slices.Equal(v.classify.positions, []int{0}) {
		t.Errorf("bare positions = %#v", v.classify.positions)
	}
	if v.maxRunLen != 31 || v.totalNonStarters != 31 {
		t.Errorf("bare summaries: %d %d", v.maxRunLen, v.totalNonStarters)
	}

	// Two separate runs each under the limit stay clear but are both counted.
	// "a" + 30 marks + "b" + 30 marks.
	twoRuns := aPlusMarks(30)
	twoRuns = append(twoRuns, 0x62)
	for i := 0; i < 30; i++ {
		twoRuns = append(twoRuns, streamSafeAcute)
	}
	v = streamSafeViolationDetect(twoRuns)
	if _, ok := v.classify.tag(); ok {
		t.Errorf("two-runs: expected clear")
	}
	if v.maxRunLen != 30 || v.overrunCount != 0 || v.totalNonStarters != 60 {
		t.Errorf("two-runs summaries: %d %d %d", v.maxRunLen, v.overrunCount, v.totalNonStarters)
	}

	// The first overrun wins: a short run before a long run does not shadow it,
	// and the reported basePos is the long run's start. "a" + 5 marks + "b" + 31
	// marks — the run starting at index 7 fires.
	firstWins := aPlusMarks(5)
	firstWins = append(firstWins, 0x62)
	for i := 0; i < 31; i++ {
		firstWins = append(firstWins, streamSafeAcute)
	}
	v = streamSafeViolationDetect(firstWins)
	if tag, ok := v.classify.tag(); !ok || tag != "StreamSafeOverrun" {
		t.Errorf("first-wins tag = %q, %v", tag, ok)
	}
	if !slices.Equal(v.classify.positions, []int{7}) {
		t.Errorf("first-wins positions = %#v", v.classify.positions)
	}
	if v.maxRunLen != 31 || v.overrunCount != 1 || v.totalNonStarters != 36 {
		t.Errorf("first-wins summaries: %d %d %d", v.maxRunLen, v.overrunCount, v.totalNonStarters)
	}
}
