package security

import (
	"slices"
	"testing"
)

// Ground truth: every detect_* theorem in
// Unicode/Security/Form/CaseExpansionMismatch.lean, mirrored from the verified
// Rust reference implementation. The shared context-free detector fixture
// (bundled under testdata) carries the same vectors.

func cemTagOf(input []uint32) (string, bool) {
	return caseExpansionMismatchDetect(input).classify.tag()
}

// TestCaseExpansionMismatchFixture runs the shared context-free detector fixture
// through caseExpansionMismatchDetect, mapping the classification tag onto its
// reason code the way TestDetectorFixtures checks required_findings.
func TestCaseExpansionMismatchFixture(t *testing.T) {
	var fixture detectorFixture
	loadJSON(t, fixturePath(t, "fixtures", "security", "detectors", "case_expansion_mismatch.json"), &fixture)
	if fixture.Schema != 1 {
		t.Fatalf("unexpected detector schema: %d", fixture.Schema)
	}
	if fixture.Family != string(FamilyCaseExpansionMismatch) {
		t.Fatalf("unexpected family: %s", fixture.Family)
	}
	for _, tc := range fixture.Cases {
		verdict := caseExpansionMismatchDetect(tc.Input)
		findings := []string{}
		if tag, ok := verdict.classify.tag(); ok {
			findings = append(findings, reasonCode(FamilyCaseExpansionMismatch, tag))
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

// ── detect spot checks (one per Rust #[test]) ────────────────────────────

func TestCaseExpansionMismatchDetectSpotChecks(t *testing.T) {
	// detect_empty_clear
	if !caseExpansionMismatchDetect([]uint32{}).classify.isClear() {
		t.Errorf("empty should be clear")
	}

	// detect_ascii_clear — "Hello"; every ASCII cp case-maps to a single cp.
	v := caseExpansionMismatchDetect([]uint32{0x48, 0x65, 0x6C, 0x6C, 0x6F})
	if !v.classify.isClear() {
		t.Errorf("Hello should be clear")
	}
	if v.maxExpansionLen != 1 {
		t.Errorf("Hello maxExpansionLen: got %d, want 1", v.maxExpansionLen)
	}

	// detect_sharp_s_upper — ß (U+00DF) toUpper → "SS".
	v = caseExpansionMismatchDetect([]uint32{0x00DF})
	if tag, _ := v.classify.tag(); tag != "UpperExpansion" {
		t.Errorf("sharp-s tag: got %q, want UpperExpansion", tag)
	}
	if !slices.Equal(v.classify.posns(), []int{0}) {
		t.Errorf("sharp-s positions: got %v, want [0]", v.classify.posns())
	}
	if v.upperExpansionCount != 1 {
		t.Errorf("sharp-s upperExpansionCount: got %d, want 1", v.upperExpansionCount)
	}
	if v.maxExpansionLen != 2 {
		t.Errorf("sharp-s maxExpansionLen: got %d, want 2", v.maxExpansionLen)
	}

	// detect_fi_ligature_upper — ﬁ (U+FB01) toUpper → "FI".
	if tag, _ := cemTagOf([]uint32{0xFB01}); tag != "UpperExpansion" {
		t.Errorf("fi-ligature tag: got %q, want UpperExpansion", tag)
	}

	// detect_dotted_I_lower — İ (U+0130) toLower under default → "i + 0307";
	// no upper expansion, so the detector falls through to the lower scan.
	v = caseExpansionMismatchDetect([]uint32{0x0130})
	if tag, _ := v.classify.tag(); tag != "LowerExpansion" {
		t.Errorf("dotted-I tag: got %q, want LowerExpansion", tag)
	}
	if v.lowerExpansionCount != 1 {
		t.Errorf("dotted-I lowerExpansionCount: got %d, want 1", v.lowerExpansionCount)
	}

	// ﬃ (U+FB03) toUpper → "FFI" (length 3) — the expansion length is reported.
	v = caseExpansionMismatchDetect([]uint32{0xFB03})
	if tag, _ := v.classify.tag(); tag != "UpperExpansion" {
		t.Errorf("ffi-ligature tag: got %q, want UpperExpansion", tag)
	}
	if v.maxExpansionLen != 3 {
		t.Errorf("ffi-ligature maxExpansionLen: got %d, want 3", v.maxExpansionLen)
	}

	// A leading ASCII then ß: the upper expansion is reported at position 1.
	v = caseExpansionMismatchDetect([]uint32{0x61, 0x00DF})
	if !slices.Equal(v.classify.posns(), []int{1}) {
		t.Errorf("mid-string positions: got %v, want [1]", v.classify.posns())
	}
}

// The composed reason codes for each sub-threat.
func TestCaseExpansionMismatchReasonCode(t *testing.T) {
	if got := reasonCode(FamilyCaseExpansionMismatch, "UpperExpansion"); got != "unicode.security.F.case-expansion-mismatch.UpperExpansion" {
		t.Errorf("UpperExpansion reason code: got %q", got)
	}
	if got := reasonCode(FamilyCaseExpansionMismatch, "LowerExpansion"); got != "unicode.security.F.case-expansion-mismatch.LowerExpansion" {
		t.Errorf("LowerExpansion reason code: got %q", got)
	}
}
