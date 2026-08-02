package security

import (
	"slices"
	"testing"
)

// Ground truth: every detect_* theorem in
// Unicode.Security.Boundary.IdentifierFormDrift, mirrored from the verified Rust
// reference implementation. This detector is context-free — every vector is
// expressible in the shared detector fixture
// (fixtures/security/detectors/identifier_form_drift.json, bundled under
// testdata).

func ifdTagOf(input []uint32) (string, bool) {
	return identifierFormDriftDetect(input).classify.tag()
}

// TestIdentifierFormDriftFixture runs the shared context-free detector fixture
// through identifierFormDriftDetect, mapping the classification tag onto its
// reason code the way TestDetectorFixtures checks required_findings.
func TestIdentifierFormDriftFixture(t *testing.T) {
	var fixture detectorFixture
	loadJSON(t, fixturePath(t, "fixtures", "security", "detectors", "identifier_form_drift.json"), &fixture)
	if fixture.Schema != 1 {
		t.Fatalf("unexpected detector schema: %d", fixture.Schema)
	}
	if fixture.Family != string(FamilyIdentifierFormDrift) {
		t.Fatalf("unexpected family: %s", fixture.Family)
	}
	for _, tc := range fixture.Cases {
		verdict := identifierFormDriftDetect(tc.Input)
		findings := []string{}
		if tag, ok := verdict.classify.tag(); ok {
			findings = append(findings, reasonCode(FamilyIdentifierFormDrift, tag))
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

// ── §6 detect spot checks (one per Rust #[test]) ─────────────────────────

func TestIdentifierFormDriftDetectSpotChecks(t *testing.T) {
	// detect_empty_clear
	if !identifierFormDriftDetect([]uint32{}).classify.isClear() {
		t.Errorf("empty should be clear")
	}

	// detect_ascii_clear — "Hello"; every ASCII letter is Allowed, identity NFKD.
	v := identifierFormDriftDetect([]uint32{0x48, 0x65, 0x6C, 0x6C, 0x6F})
	if !v.classify.isClear() {
		t.Errorf("Hello should be clear")
	}
	if v.shiftCount != 0 {
		t.Errorf("Hello shiftCount = %d, want 0", v.shiftCount)
	}

	// detect_greek_alpha_clear — α is Allowed with identity NFKD.
	if !identifierFormDriftDetect([]uint32{0x03B1}).classify.isClear() {
		t.Errorf("greek alpha should be clear")
	}

	// detect_math_italic_a_shift — U+1D44E Restricted, NFKD head U+0061 Allowed.
	v = identifierFormDriftDetect([]uint32{0x1D44E})
	if tag, _ := v.classify.tag(); tag != "IdentifierStatusShift" {
		t.Errorf("math italic a: tag=%q", tag)
	}
	if !slices.Equal(v.classify.posns(), []int{0}) {
		t.Errorf("math italic a positions: %#v", v.classify.posns())
	}
	if v.shiftCount != 1 {
		t.Errorf("math italic a shiftCount = %d, want 1", v.shiftCount)
	}

	// detect_fullwidth_A_shift — U+FF21 Restricted, NFKD head U+0041 Allowed.
	if tag, _ := ifdTagOf([]uint32{0xFF21}); tag != "IdentifierStatusShift" {
		t.Errorf("fullwidth A: tag=%q", tag)
	}

	// detect_circled_A_shift — U+24B6 CIRCLED LATIN CAPITAL LETTER A → A.
	if tag, _ := ifdTagOf([]uint32{0x24B6}); tag != "IdentifierStatusShift" {
		t.Errorf("circled A: tag=%q", tag)
	}

	// detect_fi_ligature_shift — U+FB01 'ﬁ' ligature → f.
	if tag, _ := ifdTagOf([]uint32{0xFB01}); tag != "IdentifierStatusShift" {
		t.Errorf("fi ligature: tag=%q", tag)
	}

	// detect_roman_iv_shift — U+2163 ROMAN NUMERAL FOUR → I.
	if tag, _ := ifdTagOf([]uint32{0x2163}); tag != "IdentifierStatusShift" {
		t.Errorf("roman IV: tag=%q", tag)
	}
}

// A shift embedded mid-string reports the first shifting position, not 0.
func TestIdentifierFormDriftReportsFirstShiftPosition(t *testing.T) {
	// "ab" + U+1D44E: positions 0,1 are Allowed/identity, position 2 shifts.
	v := identifierFormDriftDetect([]uint32{0x61, 0x62, 0x1D44E})
	if !slices.Equal(v.classify.posns(), []int{2}) {
		t.Errorf("first shift positions: %#v", v.classify.posns())
	}
	if v.shiftCount != 1 {
		t.Errorf("first shift shiftCount = %d, want 1", v.shiftCount)
	}
}

// ── reason-code stability ────────────────────────────────────────────────

func TestIdentifierFormDriftReasonCode(t *testing.T) {
	if code := reasonCode(FamilyIdentifierFormDrift, "IdentifierStatusShift"); code != "unicode.security.X.identifier-form-drift.IdentifierStatusShift" {
		t.Errorf("reason code = %q", code)
	}
}

// ── data-layer sanity: reused predicates ─────────────────────────────────

func TestIdentifierFormDriftPredicateReuse(t *testing.T) {
	// Reuses the port's own UTS #39 Identifier_Status predicate (isIdAllowed):
	// plain ASCII 'a'/'A' are Allowed; the compatibility forms are Restricted.
	if !isIdAllowed(0x0061) || !isIdAllowed(0x0041) {
		t.Errorf("ASCII 'a'/'A' should be Identifier_Status = Allowed")
	}
	if isIdAllowed(0x1D44E) || isIdAllowed(0xFF21) {
		t.Errorf("math-italic-a and fullwidth-A should be Restricted")
	}
	// Reuses the port's own NFKD pipeline (toNFKD): the head of each
	// compatibility form is its plain ASCII counterpart.
	if head := toNFKD([]uint32{0x1D44E}); len(head) == 0 || head[0] != 0x0061 {
		t.Errorf("NFKD head of U+1D44E = %#v, want [0x61 ...]", head)
	}
}
