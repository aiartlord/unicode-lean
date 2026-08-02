package security

import (
	"slices"
	"testing"
)

// Ground truth: every detect_* theorem in
// Unicode.Security.Boundary.AdmissibilityFormDrift, mirrored from the verified
// Rust reference implementation. This detector is context-free — every vector is
// expressible in the shared detector fixture
// (fixtures/security/detectors/admissibility_form_drift.json, bundled under
// testdata).

func afdTagOf(input []uint32) (string, bool) {
	return admissibilityFormDriftDetect(input).classify.tag()
}

// TestAdmissibilityFormDriftFixture runs the shared context-free detector
// fixture through admissibilityFormDriftDetect, mapping the classification tag
// onto its reason code the way TestDetectorFixtures checks required_findings.
func TestAdmissibilityFormDriftFixture(t *testing.T) {
	var fixture detectorFixture
	loadJSON(t, fixturePath(t, "fixtures", "security", "detectors", "admissibility_form_drift.json"), &fixture)
	if fixture.Schema != 1 {
		t.Fatalf("unexpected detector schema: %d", fixture.Schema)
	}
	if fixture.Family != string(FamilyAdmissibilityFormDrift) {
		t.Fatalf("unexpected family: %s", fixture.Family)
	}
	for _, tc := range fixture.Cases {
		verdict := admissibilityFormDriftDetect(tc.Input)
		findings := []string{}
		if tag, ok := verdict.classify.tag(); ok {
			findings = append(findings, reasonCode(FamilyAdmissibilityFormDrift, tag))
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

func TestAdmissibilityFormDriftDetectSpotChecks(t *testing.T) {
	// detect_empty_clear — both admissibility calls return false, so they agree.
	if !admissibilityFormDriftDetect([]uint32{}).classify.isClear() {
		t.Errorf("empty should be clear")
	}

	// detect_ascii_clear — "admin"; admissible on both sides (NFKC is identity).
	v := admissibilityFormDriftDetect([]uint32{0x61, 0x64, 0x6D, 0x69, 0x6E})
	if !v.classify.isClear() {
		t.Errorf("admin should be clear")
	}
	if !v.inputAdmissible {
		t.Errorf("admin inputAdmissible = false, want true")
	}
	if !v.nfkcAdmissible {
		t.Errorf("admin nfkcAdmissible = false, want true")
	}

	// detect_fi_ligature_drift — ﬁ (U+FB01) is Restricted (inadmissible), but
	// NFKC decomposes it to "fi" (admissible). Drift fires.
	v = admissibilityFormDriftDetect([]uint32{0xFB01})
	if tag, _ := v.classify.tag(); tag != "AdmissibilityFormDrift" {
		t.Errorf("fi ligature: tag=%q", tag)
	}
	if v.inputAdmissible {
		t.Errorf("fi ligature inputAdmissible = true, want false")
	}
	if !v.nfkcAdmissible {
		t.Errorf("fi ligature nfkcAdmissible = false, want true")
	}

	// detect_jamo_sequence_drift — decomposed Hangul jamos [U+1112, U+1161,
	// U+11AB] are inadmissible, but NFKC composes them to U+D55C 한 (admissible).
	if tag, _ := afdTagOf([]uint32{0x1112, 0x1161, 0x11AB}); tag != "AdmissibilityFormDrift" {
		t.Errorf("jamo sequence: tag=%q", tag)
	}
}

// ── reason-code stability ────────────────────────────────────────────────

func TestAdmissibilityFormDriftReasonCode(t *testing.T) {
	if code := reasonCode(FamilyAdmissibilityFormDrift, "AdmissibilityFormDrift"); code != "unicode.security.X.admissibility-form-drift.AdmissibilityFormDrift" {
		t.Errorf("reason code = %q", code)
	}
}

// ── data-layer sanity: reused + built predicates ─────────────────────────

func TestAdmissibilityFormDriftPredicateReuse(t *testing.T) {
	// Reuses the port's own UTS #39 Identifier_Status predicate (isIdAllowed).
	if !isIdAllowed(0x0061) {
		t.Errorf("ASCII 'a' should be Identifier_Status = Allowed")
	}
	// XID_Start / XID_Continue built from the bundled DerivedCoreProperties.txt:
	// 'a' is a start; a digit is a continue but not a start; U+005F is a start
	// (LOW LINE) but not XID_Start.
	if !isXidStart(0x0061) {
		t.Errorf("'a' should be XID_Start")
	}
	if isXidStart(0x0030) {
		t.Errorf("'0' should not be XID_Start")
	}
	if !isXidContinue(0x0030) {
		t.Errorf("'0' should be XID_Continue")
	}
	if isXidStart(0x005F) {
		t.Errorf("U+005F should not be XID_Start (it is a default-id start only)")
	}
	if !isDefaultIDStart(0x005F) {
		t.Errorf("U+005F should be a default-id start")
	}
	// isAllowedIdentifier is the whole-string admissibility predicate.
	if !isAllowedIdentifier([]uint32{0x61, 0x64, 0x6D, 0x69, 0x6E}) {
		t.Errorf("\"admin\" should be an allowed identifier")
	}
	if isAllowedIdentifier([]uint32{}) {
		t.Errorf("empty should not be an allowed identifier")
	}
	if isAllowedIdentifier([]uint32{0xFB01}) {
		t.Errorf("fi ligature should not be an allowed identifier")
	}
}
