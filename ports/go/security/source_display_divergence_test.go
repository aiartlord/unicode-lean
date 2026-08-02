package security

import (
	"slices"
	"testing"
)

// Ground truth: the detect_* spot-check theorems in
// Unicode.Security.Display.SourceDisplayDivergence, mirrored from the verified
// Rust port security/display/source_display_divergence.rs. This detector is
// context-free — every vector is expressible in the shared detector fixture
// (fixtures/security/detectors/source_display_divergence.json).

func sddSub(input []uint32) (string, bool) {
	return sourceDisplayDivergenceDetect(input).tag()
}

// TestSourceDisplayDivergenceFixture runs the shared context-free detector
// fixture through sourceDisplayDivergenceDetect, mapping the aggregate tag onto
// its reason code the way TestDetectorFixtures checks required_findings.
func TestSourceDisplayDivergenceFixture(t *testing.T) {
	var fixture detectorFixture
	loadJSON(t, fixturePath(t, "fixtures", "security", "detectors", "source_display_divergence.json"), &fixture)
	if fixture.Schema != 1 {
		t.Fatalf("unexpected detector schema: %d", fixture.Schema)
	}
	if fixture.Family != string(FamilySourceDisplayDivergence) {
		t.Fatalf("unexpected family: %s", fixture.Family)
	}
	for _, tc := range fixture.Cases {
		detection := sourceDisplayDivergenceDetect(tc.Input)
		findings := []string{}
		if tag, ok := detection.tag(); ok {
			findings = append(findings, reasonCode(FamilySourceDisplayDivergence, tag))
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

// TestSourceDisplayDivergenceSpotChecks mirrors the Rust #[test] blocks: the
// clear cases, single-fire pass-through per constituent, and 2-or-more Compound.
func TestSourceDisplayDivergenceSpotChecks(t *testing.T) {
	// clear_cases
	if !sourceDisplayDivergenceDetect([]uint32{}).isClear() {
		t.Errorf("empty should be clear")
	}
	// "Hello world"
	if !sourceDisplayDivergenceDetect([]uint32{0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64}).isClear() {
		t.Errorf("hello world should be clear")
	}
	// "let x = 1;"
	if !sourceDisplayDivergenceDetect([]uint32{0x6C, 0x65, 0x74, 0x20, 0x78, 0x20, 0x3D, 0x20, 0x31, 0x3B}).isClear() {
		t.Errorf("let x = 1; should be clear")
	}

	// single_fire_passthrough
	// tag-encoded "AB"
	if tag, _ := sddSub([]uint32{0xE0041, 0xE0042}); tag != "TagBlock" {
		t.Errorf("tag block: tag=%q", tag)
	}
	// A + VS16
	if tag, _ := sddSub([]uint32{0x0041, 0xFE0F}); tag != "VariationSelector" {
		t.Errorf("variation selector: tag=%q", tag)
	}
	// H + ZWSP + i
	if tag, _ := sddSub([]uint32{0x0048, 0x200B, 0x69}); tag != "ZeroWidth" {
		t.Errorf("zero width: tag=%q", tag)
	}
	// RLO + A
	if tag, _ := sddSub([]uint32{0x202E, 0x41}); tag != "BidiControl" {
		t.Errorf("bidi control: tag=%q", tag)
	}
	// "Neth<Cyrillic е>um"
	if tag, _ := sddSub([]uint32{0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D}); tag != "IdentifierHomoglyph" {
		t.Errorf("identifier homoglyph: tag=%q", tag)
	}

	// two_or_more_is_compound
	// A + VS16 + ZWSP
	if tag, _ := sddSub([]uint32{0x0041, 0xFE0F, 0x200B}); tag != "Compound" {
		t.Errorf("vs+zwsp compound: tag=%q", tag)
	}
	// tag "AB" + ZWSP
	if tag, _ := sddSub([]uint32{0xE0041, 0xE0042, 0x200B}); tag != "Compound" {
		t.Errorf("tag+zwsp compound: tag=%q", tag)
	}
}
