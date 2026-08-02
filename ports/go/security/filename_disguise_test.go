package security

import (
	"slices"
	"testing"
)

// Ground truth: every detect_* / structural check in
// Unicode.Security.Display.FilenameDisguise, mirrored from the verified Rust
// reference implementation. This detector is context-free — every vector is
// expressible in the shared detector fixture
// (fixtures/security/detectors/filename_disguise.json, bundled under testdata).

func fdTagOf(input []uint32) (string, bool) {
	return filenameDisguiseDetect(input).classify.tag()
}

// TestFilenameDisguiseFixture runs the shared context-free detector fixture
// through filenameDisguiseDetect, mapping the classification tag onto its reason
// code the way TestDetectorFixtures checks required_findings.
func TestFilenameDisguiseFixture(t *testing.T) {
	var fixture detectorFixture
	loadJSON(t, fixturePath(t, "fixtures", "security", "detectors", "filename_disguise.json"), &fixture)
	if fixture.Schema != 1 {
		t.Fatalf("unexpected detector schema: %d", fixture.Schema)
	}
	if fixture.Family != string(FamilyFilenameDisguise) {
		t.Fatalf("unexpected family: %s", fixture.Family)
	}
	for _, tc := range fixture.Cases {
		verdict := filenameDisguiseDetect(tc.Input)
		findings := []string{}
		if tag, ok := verdict.classify.tag(); ok {
			findings = append(findings, reasonCode(FamilyFilenameDisguise, tag))
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

func TestFilenameDisguiseDetectSpotChecks(t *testing.T) {
	// detect_empty_clear
	if !filenameDisguiseDetect([]uint32{}).classify.isClear() {
		t.Errorf("empty should be clear")
	}

	// detect_plain_txt_clear — "document.txt"
	v := filenameDisguiseDetect([]uint32{
		0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x2E, 0x74, 0x78, 0x74,
	})
	if !v.classify.isClear() {
		t.Errorf("document.txt should be clear")
	}
	if !v.hasLastDot || v.lastDotPos != 8 {
		t.Errorf("document.txt lastDotPos: hasLastDot=%v pos=%d", v.hasLastDot, v.lastDotPos)
	}

	// detect_no_extension_clear — "foo"
	v = filenameDisguiseDetect([]uint32{0x66, 0x6F, 0x6F})
	if !v.classify.isClear() {
		t.Errorf("foo should be clear")
	}
	if v.hasLastDot {
		t.Errorf("foo should have no last dot, got pos=%d", v.lastDotPos)
	}

	// detect_tar_gz_clear — "archive.tar.gz" (2 dots, below the multi-ext bound)
	if !filenameDisguiseDetect([]uint32{
		0x61, 0x72, 0x63, 0x68, 0x69, 0x76, 0x65, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A,
	}).classify.isClear() {
		t.Errorf("archive.tar.gz should be clear")
	}

	// detect_hebrew_clear — native Hebrew name, no bidi controls.
	if !filenameDisguiseDetect([]uint32{0x05D0, 0x05D1, 0x05D2, 0x2E, 0x74, 0x78, 0x74}).classify.isClear() {
		t.Errorf("hebrew name should be clear")
	}

	// detect_rlo_flip — "document<RLO>txt.exe"
	v = filenameDisguiseDetect([]uint32{
		0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x202E, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65,
	})
	if tag, _ := v.classify.tag(); tag != "RloFlip" {
		t.Errorf("rlo flip: tag=%q", tag)
	}
	if !slices.Equal(v.classify.posns(), []int{8}) {
		t.Errorf("rlo flip positions: %#v", v.classify.posns())
	}

	// detect_isolate_flip — RLI/PDI isolate variant, also RloFlip.
	if tag, _ := fdTagOf([]uint32{
		0x64, 0x6F, 0x63, 0x2067, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65, 0x2069,
	}); tag != "RloFlip" {
		t.Errorf("isolate flip: tag=%q", tag)
	}

	// detect_fullwidth_exe — "file.ＥＸＥ"
	if tag, _ := fdTagOf([]uint32{0x66, 0x69, 0x6C, 0x65, 0x2E, 0xFF25, 0xFF38, 0xFF25}); tag != "WidthClassExt" {
		t.Errorf("fullwidth ext: tag=%q", tag)
	}

	// detect_combining_in_ext — "file.é xe" (combining acute in the extension)
	if tag, _ := fdTagOf([]uint32{0x66, 0x69, 0x6C, 0x65, 0x2E, 0x65, 0x0301, 0x78, 0x65}); tag != "CombiningInExt" {
		t.Errorf("combining in ext: tag=%q", tag)
	}

	// detect_triple_extension — "setup.tar.gz.sig"
	if tag, _ := fdTagOf([]uint32{
		0x73, 0x65, 0x74, 0x75, 0x70, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A, 0x2E, 0x73, 0x69, 0x67,
	}); tag != "MultipleExtensions" {
		t.Errorf("triple extension: tag=%q", tag)
	}
}

// ── priority-ladder structural check ─────────────────────────────────────

func TestFilenameDisguiseStructural(t *testing.T) {
	// A bidi control outranks a fullwidth extension: <RLO>f.Ｅ → RloFlip.
	if tag, _ := fdTagOf([]uint32{0x202E, 0x66, 0x2E, 0xFF25}); tag != "RloFlip" {
		t.Errorf("bidi control should beat fullwidth: tag=%q", tag)
	}
}

// ── data-layer sanity: reused predicates ─────────────────────────────────

func TestFilenameDisguisePredicateReuse(t *testing.T) {
	// Reuses the port's own bidi-format-control set (isBidiFormatControl).
	if !isBidiFormatControl(0x202E) || !isBidiFormatControl(0x2067) {
		t.Errorf("RLO and RLI should be bidi format-controls")
	}
	if isBidiFormatControl(0x0041) {
		t.Errorf("plain 'A' is not a bidi format-control")
	}
	// Reuses the port's grapheme Extend predicate (rdIsGraphemeExtend).
	if !rdIsGraphemeExtend(0x0301) {
		t.Errorf("combining acute should be grapheme-extend")
	}
	if rdIsGraphemeExtend(0x0065) {
		t.Errorf("base letter 'e' should not be grapheme-extend")
	}
}
