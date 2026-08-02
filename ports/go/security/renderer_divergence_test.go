package security

import (
	"slices"
	"testing"
)

// Ground truth: every detect_* / structural check in
// Unicode.Security.Display.RendererDivergence, mirrored from the verified Rust
// port security/display/renderer_divergence.rs. This detector is context-free —
// every vector is expressible in the shared detector fixture
// (fixtures/security/detectors/renderer_divergence.json).

func rdTagOf(input []uint32) (string, bool) {
	return rendererDivergenceDetect(input).classify.tag()
}

// TestRendererDivergenceFixture runs the shared context-free detector fixture
// through rendererDivergenceDetect, mapping the classification tag onto its
// reason code the way TestDetectorFixtures checks required_findings.
func TestRendererDivergenceFixture(t *testing.T) {
	var fixture detectorFixture
	loadJSON(t, fixturePath(t, "fixtures", "security", "detectors", "renderer_divergence.json"), &fixture)
	if fixture.Schema != 1 {
		t.Fatalf("unexpected detector schema: %d", fixture.Schema)
	}
	if fixture.Family != string(FamilyRendererDivergence) {
		t.Fatalf("unexpected family: %s", fixture.Family)
	}
	for _, tc := range fixture.Cases {
		verdict := rendererDivergenceDetect(tc.Input)
		findings := []string{}
		if tag, ok := verdict.classify.tag(); ok {
			findings = append(findings, reasonCode(FamilyRendererDivergence, tag))
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

func TestRendererDivergenceDetectSpotChecks(t *testing.T) {
	// detect_empty_clear
	if !rendererDivergenceDetect([]uint32{}).classify.isClear() {
		t.Errorf("empty should be clear")
	}

	// detect_ascii_clear
	if !rendererDivergenceDetect([]uint32{0x48, 0x65, 0x6C, 0x6C, 0x6F}).classify.isClear() {
		t.Errorf("ascii should be clear")
	}

	// detect_han_clear
	if !rendererDivergenceDetect([]uint32{0x4E2D, 0x6587}).classify.isClear() {
		t.Errorf("han should be clear")
	}

	// detect_vs_variance — a single VS (FE0F) after an emoji.
	if tag, _ := rdTagOf([]uint32{0x1F600, 0xFE0F}); tag != "VariationSelectorVariance" {
		t.Errorf("vs variance: tag=%q", tag)
	}

	// detect_rgi_family_clear — a registered RGI family ZWJ sequence.
	v := rendererDivergenceDetect([]uint32{0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466})
	if !v.classify.isClear() || !v.hasZwj {
		t.Errorf("rgi family: clear=%v hasZwj=%v", v.classify.isClear(), v.hasZwj)
	}

	// detect_unregistered_zwj_variance — man + ZWJ + woman, not in RGI.
	if tag, _ := rdTagOf([]uint32{0x1F468, 0x200D, 0x1F469}); tag != "UnregisteredZwjVariance" {
		t.Errorf("unregistered zwj: tag=%q", tag)
	}

	// detect_zalgo_variance — a 4-deep combining stack.
	v = rendererDivergenceDetect([]uint32{0x0061, 0x0301, 0x0302, 0x0303, 0x0304})
	if tag, _ := v.classify.tag(); tag != "CombiningStackOverflow" {
		t.Errorf("zalgo: tag=%q", tag)
	}
	if !slices.Equal(v.classify.posns(), []int{0}) {
		t.Errorf("zalgo positions: %#v", v.classify.posns())
	}
	if v.combiningCount != 4 {
		t.Errorf("zalgo combiningCount=%d", v.combiningCount)
	}

	// detect_fullwidth_variance — fullwidth 'A'.
	if tag, _ := rdTagOf([]uint32{0xFF21}); tag != "FullwidthVariance" {
		t.Errorf("fullwidth: tag=%q", tag)
	}

	// detect_mixed_direction — Latin + Hebrew in one input.
	v = rendererDivergenceDetect([]uint32{0x41, 0x42, 0x05D0, 0x05D1})
	if tag, _ := v.classify.tag(); tag != "MixedDirectionVariance" {
		t.Errorf("mixed direction: tag=%q", tag)
	}
	if !(v.strongLtrCount > 0 && v.strongRtlCount > 0) {
		t.Errorf("mixed direction counts: ltr=%d rtl=%d", v.strongLtrCount, v.strongRtlCount)
	}
}

// ── priority-ladder structural checks ────────────────────────────────────

func TestRendererDivergenceStructural(t *testing.T) {
	// A combining stack outranks a variation selector present later.
	v := rendererDivergenceDetect([]uint32{0x0061, 0x0301, 0x0302, 0x0303, 0x0304, 0xFE0F})
	if tag, _ := v.classify.tag(); tag != "CombiningStackOverflow" {
		t.Errorf("combining stack should beat vs: tag=%q", tag)
	}

	// Exactly three combining marks is below the stack threshold — no overflow.
	v = rendererDivergenceDetect([]uint32{0x0061, 0x0301, 0x0302, 0x0303})
	if tag, ok := v.classify.tag(); ok && tag == "CombiningStackOverflow" {
		t.Errorf("three marks below threshold should not overflow: tag=%q", tag)
	}
}

// ── §4 data-layer sanity: grapheme-Extend reuse ──────────────────────────

func TestRendererDivergenceGraphemeExtend(t *testing.T) {
	// Combining diacriticals are Grapheme_Extend (from DerivedCoreProperties).
	if !rdIsGraphemeExtend(0x0301) || !rdIsGraphemeExtend(0x036F) {
		t.Errorf("combining diacriticals should be grapheme-extend")
	}
	// Base letters are not.
	if rdIsGraphemeExtend(0x0061) || rdIsGraphemeExtend(0x4E2D) {
		t.Errorf("base letters should not be grapheme-extend")
	}
	// Emoji skin-tone modifiers have GCB=Extend though they lack the
	// Grapheme_Extend property — the union with ezwjIsEmojiModifier restores
	// parity with the Rust GCB Extend table.
	if !rdIsGraphemeExtend(0x1F3FB) || !rdIsGraphemeExtend(0x1F3FF) {
		t.Errorf("skin-tone modifiers should be grapheme-extend (GCB Extend)")
	}
}
