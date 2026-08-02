package security

import (
	"slices"
	"testing"
)

// Ground truth: every probe spot-check, detect_*, priority, tolerance, and
// cue-class theorem in Unicode.Security.Crypto.AiWatermarkDetectability,
// mirrored from the verified Rust port
// security/crypto/ai_watermark_detectability.rs. Each Rust #[test] maps to one
// assertion (or assertion group) below.

func aiwmTagOf(input []uint32) (string, bool) {
	return aiwmDetect(input).classify.tag()
}

// TestAiWatermarkDetectabilityFixture runs the shared context-free detector
// fixture through aiwmDetect, mapping the classification tag onto its reason
// code the way TestDetectorFixtures checks required_findings.
func TestAiWatermarkDetectabilityFixture(t *testing.T) {
	var fixture detectorFixture
	loadJSON(t, fixturePath(t, "fixtures", "security", "detectors", "ai_watermark_detectability.json"), &fixture)
	if fixture.Schema != 1 {
		t.Fatalf("unexpected detector schema: %d", fixture.Schema)
	}
	if fixture.Family != string(FamilyAiWatermarkDetect) {
		t.Fatalf("unexpected family: %s", fixture.Family)
	}
	for _, tc := range fixture.Cases {
		verdict := aiwmDetect(tc.Input)
		findings := []string{}
		if tag, ok := verdict.classify.tag(); ok {
			findings = append(findings, reasonCode(FamilyAiWatermarkDetect, tag))
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

// TestAiWatermarkDetectabilityToleranceVectors transcribes the Rust reference's
// two Context-tolerance vectors (detect_zwsp_jittered_strict_clear /
// detect_zwsp_jittered_tolerant_fires): ZWSPs at positions 1, 3, 6 (gaps 2, 3).
func TestAiWatermarkDetectabilityToleranceVectors(t *testing.T) {
	input := []uint32{0x61, 0x200B, 0x62, 0x200B, 0x63, 0x64, 0x200B, 0x65}

	// Bare detect (tolerance 0) does not fire gpt5ZwspModulo; falls through to
	// defaultIgnorableCarrier.
	if tag, ok := aiwmTagOf(input); !ok || tag != "DefaultIgnorableCarrier" {
		t.Fatalf("jittered-strict tag = %q, %v; want DefaultIgnorableCarrier", tag, ok)
	}

	// With zwspModuloTolerance = 1 the jittered progression fires gpt5ZwspModulo.
	ctx := aiwmContext{zwspModuloTolerance: 1}
	if tag, ok := aiwmDetectWithContext(ctx, input).classify.tag(); !ok || tag != "Gpt5ZwspModulo" {
		t.Fatalf("jittered-tolerant tag = %q, %v; want Gpt5ZwspModulo", tag, ok)
	}
}

// ── §4 probe spot checks ────────────────────────────────────────────────

func TestAiWatermarkProbeSpotChecks(t *testing.T) {
	if !aiwmIsNnbsp(0x202F) || aiwmIsNnbsp(0x20) || aiwmIsNnbsp(0x3000) {
		t.Errorf("aiwmIsNnbsp")
	}
	if !aiwmIsZwj(0x200D) || aiwmIsZwj(0x200B) || aiwmIsZwj(0x200C) {
		t.Errorf("aiwmIsZwj")
	}
	if !aiwmIsVariationSelector(0xFE00) || !aiwmIsVariationSelector(0xFE0F) ||
		!aiwmIsVariationSelector(0xE0100) || aiwmIsVariationSelector(0x61) ||
		aiwmIsVariationSelector(0x200D) {
		t.Errorf("aiwmIsVariationSelector")
	}
	if !aiwmIsDefaultIgnorable(0x200B) || !aiwmIsDefaultIgnorable(0x200D) ||
		!aiwmIsDefaultIgnorable(0x00AD) || aiwmIsDefaultIgnorable(0x202F) ||
		aiwmIsDefaultIgnorable(0x61) {
		t.Errorf("aiwmIsDefaultIgnorable")
	}
	if !aiwmIsEmoji(0x1F600) || aiwmIsEmoji(0x200D) || aiwmIsEmoji(0x61) {
		t.Errorf("aiwmIsEmoji")
	}
	if aiwmIsAdjacentToEmoji([]uint32{0x61, 0xFE0F, 0x62}, 1) {
		t.Errorf("aiwmIsAdjacentToEmoji negative")
	}
	if !aiwmIsAdjacentToEmoji([]uint32{0x1F600, 0xFE0F}, 1) {
		t.Errorf("aiwmIsAdjacentToEmoji after smiley")
	}
	if !aiwmIsAdjacentToEmoji([]uint32{0xFE0F, 0x1F600}, 0) {
		t.Errorf("aiwmIsAdjacentToEmoji before smiley")
	}
}

// ── §6 detect spot checks ───────────────────────────────────────────────

func TestAiWatermarkDetectSpotChecks(t *testing.T) {
	if !aiwmDetect([]uint32{}).classify.isClear() {
		t.Errorf("empty should be clear")
	}
	if !aiwmDetect([]uint32{0x61, 0x62, 0x63}).classify.isClear() {
		t.Errorf("ascii should be clear")
	}
	if !aiwmDetect([]uint32{0x4E2D, 0x6587}).classify.isClear() {
		t.Errorf("han should be clear")
	}

	// nnbsp fires: NnbspBoundary, positions [1], markerCount 1.
	v := aiwmDetect([]uint32{0x61, 0x202F, 0x62})
	if tag, _ := v.classify.tag(); tag != "NnbspBoundary" || !slices.Equal(v.classify.positions, []int{1}) || v.markerCount != 1 {
		t.Errorf("nnbsp fires: tag=%q pos=%#v mc=%d", tag, v.classify.positions, v.markerCount)
	}

	// vs in plain text fires.
	v = aiwmDetect([]uint32{0x61, 0xFE0F, 0x62})
	if tag, _ := v.classify.tag(); tag != "VariationSelectorCarrier" || v.markerCount != 1 {
		t.Errorf("vs plain: tag=%q mc=%d", tag, v.markerCount)
	}
	// vs after emoji is clear.
	if !aiwmDetect([]uint32{0x1F600, 0xFE0F}).classify.isClear() {
		t.Errorf("vs after emoji should be clear")
	}

	// zwj in plain text fires.
	v = aiwmDetect([]uint32{0x61, 0x200D, 0x62})
	if tag, _ := v.classify.tag(); tag != "ZwjNonEmoji" || v.markerCount != 1 {
		t.Errorf("zwj plain: tag=%q mc=%d", tag, v.markerCount)
	}
	// zwj emoji sequence is clear.
	if !aiwmDetect([]uint32{0x1F469, 0x200D, 0x1F52C}).classify.isClear() {
		t.Errorf("zwj emoji sequence should be clear")
	}

	// soft hyphen fires DefaultIgnorableCarrier.
	v = aiwmDetect([]uint32{0x61, 0x00AD, 0x62})
	if tag, _ := v.classify.tag(); tag != "DefaultIgnorableCarrier" || v.markerCount != 1 {
		t.Errorf("soft hyphen: tag=%q mc=%d", tag, v.markerCount)
	}
	// zwsp (single) fires DefaultIgnorableCarrier.
	v = aiwmDetect([]uint32{0x61, 0x200B, 0x62})
	if tag, _ := v.classify.tag(); tag != "DefaultIgnorableCarrier" || v.markerCount != 1 {
		t.Errorf("zwsp: tag=%q mc=%d", tag, v.markerCount)
	}

	// priority: unknown over nnbsp+di, unknown over vs+zwj.
	if tag, _ := aiwmTagOf([]uint32{0x61, 0x202F, 0x00AD, 0x62}); tag != "Unknown" {
		t.Errorf("unknown over nnbsp+di: %q", tag)
	}
	if tag, _ := aiwmTagOf([]uint32{0x61, 0xFE0F, 0x200D, 0x62}); tag != "Unknown" {
		t.Errorf("unknown over vs+zwj: %q", tag)
	}

	// multiple nnbsp aggregates.
	v = aiwmDetect([]uint32{0x61, 0x202F, 0x62, 0x202F, 0x63})
	if tag, _ := v.classify.tag(); tag != "NnbspBoundary" || v.markerCount != 2 || !slices.Equal(v.classify.positions, []int{1, 3}) {
		t.Errorf("multiple nnbsp: tag=%q mc=%d pos=%#v", tag, v.markerCount, v.classify.positions)
	}
}

// ── §7 refinement-probe spot checks ─────────────────────────────────────

func TestAiWatermarkRefinementProbes(t *testing.T) {
	// adversarial arithmetic nnbsp.
	v := aiwmDetect([]uint32{0x61, 0x202F, 0x62, 0x202F, 0x63, 0x202F, 0x64})
	if tag, _ := v.classify.tag(); tag != "Adversarial" || v.markerCount != 3 {
		t.Errorf("adversarial: tag=%q mc=%d", tag, v.markerCount)
	}
	// two nnbsp below adversarial threshold.
	if tag, _ := aiwmTagOf([]uint32{0x61, 0x202F, 0x62, 0x202F, 0x63}); tag != "NnbspBoundary" {
		t.Errorf("two nnbsp below adversarial: %q", tag)
	}
	// gpt5 zwsp modulo.
	v = aiwmDetect([]uint32{0x61, 0x200B, 0x62, 0x200B, 0x63, 0x200B, 0x64})
	if tag, _ := v.classify.tag(); tag != "Gpt5ZwspModulo" || v.markerCount != 3 {
		t.Errorf("gpt5 zwsp modulo: tag=%q mc=%d", tag, v.markerCount)
	}
	// zwsp two below modulo threshold.
	if tag, _ := aiwmTagOf([]uint32{0x61, 0x200B, 0x62, 0x200B, 0x63}); tag != "DefaultIgnorableCarrier" {
		t.Errorf("zwsp two below modulo: %q", tag)
	}
	// smart quote alternation.
	v = aiwmDetect([]uint32{0x201C, 0x61, 0x62, 0x63, 0x201D})
	if tag, _ := v.classify.tag(); tag != "SmartQuoteAlternation" || v.markerCount != 2 {
		t.Errorf("smart quote: tag=%q mc=%d", tag, v.markerCount)
	}
	// smart quote with straight is clear.
	if !aiwmDetect([]uint32{0x201C, 0x61, 0x22, 0x201D}).classify.isClear() {
		t.Errorf("smart quote with straight should be clear")
	}
	// em dash pattern.
	v = aiwmDetect([]uint32{0x61, 0x62, 0x20, 0x2014, 0x20, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66})
	if tag, _ := v.classify.tag(); tag != "EmDashPattern" || v.markerCount != 2 {
		t.Errorf("em dash: tag=%q mc=%d", tag, v.markerCount)
	}
	// em dash with hyphen is clear.
	if !aiwmDetect([]uint32{0x61, 0x62, 0x2D, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66}).classify.isClear() {
		t.Errorf("em dash with hyphen should be clear")
	}
	// statistical token delve.
	v = aiwmDetect([]uint32{0x64, 0x65, 0x6C, 0x76, 0x65})
	if tag, _ := v.classify.tag(); tag != "StatisticalTokenChoice" || v.markerCount != 1 {
		t.Errorf("statistical delve: tag=%q mc=%d", tag, v.markerCount)
	}
	// statistical token moreover embedded, first_pos 2.
	v = aiwmDetect([]uint32{0x3B, 0x20, 0x6D, 0x6F, 0x72, 0x65, 0x6F, 0x76, 0x65, 0x72, 0x2C, 0x20})
	if tag, _ := v.classify.tag(); tag != "StatisticalTokenChoice" || !slices.Equal(v.classify.positions, []int{2}) {
		t.Errorf("statistical moreover: tag=%q pos=%#v", tag, v.classify.positions)
	}

	// unknown combinations, markerCount 2 each.
	for _, in := range [][]uint32{
		{0x61, 0x202F, 0x00AD, 0x62},
		{0x61, 0xFE0F, 0x200D, 0x62},
		{0x61, 0x202F, 0x200D, 0x62},
	} {
		v = aiwmDetect(in)
		if tag, _ := v.classify.tag(); tag != "Unknown" || v.markerCount != 2 {
			t.Errorf("unknown %#v: tag=%q mc=%d", in, tag, v.markerCount)
		}
	}
	// single category skips unknown.
	if tag, _ := aiwmTagOf([]uint32{0x61, 0x202F, 0x62}); tag != "NnbspBoundary" {
		t.Errorf("single category skips unknown: %q", tag)
	}
	// priority adversarial over nnbsp, zwsp modulo over di.
	if tag, _ := aiwmTagOf([]uint32{0x61, 0x202F, 0x62, 0x202F, 0x63, 0x202F, 0x64}); tag != "Adversarial" {
		t.Errorf("priority adversarial over nnbsp: %q", tag)
	}
	if tag, _ := aiwmTagOf([]uint32{0x61, 0x200B, 0x62, 0x200B, 0x63, 0x200B, 0x64}); tag != "Gpt5ZwspModulo" {
		t.Errorf("priority zwsp modulo over di: %q", tag)
	}
}

// TestAiWatermarkDefaultContextMatchesDetect mirrors
// detect_with_context_default_matches_detect.
func TestAiWatermarkDefaultContextMatchesDetect(t *testing.T) {
	d := aiwmDetect([]uint32{0x61, 0x202F, 0x62})
	c := aiwmDetectWithContext(aiwmContext{}, []uint32{0x61, 0x202F, 0x62})
	dTag, dOK := d.classify.tag()
	cTag, cOK := c.classify.tag()
	if dTag != cTag || dOK != cOK || !slices.Equal(d.classify.positions, c.classify.positions) {
		t.Errorf("default context should match bare detect")
	}
}

// ── §7 cue-class coverage ───────────────────────────────────────────────

func TestAiWatermarkCueClassCoverage(t *testing.T) {
	classes := []aiwmCueClass{aiwmGreenListBias, aiwmPseudorandomSeq, aiwmSemanticDrift}
	subThreats := []aiwmSubThreat{
		{tag: "NnbspBoundary"},
		{tag: "VariationSelectorCarrier"},
		{tag: "ZwjNonEmoji"},
		{tag: "DefaultIgnorableCarrier"},
		{tag: "Gpt5ZwspModulo"},
		{tag: "EmDashPattern"},
		{tag: "SmartQuoteAlternation"},
		{tag: "StatisticalTokenChoice"},
		{tag: "Adversarial"},
	}
	for _, cls := range classes {
		found := false
		for _, st := range subThreats {
			if c, ok := st.cueClass(); ok && c == cls {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("cue class %d is not probed by any sub-threat", cls)
		}
	}
	// Unknown maps to no single cue class.
	if _, ok := (aiwmSubThreat{tag: "Unknown"}).cueClass(); ok {
		t.Errorf("Unknown should have no cue class")
	}
}
