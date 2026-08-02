package security

import (
	"slices"
	"testing"
)

// Ground truth: every detect_* theorem in
// Unicode.Security.Identity.SkinToneVariationForgery, mirrored from the verified
// Rust reference implementation. This detector is context-free — every vector is
// expressible in the shared detector fixture
// (skin_tone_variation_forgery.json, bundled under testdata).

func stvfTagOf(input []uint32) (string, bool) {
	return stvfDetect(input).classify.tag()
}

// TestSkinToneVariationForgeryFixture runs the shared context-free detector
// fixture through stvfDetect, mapping the classification tag onto its reason code
// the way TestDetectorFixtures checks required_findings.
func TestSkinToneVariationForgeryFixture(t *testing.T) {
	var fixture detectorFixture
	loadJSON(t, fixturePath(t, "fixtures", "security", "detectors", "skin_tone_variation_forgery.json"), &fixture)
	if fixture.Schema != 1 {
		t.Fatalf("unexpected detector schema: %d", fixture.Schema)
	}
	if fixture.Family != string(FamilySkinToneVariationForgery) {
		t.Fatalf("unexpected family: %s", fixture.Family)
	}
	for _, tc := range fixture.Cases {
		verdict := stvfDetect(tc.Input)
		findings := []string{}
		if tag, ok := verdict.classify.tag(); ok {
			findings = append(findings, reasonCode(FamilySkinToneVariationForgery, tag))
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

func TestSkinToneVariationForgeryDetectSpotChecks(t *testing.T) {
	// detect_empty_clear
	if !stvfDetect([]uint32{}).classify.isClear() {
		t.Errorf("empty should be clear")
	}

	// detect_ascii_clear — "He"
	if !stvfDetect([]uint32{0x48, 0x65}).classify.isClear() {
		t.Errorf("ASCII \"He\" should be clear")
	}

	// detect_plain_emoji_clear — grinning face
	if !stvfDetect([]uint32{0x1F600}).classify.isClear() {
		t.Errorf("plain grinning face should be clear")
	}

	// detect_wave_skin_tone_clear — waving hand (a modifier base) + one skin tone.
	v := stvfDetect([]uint32{0x1F44B, 0x1F3FB})
	if !v.classify.isClear() {
		t.Errorf("waving hand + one skin tone should be clear")
	}
	if v.skinToneCount != 1 {
		t.Errorf("wave+tone skinToneCount = %d, want 1", v.skinToneCount)
	}

	// detect_stacked_skin_tones — waving hand + two skin tones.
	v = stvfDetect([]uint32{0x1F44B, 0x1F3FB, 0x1F3FC})
	if tag, _ := v.classify.tag(); tag != "StackedSkinTones" {
		t.Errorf("stacked skin tones: tag=%q", tag)
	}
	if !slices.Equal(v.classify.posns(), []int{1, 2}) {
		t.Errorf("stacked skin tones positions: %#v", v.classify.posns())
	}

	// detect_invalid_target_ascii — skin tone on ASCII 'A'.
	v = stvfDetect([]uint32{0x0041, 0x1F3FB})
	if tag, _ := v.classify.tag(); tag != "InvalidSkinToneTarget" {
		t.Errorf("invalid target ascii: tag=%q", tag)
	}
	if !slices.Equal(v.classify.posns(), []int{1}) {
		t.Errorf("invalid target ascii positions: %#v", v.classify.posns())
	}

	// detect_invalid_target_smiley — skin tone on grinning face (not a modifier base).
	if tag, _ := stvfTagOf([]uint32{0x1F600, 0x1F3FB}); tag != "InvalidSkinToneTarget" {
		t.Errorf("invalid target smiley: tag=%q", tag)
	}

	// detect_forced_text_style — VS15 on grinning face (Emoji_Presentation).
	v = stvfDetect([]uint32{0x1F600, 0xFE0E})
	if tag, _ := v.classify.tag(); tag != "ForcedTextStyle" {
		t.Errorf("forced text style: tag=%q", tag)
	}
	if v.variationSelector15Count != 1 {
		t.Errorf("forced text style variationSelector15Count = %d, want 1", v.variationSelector15Count)
	}
}

// ── reason-code composition ──────────────────────────────────────────────

func TestSkinToneVariationForgeryReasonCode(t *testing.T) {
	if got := reasonCode(FamilySkinToneVariationForgery, "StackedSkinTones"); got != "unicode.security.I.skin-tone-variation-forgery.StackedSkinTones" {
		t.Errorf("StackedSkinTones reason code = %q", got)
	}
	if got := reasonCode(FamilySkinToneVariationForgery, "ForcedTextStyle"); got != "unicode.security.I.skin-tone-variation-forgery.ForcedTextStyle" {
		t.Errorf("ForcedTextStyle reason code = %q", got)
	}
}

// ── data-layer sanity: reused predicates ─────────────────────────────────

func TestSkinToneVariationForgeryPredicateReuse(t *testing.T) {
	// Reuses the port's own skin-tone modifier set (ezwjIsEmojiModifier).
	if !stvfIsSkinTone(0x1F3FB) || !stvfIsSkinTone(0x1F3FF) {
		t.Errorf("U+1F3FB and U+1F3FF should be skin-tone modifiers")
	}
	if stvfIsSkinTone(0x1F600) {
		t.Errorf("grinning face is not a skin-tone modifier")
	}
	// Emoji_Modifier_Base parsed from the bundled emoji-data.txt.
	if !stvfIsSkinToneBase(0x1F44B) {
		t.Errorf("waving hand should have Emoji_Modifier_Base")
	}
	if stvfIsSkinToneBase(0x1F600) || stvfIsSkinToneBase(0x0041) {
		t.Errorf("grinning face and 'A' should not have Emoji_Modifier_Base")
	}
	// Emoji_Presentation parsed from the bundled emoji-data.txt.
	if !stvfIsEmojiPresentation(0x1F600) {
		t.Errorf("grinning face should have Emoji_Presentation")
	}
	if stvfIsEmojiPresentation(0x0041) {
		t.Errorf("'A' should not have Emoji_Presentation")
	}
}
