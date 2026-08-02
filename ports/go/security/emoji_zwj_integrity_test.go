package security

import (
	"slices"
	"testing"
)

// Ground truth: every detect_* / data-layer / structural check in
// Unicode.Security.Identity.EmojiZwjIntegrity, mirrored from the verified Rust
// port security/identity/emoji_zwj_integrity.rs. This detector is context-free —
// every vector is expressible in the shared detector fixture
// (fixtures/security/detectors/emoji_zwj_integrity.json).

func ezwjTagOf(input []uint32) (string, bool) {
	return ezwjDetect(input).classify.tag()
}

// TestEmojiZwjIntegrityFixture runs the shared context-free detector fixture
// through ezwjDetect, mapping the classification tag onto its reason code the
// way TestDetectorFixtures checks required_findings.
func TestEmojiZwjIntegrityFixture(t *testing.T) {
	var fixture detectorFixture
	loadJSON(t, fixturePath(t, "fixtures", "security", "detectors", "emoji_zwj_integrity.json"), &fixture)
	if fixture.Schema != 1 {
		t.Fatalf("unexpected detector schema: %d", fixture.Schema)
	}
	if fixture.Family != string(FamilyEmojiZwjIntegrity) {
		t.Fatalf("unexpected family: %s", fixture.Family)
	}
	for _, tc := range fixture.Cases {
		verdict := ezwjDetect(tc.Input)
		findings := []string{}
		if tag, ok := verdict.classify.tag(); ok {
			findings = append(findings, reasonCode(FamilyEmojiZwjIntegrity, tag))
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

// ── §3/§4 data-layer sanity ──────────────────────────────────────────────

func TestEmojiZwjIntegrityDataLayer(t *testing.T) {
	// is_emoji_modifier boundary.
	if !ezwjIsEmojiModifier(0x1F3FB) || !ezwjIsEmojiModifier(0x1F3FF) ||
		ezwjIsEmojiModifier(0x1F3FA) || ezwjIsEmojiModifier(0x1F600) {
		t.Errorf("ezwjIsEmojiModifier")
	}
	// ZWJ alphabet admits heart + man, rejects grinning + the joiner itself.
	if !ezwjIsEmojiTarget(0x2764) { // HEAVY BLACK HEART (couple-with-heart RGI)
		t.Errorf("alphabet should admit U+2764")
	}
	if !ezwjIsEmojiTarget(0x1F468) { // MAN (family/couple RGI)
		t.Errorf("alphabet should admit U+1F468")
	}
	if ezwjIsEmojiTarget(0x1F600) { // GRINNING FACE — in no registered RGI ZWJ sequence
		t.Errorf("alphabet should reject U+1F600")
	}
	if ezwjIsEmojiTarget(ezwjZWJ) { // the joiner is excluded from the alphabet
		t.Errorf("alphabet should exclude the joiner")
	}
	// Registered-membership is exact.
	if !ezwjIsRegisteredZwjSequence([]uint32{0x1F468, 0x200D, 0x1F4BB}) {
		t.Errorf("man technologist should be registered")
	}
	if ezwjIsRegisteredZwjSequence([]uint32{0x1F468, 0x200D, 0x1F469}) {
		t.Errorf("man + ZWJ + woman should not be registered")
	}
}

// ── §5 detect spot checks (one per Rust #[test]) ─────────────────────────

func TestEmojiZwjIntegrityDetectSpotChecks(t *testing.T) {
	// detect_empty_clear
	v := ezwjDetect([]uint32{})
	if !v.classify.isClear() {
		t.Errorf("empty should be clear")
	}
	if _, ok := v.classify.tag(); ok {
		t.Errorf("empty tag should be absent")
	}
	if !slices.Equal(v.zwjPositions, []int{}) || v.chainLength != 0 || v.skinToneCount != 0 {
		t.Errorf("empty verdict fields: zwj=%#v chain=%d st=%d", v.zwjPositions, v.chainLength, v.skinToneCount)
	}

	// detect_ascii_clear
	if !ezwjDetect([]uint32{0x48, 0x65, 0x6C, 0x6C, 0x6F}).classify.isClear() {
		t.Errorf("ascii should be clear")
	}

	// detect_plain_emoji_clear
	if !ezwjDetect([]uint32{0x1F600}).classify.isClear() {
		t.Errorf("plain emoji should be clear")
	}

	// detect_one_skintone_clear — base plus a single skin-tone (count = 1).
	v = ezwjDetect([]uint32{0x1F44B, 0x1F3FB})
	if !v.classify.isClear() || v.skinToneCount != 1 {
		t.Errorf("one skintone: clear=%v st=%d", v.classify.isClear(), v.skinToneCount)
	}

	// detect_family_rgi_clear — man + woman + girl + boy via ZWJs (registered).
	v = ezwjDetect([]uint32{0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466})
	if !v.classify.isClear() || !v.isRegisteredRgi {
		t.Errorf("family rgi: clear=%v rgi=%v", v.classify.isClear(), v.isRegisteredRgi)
	}

	// detect_double_zwj — ZWJ + ZWJ adjacency.
	v = ezwjDetect([]uint32{0x1F600, 0x200D, 0x200D, 0x1F600})
	if tag, _ := v.classify.tag(); tag != "DoubleZWJ" || !slices.Equal(v.classify.positions, []int{1}) {
		t.Errorf("double zwj: tag=%q pos=%#v", tag, v.classify.positions)
	}

	// detect_non_emoji_injection — ZWJ joining ASCII 'a'.
	if tag, _ := ezwjTagOf([]uint32{0x1F600, 0x200D, 0x0061}); tag != "NonEmojiInjection" {
		t.Errorf("non-emoji injection: tag=%q", tag)
	}

	// detect_skin_tone_overflow — five skin-tone modifiers.
	v = ezwjDetect([]uint32{0x1F44B, 0x1F3FB, 0x1F3FC, 0x1F3FD, 0x1F3FE, 0x1F3FF})
	if tag, _ := v.classify.tag(); tag != "SkinToneOverflow" || v.skinToneCount != 5 {
		t.Errorf("skin-tone overflow: tag=%q st=%d", tag, v.skinToneCount)
	}

	// detect_man_laptop_registered_clear — man technologist (registered).
	if !ezwjDetect([]uint32{0x1F468, 0x200D, 0x1F4BB}).classify.isClear() {
		t.Errorf("man technologist should be clear")
	}

	// detect_unregistered — man + ZWJ + woman: both flanks in the RGI alphabet
	// but the joined sequence is not registered.
	if tag, _ := ezwjTagOf([]uint32{0x1F468, 0x200D, 0x1F469}); tag != "UnregisteredSequence" {
		t.Errorf("unregistered man+woman: tag=%q", tag)
	}

	// detect_grinning_laptop_non_emoji_injection — grinning face is not a valid
	// ZWJ-join target, so this surfaces as NonEmojiInjection.
	if tag, _ := ezwjTagOf([]uint32{0x1F600, 0x200D, 0x1F4BB}); tag != "NonEmojiInjection" {
		t.Errorf("grinning + laptop: tag=%q", tag)
	}
}

// ── structural checks (follow from the priority ladder) ──────────────────

func TestEmojiZwjIntegrityStructural(t *testing.T) {
	// A long chain of valid ZWJ-joined targets that is not registered and hits
	// no earlier sub-threat surfaces as OverLength once it exceeds the cap:
	// 9 men joined by 8 ZWJs = 17 codepoints (> ezwjMaxRgiLength).
	input := []uint32{}
	for i := 0; i < 9; i++ {
		if i > 0 {
			input = append(input, 0x200D)
		}
		input = append(input, 0x1F468)
	}
	if len(input) != 17 {
		t.Fatalf("over-length input built wrong: len=%d", len(input))
	}
	v := ezwjDetect(input)
	if tag, _ := v.classify.tag(); tag != "OverLength" {
		t.Errorf("over-length: tag=%q", tag)
	}
	if !slices.Equal(v.classify.positions, []int{}) {
		t.Errorf("over-length positions should be empty: %#v", v.classify.positions)
	}
	if v.classify.sub.length != 17 || v.classify.sub.maxLength != ezwjMaxRgiLength {
		t.Errorf("over-length sub: length=%d maxLength=%d", v.classify.sub.length, v.classify.sub.maxLength)
	}

	// A ZWJ at the trailing edge of input is an injection-class hazard.
	v = ezwjDetect([]uint32{0x1F468, 0x200D})
	if tag, _ := v.classify.tag(); tag != "NonEmojiInjection" || !slices.Equal(v.classify.positions, []int{1}) {
		t.Errorf("trailing zwj: tag=%q pos=%#v", tag, v.classify.positions)
	}

	// Double-ZWJ wins over the unregistered catch-all (priority order):
	// man ZWJ ZWJ boy — adjacent ZWJs present.
	if tag, _ := ezwjTagOf([]uint32{0x1F468, 0x200D, 0x200D, 0x1F466}); tag != "DoubleZWJ" {
		t.Errorf("double-zwj beats unregistered: tag=%q", tag)
	}
}
