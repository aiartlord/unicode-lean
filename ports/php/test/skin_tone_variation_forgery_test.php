<?php

declare(strict_types=1);

require_once __DIR__ . '/test_helper.php';

use UnicodePhp\Security\Identity\SkinToneVariationForgery;
use UnicodePhp\Security\Mode;
use UnicodePhp\Security\Policy;
use UnicodePhp\Security\Profile;

/** @param list<int> $input */
function skin_tone_variation_forgery_tag(array $input): ?string
{
    return SkinToneVariationForgery::detect($input)->classify->tag();
}

// ── (a) shared context-free fixture, driven through scanSkinToneVariationForgery ──
$fixture = fixture_json('detectors/skin_tone_variation_forgery.json');
$fixtureCases = 0;
foreach ($fixture['cases'] as $case) {
    $verdict = Policy::scanSkinToneVariationForgery(Profile::GatewayHeader, Mode::Observe, $case['input']);
    $codes = verdict_codes($verdict);
    foreach ($case['required_findings'] as $required) {
        assert_includes_value($codes, $required, 'fixture/' . $case['name']);
    }
    if ($case['required_findings'] === []) {
        $needle = '.' . $fixture['family'] . '.';
        foreach ($codes as $code) {
            if (str_contains($code, $needle)) {
                throw new RuntimeException('fixture/' . $case['name'] . ' unexpected family ' . $fixture['family']);
            }
        }
    }
    $fixtureCases++;
}

// ── data-layer sanity: confirm reuse of the port's own predicates ────────────
// Skin-tone modifier — EmojiZwjIntegrity::isEmojiModifier (U+1F3FB..U+1F3FF).
assert_same_value(true, SkinToneVariationForgery::isSkinTone(0x1F3FB), 'skin tone light');
assert_same_value(true, SkinToneVariationForgery::isSkinTone(0x1F3FF), 'skin tone dark');
assert_same_value(false, SkinToneVariationForgery::isSkinTone(0x1F44B), 'wave not skin tone');
// Emoji_Modifier_Base — parsed from the bundled emoji-data.txt.
assert_same_value(true, SkinToneVariationForgery::isSkinToneBase(0x1F44B), 'waving hand is modifier base');
assert_same_value(false, SkinToneVariationForgery::isSkinToneBase(0x0041), 'ascii A not modifier base');
assert_same_value(false, SkinToneVariationForgery::isSkinToneBase(0x1F600), 'grinning face not modifier base');
// Emoji_Presentation — parsed from the bundled emoji-data.txt.
assert_same_value(true, SkinToneVariationForgery::isEmojiPresentation(0x1F600), 'grinning face is emoji presentation');
assert_same_value(false, SkinToneVariationForgery::isEmojiPresentation(0x0041), 'ascii A not emoji presentation');
// Variation selectors.
assert_same_value(true, SkinToneVariationForgery::isVs15(0xFE0E), 'vs15');
assert_same_value(false, SkinToneVariationForgery::isVs15(0xFE0F), 'vs16 is not vs15');
assert_same_value(true, SkinToneVariationForgery::isVs16(0xFE0F), 'vs16');
assert_same_value(false, SkinToneVariationForgery::isVs16(0xFE0E), 'vs15 is not vs16');

// ── §5 detect spot checks (one per rust `detect_*` test) ─────────────────────

// detect_empty_clear
assert_same_value(true, SkinToneVariationForgery::detect([])->classify->isClear(), 'empty clear');

// detect_ascii_clear — "He"
assert_same_value(true, SkinToneVariationForgery::detect([0x48, 0x65])->classify->isClear(), 'ascii clear');

// detect_plain_emoji_clear — grinning face
assert_same_value(true, SkinToneVariationForgery::detect([0x1F600])->classify->isClear(), 'plain emoji clear');

// detect_wave_skin_tone_clear — waving hand (a modifier base) + one skin tone.
$v = SkinToneVariationForgery::detect([0x1F44B, 0x1F3FB]);
assert_same_value(true, $v->classify->isClear(), 'wave skin tone clear');
assert_same_value(1, $v->skinToneCount, 'wave skin tone count');

// detect_stacked_skin_tones — waving hand + two skin tones.
$v = SkinToneVariationForgery::detect([0x1F44B, 0x1F3FB, 0x1F3FC]);
assert_same_value('StackedSkinTones', $v->classify->tag(), 'stacked skin tones tag');
assert_same_value([1, 2], $v->classify->positions(), 'stacked skin tones positions');

// detect_invalid_target_ascii — skin tone on ASCII 'A'.
$v = SkinToneVariationForgery::detect([0x0041, 0x1F3FB]);
assert_same_value('InvalidSkinToneTarget', $v->classify->tag(), 'invalid target ascii tag');
assert_same_value([1], $v->classify->positions(), 'invalid target ascii positions');

// detect_invalid_target_smiley — skin tone on grinning face (not a modifier base).
assert_same_value('InvalidSkinToneTarget', skin_tone_variation_forgery_tag([0x1F600, 0x1F3FB]), 'invalid target smiley');

// detect_forced_text_style — VS15 on grinning face (Emoji_Presentation).
$v = SkinToneVariationForgery::detect([0x1F600, 0xFE0E]);
assert_same_value('ForcedTextStyle', $v->classify->tag(), 'forced text style tag');
assert_same_value(1, $v->variationSelector15Count, 'forced text style vs15 count');

// ── priority-ladder structural check ─────────────────────────────────────────

// Stacked skin tones outrank the invalid-target case they also satisfy.
assert_same_value('StackedSkinTones', skin_tone_variation_forgery_tag([0x0041, 0x1F3FB, 0x1F3FC]), 'stacked beats invalid target');

// ── reason-code stability ────────────────────────────────────────────────────
assert_same_value(
    'unicode.security.I.skin-tone-variation-forgery.StackedSkinTones',
    Policy::reasonCode(\UnicodePhp\Security\Family::SkinToneVariationForgery, 'StackedSkinTones'),
    'reason code stacked',
);
assert_same_value(
    'unicode.security.I.skin-tone-variation-forgery.ForcedTextStyle',
    Policy::reasonCode(\UnicodePhp\Security\Family::SkinToneVariationForgery, 'ForcedTextStyle'),
    'reason code forced text style',
);

echo 'skin_tone_variation_forgery_test: OK (' . $fixtureCases . " fixture cases)\n";
