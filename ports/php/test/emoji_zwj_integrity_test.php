<?php

declare(strict_types=1);

require_once __DIR__ . '/test_helper.php';

use UnicodePhp\Security\Identity\EmojiZwjIntegrity;
use UnicodePhp\Security\Mode;
use UnicodePhp\Security\Policy;
use UnicodePhp\Security\Profile;

/** @param list<int> $input */
function emoji_zwj_tag(array $input): ?string
{
    return EmojiZwjIntegrity::detect($input)->classify->tag();
}

// ── (a) shared context-free fixture, driven through scanEmojiZwjIntegrity ────
$fixture = fixture_json('detectors/emoji_zwj_integrity.json');
$fixtureCases = 0;
foreach ($fixture['cases'] as $case) {
    $verdict = Policy::scanEmojiZwjIntegrity(Profile::GatewayHeader, Mode::Observe, $case['input']);
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

// ── data-layer sanity (rust `is_emoji_modifier_checks`, etc.) ───────────────
// Reuse the port's own emoji-modifier predicate — no host emoji/ICU library.
assert_same_value(true, EmojiZwjIntegrity::isEmojiModifier(0x1F3FB), 'modifier lo');
assert_same_value(true, EmojiZwjIntegrity::isEmojiModifier(0x1F3FF), 'modifier hi');
assert_same_value(false, EmojiZwjIntegrity::isEmojiModifier(0x1F3FA), 'modifier below');
assert_same_value(false, EmojiZwjIntegrity::isEmojiModifier(0x1F600), 'modifier unrelated');

// ZWJ alphabet admits heart + man, rejects grinning + the joiner itself.
assert_same_value(true, EmojiZwjIntegrity::isEmojiTarget(0x2764), 'alphabet heart');
assert_same_value(true, EmojiZwjIntegrity::isEmojiTarget(0x1F468), 'alphabet man');
assert_same_value(false, EmojiZwjIntegrity::isEmojiTarget(0x1F600), 'alphabet grinning');
assert_same_value(false, EmojiZwjIntegrity::isEmojiTarget(EmojiZwjIntegrity::ZWJ), 'alphabet excludes joiner');

// Registered-membership is exact.
assert_same_value(true, EmojiZwjIntegrity::isRegisteredZwjSequence([0x1F468, 0x200D, 0x1F4BB]), 'man laptop registered');
assert_same_value(false, EmojiZwjIntegrity::isRegisteredZwjSequence([0x1F468, 0x200D, 0x1F469]), 'man woman unregistered');

// ── §5 detect spot checks (one per rust `detect_*` test) ────────────────────

// detect_empty_clear
$v = EmojiZwjIntegrity::detect([]);
assert_same_value(true, $v->classify->isClear(), 'empty clear');
assert_same_value(null, $v->classify->tag(), 'empty tag');
assert_same_value([], $v->zwjPositions, 'empty zwj positions');
assert_same_value(0, $v->chainLength, 'empty chain length');
assert_same_value(0, $v->skinToneCount, 'empty skin tone count');

// detect_ascii_clear
assert_same_value(true, EmojiZwjIntegrity::detect([0x48, 0x65, 0x6C, 0x6C, 0x6F])->classify->isClear(), 'ascii clear');

// detect_plain_emoji_clear
assert_same_value(true, EmojiZwjIntegrity::detect([0x1F600])->classify->isClear(), 'plain emoji clear');

// detect_one_skintone_clear
$v = EmojiZwjIntegrity::detect([0x1F44B, 0x1F3FB]);
assert_same_value(true, $v->classify->isClear(), 'one skintone clear');
assert_same_value(1, $v->skinToneCount, 'one skintone count');

// detect_family_rgi_clear
$v = EmojiZwjIntegrity::detect([0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466]);
assert_same_value(true, $v->classify->isClear(), 'family rgi clear');
assert_same_value(true, $v->isRegisteredRgi, 'family rgi registered');

// detect_double_zwj
$v = EmojiZwjIntegrity::detect([0x1F600, 0x200D, 0x200D, 0x1F600]);
assert_same_value('DoubleZWJ', $v->classify->tag(), 'double zwj tag');
assert_same_value([1], $v->classify->positions(), 'double zwj positions');

// detect_non_emoji_injection
assert_same_value('NonEmojiInjection', emoji_zwj_tag([0x1F600, 0x200D, 0x0061]), 'non emoji injection');

// detect_skin_tone_overflow
$v = EmojiZwjIntegrity::detect([0x1F44B, 0x1F3FB, 0x1F3FC, 0x1F3FD, 0x1F3FE, 0x1F3FF]);
assert_same_value('SkinToneOverflow', $v->classify->tag(), 'skin tone overflow tag');
assert_same_value(5, $v->skinToneCount, 'skin tone overflow count');

// detect_man_laptop_registered_clear
assert_same_value(true, EmojiZwjIntegrity::detect([0x1F468, 0x200D, 0x1F4BB])->classify->isClear(), 'man laptop clear');

// detect_unregistered — man + ZWJ + woman: both flanks in alphabet, not registered.
assert_same_value('UnregisteredSequence', emoji_zwj_tag([0x1F468, 0x200D, 0x1F469]), 'unregistered man woman');

// detect_grinning_laptop_non_emoji_injection — grinning is not a valid join target.
assert_same_value('NonEmojiInjection', emoji_zwj_tag([0x1F600, 0x200D, 0x1F4BB]), 'grinning laptop injection');

// ── structural checks (follow from the priority ladder) ─────────────────────

// A long chain of valid ZWJ-joined targets, unregistered, hitting no earlier
// sub-threat, surfaces as OverLength once it exceeds the cap.
$overLength = [];
for ($i = 0; $i < 9; $i++) {
    if ($i > 0) {
        $overLength[] = 0x200D;
    }
    $overLength[] = 0x1F468;
}
assert_same_value(17, count($overLength), 'over length input size');
$v = EmojiZwjIntegrity::detect($overLength);
assert_same_value('OverLength', $v->classify->tag(), 'over length tag');
assert_same_value([], $v->classify->positions(), 'over length positions empty');
assert_same_value(17, $v->classify->sub->length, 'over length observed length');
assert_same_value(EmojiZwjIntegrity::MAX_RGI_LENGTH, $v->classify->sub->maxLength, 'over length cap');

// A ZWJ at the trailing edge of input is an injection-class hazard.
$v = EmojiZwjIntegrity::detect([0x1F468, 0x200D]);
assert_same_value('NonEmojiInjection', $v->classify->tag(), 'trailing zwj tag');
assert_same_value([1], $v->classify->positions(), 'trailing zwj positions');
assert_same_value(0, $v->classify->sub->nonEmojiCp, 'trailing zwj edge offending cp');

// Double-ZWJ wins over the unregistered catch-all (priority order).
assert_same_value('DoubleZWJ', emoji_zwj_tag([0x1F468, 0x200D, 0x200D, 0x1F466]), 'double zwj beats unregistered');

echo 'emoji_zwj_integrity_test: OK (' . $fixtureCases . " fixture cases)\n";
