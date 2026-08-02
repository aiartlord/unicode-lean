<?php

declare(strict_types=1);

require_once __DIR__ . '/test_helper.php';

use UnicodePhp\Security\Display\RendererDivergence;
use UnicodePhp\Security\Mode;
use UnicodePhp\Security\Policy;
use UnicodePhp\Security\Profile;

/** @param list<int> $input */
function renderer_divergence_tag(array $input): ?string
{
    return RendererDivergence::detect($input)->classify->tag();
}

// ── (a) shared context-free fixture, driven through scanRendererDivergence ───
$fixture = fixture_json('detectors/renderer_divergence.json');
$fixtureCases = 0;
foreach ($fixture['cases'] as $case) {
    $verdict = Policy::scanRendererDivergence(Profile::GatewayHeader, Mode::Observe, $case['input']);
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
// Variation selector — VariationSelectorPayload::isVariationSelector.
assert_same_value(true, RendererDivergence::isVariationSelector(0xFE0F), 'vs FE0F');
assert_same_value(false, RendererDivergence::isVariationSelector(0x0041), 'vs ascii');
// Grapheme Extend — Grapheme::lookupGcb === Gcb::Extend.
assert_same_value(true, RendererDivergence::isGraphemeExtend(0x0301), 'extend combining acute');
assert_same_value(false, RendererDivergence::isGraphemeExtend(0x0061), 'extend ascii a');
// Fullwidth/halfwidth block.
assert_same_value(true, RendererDivergence::isFullwidthHalfwidth(0xFF21), 'fullwidth A');
assert_same_value(false, RendererDivergence::isFullwidthHalfwidth(0x0041), 'fullwidth ascii A');
// ZWJ codepoint.
assert_same_value(true, RendererDivergence::isZwj(0x200D), 'zwj');
assert_same_value(false, RendererDivergence::isZwj(0x200C), 'zwnj not zwj');

// ── §5 detect spot checks (one per rust `detect_*` test) ─────────────────────

// detect_empty_clear
assert_same_value(true, RendererDivergence::detect([])->classify->isClear(), 'empty clear');

// detect_ascii_clear
assert_same_value(true, RendererDivergence::detect([0x48, 0x65, 0x6C, 0x6C, 0x6F])->classify->isClear(), 'ascii clear');

// detect_han_clear
assert_same_value(true, RendererDivergence::detect([0x4E2D, 0x6587])->classify->isClear(), 'han clear');

// detect_vs_variance — a single VS (FE0F) after an emoji.
assert_same_value('VariationSelectorVariance', renderer_divergence_tag([0x1F600, 0xFE0F]), 'vs variance');

// detect_rgi_family_clear — a registered RGI family ZWJ sequence.
$v = RendererDivergence::detect([0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466]);
assert_same_value(true, $v->classify->isClear(), 'rgi family clear');
assert_same_value(true, $v->hasZwj, 'rgi family has zwj');

// detect_unregistered_zwj_variance — man + ZWJ + woman, not in RGI.
assert_same_value('UnregisteredZwjVariance', renderer_divergence_tag([0x1F468, 0x200D, 0x1F469]), 'unregistered zwj');

// detect_zalgo_variance — a 4-deep combining stack.
$v = RendererDivergence::detect([0x0061, 0x0301, 0x0302, 0x0303, 0x0304]);
assert_same_value('CombiningStackOverflow', $v->classify->tag(), 'zalgo tag');
assert_same_value([0], $v->classify->positions(), 'zalgo positions');
assert_same_value(4, $v->combiningCount, 'zalgo combining count');

// detect_fullwidth_variance — fullwidth 'A'.
assert_same_value('FullwidthVariance', renderer_divergence_tag([0xFF21]), 'fullwidth variance');

// detect_mixed_direction — Latin + Hebrew in one input.
$v = RendererDivergence::detect([0x41, 0x42, 0x05D0, 0x05D1]);
assert_same_value('MixedDirectionVariance', $v->classify->tag(), 'mixed direction tag');
if (!($v->strongLtrCount > 0 && $v->strongRtlCount > 0)) {
    throw new RuntimeException('mixed direction expected both strong LTR and RTL counts positive');
}
assert_same_value([], $v->classify->positions(), 'mixed direction positions empty');

// ── priority-ladder structural checks ────────────────────────────────────────

// A combining stack outranks a variation selector present later.
$v = RendererDivergence::detect([0x0061, 0x0301, 0x0302, 0x0303, 0x0304, 0xFE0F]);
assert_same_value('CombiningStackOverflow', $v->classify->tag(), 'combining stack beats vs');

// Exactly three combining marks is below the stack threshold — no overflow.
$v = RendererDivergence::detect([0x0061, 0x0301, 0x0302, 0x0303]);
if ($v->classify->tag() === 'CombiningStackOverflow') {
    throw new RuntimeException('three marks should be below the combining-stack threshold');
}

echo 'renderer_divergence_test: OK (' . $fixtureCases . " fixture cases)\n";
