<?php

declare(strict_types=1);

require_once __DIR__ . '/test_helper.php';

use UnicodePhp\Security\Display\SourceDisplayDivergence;
use UnicodePhp\Security\Mode;
use UnicodePhp\Security\Policy;
use UnicodePhp\Security\Profile;

/** @param list<int> $input */
function source_display_divergence_tag(array $input): ?string
{
    return SourceDisplayDivergence::detect($input)->classify->tag();
}

// ── (a) shared context-free fixture, driven through scanSourceDisplayDivergence ─
$fixture = fixture_json('detectors/source_display_divergence.json');
$fixtureCases = 0;
foreach ($fixture['cases'] as $case) {
    $verdict = Policy::scanSourceDisplayDivergence(Profile::GatewayHeader, Mode::Observe, $case['input']);
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

// ── §clear cases (rust `clear_cases`) ────────────────────────────────────────
assert_same_value(null, source_display_divergence_tag([]), 'empty clear');
assert_same_value(true, SourceDisplayDivergence::detect([])->classify->isClear(), 'empty isClear');
// "Hello world"
assert_same_value(null, source_display_divergence_tag([0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64]), 'hello world clear');
// "let x = 1;"
assert_same_value(null, source_display_divergence_tag([0x6C, 0x65, 0x74, 0x20, 0x78, 0x20, 0x3D, 0x20, 0x31, 0x3B]), 'let x = 1 clear');

// ── §single-fire pass-through (rust `single_fire_passthrough`) ────────────────
// tag-encoded "AB" → TagBlock
assert_same_value('TagBlock', source_display_divergence_tag([0xE0041, 0xE0042]), 'tag block passthrough');
// A + VS16 → VariationSelector
assert_same_value('VariationSelector', source_display_divergence_tag([0x0041, 0xFE0F]), 'variation selector passthrough');
// H + ZWSP + i → ZeroWidth
assert_same_value('ZeroWidth', source_display_divergence_tag([0x0048, 0x200B, 0x69]), 'zero width passthrough');
// RLO + A → BidiControl
assert_same_value('BidiControl', source_display_divergence_tag([0x202E, 0x41]), 'bidi control passthrough');
// "Neth<Cyrillic е>um" → IdentifierHomoglyph
assert_same_value('IdentifierHomoglyph', source_display_divergence_tag([0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D]), 'identifier homoglyph passthrough');

// ── §two-or-more is Compound (rust `two_or_more_is_compound`) ─────────────────
// A + VS16 + ZWSP → Compound (VariationSelector + ZeroWidth)
assert_same_value('Compound', source_display_divergence_tag([0x0041, 0xFE0F, 0x200B]), 'vs + zwsp compound');
// tag "AB" + ZWSP → Compound (TagBlock + ZeroWidth)
assert_same_value('Compound', source_display_divergence_tag([0xE0041, 0xE0042, 0x200B]), 'tag + zwsp compound');

// ── aggregation-order / positions-empty structural checks ────────────────────
// The fired list preserves canonical order for a compound hit.
assert_same_value(['VariationSelector', 'ZeroWidth'], SourceDisplayDivergence::detect([0x0041, 0xFE0F, 0x200B])->fires, 'compound fires order');
// Positions are always empty at this aggregation layer.
assert_same_value([], SourceDisplayDivergence::detect([0xE0041, 0xE0042])->classify->positions(), 'positions empty on hazard');

echo 'source_display_divergence_test: OK (' . $fixtureCases . " fixture cases)\n";
