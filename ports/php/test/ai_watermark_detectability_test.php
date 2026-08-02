<?php

declare(strict_types=1);

require_once __DIR__ . '/test_helper.php';

use UnicodePhp\Security\Crypto\AiWatermarkContext;
use UnicodePhp\Security\Crypto\AiWatermarkCueClass;
use UnicodePhp\Security\Crypto\AiWatermarkDetectability;
use UnicodePhp\Security\Crypto\AiWatermarkSubThreat;
use UnicodePhp\Security\Mode;
use UnicodePhp\Security\Policy;
use UnicodePhp\Security\Profile;

/** @param list<int> $input */
function watermark_tag(array $input): ?string
{
    return AiWatermarkDetectability::detect($input)->classify->tag();
}

// ── (a) shared context-free fixture, driven through scanAiWatermark ─────────
$fixture = fixture_json('detectors/ai_watermark_detectability.json');
$fixtureCases = 0;
foreach ($fixture['cases'] as $case) {
    $verdict = Policy::scanAiWatermark(Profile::OpaqueSecret, Mode::Observe, $case['input']);
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

// The same fixture inputs also exercise the direct `detect` entry point.
assert_same_value(true, AiWatermarkDetectability::detect([])->classify->isClear(), 'detect empty clear');
assert_same_value(true, AiWatermarkDetectability::detect([0x61, 0x62, 0x63])->classify->isClear(), 'detect ascii clear');
assert_same_value(true, AiWatermarkDetectability::detect([0x4E2D, 0x6587])->classify->isClear(), 'detect han clear');

// ── §4 probe spot checks (rust `is_*` unit tests) ───────────────────────────
// NNBSP fires; single marker at position 1.
$v = AiWatermarkDetectability::detect([0x61, 0x202F, 0x62]);
assert_same_value('NnbspBoundary', $v->classify->tag(), 'nnbsp fires');
assert_same_value([1], $v->classify->positions(), 'nnbsp positions');
assert_same_value(1, $v->markerCount, 'nnbsp marker count');

// VS in plain text fires; VS after emoji is clear (emoji-adjacency exemption).
$v = AiWatermarkDetectability::detect([0x61, 0xFE0F, 0x62]);
assert_same_value('VariationSelectorCarrier', $v->classify->tag(), 'vs plain fires');
assert_same_value(1, $v->markerCount, 'vs plain marker count');
assert_same_value(true, AiWatermarkDetectability::detect([0x1F600, 0xFE0F])->classify->isClear(), 'vs after emoji clear');

// ZWJ in plain text fires; ZWJ emoji sequence is clear.
$v = AiWatermarkDetectability::detect([0x61, 0x200D, 0x62]);
assert_same_value('ZwjNonEmoji', $v->classify->tag(), 'zwj plain fires');
assert_same_value(1, $v->markerCount, 'zwj plain marker count');
assert_same_value(true, AiWatermarkDetectability::detect([0x1F469, 0x200D, 0x1F52C])->classify->isClear(), 'zwj emoji seq clear');

// Soft hyphen and ZWSP surface as residual default-ignorable carriers.
$v = AiWatermarkDetectability::detect([0x61, 0x00AD, 0x62]);
assert_same_value('DefaultIgnorableCarrier', $v->classify->tag(), 'soft hyphen fires');
assert_same_value(1, $v->markerCount, 'soft hyphen marker count');
$v = AiWatermarkDetectability::detect([0x61, 0x200B, 0x62]);
assert_same_value('DefaultIgnorableCarrier', $v->classify->tag(), 'zwsp single fires di');
assert_same_value(1, $v->markerCount, 'zwsp single marker count');

// Multiple NNBSP aggregate (below the adversarial threshold of 3).
$v = AiWatermarkDetectability::detect([0x61, 0x202F, 0x62, 0x202F, 0x63]);
assert_same_value('NnbspBoundary', $v->classify->tag(), 'two nnbsp aggregate');
assert_same_value(2, $v->markerCount, 'two nnbsp marker count');
assert_same_value([1, 3], $v->classify->positions(), 'two nnbsp positions');

// ── §7 priority / refinement probes ─────────────────────────────────────────
// Adversarial arithmetic NNBSP (three at equal gaps).
$v = AiWatermarkDetectability::detect([0x61, 0x202F, 0x62, 0x202F, 0x63, 0x202F, 0x64]);
assert_same_value('Adversarial', $v->classify->tag(), 'adversarial arithmetic nnbsp');
assert_same_value(3, $v->markerCount, 'adversarial marker count');

// GPT-5 ZWSP modulo (three at equal gaps).
$v = AiWatermarkDetectability::detect([0x61, 0x200B, 0x62, 0x200B, 0x63, 0x200B, 0x64]);
assert_same_value('Gpt5ZwspModulo', $v->classify->tag(), 'gpt5 zwsp modulo');
assert_same_value(3, $v->markerCount, 'gpt5 zwsp marker count');

// Two ZWSP fall below the modulo threshold — residual default-ignorable.
assert_same_value('DefaultIgnorableCarrier', watermark_tag([0x61, 0x200B, 0x62, 0x200B, 0x63]), 'two zwsp below threshold');

// Smart-quote alternation without any straight quote; with a straight quote → clear.
$v = AiWatermarkDetectability::detect([0x201C, 0x61, 0x62, 0x63, 0x201D]);
assert_same_value('SmartQuoteAlternation', $v->classify->tag(), 'smart quote alternation');
assert_same_value(2, $v->markerCount, 'smart quote marker count');
assert_same_value(true, AiWatermarkDetectability::detect([0x201C, 0x61, 0x22, 0x201D])->classify->isClear(), 'smart quote with straight clear');

// Em-dash pattern without hyphen-minus; with a hyphen-minus → clear.
$v = AiWatermarkDetectability::detect([0x61, 0x62, 0x20, 0x2014, 0x20, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66]);
assert_same_value('EmDashPattern', $v->classify->tag(), 'em dash pattern');
assert_same_value(2, $v->markerCount, 'em dash marker count');
assert_same_value(true, AiWatermarkDetectability::detect([0x61, 0x62, 0x2D, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66])->classify->isClear(), 'em dash with hyphen clear');

// Statistical token: bare "delve", and "moreover" embedded at position 2.
$v = AiWatermarkDetectability::detect([0x64, 0x65, 0x6C, 0x76, 0x65]);
assert_same_value('StatisticalTokenChoice', $v->classify->tag(), 'statistical token delve');
assert_same_value(1, $v->markerCount, 'statistical token marker count');
$v = AiWatermarkDetectability::detect([0x3B, 0x20, 0x6D, 0x6F, 0x72, 0x65, 0x6F, 0x76, 0x65, 0x72, 0x2C, 0x20]);
assert_same_value('StatisticalTokenChoice', $v->classify->tag(), 'statistical token moreover embedded');
assert_same_value([2], $v->classify->positions(), 'statistical token moreover position');

// Multi-category mixing → Unknown (attribution to a single scheme fails).
$v = AiWatermarkDetectability::detect([0x61, 0x202F, 0x00AD, 0x62]);
assert_same_value('Unknown', $v->classify->tag(), 'unknown nnbsp+di');
assert_same_value(2, $v->markerCount, 'unknown nnbsp+di marker count');
$v = AiWatermarkDetectability::detect([0x61, 0xFE0F, 0x200D, 0x62]);
assert_same_value('Unknown', $v->classify->tag(), 'unknown vs+zwj');
assert_same_value(2, $v->markerCount, 'unknown vs+zwj marker count');
$v = AiWatermarkDetectability::detect([0x61, 0x202F, 0x200D, 0x62]);
assert_same_value('Unknown', $v->classify->tag(), 'unknown nnbsp+zwj');
assert_same_value(2, $v->markerCount, 'unknown nnbsp+zwj marker count');

// Single-category input skips Unknown.
assert_same_value('NnbspBoundary', watermark_tag([0x61, 0x202F, 0x62]), 'single category skips unknown');
// Priority: adversarial over nnbsp, zwsp-modulo over default-ignorable.
assert_same_value('Adversarial', watermark_tag([0x61, 0x202F, 0x62, 0x202F, 0x63, 0x202F, 0x64]), 'priority adversarial over nnbsp');
assert_same_value('Gpt5ZwspModulo', watermark_tag([0x61, 0x200B, 0x62, 0x200B, 0x63, 0x200B, 0x64]), 'priority zwsp modulo over di');

// ── §8 tolerance-parameterised probes (the two Context vectors) ─────────────
$tolerance_vectors = 0;

// ZWSPs at 1, 3, 6 (gaps 2, 3). Bare detect (tolerance 0) does NOT fire
// gpt5ZwspModulo; falls through to defaultIgnorableCarrier.
$jittered = [0x61, 0x200B, 0x62, 0x200B, 0x63, 0x64, 0x200B, 0x65];
assert_same_value('DefaultIgnorableCarrier', watermark_tag($jittered), 'zwsp jittered strict clear');
$tolerance_vectors++;

// With zwspModuloTolerance = 1 the jittered progression fires gpt5ZwspModulo.
$v = AiWatermarkDetectability::detectWithContext(new AiWatermarkContext(zwspModuloTolerance: 1), $jittered);
assert_same_value('Gpt5ZwspModulo', $v->classify->tag(), 'zwsp jittered tolerant fires');
$tolerance_vectors++;

// Default context matches bare detect.
$d = AiWatermarkDetectability::detect([0x61, 0x202F, 0x62]);
$c = AiWatermarkDetectability::detectWithContext(new AiWatermarkContext(), [0x61, 0x202F, 0x62]);
assert_same_value($d->classify->tag(), $c->classify->tag(), 'context default matches detect');

// ── §7 cue-class coverage ───────────────────────────────────────────────────
$classes = [
    AiWatermarkCueClass::GreenListBias,
    AiWatermarkCueClass::PseudorandomSeq,
    AiWatermarkCueClass::SemanticDrift,
];
$subThreats = [
    AiWatermarkSubThreat::nnbspBoundary(0),
    AiWatermarkSubThreat::variationSelectorCarrier(0),
    AiWatermarkSubThreat::zwjNonEmoji(0),
    AiWatermarkSubThreat::defaultIgnorableCarrier(0),
    AiWatermarkSubThreat::gpt5ZwspModulo(0),
    AiWatermarkSubThreat::emDashPattern(0),
    AiWatermarkSubThreat::smartQuoteAlternation(0),
    AiWatermarkSubThreat::statisticalTokenChoice(0),
    AiWatermarkSubThreat::adversarial('', 0),
];
foreach ($classes as $cls) {
    $probed = false;
    foreach ($subThreats as $st) {
        if ($st->cueClass() === $cls) {
            $probed = true;
            break;
        }
    }
    assert_same_value(true, $probed, 'cue class probed ' . $cls->name);
}
// Unknown maps to no single cue class.
assert_same_value(null, AiWatermarkSubThreat::unknown(0)->cueClass(), 'unknown has no cue class');

if ($tolerance_vectors !== 2) {
    throw new RuntimeException('expected 2 tolerance vectors, ran ' . $tolerance_vectors);
}

echo 'ai_watermark_detectability_test: OK (' . $fixtureCases . ' fixture cases, ' . $tolerance_vectors . " tolerance vectors)\n";
