<?php

declare(strict_types=1);

require_once __DIR__ . '/test_helper.php';

use UnicodePhp\Security\Form\CaseExpansionMismatch;
use UnicodePhp\Security\Mode;
use UnicodePhp\Security\Policy;
use UnicodePhp\Security\Profile;

/** @param list<int> $input */
function case_expansion_tag(array $input): ?string
{
    return CaseExpansionMismatch::detect($input)->classify->tag();
}

// ── (a) shared context-free fixture, driven through scanCaseExpansionMismatch ──
$fixture = fixture_json('detectors/case_expansion_mismatch.json');
$fixtureCases = 0;
foreach ($fixture['cases'] as $case) {
    $verdict = Policy::scanCaseExpansionMismatch(Profile::GatewayHeader, Mode::Observe, $case['input']);
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

// ── §5 detect spot checks (one per reference `detect_*` test) ─────────────────

// detect_empty_clear
assert_same_value(true, CaseExpansionMismatch::detect([])->classify->isClear(), 'empty clear');
assert_same_value(0, CaseExpansionMismatch::detect([])->maxExpansionLen, 'empty max len 0');

// detect_ascii_clear — "Hello"; every ASCII cp case-maps to a single cp.
$v = CaseExpansionMismatch::detect([0x48, 0x65, 0x6C, 0x6C, 0x6F]);
assert_same_value(true, $v->classify->isClear(), 'ascii hello clear');
assert_same_value(1, $v->maxExpansionLen, 'ascii hello max len 1');

// detect_sharp_s_upper — ß (U+00DF) toUpper → "SS".
$v = CaseExpansionMismatch::detect([0x00DF]);
assert_same_value('UpperExpansion', $v->classify->tag(), 'sharp s upper tag');
assert_same_value([0], $v->classify->positions(), 'sharp s upper positions');
assert_same_value(1, $v->upperExpansionCount, 'sharp s upper count');
assert_same_value(2, $v->maxExpansionLen, 'sharp s max len 2');

// detect_fi_ligature_upper — ﬁ (U+FB01) toUpper → "FI".
assert_same_value('UpperExpansion', case_expansion_tag([0xFB01]), 'fi ligature upper');

// detect_dotted_I_lower — İ (U+0130) toLower under default → "i + 0307";
// no upper expansion, so the detector falls through to the lower scan.
$v = CaseExpansionMismatch::detect([0x0130]);
assert_same_value('LowerExpansion', $v->classify->tag(), 'dotted I lower tag');
assert_same_value(1, $v->lowerExpansionCount, 'dotted I lower count');

// detect_ffi_ligature_len3 — ﬃ (U+FB03) toUpper → "FFI" (length 3).
$v = CaseExpansionMismatch::detect([0xFB03]);
assert_same_value('UpperExpansion', $v->classify->tag(), 'ffi ligature upper tag');
assert_same_value(3, $v->maxExpansionLen, 'ffi ligature max len 3');

// detect_reports_first_expansion_position — a leading ASCII then ß: reported at 1.
$v = CaseExpansionMismatch::detect([0x61, 0x00DF]);
assert_same_value([1], $v->classify->positions(), 'first expansion position 1');

// ── reason-code stability ─────────────────────────────────────────────────────
assert_same_value(
    'unicode.security.F.case-expansion-mismatch.UpperExpansion',
    Policy::reasonCode(\UnicodePhp\Security\Family::CaseExpansionMismatch, 'UpperExpansion'),
    'reason code upper',
);
assert_same_value(
    'unicode.security.F.case-expansion-mismatch.LowerExpansion',
    Policy::reasonCode(\UnicodePhp\Security\Family::CaseExpansionMismatch, 'LowerExpansion'),
    'reason code lower',
);

echo 'case_expansion_mismatch_test: OK (' . $fixtureCases . " fixture cases)\n";
