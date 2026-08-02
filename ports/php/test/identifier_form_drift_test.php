<?php

declare(strict_types=1);

require_once __DIR__ . '/test_helper.php';

use UnicodePhp\Security\Boundary\IdentifierFormDrift;
use UnicodePhp\Security\Mode;
use UnicodePhp\Security\Policy;
use UnicodePhp\Security\Profile;

/** @param list<int> $input */
function identifier_form_drift_tag(array $input): ?string
{
    return IdentifierFormDrift::detect($input)->classify->tag();
}

// ── (a) shared context-free fixture, driven through scanIdentifierFormDrift ───
$fixture = fixture_json('detectors/identifier_form_drift.json');
$fixtureCases = 0;
foreach ($fixture['cases'] as $case) {
    $verdict = Policy::scanIdentifierFormDrift(Profile::GatewayHeader, Mode::Observe, $case['input']);
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
// UTS #39 Identifier_Status — Ucd::isIdAllowed (via nfkdHeadAllowed).
// U+1D44E MATHEMATICAL ITALIC SMALL A is Restricted; its NFKD head U+0061 is Allowed.
assert_same_value(true, IdentifierFormDrift::nfkdHeadAllowed(0x1D44E), 'nfkd head allowed for math-italic-a');
// Plain ASCII 'a' is Allowed and NFKD-identity.
assert_same_value(true, IdentifierFormDrift::nfkdHeadAllowed(0x0061), 'nfkd head allowed for ascii a');

// ── §5 detect spot checks (one per rust `detect_*` test) ─────────────────────

// detect_empty_clear
assert_same_value(true, IdentifierFormDrift::detect([])->classify->isClear(), 'empty clear');

// detect_ascii_clear — "Hello"; every ASCII letter is Allowed, identity NFKD.
$v = IdentifierFormDrift::detect([0x48, 0x65, 0x6C, 0x6C, 0x6F]);
assert_same_value(true, $v->classify->isClear(), 'ascii hello clear');
assert_same_value(0, $v->shiftCount, 'ascii hello shift count 0');

// detect_greek_alpha_clear — α is Allowed with identity NFKD.
assert_same_value(true, IdentifierFormDrift::detect([0x03B1])->classify->isClear(), 'greek alpha clear');

// detect_math_italic_a_shift — U+1D44E Restricted, NFKD head U+0061 Allowed.
$v = IdentifierFormDrift::detect([0x1D44E]);
assert_same_value('IdentifierStatusShift', $v->classify->tag(), 'math italic a tag');
assert_same_value([0], $v->classify->positions(), 'math italic a positions');
assert_same_value(1, $v->shiftCount, 'math italic a shift count');

// detect_fullwidth_A_shift — U+FF21 Restricted, NFKD head U+0041 Allowed.
assert_same_value('IdentifierStatusShift', identifier_form_drift_tag([0xFF21]), 'fullwidth A shift');

// detect_circled_A_shift — U+24B6 → Restricted → Allowed (A).
assert_same_value('IdentifierStatusShift', identifier_form_drift_tag([0x24B6]), 'circled A shift');

// detect_fi_ligature_shift — U+FB01 'ﬁ' ligature → Restricted → Allowed (f).
assert_same_value('IdentifierStatusShift', identifier_form_drift_tag([0xFB01]), 'fi ligature shift');

// detect_roman_iv_shift — U+2163 ROMAN NUMERAL FOUR → Restricted → Allowed (I).
assert_same_value('IdentifierStatusShift', identifier_form_drift_tag([0x2163]), 'roman iv shift');

// detect_reports_first_shift_position — "ab" + U+1D44E: positions 0,1 clear, position 2 shifts.
$v = IdentifierFormDrift::detect([0x61, 0x62, 0x1D44E]);
assert_same_value([2], $v->classify->positions(), 'mid-string first shift positions');
assert_same_value(1, $v->shiftCount, 'mid-string first shift count');

// reason_code_is_stable — the composed reason code for the sole sub-threat.
assert_same_value(
    'unicode.security.X.identifier-form-drift.IdentifierStatusShift',
    Policy::reasonCode(\UnicodePhp\Security\Family::IdentifierFormDrift, 'IdentifierStatusShift'),
    'reason code stable',
);

echo 'identifier_form_drift_test: OK (' . $fixtureCases . " fixture cases)\n";
