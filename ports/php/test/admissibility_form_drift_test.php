<?php

declare(strict_types=1);

require_once __DIR__ . '/test_helper.php';

use UnicodePhp\Security\Boundary\AdmissibilityFormDrift;
use UnicodePhp\Security\Mode;
use UnicodePhp\Security\Policy;
use UnicodePhp\Security\Profile;

/** @param list<int> $input */
function admissibility_form_drift_tag(array $input): ?string
{
    return AdmissibilityFormDrift::detect($input)->classify->tag();
}

// ── (a) shared context-free fixture, driven through scanAdmissibilityFormDrift ──
$fixture = fixture_json('detectors/admissibility_form_drift.json');
$fixtureCases = 0;
foreach ($fixture['cases'] as $case) {
    $verdict = Policy::scanAdmissibilityFormDrift(Profile::GatewayHeader, Mode::Observe, $case['input']);
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

// ── §5 detect spot checks (one per rust `detect_*` test) ─────────────────────

// detect_empty_clear — both admissibility calls return false, so they agree.
assert_same_value(true, AdmissibilityFormDrift::detect([])->classify->isClear(), 'empty clear');

// detect_ascii_clear — "admin"; admissible on both sides (NFKC is identity).
$v = AdmissibilityFormDrift::detect([0x61, 0x64, 0x6D, 0x69, 0x6E]);
assert_same_value(true, $v->classify->isClear(), 'admin clear');
assert_same_value(true, $v->inputAdmissible, 'admin input admissible');
assert_same_value(true, $v->nfkcAdmissible, 'admin nfkc admissible');

// detect_fi_ligature_drift — U+FB01 is Restricted (inadmissible), but NFKC
// decomposes it to "fi" (admissible). Drift fires.
$v = AdmissibilityFormDrift::detect([0xFB01]);
assert_same_value('AdmissibilityFormDrift', $v->classify->tag(), 'fi ligature tag');
assert_same_value(false, $v->inputAdmissible, 'fi ligature input inadmissible');
assert_same_value(true, $v->nfkcAdmissible, 'fi ligature nfkc admissible');
assert_same_value([], $v->classify->positions(), 'fi ligature no positions');

// detect_jamo_sequence_drift — decomposed Hangul jamos [U+1112, U+1161, U+11AB]
// are inadmissible, but NFKC composes them to U+D55C 한 (admissible).
assert_same_value('AdmissibilityFormDrift', admissibility_form_drift_tag([0x1112, 0x1161, 0x11AB]), 'jamo sequence drift');

// ── reason-code stability ────────────────────────────────────────────────────
assert_same_value(
    'unicode.security.X.admissibility-form-drift.AdmissibilityFormDrift',
    Policy::reasonCode(\UnicodePhp\Security\Family::AdmissibilityFormDrift, 'AdmissibilityFormDrift'),
    'reason code stable'
);

echo 'admissibility_form_drift_test: OK (' . $fixtureCases . " fixture cases)\n";
