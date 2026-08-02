<?php

declare(strict_types=1);

require_once __DIR__ . '/test_helper.php';

use UnicodePhp\Security\Form\StreamSafeViolation;
use UnicodePhp\Security\Mode;
use UnicodePhp\Security\Policy;
use UnicodePhp\Security\Profile;

/** @param list<int> $expected @param list<int> $actual */
function assert_stream_positions(array $expected, array $actual, string $label): void
{
    assert_same_value($expected, $actual, $label);
}

/**
 * "a" followed by $n combining acute accents (U+0301, CCC = 230).
 *
 * @return list<int>
 */
function a_plus_marks(int $n): array
{
    $v = [0x61];
    for ($i = 0; $i < $n; $i++) {
        $v[] = 0x0301;
    }
    return $v;
}

// ── (a) shared context-free fixture, driven through scanForms ───────────────
$fixture = fixture_json('detectors/stream_safe_violation.json');
foreach ($fixture['cases'] as $case) {
    $verdict = Policy::scanForms(Profile::OpaqueSecret, Mode::Observe, $case['input']);
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
}

// ── (b) every rust `#[test]` vector transcribed verbatim ────────────────────
$vectors = 0;

// detect_empty_clear
$v = StreamSafeViolation::detect([]);
assert_same_value(true, $v->classify->isClear(), 'empty clear');
assert_same_value(null, $v->classify->tag(), 'empty tag none');
assert_same_value(0, $v->maxRunLen, 'empty maxRunLen');
assert_same_value(0, $v->overrunCount, 'empty overrunCount');
assert_same_value(0, $v->totalNonStarters, 'empty totalNonStarters');
$vectors++;

// detect_ascii_clear — "Hello"
$v = StreamSafeViolation::detect([0x48, 0x65, 0x6C, 0x6C, 0x6F]);
assert_same_value(true, $v->classify->isClear(), 'ascii clear');
assert_same_value(0, $v->maxRunLen, 'ascii maxRunLen');
assert_same_value(0, $v->totalNonStarters, 'ascii totalNonStarters');
$vectors++;

// detect_one_combine_clear — "a" + U+0301
$v = StreamSafeViolation::detect([0x61, 0x0301]);
assert_same_value(true, $v->classify->isClear(), 'one combine clear');
assert_same_value(1, $v->maxRunLen, 'one combine maxRunLen');
assert_same_value(0, $v->overrunCount, 'one combine overrunCount');
assert_same_value(1, $v->totalNonStarters, 'one combine totalNonStarters');
$vectors++;

// detect_thirty_marks_clear — boundary case, stays clear under strict `>`
$v = StreamSafeViolation::detect(a_plus_marks(30));
assert_same_value(true, $v->classify->isClear(), 'thirty marks clear');
assert_same_value(null, $v->classify->tag(), 'thirty marks tag none');
assert_same_value(30, $v->maxRunLen, 'thirty marks maxRunLen');
assert_same_value(0, $v->overrunCount, 'thirty marks overrunCount');
assert_same_value(30, $v->totalNonStarters, 'thirty marks totalNonStarters');
$vectors++;

// detect_thirtyone_marks_hazard — fires with firstOverrun = (1, 31), positions [1]
$v = StreamSafeViolation::detect(a_plus_marks(31));
assert_same_value(false, $v->classify->isClear(), 'thirtyone marks hazard');
assert_same_value('StreamSafeOverrun', $v->classify->tag(), 'thirtyone marks tag');
assert_stream_positions([1], $v->classify->positions(), 'thirtyone marks positions');
assert_same_value(1, $v->classify->sub->basePos, 'thirtyone marks basePos');
assert_same_value(31, $v->classify->sub->runLen, 'thirtyone marks runLen');
assert_same_value(31, $v->maxRunLen, 'thirtyone marks maxRunLen');
assert_same_value(1, $v->overrunCount, 'thirtyone marks overrunCount');
assert_same_value(31, $v->totalNonStarters, 'thirtyone marks totalNonStarters');
$vectors++;

// bare_mark_run_starts_at_zero — 31 bare marks, run opens at index 0
$bare = [];
for ($i = 0; $i < 31; $i++) {
    $bare[] = 0x0301;
}
$v = StreamSafeViolation::detect($bare);
assert_same_value('StreamSafeOverrun', $v->classify->tag(), 'bare run tag');
assert_stream_positions([0], $v->classify->positions(), 'bare run positions');
assert_same_value(31, $v->maxRunLen, 'bare run maxRunLen');
assert_same_value(31, $v->totalNonStarters, 'bare run totalNonStarters');
$vectors++;

// two_short_runs_clear_totals_summed — "a" + 30 marks + "b" + 30 marks
$two = a_plus_marks(30);
$two[] = 0x62;
for ($i = 0; $i < 30; $i++) {
    $two[] = 0x0301;
}
$v = StreamSafeViolation::detect($two);
assert_same_value(true, $v->classify->isClear(), 'two short runs clear');
assert_same_value(30, $v->maxRunLen, 'two short runs maxRunLen');
assert_same_value(0, $v->overrunCount, 'two short runs overrunCount');
assert_same_value(60, $v->totalNonStarters, 'two short runs totalNonStarters');
$vectors++;

// first_overrun_reports_long_run_start — "a" + 5 marks + "b" + 31 marks
$first = a_plus_marks(5);
$first[] = 0x62;
for ($i = 0; $i < 31; $i++) {
    $first[] = 0x0301;
}
$v = StreamSafeViolation::detect($first);
assert_same_value('StreamSafeOverrun', $v->classify->tag(), 'first overrun tag');
assert_stream_positions([7], $v->classify->positions(), 'first overrun positions');
assert_same_value(31, $v->maxRunLen, 'first overrun maxRunLen');
assert_same_value(1, $v->overrunCount, 'first overrun overrunCount');
assert_same_value(36, $v->totalNonStarters, 'first overrun totalNonStarters');
$vectors++;

// ── (c) 30/31 boundary drives the reason code through the policy scan ───────
$clear = Policy::scanForms(Profile::OpaqueSecret, Mode::Observe, a_plus_marks(30));
foreach (verdict_codes($clear) as $code) {
    if (str_contains($code, '.stream-safe-violation.')) {
        throw new RuntimeException('30-mark boundary must stay clear, got ' . $code);
    }
}
$hazard = Policy::scanForms(Profile::OpaqueSecret, Mode::Observe, a_plus_marks(31));
assert_includes_value(
    verdict_codes($hazard),
    'unicode.security.F.stream-safe-violation.StreamSafeOverrun',
    '31-mark boundary reason code',
);

if ($vectors !== 8) {
    throw new RuntimeException('expected 8 rust vectors, transcribed ' . $vectors);
}

echo "stream_safe_violation_test: OK (" . $vectors . " rust vectors)\n";
