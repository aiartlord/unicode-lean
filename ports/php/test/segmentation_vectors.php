<?php

declare(strict_types=1);

// The shared segmentation vector fixtures and the published break corpora,
// read the same way by both segmentation suites: one case per UAX rule, the
// same bytes every port replays, so each port's segmentation tests ask the
// same questions rather than a per-port selection of them.

require_once __DIR__ . '/../src/autoload.php';

/**
 * One fixture, with the shape every consumer relies on established first.
 *
 * @return array{schema: int, algorithm: string, published_row_count: int, cases: list<array{name: string, rule: string, input: list<int>, breaks: list<bool>}>}
 */
function segmentation_fixture(string $name, string $algorithm): array
{
    $path = dirname(__DIR__) . '/testdata/fixtures/segmentation/' . $name;
    $json = file_get_contents($path);
    if ($json === false) {
        throw new RuntimeException("cannot read fixture {$name}");
    }
    $document = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
    if (!is_array($document)) {
        throw new RuntimeException("fixture {$name} did not decode to an object");
    }
    if ($document['schema'] !== 1) {
        throw new RuntimeException("fixture {$name} carries schema " . json_encode($document['schema']));
    }
    if ($document['algorithm'] !== $algorithm) {
        throw new RuntimeException("fixture {$name} is for {$document['algorithm']}, not {$algorithm}");
    }
    if ($document['cases'] === []) {
        throw new RuntimeException("fixture {$name} carries no cases");
    }
    return $document;
}

/**
 * Every case's boundary mask, reproduced, and how many were replayed. A
 * failure names the rule and what the case is for, so the red reads as a
 * sentence rather than an index.
 *
 * @param array{cases: list<array{name: string, rule: string, input: list<int>, breaks: list<bool>}>} $fixture
 * @param callable(list<int>): list<bool> $breaksOf
 */
function replay_segmentation_vectors(array $fixture, callable $breaksOf): int
{
    $replayed = 0;
    foreach ($fixture['cases'] as $case) {
        $actual = $breaksOf($case['input']);
        if ($actual !== $case['breaks']) {
            throw new RuntimeException(
                $case['rule'] . ': ' . $case['name']
                . "\n  cps      " . json_encode($case['input'])
                . "\n  expected " . json_encode($case['breaks'])
                . "\n  actual   " . json_encode($actual)
            );
        }
        $replayed++;
    }
    return $replayed;
}

/**
 * Parse one data row of a published break corpus into its code points and its
 * expected boundary mask.
 *
 * A row is a sequence of boundary markers (`÷` break, `×` no break)
 * alternating with hex code points, e.g. `÷ 000D × 000A ÷`. The mask has one
 * entry per marker (length = number of code points + 1); entry `i` is `true`
 * at `÷`.
 *
 * @return array{cps: list<int>, breaks: list<bool>}
 */
function parse_break_row(string $row): array
{
    $cps = [];
    $breaks = [];
    foreach (preg_split('/\s+/', trim($row), -1, PREG_SPLIT_NO_EMPTY) as $token) {
        switch ($token) {
            case '÷':
                $breaks[] = true;
                break;
            case '×':
                $breaks[] = false;
                break;
            default:
                $cps[] = intval($token, 16);
                break;
        }
    }
    return ['cps' => $cps, 'breaks' => $breaks];
}

/// The two gates count the same published file, so a disagreement between
/// them is a corpus one of them is not reading whole.
function assert_published_row_count(int $expected, int $actual, string $label): void
{
    if ($expected !== $actual) {
        throw new RuntimeException(
            $label . ' accounts for ' . $actual . ' rows, expected ' . $expected
        );
    }
}
