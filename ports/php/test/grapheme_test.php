<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';
require_once __DIR__ . '/segmentation_vectors.php';

use UnicodePhp\Segmentation\Grapheme;

function assert_breaks(array $cps, array $expected, string $label): void
{
    $actual = Grapheme::graphemeBreaks($cps);
    if ($actual !== $expected) {
        throw new RuntimeException(
            $label . "\n  cps      " . json_encode($cps)
            . "\n  expected " . json_encode($expected)
            . "\n  actual   " . json_encode($actual)
        );
    }
}

// ---- Full GraphemeBreakTest.txt conformance ------------------------------- //

$path = dirname(__DIR__) . '/testdata/GraphemeBreakTest.txt';
$contents = file_get_contents($path);
if ($contents === false) {
    throw new RuntimeException('cannot read GraphemeBreakTest.txt');
}

$validated = 0;
foreach (explode("\n", $contents) as $lineNo => $rawLine) {
    // Drop the trailing `# comment`, then blank/comment lines.
    $hash = strpos($rawLine, '#');
    $data = $hash === false ? $rawLine : substr($rawLine, 0, $hash);
    $data = trim($data);
    if ($data === '') {
        continue;
    }
    $parsed = parse_break_row($data);
    if (count($parsed['breaks']) !== count($parsed['cps']) + 1) {
        throw new RuntimeException('malformed row ' . ($lineNo + 1) . ': ' . $data);
    }
    assert_breaks($parsed['cps'], $parsed['breaks'], 'GraphemeBreakTest.txt line ' . ($lineNo + 1));
    $validated++;
}

// ---- The shared UAX #29 vectors ------------------------------------------- //

// One case per rule, the same bytes every port replays, so no port carries a
// weaker set of rule checks than another.
$fixture = segmentation_fixture('grapheme_vectors.json', 'uax29-grapheme-cluster');
$replayed = replay_segmentation_vectors(
    $fixture,
    static fn (array $cps): array => Grapheme::graphemeBreaks($cps),
);

// The whole corpus must be accounted for, so a row lost between the file and
// the fold above fails rather than quietly shrinking the denominator. The
// count comes from the fixture, which the generator counts from the canonical
// GraphemeBreakTest.txt, so the corpus gate and the vector gate cannot
// disagree about the size of the corpus.
assert_published_row_count($fixture['published_row_count'], $validated, 'GraphemeBreakTest.txt');

// ---- Targeted vectors mirrored from the rust port ------------------------- //

// "abc" -> break before each + eot (GB999).
assert_breaks([0x61, 0x62, 0x63], [true, true, true, true], 'ascii each its own cluster');
if (count(Grapheme::graphemeClusters([0x61, 0x62, 0x63])) !== 3) {
    throw new RuntimeException('ascii should be 3 clusters');
}

// e + COMBINING ACUTE (U+0301) is one cluster (GB9).
assert_breaks([0x65, 0x0301], [true, false, true], 'combining mark joins');
if (count(Grapheme::graphemeClusters([0x65, 0x0301])) !== 1) {
    throw new RuntimeException('e + combining acute should be 1 cluster');
}

// CR LF is a single cluster (GB3).
assert_breaks([0x0D, 0x0A], [true, false, true], 'crlf is one cluster');

// Regional indicators 🇯🇵 form one cluster (GB12).
assert_breaks([0x1F1EF, 0x1F1F5], [true, false, true], 'flag pair is one cluster');
if (count(Grapheme::graphemeClusters([0x1F1EF, 0x1F1F5])) !== 1) {
    throw new RuntimeException('flag pair should be 1 cluster');
}

// Four regional indicators = two flags = two clusters (GB12/13 parity).
if (count(Grapheme::graphemeClusters([0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8])) !== 2) {
    throw new RuntimeException('four RI should be 2 clusters');
}

// man ZWJ woman ZWJ girl is one cluster (GB11).
if (count(Grapheme::graphemeClusters([0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467])) !== 1) {
    throw new RuntimeException('emoji ZWJ sequence should be 1 cluster');
}

echo 'grapheme_test OK: validated ' . $validated . ' GraphemeBreakTest.txt rows + '
    . $replayed . " shared vectors + targeted vectors\n";
