<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';
require_once __DIR__ . '/segmentation_vectors.php';

use UnicodePhp\Segmentation\Eaw;
use UnicodePhp\Segmentation\Gc;
use UnicodePhp\Segmentation\Lb;
use UnicodePhp\Segmentation\LineBreak;
use UnicodePhp\Segmentation\LineBreakTables;

function assert_line_breaks(array $cps, array $expected, string $label): void
{
    $actual = LineBreak::lineBreaks($cps);
    if ($actual !== $expected) {
        throw new RuntimeException(
            $label . "\n  cps      " . json_encode($cps)
            . "\n  expected " . json_encode($expected)
            . "\n  actual   " . json_encode($actual)
        );
    }
}

// ---- Full LineBreakTest.txt conformance ----------------------------------- //

// Hand-written vectors cannot establish a segmentation algorithm: its rules
// read context on both sides of a boundary and the answer depends on state
// carried from earlier in the sequence, so a wrong rule survives any vector a
// person would pick. Agreeing with every published row is also the evidence
// the two departures declared at the head of LineBreak.php needed — bounded
// reads in place of the Lean's positional `lits[i]!`, and dropping its
// write-only `spSinceNoSp` snapshot field.

$path = dirname(__DIR__) . '/testdata/LineBreakTest.txt';
$contents = file_get_contents($path);
if ($contents === false) {
    throw new RuntimeException('cannot read LineBreakTest.txt');
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
    assert_line_breaks($parsed['cps'], $parsed['breaks'], 'LineBreakTest.txt line ' . ($lineNo + 1));
    $validated++;
}

// The whole file must be accounted for, so a row lost between the file and
// this fold fails rather than quietly shrinking the denominator.
assert_published_row_count($validated, LineBreakTables::PUBLISHED_ROW_COUNT, 'LineBreakTest.txt');

// ---- The shared UAX #14 vectors ------------------------------------------- //

// One case per rule, the same bytes every port replays, so no port carries a
// weaker set of rule checks than another. Both gates count the same published
// file, so they cannot drift apart.
$fixture = segmentation_fixture('line_break_vectors.json', 'uax14-line-break');
$replayed = replay_segmentation_vectors(
    $fixture,
    static fn (array $cps): array => LineBreak::lineBreaks($cps),
);
assert_published_row_count(
    LineBreakTables::PUBLISHED_ROW_COUNT,
    $fixture['published_row_count'],
    'line_break_vectors.json'
);

// ---- Targeted vectors ----------------------------------------------------- //

// One flag per boundary, so n code points yield n + 1 flags.
for ($length = 0; $length < 8; $length++) {
    $cps = [];
    for ($i = 0; $i < $length; $i++) {
        $cps[] = 0x61 + $i;
    }
    if (count(LineBreak::lineBreaks($cps)) !== $length + 1) {
        throw new RuntimeException('line-break flag count at length ' . $length);
    }
}

// LB18 breaks after a space, so the space stays with the word before it. The
// run split is a shape the boundary masks do not state.
$runs = LineBreak::lineRuns([0x61, 0x20, 0x62]);
if ($runs !== [[0x61, 0x20], [0x62]]) {
    throw new RuntimeException('a space should open the next run: ' . json_encode($runs));
}

// LB25: "1,000" is one run across its separator.
if (count(LineBreak::lineRuns([0x31, 0x2C, 0x30, 0x30, 0x30])) !== 1) {
    throw new RuntimeException('a numeric chain should be one run');
}

// LB1 folds the tailorable classes into the working alphabet. U+3041 HIRAGANA
// LETTER SMALL A is CJ, resolving to NS; U+00A7 SECTION SIGN is AI and a
// surrogate is SG, both resolving to AL; U+05EB lies in the Hebrew block's
// unassigned gap, which no range covers, so it takes the @missing XX default
// and reads as AL.
$classExpectations = [
    [0x3041, Lb::Cj, Lb::Ns],
    [0x00A7, Lb::Ai, Lb::Al],
    [0xD800, Lb::Sg, Lb::Al],
    [0x05EB, Lb::Xx, Lb::Al],
    // LB1 resolves SA by General_Category: U+0E31 THAI CHARACTER MAI HAN-AKAT
    // is SA with category Mn, so it reads as CM; U+0E01 THAI CHARACTER KO KAI
    // is SA with category Lo, so it reads as AL.
    [0x0E31, Lb::Sa, Lb::Cm],
    [0x0E01, Lb::Sa, Lb::Al],
];
foreach ($classExpectations as [$cp, $raw, $resolved]) {
    if (LineBreak::rawClass($cp) !== $raw) {
        throw new RuntimeException(sprintf(
            'U+%04X raw class is %s, expected %s',
            $cp,
            LineBreak::rawClass($cp)->name,
            $raw->name
        ));
    }
    if (LineBreak::resolvedClass($cp) !== $resolved) {
        throw new RuntimeException(sprintf(
            'U+%04X resolved class is %s, expected %s',
            $cp,
            LineBreak::resolvedClass($cp)->name,
            $resolved->name
        ));
    }
}

// The East_Asian_Width LB19a, LB25 and LB30 read: U+FF21 FULLWIDTH LATIN
// CAPITAL LETTER A is F and U+0041 is Na.
if (LineBreak::widthOf(0xFF21) !== Eaw::F || LineBreak::widthOf(0x0041) !== Eaw::Na) {
    throw new RuntimeException('East_Asian_Width lookup disagrees with UAX #11');
}

// The General_Category LB15a, LB15b and LB30b read.
if (LineBreak::categoryOf(0x2018) !== Gc::Pi || LineBreak::categoryOf(0x2019) !== Gc::Pf) {
    throw new RuntimeException('General_Category lookup disagrees with UAX #44');
}

// The Extended_Pictographic LB30b reads.
if (!LineBreak::isExtendedPictographic(0x1F466) || LineBreak::isExtendedPictographic(0x0061)) {
    throw new RuntimeException('Extended_Pictographic lookup disagrees with emoji-data');
}

echo 'line_break_test OK: validated ' . $validated . ' LineBreakTest.txt rows + '
    . $replayed . " shared vectors + targeted vectors\n";
