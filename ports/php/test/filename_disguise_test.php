<?php

declare(strict_types=1);

require_once __DIR__ . '/test_helper.php';

use UnicodePhp\Security\Display\FilenameDisguise;
use UnicodePhp\Security\Mode;
use UnicodePhp\Security\Policy;
use UnicodePhp\Security\Profile;

/** @param list<int> $input */
function filename_disguise_tag(array $input): ?string
{
    return FilenameDisguise::detect($input)->classify->tag();
}

// ── (a) shared context-free fixture, driven through scanFilenameDisguise ──────
$fixture = fixture_json('detectors/filename_disguise.json');
$fixtureCases = 0;
foreach ($fixture['cases'] as $case) {
    $verdict = Policy::scanFilenameDisguise(Profile::GatewayHeader, Mode::Observe, $case['input']);
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
// Bidi format-control — BidiControlBalance::isBidiFormatControl.
assert_same_value(true, FilenameDisguise::isBidiFormatControl(0x202E), 'bidi RLO');
assert_same_value(true, FilenameDisguise::isBidiFormatControl(0x2067), 'bidi RLI');
assert_same_value(false, FilenameDisguise::isBidiFormatControl(0x0041), 'bidi ascii');
// Grapheme Extend — Grapheme::lookupGcb === Gcb::Extend.
assert_same_value(true, FilenameDisguise::isGraphemeExtend(0x0301), 'extend combining acute');
assert_same_value(false, FilenameDisguise::isGraphemeExtend(0x0061), 'extend ascii a');
// Fullwidth/halfwidth block.
assert_same_value(true, FilenameDisguise::isFullwidthHalfwidth(0xFF25), 'fullwidth E');
assert_same_value(false, FilenameDisguise::isFullwidthHalfwidth(0x0045), 'fullwidth ascii E');
// ASCII dot.
assert_same_value(true, FilenameDisguise::isAsciiDot(0x2E), 'ascii dot');
assert_same_value(false, FilenameDisguise::isAsciiDot(0x2C), 'comma not dot');

// ── §5 detect spot checks (one per rust `detect_*` test) ─────────────────────

// detect_empty_clear
assert_same_value(true, FilenameDisguise::detect([])->classify->isClear(), 'empty clear');

// detect_plain_txt_clear — "document.txt"
$v = FilenameDisguise::detect([0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x2E, 0x74, 0x78, 0x74]);
assert_same_value(true, $v->classify->isClear(), 'plain txt clear');
assert_same_value(8, $v->lastDotPos, 'plain txt last dot pos');

// detect_no_extension_clear — "foo"
$v = FilenameDisguise::detect([0x66, 0x6F, 0x6F]);
assert_same_value(true, $v->classify->isClear(), 'no ext clear');
assert_same_value(null, $v->lastDotPos, 'no ext last dot pos null');

// detect_tar_gz_clear — "archive.tar.gz" (2 dots, below the multi-ext bound)
assert_same_value(true, FilenameDisguise::detect([0x61, 0x72, 0x63, 0x68, 0x69, 0x76, 0x65, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A])->classify->isClear(), 'tar gz clear');

// detect_hebrew_clear — native Hebrew name, no bidi controls.
assert_same_value(true, FilenameDisguise::detect([0x05D0, 0x05D1, 0x05D2, 0x2E, 0x74, 0x78, 0x74])->classify->isClear(), 'hebrew clear');

// detect_rlo_flip — "document<RLO>txt.exe"
$v = FilenameDisguise::detect([0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x202E, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65]);
assert_same_value('RloFlip', $v->classify->tag(), 'rlo flip tag');
assert_same_value([8], $v->classify->positions(), 'rlo flip positions');

// detect_isolate_flip — RLI/PDI isolate variant, also RloFlip.
assert_same_value('RloFlip', filename_disguise_tag([0x64, 0x6F, 0x63, 0x2067, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65, 0x2069]), 'isolate flip');

// detect_fullwidth_exe — "file.ＥＸＥ"
assert_same_value('WidthClassExt', filename_disguise_tag([0x66, 0x69, 0x6C, 0x65, 0x2E, 0xFF25, 0xFF38, 0xFF25]), 'fullwidth ext');

// detect_combining_in_ext — "file.é xe" (combining acute in the extension)
assert_same_value('CombiningInExt', filename_disguise_tag([0x66, 0x69, 0x6C, 0x65, 0x2E, 0x65, 0x0301, 0x78, 0x65]), 'combining in ext');

// detect_triple_extension — "setup.tar.gz.sig"
assert_same_value('MultipleExtensions', filename_disguise_tag([0x73, 0x65, 0x74, 0x75, 0x70, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A, 0x2E, 0x73, 0x69, 0x67]), 'triple extension');

// ── priority-ladder structural check ─────────────────────────────────────────

// A bidi control outranks a fullwidth extension.
assert_same_value('RloFlip', filename_disguise_tag([0x202E, 0x66, 0x2E, 0xFF25]), 'bidi beats fullwidth');

echo 'filename_disguise_test: OK (' . $fixtureCases . " fixture cases)\n";
