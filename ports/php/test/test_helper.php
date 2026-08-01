<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use UnicodePhp\Security\Mode;
use UnicodePhp\Security\Policy;
use UnicodePhp\Security\Profile;
use UnicodePhp\Security\Verdict;

function fixture_json(string $relative): array
{
    $path = dirname(__DIR__) . '/testdata/fixtures/security/' . $relative;
    $json = file_get_contents($path);
    if ($json === false) {
        throw new RuntimeException("cannot read fixture {$relative}");
    }
    $decoded = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
    if (!is_array($decoded)) {
        throw new RuntimeException("fixture {$relative} did not decode to an object");
    }
    return $decoded;
}

function assert_same_value(mixed $expected, mixed $actual, string $label): void
{
    if ($expected !== $actual) {
        throw new RuntimeException($label . ' expected ' . json_encode($expected) . ' got ' . json_encode($actual));
    }
}

function assert_includes_value(array $haystack, mixed $needle, string $label): void
{
    if (!in_array($needle, $haystack, true)) {
        throw new RuntimeException($label . ' missing ' . json_encode($needle) . ' in ' . json_encode($haystack));
    }
}

function profile_from_string(string $profile): Profile
{
    return Profile::from($profile);
}

function mode_from_string(string $mode): Mode
{
    return Mode::from($mode);
}

/** @return list<string> */
function verdict_codes(Verdict $verdict): array
{
    return array_map(static fn ($finding): string => $finding->code, $verdict->findings);
}

function assert_required_findings_and_positions(array $case, Verdict $verdict): void
{
    $codes = verdict_codes($verdict);
    foreach ($case['required_findings'] as $required) {
        assert_includes_value($codes, $required, $case['name']);
    }
    $positionsByCode = [];
    foreach ($verdict->findings as $finding) {
        $positionsByCode[$finding->code] = $finding->positions;
    }
    foreach ($case['required_positions'] as $expected) {
        if (!array_key_exists($expected['code'], $positionsByCode)) {
            throw new RuntimeException($case['name'] . ' missing positions for ' . $expected['code']);
        }
        assert_same_value($expected['positions'], $positionsByCode[$expected['code']], $case['name']);
    }
}

function scan_encoded_case(array $case): Verdict
{
    $profile = profile_from_string($case['profile']);
    $mode = mode_from_string($case['mode']);
    $bytes = $case['input_bytes'];
    return match ($case['encoding']) {
        'utf-8' => Policy::scanUtf8($profile, $mode, $bytes),
        'utf-16be' => Policy::scanUtf16be($profile, $mode, $bytes),
        'utf-16le' => Policy::scanUtf16le($profile, $mode, $bytes),
        'utf-32be' => Policy::scanUtf32be($profile, $mode, $bytes),
        'utf-32le' => Policy::scanUtf32le($profile, $mode, $bytes),
        default => throw new RuntimeException('unknown encoding ' . $case['encoding']),
    };
}
