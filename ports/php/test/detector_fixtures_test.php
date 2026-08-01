<?php

declare(strict_types=1);

require_once __DIR__ . '/test_helper.php';

use UnicodePhp\Security\Mode;
use UnicodePhp\Security\Policy;
use UnicodePhp\Security\Profile;

$fixtures = [
    'tag_block_payload.json',
    'variation_selector_payload.json',
    'zero_width_payload.json',
    'surrogate_reassembly.json',
    'bidi_control_balance.json',
    'noncharacter_control.json',
    'homoglyph_confusable.json',
    'mixed_script_admissibility.json',
    'rtl_injection.json',
    'covert_display_compound.json',
    'confusable_bidi_compound.json',
];

foreach ($fixtures as $name) {
    $fixture = fixture_json('detectors/' . $name);
    foreach ($fixture['cases'] as $case) {
        $verdict = Policy::scan(Profile::GatewayHeader, Mode::Observe, $case['input']);
        $codes = verdict_codes($verdict);
        foreach ($case['required_findings'] as $required) {
            assert_includes_value($codes, $required, $name . '/' . $case['name']);
        }
        if ($case['required_findings'] === []) {
            $needle = '.' . $fixture['family'] . '.';
            foreach ($codes as $code) {
                if (str_contains($code, $needle)) {
                    throw new RuntimeException($name . '/' . $case['name'] . ' unexpected family ' . $fixture['family']);
                }
            }
        }
    }
}
