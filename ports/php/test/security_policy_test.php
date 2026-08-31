<?php

declare(strict_types=1);

require_once __DIR__ . '/test_helper.php';

use UnicodePhp\Security\Family;
use UnicodePhp\Security\Policy;

assert_same_value('unicode.security.C.tag-block-payload.DirectAscii', Policy::reasonCode(Family::TagBlockPayload, 'DirectAscii'), 'reason tag');
assert_same_value('unicode.security.C.bidi-control-balance.hazard', Policy::reasonCode(Family::BidiControlBalance), 'reason bidi');
assert_same_value('unicode.security.I.homoglyph-confusable.TargetMatch', Policy::reasonCode(Family::HomoglyphConfusable, 'TargetMatch'), 'reason homoglyph');
assert_same_value('unicode.security.I.mixed-script-admissibility.CrossScriptMix', Policy::reasonCode(Family::MixedScriptAdmissibility, 'CrossScriptMix'), 'reason mixed');
assert_same_value('unicode.security.C.noncharacter-control.Noncharacter', Policy::reasonCode(Family::NoncharacterControl, 'Noncharacter'), 'reason noncharacter');
assert_same_value('unicode.security.C.malformed-utf8.InvalidStartByte', Policy::reasonCode(Family::MalformedUtf8, 'InvalidStartByte'), 'reason utf8');

$policy = fixture_json('policy_contract.json');
assert_same_value('unicode-security-policy-v0', $policy['contract'], 'policy contract');
foreach ($policy['cases'] as $case) {
    $verdict = Policy::scan(profile_from_string($case['profile']), mode_from_string($case['mode']), $case['input']);
    assert_same_value($case['action'], $verdict->action->value, $case['name']);
    $codes = verdict_codes($verdict);
    foreach ($case['required_findings'] as $required) {
        assert_includes_value($codes, $required, $case['name']);
    }
}

$verdictFixture = fixture_json('verdict_contract.json');
assert_same_value('unicode-security-verdict-v0', $verdictFixture['contract'], 'verdict contract');
foreach ($verdictFixture['cases'] as $case) {
    $verdict = Policy::scan(profile_from_string($case['profile']), mode_from_string($case['mode']), $case['input']);
    assert_same_value($case['verdict'], Policy::verdictToWire($verdict), $case['name']);
    assert_same_value(json_encode($case['verdict'], JSON_UNESCAPED_SLASHES), Policy::verdictToJson($verdict), $case['name'] . ' json');
}

// Agreement with the reference over a generated input stream. The corpus shares
// the verdict contract's schema, so it runs through the same comparison, but its
// cases come from the Rust reference over a deterministic stream rather than
// being hand-written: agreement here is evidence that this port decides as the
// reference does on inputs nobody chose, across every profile.
$corpus = fixture_json('differential_corpus.json');
assert_same_value('unicode-security-verdict-v0', $corpus['contract'], 'differential corpus');
foreach ($corpus['cases'] as $case) {
    $verdict = Policy::scan(profile_from_string($case['profile']), mode_from_string($case['mode']), $case['input']);
    assert_same_value($case['verdict'], Policy::verdictToWire($verdict), $case['name']);
    assert_same_value(json_encode($case['verdict'], JSON_UNESCAPED_SLASHES), Policy::verdictToJson($verdict), $case['name'] . ' json');
}

$decode = fixture_json('decode_contract.json');
assert_same_value('unicode-security-decode-v0', $decode['contract'], 'decode contract');
foreach ($decode['cases'] as $case) {
    $verdict = Policy::scanUtf8(profile_from_string($case['profile']), mode_from_string($case['mode']), $case['input_bytes']);
    assert_same_value($case['action'], $verdict->action->value, $case['name']);
    assert_same_value($case['input'], $verdict->input, $case['name']);
    assert_required_findings_and_positions($case, $verdict);
}

$multi = fixture_json('decode_multiencoding_contract.json');
assert_same_value('unicode-security-multiencoding-decode-v0', $multi['contract'], 'multiencoding contract');
foreach ($multi['cases'] as $case) {
    $verdict = scan_encoded_case($case);
    assert_same_value($case['action'], $verdict->action->value, $case['name']);
    assert_same_value($case['input'], $verdict->input, $case['name']);
    assert_required_findings_and_positions($case, $verdict);
}
