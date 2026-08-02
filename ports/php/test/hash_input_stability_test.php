<?php

declare(strict_types=1);

require_once __DIR__ . '/test_helper.php';

use UnicodePhp\Security\Crypto\Context;
use UnicodePhp\Security\Crypto\HashInputStability;
use UnicodePhp\Security\Crypto\RfcRule;
use UnicodePhp\Security\Mode;
use UnicodePhp\Security\Policy;
use UnicodePhp\Security\Profile;

/** @param list<int> $expected @param list<int> $actual */
function assert_positions(array $expected, array $actual, string $label): void
{
    assert_same_value($expected, $actual, $label);
}

// ── (a) shared context-free fixture, driven through scanHashInput ───────────
$fixture = fixture_json('detectors/hash_input_stability.json');
foreach ($fixture['cases'] as $case) {
    $verdict = Policy::scanHashInput(Profile::OpaqueSecret, Mode::Observe, $case['input']);
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

// The same fixture inputs also exercise the direct `detect` entry point.
assert_same_value('TrailingWhitespace', HashInputStability::detect([0x61, 0x20])->classify->tag(), 'detect trailing');
assert_positions([1], HashInputStability::detect([0x61, 0x20])->classify->positions(), 'detect trailing pos');
assert_same_value('NormalizationDrift', HashInputStability::detect([0x65, 0x301])->classify->tag(), 'detect nfc');
assert_same_value(null, HashInputStability::detect([0xE9])->classify->tag(), 'detect precomposed clear');
assert_same_value(true, HashInputStability::detect([])->classify->isClear(), 'detect empty clear');

// ── §4 hash-stable spot checks (NFC + trailing-trim pipeline) ───────────────
assert_same_value([], HashInputStability::hashStable([]), 'stable empty');
assert_same_value([0x61, 0x62, 0x63], HashInputStability::hashStable([0x61, 0x62, 0x63]), 'stable ascii');
assert_same_value([0x61], HashInputStability::hashStable([0x61, 0x20]), 'stable strip space');
assert_same_value([0x61], HashInputStability::hashStable([0x61, 0x09]), 'stable strip tab');
assert_same_value([0x61], HashInputStability::hashStable([0x61, 0x0A]), 'stable strip lf');
assert_same_value([0x61], HashInputStability::hashStable([0x61, 0x0D, 0x0A]), 'stable strip crlf');
assert_same_value([0x61, 0x20, 0x62], HashInputStability::hashStable([0x61, 0x20, 0x62]), 'stable internal space');
assert_same_value([0xE9], HashInputStability::hashStable([0x65, 0x301]), 'stable composes nfc');
assert_same_value([0x61, 0xA0], HashInputStability::hashStable([0x61, 0xA0]), 'stable keeps nbsp');

// ── (b) every Context vector transcribed verbatim from the rust test block ──
$vectors = 0;

// declared_encoding = Some("utf-16"), [0x61,0x62,0x63] → EncodingMismatch, [0]
$v = HashInputStability::detectWithContext(new Context(declaredEncoding: 'utf-16'), [0x61, 0x62, 0x63]);
assert_same_value('EncodingMismatch', $v->classify->tag(), 'ctx encoding utf-16');
assert_positions([0], $v->classify->positions(), 'ctx encoding utf-16 pos');
$vectors++;

// declared_encoding = Some("utf-8"), [0x61,0xD800,0x62] → EncodingMismatch, [1] (invalid surrogate)
$v = HashInputStability::detectWithContext(new Context(declaredEncoding: 'utf-8'), [0x61, 0xD800, 0x62]);
assert_same_value('EncodingMismatch', $v->classify->tag(), 'ctx encoding surrogate');
assert_positions([1], $v->classify->positions(), 'ctx encoding surrogate pos');
$vectors++;

// declared_encoding = Some("utf-8"), [0x61,0x110000,0x62] → EncodingMismatch, [1] (out of range)
$v = HashInputStability::detectWithContext(new Context(declaredEncoding: 'utf-8'), [0x61, 0x110000, 0x62]);
assert_same_value('EncodingMismatch', $v->classify->tag(), 'ctx encoding out of range');
assert_positions([1], $v->classify->positions(), 'ctx encoding out of range pos');
$vectors++;

// declared_encoding = Some("UTF-8"|"utf-8"|"UTF8"|"utf8"), [0x61,0x62,0x63] → clear
foreach (['UTF-8', 'utf-8', 'UTF8', 'utf8'] as $label) {
    $v = HashInputStability::detectWithContext(new Context(declaredEncoding: $label), [0x61, 0x62, 0x63]);
    assert_same_value(true, $v->classify->isClear(), 'ctx encoding utf8 label ' . $label . ' clear');
}
$vectors++;

// rfc_rule = Pgp4880TrailingWhitespace, [0x61,0x20] → SignedMessageRule, [1]
$v = HashInputStability::detectWithContext(new Context(rfcRule: RfcRule::Pgp4880TrailingWhitespace), [0x61, 0x20]);
assert_same_value('SignedMessageRule', $v->classify->tag(), 'ctx pgp4880');
assert_positions([1], $v->classify->positions(), 'ctx pgp4880 pos');
$vectors++;

// rfc_rule = Pgp9580LineEnding, [0x61,0x0A,0x62] → SignedMessageRule, [1] (bare LF)
$v = HashInputStability::detectWithContext(new Context(rfcRule: RfcRule::Pgp9580LineEnding), [0x61, 0x0A, 0x62]);
assert_same_value('SignedMessageRule', $v->classify->tag(), 'ctx pgp9580 bare lf');
assert_positions([1], $v->classify->positions(), 'ctx pgp9580 bare lf pos');
$vectors++;

// rfc_rule = Pgp9580LineEnding, [0x61,0x62,0x63,0x0D,0x0A,0x64,0x65,0x66] → clear (CRLF)
$v = HashInputStability::detectWithContext(new Context(rfcRule: RfcRule::Pgp9580LineEnding), [0x61, 0x62, 0x63, 0x0D, 0x0A, 0x64, 0x65, 0x66]);
assert_same_value(true, $v->classify->isClear(), 'ctx pgp9580 crlf clear');
$vectors++;

// rfc_rule = Rfc8785NfcRequirement, [0x0065,0x0301] → SignedMessageRule, [0]
$v = HashInputStability::detectWithContext(new Context(rfcRule: RfcRule::Rfc8785NfcRequirement), [0x65, 0x301]);
assert_same_value('SignedMessageRule', $v->classify->tag(), 'ctx rfc8785');
assert_positions([0], $v->classify->positions(), 'ctx rfc8785 pos');
$vectors++;

// rfc_rule = Rfc8259ControlChar, [0x61,0x01,0x62] → SignedMessageRule, [1]
$v = HashInputStability::detectWithContext(new Context(rfcRule: RfcRule::Rfc8259ControlChar), [0x61, 0x01, 0x62]);
assert_same_value('SignedMessageRule', $v->classify->tag(), 'ctx rfc8259');
assert_positions([1], $v->classify->positions(), 'ctx rfc8259 pos');
$vectors++;

// rfc_rule = Rfc7515JwsBase64Url, [0x41,0x2B,0x42] → SignedMessageRule, [1] ('+')
$v = HashInputStability::detectWithContext(new Context(rfcRule: RfcRule::Rfc7515JwsBase64Url), [0x41, 0x2B, 0x42]);
assert_same_value('SignedMessageRule', $v->classify->tag(), 'ctx rfc7515 plus');
assert_positions([1], $v->classify->positions(), 'ctx rfc7515 plus pos');
$vectors++;

// rfc_rule = Rfc7515JwsBase64Url, [0x41,0x61,0x30,0x2D,0x5F,0x7A,0x5A,0x39] → clear
$v = HashInputStability::detectWithContext(new Context(rfcRule: RfcRule::Rfc7515JwsBase64Url), [0x41, 0x61, 0x30, 0x2D, 0x5F, 0x7A, 0x5A, 0x39]);
assert_same_value(true, $v->classify->isClear(), 'ctx rfc7515 clean clear');
$vectors++;

// rfc_rule = Rfc6376DkimRelaxed, [0x61,0x20,0x20,0x62] → SignedMessageRule, [2]
$v = HashInputStability::detectWithContext(new Context(rfcRule: RfcRule::Rfc6376DkimRelaxed), [0x61, 0x20, 0x20, 0x62]);
assert_same_value('SignedMessageRule', $v->classify->tag(), 'ctx rfc6376 double space');
assert_positions([2], $v->classify->positions(), 'ctx rfc6376 double space pos');
$vectors++;

// rfc_rule = Rfc6376DkimRelaxed, [0x61,0x20,0x62] → clear (single space)
$v = HashInputStability::detectWithContext(new Context(rfcRule: RfcRule::Rfc6376DkimRelaxed), [0x61, 0x20, 0x62]);
assert_same_value(true, $v->classify->isClear(), 'ctx rfc6376 single space clear');
$vectors++;

// rfc_rule = Rfc5751SmimeLineEnding, [0x61,0x0A,0x62] → SignedMessageRule, [1] (bare LF)
$v = HashInputStability::detectWithContext(new Context(rfcRule: RfcRule::Rfc5751SmimeLineEnding), [0x61, 0x0A, 0x62]);
assert_same_value('SignedMessageRule', $v->classify->tag(), 'ctx rfc5751 bare lf');
assert_positions([1], $v->classify->positions(), 'ctx rfc5751 bare lf pos');
$vectors++;

// as_written = Some([0x61,0x62,0x63]), input [0x61,0x62,0x64] → AuditLogReinterpretation, [2]
$v = HashInputStability::detectWithContext(new Context(asWritten: [0x61, 0x62, 0x63]), [0x61, 0x62, 0x64]);
assert_same_value('AuditLogReinterpretation', $v->classify->tag(), 'ctx audit divergence');
assert_positions([2], $v->classify->positions(), 'ctx audit divergence pos');
$vectors++;

// as_written = Some([0x61,0x62,0x63]), input [0x61,0x62,0x63] → clear
$v = HashInputStability::detectWithContext(new Context(asWritten: [0x61, 0x62, 0x63]), [0x61, 0x62, 0x63]);
assert_same_value(true, $v->classify->isClear(), 'ctx audit identical clear');
$vectors++;

// server_bytes = Some([0x61,0x62,0x64]), input [0x61,0x62,0x63] → WebhookSignatureDrift, [2]
$v = HashInputStability::detectWithContext(new Context(serverBytes: [0x61, 0x62, 0x64]), [0x61, 0x62, 0x63]);
assert_same_value('WebhookSignatureDrift', $v->classify->tag(), 'ctx webhook drift');
assert_positions([2], $v->classify->positions(), 'ctx webhook drift pos');
$vectors++;

// server_bytes = Some([0x61,0x62,0x63]), input [0x61,0x62,0x63] → clear
$v = HashInputStability::detectWithContext(new Context(serverBytes: [0x61, 0x62, 0x63]), [0x61, 0x62, 0x63]);
assert_same_value(true, $v->classify->isClear(), 'ctx webhook match clear');
$vectors++;

// declared_encoding = Some("utf-16") + rfc_rule = Pgp9580LineEnding,
//   [0x0065,0x0301,0x0A] → EncodingMismatch (priority over rfc)
$v = HashInputStability::detectWithContext(
    new Context(declaredEncoding: 'utf-16', rfcRule: RfcRule::Pgp9580LineEnding),
    [0x65, 0x301, 0x0A],
);
assert_same_value('EncodingMismatch', $v->classify->tag(), 'ctx priority encoding over rfc');
$vectors++;

// server_bytes = Some([0x61,0x62,0x65]) + as_written = Some([0x61,0x62,0x66]),
//   input [0x61,0x62,0x63] → WebhookSignatureDrift (priority over audit)
$v = HashInputStability::detectWithContext(
    new Context(asWritten: [0x61, 0x62, 0x66], serverBytes: [0x61, 0x62, 0x65]),
    [0x61, 0x62, 0x63],
);
assert_same_value('WebhookSignatureDrift', $v->classify->tag(), 'ctx priority webhook over audit');
$vectors++;

// rfc_rule = Pgp4880TrailingWhitespace, [0x61,0x20] → SignedMessageRule (priority over trailing)
$v = HashInputStability::detectWithContext(new Context(rfcRule: RfcRule::Pgp4880TrailingWhitespace), [0x61, 0x20]);
assert_same_value('SignedMessageRule', $v->classify->tag(), 'ctx priority rfc over trailing');
$vectors++;

// default Context matches bare detect.
$d = HashInputStability::detect([0x61, 0x62, 0x63]);
$c = HashInputStability::detectWithContext(new Context(), [0x61, 0x62, 0x63]);
assert_same_value($d->classify->tag(), $c->classify->tag(), 'ctx default matches detect tag');
assert_same_value($d->stableSize, $c->stableSize, 'ctx default matches detect size');

// RfcRule tag round-trip.
foreach ([
    RfcRule::Pgp4880TrailingWhitespace,
    RfcRule::Pgp9580LineEnding,
    RfcRule::Rfc8785NfcRequirement,
    RfcRule::Rfc8259ControlChar,
    RfcRule::Rfc7515JwsBase64Url,
    RfcRule::Rfc6376DkimRelaxed,
    RfcRule::Rfc5751SmimeLineEnding,
] as $rule) {
    assert_same_value($rule, RfcRule::fromTag($rule->tag()), 'rfc rule tag roundtrip ' . $rule->tag());
}
assert_same_value(null, RfcRule::fromTag('nope'), 'rfc rule from unknown tag');

if ($vectors !== 21) {
    throw new RuntimeException('expected 21 context vectors, transcribed ' . $vectors);
}

echo "hash_input_stability_test: OK (" . $vectors . " context vectors)\n";
