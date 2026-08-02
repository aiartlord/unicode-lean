"""hash-input-stability detector tests.

Ground truth: the ``stable_*``, ``detect_*``, and priority theorems in
``Unicode.Security.Crypto.HashInputStability``, transliterated from the verified
Rust reference ``ports/rust/src/security/crypto/hash_input_stability.rs``.

Two suites:

* the shared context-free fixture
  (``fixtures/security/detectors/hash_input_stability.json``) run through
  :func:`detect`, mapping each classification tag to its stable reason code the
  same way the policy layer does; and
* a dedicated transcription of every Context-probe vector from the verbatim
  comment block in the Rust reference's ``#[test]`` module (the shared
  detector-fixture schema cannot express a ``Context``, so those vectors live
  only there).
"""

import json
from pathlib import Path

from unicode_python.security.calculus import Family
from unicode_python.security.crypto.hash_input_stability import (
    Context,
    RfcRule,
    detect,
    detect_with_context,
    hash_stable,
)
from unicode_python.security.policy import reason_code

DETECTORS_DIR = (
    Path(__file__).resolve().parents[3] / "fixtures" / "security" / "detectors"
)


def _tag(cps: list[int]) -> str | None:
    return detect(cps).classify.tag


def _ctx_tag(ctx: Context, cps: list[int]) -> str | None:
    return detect_with_context(ctx, cps).classify.tag


def _ctx_positions(ctx: Context, cps: list[int]) -> list[int]:
    return detect_with_context(ctx, cps).classify.positions


# ── §4 hash_stable spot checks ─────────────────────────────────────────


def test_hash_stable_spot_checks() -> None:
    assert hash_stable([]) == []
    assert hash_stable([0x61, 0x62, 0x63]) == [0x61, 0x62, 0x63]
    # Idempotence.
    assert hash_stable(hash_stable([0x61, 0x62, 0x63])) == hash_stable(
        [0x61, 0x62, 0x63]
    )
    assert hash_stable([0x61, 0x20]) == [0x61]
    assert hash_stable([0x61, 0x09]) == [0x61]
    assert hash_stable([0x61, 0x0A]) == [0x61]
    assert hash_stable([0x61, 0x0D, 0x0A]) == [0x61]
    assert hash_stable([0x61, 0x20, 0x62]) == [0x61, 0x20, 0x62]
    assert hash_stable([0x0065, 0x0301]) == [0x00E9]
    # NBSP is content, not framing: it is preserved.
    assert hash_stable([0x61, 0x00A0]) == [0x61, 0x00A0]


# ── §8 detect spot checks (bare input) ─────────────────────────────────


def test_detect_bare_spot_checks() -> None:
    assert _tag([]) is None
    assert _tag([0x61, 0x62, 0x63]) is None

    trailing = detect([0x61, 0x20])
    assert trailing.classify.tag == "TrailingWhitespace"
    assert trailing.stable_size == 1
    assert trailing.classify.positions == [1]

    crlf = detect([0x61, 0x0D, 0x0A])
    assert crlf.classify.tag == "TrailingWhitespace"
    assert crlf.stable_size == 1

    drift = detect([0x0065, 0x0301])
    assert drift.classify.tag == "NormalizationDrift"
    assert drift.classify.positions == [0]

    assert _tag([0x00E9]) is None
    # Decomposed "é " — TrailingWhitespace wins over NormalizationDrift.
    assert _tag([0x0065, 0x0301, 0x20]) == "TrailingWhitespace"
    assert _tag([0x61, 0x20, 0x62]) is None


# ── Shared context-free fixture, run through detect ─────────────────────


def test_shared_fixture_cases() -> None:
    fixture = json.loads(
        (DETECTORS_DIR / "hash_input_stability.json").read_text(encoding="utf-8")
    )
    assert fixture["schema"] == 1
    assert fixture["family"] == "hash-input-stability"
    for case in fixture["cases"]:
        classify = detect(case["input"]).classify
        required = case["required_findings"]
        if not required:
            assert classify.tag is None, (
                f"{case['name']}: expected clear, got {classify.tag}"
            )
            continue
        code = reason_code(Family.HASH_INPUT_STABILITY, classify.tag)
        assert code in required, (
            f"{case['name']}: {code} not in required {required}"
        )


# ── §9 empty context is the identity case ──────────────────────────────


def test_default_context_matches_detect() -> None:
    plain = detect([0x61, 0x62, 0x63])
    ctx = detect_with_context(Context(), [0x61, 0x62, 0x63])
    assert ctx.classify == plain.classify
    assert ctx.stable_size == plain.stable_size


# ── Context-probe vectors transcribed from the Rust reference comment ───
#
# Each assertion corresponds one-to-one to a `→` line in the verbatim comment
# block of hash_input_stability.rs's `#[test]` module. Format there:
#   declared_encoding / rfc_rule / as_written / server_bytes, input
#     → expected tag & positions.


def test_context_vector_encoding_utf16_label() -> None:
    # declared_encoding = Some("utf-16"), [0x61,0x62,0x63] → EncodingMismatch, [0]
    ctx = Context(declared_encoding="utf-16")
    assert _ctx_tag(ctx, [0x61, 0x62, 0x63]) == "EncodingMismatch"
    assert _ctx_positions(ctx, [0x61, 0x62, 0x63]) == [0]


def test_context_vector_encoding_invalid_surrogate() -> None:
    # declared_encoding = Some("utf-8"), [0x61,0xD800,0x62] → EncodingMismatch, [1]
    ctx = Context(declared_encoding="utf-8")
    assert _ctx_tag(ctx, [0x61, 0xD800, 0x62]) == "EncodingMismatch"
    assert _ctx_positions(ctx, [0x61, 0xD800, 0x62]) == [1]


def test_context_vector_encoding_out_of_range() -> None:
    # declared_encoding = Some("utf-8"), [0x61,0x110000,0x62] → EncodingMismatch, [1]
    ctx = Context(declared_encoding="utf-8")
    assert _ctx_tag(ctx, [0x61, 0x110000, 0x62]) == "EncodingMismatch"
    assert _ctx_positions(ctx, [0x61, 0x110000, 0x62]) == [1]


def test_context_vector_encoding_utf8_labels_clear() -> None:
    # declared_encoding = Some("UTF-8"|"utf-8"|"UTF8"), [0x61,0x62,0x63] → clear
    for label in ("UTF-8", "utf-8", "UTF8"):
        ctx = Context(declared_encoding=label)
        assert _ctx_tag(ctx, [0x61, 0x62, 0x63]) is None, f"label {label}"


def test_context_vector_pgp4880_trailing() -> None:
    # rfc_rule = Pgp4880TrailingWhitespace, [0x61,0x20] → SignedMessageRule, [1]
    ctx = Context(rfc_rule=RfcRule.PGP_4880_TRAILING_WHITESPACE)
    assert _ctx_tag(ctx, [0x61, 0x20]) == "SignedMessageRule"
    assert _ctx_positions(ctx, [0x61, 0x20]) == [1]


def test_context_vector_pgp9580_bare_lf() -> None:
    # rfc_rule = Pgp9580LineEnding, [0x61,0x0A,0x62] → SignedMessageRule, [1]
    ctx = Context(rfc_rule=RfcRule.PGP_9580_LINE_ENDING)
    assert _ctx_tag(ctx, [0x61, 0x0A, 0x62]) == "SignedMessageRule"
    assert _ctx_positions(ctx, [0x61, 0x0A, 0x62]) == [1]


def test_context_vector_pgp9580_crlf_clear() -> None:
    # rfc_rule = Pgp9580LineEnding, [0x61,0x62,0x63,0x0D,0x0A,0x64,0x65,0x66] → clear
    ctx = Context(rfc_rule=RfcRule.PGP_9580_LINE_ENDING)
    assert _ctx_tag(ctx, [0x61, 0x62, 0x63, 0x0D, 0x0A, 0x64, 0x65, 0x66]) is None


def test_context_vector_rfc8785_decomposed() -> None:
    # rfc_rule = Rfc8785NfcRequirement, [0x0065,0x0301] → SignedMessageRule, [0]
    ctx = Context(rfc_rule=RfcRule.RFC_8785_NFC_REQUIREMENT)
    assert _ctx_tag(ctx, [0x0065, 0x0301]) == "SignedMessageRule"
    assert _ctx_positions(ctx, [0x0065, 0x0301]) == [0]


def test_context_vector_rfc8259_control() -> None:
    # rfc_rule = Rfc8259ControlChar, [0x61,0x01,0x62] → SignedMessageRule, [1]
    ctx = Context(rfc_rule=RfcRule.RFC_8259_CONTROL_CHAR)
    assert _ctx_tag(ctx, [0x61, 0x01, 0x62]) == "SignedMessageRule"
    assert _ctx_positions(ctx, [0x61, 0x01, 0x62]) == [1]


def test_context_vector_rfc7515_plus_char() -> None:
    # rfc_rule = Rfc7515JwsBase64Url, [0x41,0x2B,0x42] → SignedMessageRule, [1]  ('+')
    ctx = Context(rfc_rule=RfcRule.RFC_7515_JWS_BASE64_URL)
    assert _ctx_tag(ctx, [0x41, 0x2B, 0x42]) == "SignedMessageRule"
    assert _ctx_positions(ctx, [0x41, 0x2B, 0x42]) == [1]


def test_context_vector_rfc7515_clean_clear() -> None:
    # rfc_rule = Rfc7515JwsBase64Url, [0x41,0x61,0x30,0x2D,0x5F,0x7A,0x5A,0x39] → clear
    ctx = Context(rfc_rule=RfcRule.RFC_7515_JWS_BASE64_URL)
    assert _ctx_tag(ctx, [0x41, 0x61, 0x30, 0x2D, 0x5F, 0x7A, 0x5A, 0x39]) is None


def test_context_vector_rfc6376_double_space() -> None:
    # rfc_rule = Rfc6376DkimRelaxed, [0x61,0x20,0x20,0x62] → SignedMessageRule, [2]
    ctx = Context(rfc_rule=RfcRule.RFC_6376_DKIM_RELAXED)
    assert _ctx_tag(ctx, [0x61, 0x20, 0x20, 0x62]) == "SignedMessageRule"
    assert _ctx_positions(ctx, [0x61, 0x20, 0x20, 0x62]) == [2]


def test_context_vector_rfc6376_single_space_clear() -> None:
    # rfc_rule = Rfc6376DkimRelaxed, [0x61,0x20,0x62] → clear (single space)
    ctx = Context(rfc_rule=RfcRule.RFC_6376_DKIM_RELAXED)
    assert _ctx_tag(ctx, [0x61, 0x20, 0x62]) is None


def test_context_vector_rfc5751_bare_lf() -> None:
    # rfc_rule = Rfc5751SmimeLineEnding, [0x61,0x0A,0x62] → SignedMessageRule, [1]
    ctx = Context(rfc_rule=RfcRule.RFC_5751_SMIME_LINE_ENDING)
    assert _ctx_tag(ctx, [0x61, 0x0A, 0x62]) == "SignedMessageRule"
    assert _ctx_positions(ctx, [0x61, 0x0A, 0x62]) == [1]


def test_context_vector_audit_log_divergence() -> None:
    # as_written = Some([0x61,0x62,0x63]), input [0x61,0x62,0x64]
    #   → AuditLogReinterpretation, [2]
    ctx = Context(as_written=[0x61, 0x62, 0x63])
    assert _ctx_tag(ctx, [0x61, 0x62, 0x64]) == "AuditLogReinterpretation"
    assert _ctx_positions(ctx, [0x61, 0x62, 0x64]) == [2]


def test_context_vector_audit_log_identical_clear() -> None:
    # as_written = Some([0x61,0x62,0x63]), input [0x61,0x62,0x63] → clear
    ctx = Context(as_written=[0x61, 0x62, 0x63])
    assert _ctx_tag(ctx, [0x61, 0x62, 0x63]) is None


def test_context_vector_webhook_signature_drift() -> None:
    # server_bytes = Some([0x61,0x62,0x64]), input [0x61,0x62,0x63]
    #   → WebhookSignatureDrift, [2]
    ctx = Context(server_bytes=[0x61, 0x62, 0x64])
    assert _ctx_tag(ctx, [0x61, 0x62, 0x63]) == "WebhookSignatureDrift"
    assert _ctx_positions(ctx, [0x61, 0x62, 0x63]) == [2]


def test_context_vector_webhook_signature_match_clear() -> None:
    # server_bytes = Some([0x61,0x62,0x63]), input [0x61,0x62,0x63] → clear
    ctx = Context(server_bytes=[0x61, 0x62, 0x63])
    assert _ctx_tag(ctx, [0x61, 0x62, 0x63]) is None


def test_context_vector_priority_encoding_over_rfc() -> None:
    # declared_encoding = Some("utf-16") + rfc_rule = Pgp9580LineEnding,
    #   [0x0065,0x0301,0x0A] → EncodingMismatch (priority over rfc)
    ctx = Context(
        declared_encoding="utf-16", rfc_rule=RfcRule.PGP_9580_LINE_ENDING
    )
    assert _ctx_tag(ctx, [0x0065, 0x0301, 0x0A]) == "EncodingMismatch"
    assert _ctx_positions(ctx, [0x0065, 0x0301, 0x0A]) == [0]


def test_context_vector_priority_webhook_over_audit() -> None:
    # server_bytes = Some([0x61,0x62,0x65]) + as_written = Some([0x61,0x62,0x66]),
    #   input [0x61,0x62,0x63] → WebhookSignatureDrift (priority over audit)
    ctx = Context(server_bytes=[0x61, 0x62, 0x65], as_written=[0x61, 0x62, 0x66])
    assert _ctx_tag(ctx, [0x61, 0x62, 0x63]) == "WebhookSignatureDrift"
    assert _ctx_positions(ctx, [0x61, 0x62, 0x63]) == [2]


def test_context_vector_priority_rfc_over_trailing() -> None:
    # rfc_rule = Pgp4880TrailingWhitespace, [0x61,0x20]
    #   → SignedMessageRule (priority over trailing)
    ctx = Context(rfc_rule=RfcRule.PGP_4880_TRAILING_WHITESPACE)
    assert _ctx_tag(ctx, [0x61, 0x20]) == "SignedMessageRule"
    assert _ctx_positions(ctx, [0x61, 0x20]) == [1]


# ── RfcRule tag round-trip ─────────────────────────────────────────────


def test_rfc_rule_tag_roundtrip() -> None:
    for rule in RfcRule:
        assert RfcRule.from_tag(rule.tag()) is rule
    assert RfcRule.from_tag("nope") is None
