"""Policy contract tests."""

import json
from pathlib import Path

from unicode_python.security import Family
from unicode_python.security.policy import (
    Action,
    Mode,
    Profile,
    reason_code,
    scan,
    scan_utf16be,
    scan_utf16le,
    scan_utf32be,
    scan_utf32le,
    scan_utf8,
    verdict_to_json,
    verdict_to_wire,
)


FIXTURE_PATH = (
    Path(__file__).resolve().parents[3]
    / "fixtures"
    / "security"
    / "policy_contract.json"
)
VERDICT_FIXTURE_PATH = (
    Path(__file__).resolve().parents[3]
    / "fixtures"
    / "security"
    / "verdict_contract.json"
)
DECODE_FIXTURE_PATH = (
    Path(__file__).resolve().parents[3]
    / "fixtures"
    / "security"
    / "decode_contract.json"
)
MULTIENCODING_DECODE_FIXTURE_PATH = (
    Path(__file__).resolve().parents[3]
    / "fixtures"
    / "security"
    / "decode_multiencoding_contract.json"
)


def _profile(tag: str) -> Profile:
    return {profile.value: profile for profile in Profile}[tag]


def _mode(tag: str) -> Mode:
    return {mode.value: mode for mode in Mode}[tag]


def test_policy_reason_codes_are_stable() -> None:
    assert (
        reason_code(Family.TAG_BLOCK_PAYLOAD, "DirectAscii")
        == "unicode.security.C.tag-block-payload.DirectAscii"
    )
    assert (
        reason_code(Family.BIDI_CONTROL_BALANCE)
        == "unicode.security.C.bidi-control-balance.hazard"
    )
    assert (
        reason_code(Family.HOMOGLYPH_CONFUSABLE, "TargetMatch")
        == "unicode.security.I.homoglyph-confusable.TargetMatch"
    )
    assert (
        reason_code(Family.MIXED_SCRIPT_ADMISSIBILITY, "CrossScriptMix")
        == "unicode.security.I.mixed-script-admissibility.CrossScriptMix"
    )
    assert (
        reason_code(Family.NONCHARACTER_CONTROL, "Noncharacter")
        == "unicode.security.C.noncharacter-control.Noncharacter"
    )
    assert (
        reason_code(Family.MALFORMED_UTF8, "InvalidStartByte")
        == "unicode.security.C.malformed-utf8.InvalidStartByte"
    )


def test_policy_contract_fixture_cases() -> None:
    payload = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert payload["contract"] == "unicode-security-policy-v0"

    for case in payload["cases"]:
        verdict = scan(_profile(case["profile"]), _mode(case["mode"]), case["input"])
        assert verdict.action is Action(case["action"])
        actual_codes = {finding.code for finding in verdict.findings}
        assert set(case["required_findings"]).issubset(actual_codes)


def test_verdict_contract_fixture_cases() -> None:
    payload = json.loads(VERDICT_FIXTURE_PATH.read_text(encoding="utf-8"))
    assert payload["contract"] == "unicode-security-verdict-v0"

    for case in payload["cases"]:
        verdict = scan(_profile(case["profile"]), _mode(case["mode"]), case["input"])
        assert verdict_to_wire(verdict) == case["verdict"]
        assert verdict_to_json(verdict) == json.dumps(
            case["verdict"], separators=(",", ":")
        )


def test_decode_contract_fixture_cases() -> None:
    payload = json.loads(DECODE_FIXTURE_PATH.read_text(encoding="utf-8"))
    assert payload["contract"] == "unicode-security-decode-v0"

    for case in payload["cases"]:
        verdict = scan_utf8(
            _profile(case["profile"]),
            _mode(case["mode"]),
            bytes(case["input_bytes"]),
        )
        assert verdict.action is Action(case["action"])
        assert verdict.input == case["input"]
        actual_codes = {finding.code for finding in verdict.findings}
        assert set(case["required_findings"]).issubset(actual_codes)
        by_code = {finding.code: finding.positions for finding in verdict.findings}
        for expected in case["required_positions"]:
            assert by_code[expected["code"]] == expected["positions"]


def _scan_encoded_case(case):
    scanners = {
        "utf-8": scan_utf8,
        "utf-16be": scan_utf16be,
        "utf-16le": scan_utf16le,
        "utf-32be": scan_utf32be,
        "utf-32le": scan_utf32le,
    }
    return scanners[case["encoding"]](
        _profile(case["profile"]),
        _mode(case["mode"]),
        bytes(case["input_bytes"]),
    )


def test_multiencoding_decode_contract_fixture_cases() -> None:
    payload = json.loads(
        MULTIENCODING_DECODE_FIXTURE_PATH.read_text(encoding="utf-8")
    )
    assert payload["contract"] == "unicode-security-multiencoding-decode-v0"

    for case in payload["cases"]:
        verdict = _scan_encoded_case(case)
        assert verdict.action is Action(case["action"])
        assert verdict.input == case["input"]
        actual_codes = {finding.code for finding in verdict.findings}
        assert set(case["required_findings"]).issubset(actual_codes)
        by_code = {finding.code: finding.positions for finding in verdict.findings}
        for expected in case["required_positions"]:
            assert by_code[expected["code"]] == expected["positions"]
