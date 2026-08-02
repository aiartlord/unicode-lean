"""IdentifierFormDrift detector contract tests.

Ground truth: the ``detect_*`` spot-check theorems in
``Unicode.Security.Boundary.IdentifierFormDrift`` (and their mirror in the
verified Rust port).  The detector fires on the first input position whose
UTS #39 ``Identifier_Status`` disagrees with the status of that codepoint's
NFKD head — the validate-then-normalise two-stage bypass.

The eight shared context-free vectors are driven from the same per-family
conformance fixture the other runtime ports consume; the additional
spot-checks and the mid-string first-shift-position case come from the
reference test module.
"""

import json
from pathlib import Path

from unicode_python.security.boundary import identifier_form_drift
from unicode_python.security.calculus import Family
from unicode_python.security.policy import reason_code

_REASON = reason_code(Family.IDENTIFIER_FORM_DRIFT, "IdentifierStatusShift")

DETECTORS_DIR = (
    Path(__file__).resolve().parents[3] / "fixtures" / "security" / "detectors"
)


def _reasons(input_cps: list[int]) -> list[str]:
    """Reason codes produced by a detect verdict (empty list when clear)."""
    verdict = identifier_form_drift.detect(input_cps)
    tag = verdict.classify.tag()
    if tag is None:
        return []
    return [reason_code(Family.IDENTIFIER_FORM_DRIFT, tag)]


def test_reason_code_is_stable() -> None:
    assert _REASON == "unicode.security.X.identifier-form-drift.IdentifierStatusShift"


def test_shared_fixture_cases() -> None:
    fixture = json.loads(
        (DETECTORS_DIR / "identifier_form_drift.json").read_text(encoding="utf-8")
    )
    assert fixture["schema"] == 1
    assert fixture["family"] == "identifier-form-drift"
    for case in fixture["cases"]:
        reasons = _reasons(case["input"])
        for required in case["required_findings"]:
            assert required in reasons, (
                f"{case['name']}: missing {required} in {reasons}"
            )
        if not case["required_findings"]:
            assert reasons == [], f"{case['name']}: unexpected finding {reasons}"


def test_empty_is_clear() -> None:
    assert identifier_form_drift.detect([]).classify.is_clear()


def test_ascii_hello_is_clear() -> None:
    # "Hello" — every ASCII letter is Allowed with identity NFKD.
    verdict = identifier_form_drift.detect([0x48, 0x65, 0x6C, 0x6C, 0x6F])
    assert verdict.classify.is_clear()
    assert verdict.shift_count == 0


def test_greek_alpha_is_clear() -> None:
    # alpha is Allowed with identity NFKD.
    assert identifier_form_drift.detect([0x03B1]).classify.is_clear()


def test_math_italic_a_shift() -> None:
    # U+1D44E Restricted, NFKD head U+0061 Allowed.
    verdict = identifier_form_drift.detect([0x1D44E])
    assert verdict.classify.tag() == "IdentifierStatusShift"
    assert verdict.classify.positions == [0]
    assert verdict.shift_count == 1


def test_fullwidth_a_shift() -> None:
    # U+FF21 Restricted, NFKD head U+0041 Allowed.
    assert identifier_form_drift.detect([0xFF21]).classify.tag() == "IdentifierStatusShift"


def test_circled_a_shift() -> None:
    # U+24B6 CIRCLED LATIN CAPITAL LETTER A -> Restricted -> Allowed (A).
    assert identifier_form_drift.detect([0x24B6]).classify.tag() == "IdentifierStatusShift"


def test_fi_ligature_shift() -> None:
    # U+FB01 'fi' ligature -> Restricted -> Allowed (f).
    assert identifier_form_drift.detect([0xFB01]).classify.tag() == "IdentifierStatusShift"


def test_roman_iv_shift() -> None:
    # U+2163 ROMAN NUMERAL FOUR -> Restricted -> Allowed (I).
    assert identifier_form_drift.detect([0x2163]).classify.tag() == "IdentifierStatusShift"


def test_reports_first_shift_position() -> None:
    # "ab" + U+1D44E: positions 0,1 are Allowed/identity, position 2 shifts.
    verdict = identifier_form_drift.detect([0x61, 0x62, 0x1D44E])
    assert verdict.classify.positions == [2]
    assert verdict.shift_count == 1
