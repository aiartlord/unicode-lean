"""AdmissibilityFormDrift detector contract tests.

Ground truth: the ``detect_*`` spot-check theorems in
``Unicode.Security.Boundary.AdmissibilityFormDrift`` (and their mirror in the
verified Rust port).  The detector fires when the UTS #39 whole-string
``is_allowed_identifier`` verdict differs between the input and its NFKC form —
the string-level complement of IdentifierFormDrift.

The four shared context-free vectors are driven from the same per-family
conformance fixture the other runtime ports consume; the additional spot-checks
come from the reference test module.
"""

import json
from pathlib import Path

from unicode_python.security.boundary import admissibility_form_drift
from unicode_python.security.calculus import Family
from unicode_python.security.policy import reason_code

_REASON = reason_code(Family.ADMISSIBILITY_FORM_DRIFT, "AdmissibilityFormDrift")

DETECTORS_DIR = (
    Path(__file__).resolve().parents[3] / "fixtures" / "security" / "detectors"
)


def _reasons(input_cps: list[int]) -> list[str]:
    """Reason codes produced by a detect verdict (empty list when clear)."""
    verdict = admissibility_form_drift.detect(input_cps)
    tag = verdict.classify.tag()
    if tag is None:
        return []
    return [reason_code(Family.ADMISSIBILITY_FORM_DRIFT, tag)]


def test_reason_code_is_stable() -> None:
    assert _REASON == (
        "unicode.security.X.admissibility-form-drift.AdmissibilityFormDrift"
    )


def test_shared_fixture_cases() -> None:
    fixture = json.loads(
        (DETECTORS_DIR / "admissibility_form_drift.json").read_text(encoding="utf-8")
    )
    assert fixture["schema"] == 1
    assert fixture["family"] == "admissibility-form-drift"
    for case in fixture["cases"]:
        reasons = _reasons(case["input"])
        for required in case["required_findings"]:
            assert required in reasons, (
                f"{case['name']}: missing {required} in {reasons}"
            )
        if not case["required_findings"]:
            assert reasons == [], f"{case['name']}: unexpected finding {reasons}"


def test_empty_is_clear() -> None:
    # Both admissibility calls return false, so they agree.
    verdict = admissibility_form_drift.detect([])
    assert verdict.classify.is_clear()
    assert verdict.input_admissible is False
    assert verdict.nfkc_admissible is False


def test_ascii_admin_clear() -> None:
    # "admin"; admissible on both sides (NFKC is identity).
    verdict = admissibility_form_drift.detect([0x61, 0x64, 0x6D, 0x69, 0x6E])
    assert verdict.classify.is_clear()
    assert verdict.input_admissible is True
    assert verdict.nfkc_admissible is True


def test_fi_ligature_drift() -> None:
    # U+FB01 is Restricted (inadmissible), but NFKC decomposes it to "fi"
    # (admissible).  Drift fires.
    verdict = admissibility_form_drift.detect([0xFB01])
    assert verdict.classify.tag() == "AdmissibilityFormDrift"
    assert verdict.input_admissible is False
    assert verdict.nfkc_admissible is True
    assert _reasons([0xFB01]) == [_REASON]


def test_jamo_sequence_drift() -> None:
    # Decomposed Hangul jamos [U+1112, U+1161, U+11AB] are inadmissible, but
    # NFKC composes them to U+D55C 한 (admissible).
    verdict = admissibility_form_drift.detect([0x1112, 0x1161, 0x11AB])
    assert verdict.classify.tag() == "AdmissibilityFormDrift"
    assert verdict.input_admissible is False
    assert verdict.nfkc_admissible is True


def test_hazard_reports_no_positions() -> None:
    # The predicate is whole-string; a hazard carries no implicated positions.
    verdict = admissibility_form_drift.detect([0xFB01])
    assert verdict.classify.positions == []
    assert verdict.classify.decoded == []
