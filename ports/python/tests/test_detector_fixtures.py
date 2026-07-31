"""Cross-port detector-fixture contract tests.

Runs the shared per-family conformance fixtures under
``fixtures/security/detectors/`` through the policy scan, mirroring the
fixture-loop the other runtime ports use (for example Go's
``TestDetectorFixtures``). Every ``required_findings`` reason code must appear
in the verdict, and a case with no required findings must not raise the family
under test (other families may still fire on the same input)."""

import json
from pathlib import Path

from unicode_python.security.policy import Mode, Profile, scan

DETECTORS_DIR = (
    Path(__file__).resolve().parents[3] / "fixtures" / "security" / "detectors"
)

DETECTOR_FIXTURES = [
    "tag_block_payload.json",
    "variation_selector_payload.json",
    "zero_width_payload.json",
    "surrogate_reassembly.json",
    "bidi_control_balance.json",
    "noncharacter_control.json",
    "homoglyph_confusable.json",
    "mixed_script_admissibility.json",
    "rtl_injection.json",
    "covert_display_compound.json",
    "confusable_bidi_compound.json",
]


def test_detector_fixture_cases() -> None:
    for name in DETECTOR_FIXTURES:
        fixture = json.loads((DETECTORS_DIR / name).read_text(encoding="utf-8"))
        assert fixture["schema"] == 1, f"{name}: unexpected schema {fixture['schema']}"
        family = fixture["family"]
        for case in fixture["cases"]:
            verdict = scan(Profile.GATEWAY_HEADER, Mode.OBSERVE, case["input"])
            codes = {finding.code for finding in verdict.findings}
            for required in case["required_findings"]:
                assert required in codes, (
                    f"{name}/{case['name']}: missing {required} in {sorted(codes)}"
                )
            if not case["required_findings"]:
                assert not any(f".{family}." in code for code in codes), (
                    f"{name}/{case['name']}: unexpected {family} finding in {sorted(codes)}"
                )
