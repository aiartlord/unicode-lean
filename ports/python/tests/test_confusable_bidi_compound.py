"""Confusable-in-bidi-context compound detector contract tests.

Ground truth: the ``detect_*`` spot-check theorems in
``Unicode/Security/Boundary/ConfusableBidiCompound.lean`` (and their
mirror in the verified Rust port).  The compound fires only when a
confusable-source codepoint shares the input with a bidi format-control;
an override-class control outranks an isolate-class control.
"""

from unicode_python.security.boundary import confusable_bidi_compound
from unicode_python.security.policy import Mode, Profile, scan

_CODE = "unicode.security.X.confusable-bidi-compound"


def _detector_sub(input_cps: list[int]) -> str | None:
    return confusable_bidi_compound.detect(input_cps).sub


def _scan_sub(input_cps: list[int]) -> str | None:
    verdict = scan(Profile.GATEWAY_HEADER, Mode.OBSERVE, input_cps)
    for finding in verdict.findings:
        if finding.code.startswith(_CODE):
            return finding.sub_threat
    return None


def test_empty_is_clear() -> None:
    assert _detector_sub([]) is None
    assert _scan_sub([]) is None


def test_pure_ascii_is_clear() -> None:
    assert _detector_sub([0x48, 0x65, 0x6C, 0x6C, 0x6F]) is None
    assert _scan_sub([0x48, 0x65, 0x6C, 0x6C, 0x6F]) is None


def test_bidi_without_confusable_is_clear() -> None:
    # RLO + plain ASCII A B C — no confusable source.
    assert _detector_sub([0x202E, 0x0041, 0x0042, 0x0043]) is None
    assert _scan_sub([0x202E, 0x0041, 0x0042, 0x0043]) is None


def test_confusable_without_bidi_is_clear() -> None:
    # Cyrillic а alone — confusable but no bidi control.
    assert _detector_sub([0x0430]) is None
    assert _scan_sub([0x0430]) is None


def test_confusable_in_override() -> None:
    # RLO (override) + Cyrillic а (confusable).
    assert _detector_sub([0x202E, 0x0430]) == "ConfusableInOverride"
    assert _scan_sub([0x202E, 0x0430]) == "ConfusableInOverride"


def test_confusable_in_isolate() -> None:
    # LRI (isolate) + Greek ο (confusable).
    assert _detector_sub([0x2066, 0x03BF]) == "ConfusableInIsolate"
    assert _scan_sub([0x2066, 0x03BF]) == "ConfusableInIsolate"
