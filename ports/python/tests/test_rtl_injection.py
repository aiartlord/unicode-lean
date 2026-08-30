"""RTL-injection detector contract tests.

The strong-RTL / strong-LTR predicates now read ``Bidi_Class`` from
``DerivedBidiClass.txt`` via the 3-tier lookup in
:mod:`unicode_python.security.identity.ucd`, mirroring
``Unicode.Generated.DerivedBidiClass.lookup``.  These vectors pin the
seven sub-threat outcomes the detector must yield through ``scan``.
"""

from unicode_python.security.policy import Mode, Profile, scan

_RTL_CODE = "unicode.security.D.rtl-injection"


def _rtl_subthreats(input_cps: list[int]) -> set[str]:
    verdict = scan(Profile.GATEWAY_HEADER, Mode.OBSERVE, input_cps)
    return {
        finding.sub_threat
        for finding in verdict.findings
        if finding.code.startswith(_RTL_CODE) and finding.sub_threat is not None
    }


def test_ascii_digits_are_clear() -> None:
    assert _rtl_subthreats([0x30, 0x31, 0x32, 0x33]) == set()


def test_lone_cyrillic_is_clear() -> None:
    assert _rtl_subthreats([0x043F]) == set()


def test_rlo_override_fires_rlo_in_ltr_field() -> None:
    assert _rtl_subthreats([0x41, 0x202E, 0x42]) == {"BidiControlInLTRField"}


def test_leading_hebrew_fires_field_takeover() -> None:
    assert _rtl_subthreats([0x05D0, 0x42, 0x43]) == {"FieldTakeover"}


def test_leading_arabic_fires_field_takeover() -> None:
    assert _rtl_subthreats([0x0627, 0x42, 0x43]) == {"FieldTakeover"}


def test_midstream_hebrew_fires_strong_rtl_in_ltr() -> None:
    assert _rtl_subthreats([0x41, 0x42, 0x05D0, 0x44]) == {"StrongRTLInLTR"}


def test_midstream_hebrew_run_fires_mixed_overflow() -> None:
    assert _rtl_subthreats(
        [0x41, 0x42, 0x05D0, 0x05D1, 0x05D2, 0x05D3, 0x44]
    ) == {"MixedOverflow"}
