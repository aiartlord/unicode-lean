"""CaseExpansionMismatch detector contract tests.

Mirrors the ``detect_*`` ground-truth theorems in
``Unicode/Security/Form/CaseExpansionMismatch.lean`` (via the verified Rust
reference ``security/form/case_expansion_mismatch.rs``), and drives the shared
cross-port fixture ``fixtures/security/detectors/case_expansion_mismatch.json``
through ``detect``, asserting the reported positions, the expansion summaries,
and the stable reason code.
"""

import json
from pathlib import Path

from unicode_python.security.calculus import Family
from unicode_python.security.form.case_expansion_mismatch import detect
from unicode_python.security.policy import reason_code

FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "fixtures"
    / "security"
    / "detectors"
    / "case_expansion_mismatch.json"
)


def _tag(input_cps: list[int]) -> str | None:
    return detect(input_cps).classify.tag()


def test_detect_empty_clear() -> None:
    verdict = detect([])
    assert verdict.classify.is_clear()
    assert verdict.classify.tag() is None
    assert verdict.max_expansion_len == 0
    assert verdict.upper_expansion_count == 0
    assert verdict.lower_expansion_count == 0


def test_detect_ascii_clear() -> None:
    # "Hello" — every ASCII codepoint case-maps to a single codepoint.
    verdict = detect([0x48, 0x65, 0x6C, 0x6C, 0x6F])
    assert verdict.classify.is_clear()
    assert verdict.max_expansion_len == 1


def test_detect_sharp_s_upper() -> None:
    # ß (U+00DF) toUpper → "SS".
    verdict = detect([0x00DF])
    assert verdict.classify.tag() == "UpperExpansion"
    assert verdict.classify.positions == (0,)
    assert verdict.upper_expansion_count == 1
    assert verdict.max_expansion_len == 2


def test_detect_fi_ligature_upper() -> None:
    # ﬁ (U+FB01) toUpper → "FI".
    assert _tag([0xFB01]) == "UpperExpansion"


def test_detect_dotted_I_lower() -> None:
    # İ (U+0130) toLower under default → "i + 0307"; no upper expansion, so the
    # detector falls through to the lower scan.
    verdict = detect([0x0130])
    assert verdict.classify.tag() == "LowerExpansion"
    assert verdict.lower_expansion_count == 1


def test_detect_ffi_ligature_len3() -> None:
    # ﬃ (U+FB03) toUpper → "FFI" (length 3) — the expansion length is reported.
    verdict = detect([0xFB03])
    assert verdict.classify.tag() == "UpperExpansion"
    assert verdict.max_expansion_len == 3


def test_detect_reports_first_expansion_position() -> None:
    # A leading ASCII then ß: the upper expansion is reported at position 1.
    verdict = detect([0x61, 0x00DF])
    assert verdict.classify.positions == (1,)


def test_reason_code_is_stable() -> None:
    assert (
        reason_code(Family.CASE_EXPANSION_MISMATCH, "UpperExpansion")
        == "unicode.security.F.case-expansion-mismatch.UpperExpansion"
    )
    assert (
        reason_code(Family.CASE_EXPANSION_MISMATCH, "LowerExpansion")
        == "unicode.security.F.case-expansion-mismatch.LowerExpansion"
    )


def test_shared_fixture_findings_and_reason_codes() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert fixture["schema"] == 1
    assert fixture["family"] == "case-expansion-mismatch"
    for case in fixture["cases"]:
        verdict = detect(case["input"])
        tag = verdict.classify.tag()
        codes = (
            set()
            if tag is None
            else {reason_code(Family.CASE_EXPANSION_MISMATCH, tag)}
        )
        for required in case["required_findings"]:
            assert required in codes, (
                f"{case['name']}: missing {required} in {sorted(codes)}"
            )
        if not case["required_findings"]:
            assert verdict.classify.is_clear(), (
                f"{case['name']}: expected clear, got {tag}"
            )
