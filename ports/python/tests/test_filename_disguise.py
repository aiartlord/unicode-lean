"""FilenameDisguise (display-layer detector) — port tests.

Drives the 10 shared context-free fixture vectors through :func:`detect`,
composing the stable reason code the way the sibling detectors do (via
:func:`policy.reason_code`), plus the 10 Rust reference spot-checks and 1
structural priority-ladder check transcribed from the verified Rust
reference implementation.
"""

import json
from pathlib import Path

from unicode_python.security.calculus import Family
from unicode_python.security.display.filename_disguise import (
    MIN_MULTIPLE_EXTENSIONS,
    detect,
    is_ascii_dot,
    is_bidi_format_control,
    is_fullwidth_halfwidth,
    is_grapheme_extend,
)
from unicode_python.security.policy import reason_code

_FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "fixtures"
    / "security"
    / "detectors"
    / "filename_disguise.json"
)


def _tag(input_cps: list[int]) -> str | None:
    return detect(input_cps).classify.tag


# ── shared fixture contract ──────────────────────────────────────────


def test_shared_fixture_vectors() -> None:
    fixture = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    assert fixture["schema"] == 1
    assert fixture["family"] == "filename-disguise"
    for case in fixture["cases"]:
        verdict = detect(case["input"])
        required = case["required_findings"]
        if not required:
            assert verdict.classify.is_clear, case["name"]
            assert verdict.classify.tag is None, case["name"]
        else:
            assert len(required) == 1, case["name"]
            code = reason_code(
                Family.FILENAME_DISGUISE, verdict.classify.tag
            )
            assert code == required[0], case["name"]


def test_reason_code_layer_and_slug() -> None:
    # Layer D, slug filename-disguise — composed like the siblings.
    assert (
        reason_code(Family.FILENAME_DISGUISE, "RloFlip")
        == "unicode.security.D.filename-disguise.RloFlip"
    )


# ── Rust reference spot-checks ───────────────────────────────────────


def test_detect_empty_clear() -> None:
    assert detect([]).classify.is_clear


def test_detect_plain_txt_clear() -> None:
    # "document.txt"
    v = detect(
        [0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x2E, 0x74, 0x78, 0x74]
    )
    assert v.classify.is_clear
    assert v.last_dot_pos == 8


def test_detect_no_extension_clear() -> None:
    # "foo"
    v = detect([0x66, 0x6F, 0x6F])
    assert v.classify.is_clear
    assert v.last_dot_pos is None


def test_detect_tar_gz_clear() -> None:
    # "archive.tar.gz" (2 dots, below the multi-ext bound)
    assert detect(
        [0x61, 0x72, 0x63, 0x68, 0x69, 0x76, 0x65, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A]
    ).classify.is_clear


def test_detect_hebrew_clear() -> None:
    # Native Hebrew name, no bidi controls.
    assert detect([0x05D0, 0x05D1, 0x05D2, 0x2E, 0x74, 0x78, 0x74]).classify.is_clear


def test_detect_rlo_flip() -> None:
    # "document<RLO>txt.exe"
    v = detect(
        [
            0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x202E, 0x74,
            0x78, 0x74, 0x2E, 0x65, 0x78, 0x65,
        ]
    )
    assert v.classify.tag == "RloFlip"
    assert v.classify.positions == [8]


def test_detect_isolate_flip() -> None:
    # RLI/PDI isolate variant, also RloFlip.
    assert (
        _tag([0x64, 0x6F, 0x63, 0x2067, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65, 0x2069])
        == "RloFlip"
    )


def test_detect_fullwidth_exe() -> None:
    # "file.ＥＸＥ"
    assert _tag([0x66, 0x69, 0x6C, 0x65, 0x2E, 0xFF25, 0xFF38, 0xFF25]) == "WidthClassExt"


def test_detect_combining_in_ext() -> None:
    # "file.e<combining acute>xe"
    assert (
        _tag([0x66, 0x69, 0x6C, 0x65, 0x2E, 0x65, 0x0301, 0x78, 0x65])
        == "CombiningInExt"
    )


def test_detect_triple_extension() -> None:
    # "setup.tar.gz.sig"
    v = detect(
        [
            0x73, 0x65, 0x74, 0x75, 0x70, 0x2E, 0x74, 0x61, 0x72, 0x2E,
            0x67, 0x7A, 0x2E, 0x73, 0x69, 0x67,
        ]
    )
    assert v.classify.tag == "MultipleExtensions"


# ── structural priority-ladder check ─────────────────────────────────


def test_bidi_beats_fullwidth() -> None:
    # A bidi control outranks a fullwidth extension.
    assert _tag([0x202E, 0x66, 0x2E, 0xFF25]) == "RloFlip"


# ── data-layer sanity (reused port predicates) ───────────────────────


def test_reused_predicates() -> None:
    assert MIN_MULTIPLE_EXTENSIONS == 3
    assert is_ascii_dot(0x2E)
    assert not is_ascii_dot(0x2C)
    # Fullwidth/halfwidth block.
    assert is_fullwidth_halfwidth(0xFF25)
    assert not is_fullwidth_halfwidth(0x0045)
    # Bidi format-control set (reuses BidiControlBalance / RtlInjection).
    assert is_bidi_format_control(0x202E)  # RIGHT-TO-LEFT OVERRIDE
    assert is_bidi_format_control(0x2067)  # RIGHT-TO-LEFT ISOLATE
    assert not is_bidi_format_control(0x0041)
    # Grapheme Extend class (reuses the segmentation table).
    assert is_grapheme_extend(0x0301)  # COMBINING ACUTE ACCENT
    assert not is_grapheme_extend(0x0061)  # LATIN SMALL LETTER A
