"""SourceDisplayDivergence (display-layer aggregator) — port tests.

Drives the shared context-free fixture vectors through :func:`detect`,
composing the stable reason code the way the sibling detectors do (via
:func:`policy.reason_code`), plus the Rust reference spot-checks
transcribed from the verified Rust reference implementation.

The aggregator reuses the port's own five constituent detectors —
tag_block_payload, variation_selector_payload, zero_width_payload,
bidi_control_balance, homoglyph_confusable — and aggregates by how many
fired: 0 → clear, 1 → that family's tag, 2+ → ``Compound``.
"""

import json
from pathlib import Path

from unicode_python.security.calculus import Family
from unicode_python.security.display.source_display_divergence import detect
from unicode_python.security.policy import reason_code

_FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "fixtures"
    / "security"
    / "detectors"
    / "source_display_divergence.json"
)


def _sub(input_cps: list[int]) -> str | None:
    return detect(input_cps).sub


# ── shared fixture contract ──────────────────────────────────────────


def test_shared_fixture_vectors() -> None:
    fixture = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    assert fixture["schema"] == 1
    assert fixture["family"] == "source-display-divergence"
    for case in fixture["cases"]:
        detection = detect(case["input"])
        required = case["required_findings"]
        if not required:
            assert detection.is_clear, case["name"]
            assert detection.tag is None, case["name"]
        else:
            assert len(required) == 1, case["name"]
            code = reason_code(
                Family.SOURCE_DISPLAY_DIVERGENCE, detection.tag
            )
            assert code == required[0], case["name"]


def test_reason_code_layer_and_slug() -> None:
    # Layer D, slug source-display-divergence — composed like the siblings.
    assert (
        reason_code(Family.SOURCE_DISPLAY_DIVERGENCE, "TagBlock")
        == "unicode.security.D.source-display-divergence.TagBlock"
    )
    assert (
        reason_code(Family.SOURCE_DISPLAY_DIVERGENCE, "Compound")
        == "unicode.security.D.source-display-divergence.Compound"
    )


# ── Rust reference spot-checks ───────────────────────────────────────


def test_clear_cases() -> None:
    assert _sub([]) is None
    # "Hello world"
    assert (
        _sub([0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64])
        is None
    )
    # "let x = 1;"
    assert (
        _sub([0x6C, 0x65, 0x74, 0x20, 0x78, 0x20, 0x3D, 0x20, 0x31, 0x3B])
        is None
    )


def test_single_fire_tag_block() -> None:
    # tag-encoded "AB"
    assert _sub([0xE0041, 0xE0042]) == "TagBlock"


def test_single_fire_variation_selector() -> None:
    # A + VS16
    assert _sub([0x0041, 0xFE0F]) == "VariationSelector"


def test_single_fire_zero_width() -> None:
    # H + ZWSP + i
    assert _sub([0x0048, 0x200B, 0x69]) == "ZeroWidth"


def test_single_fire_bidi_control() -> None:
    # RLO + A
    assert _sub([0x202E, 0x41]) == "BidiControl"


def test_single_fire_identifier_homoglyph() -> None:
    # "Neth<Cyrillic е>um"
    assert (
        _sub([0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D])
        == "IdentifierHomoglyph"
    )


def test_two_or_more_is_compound() -> None:
    # A + VS16 + ZWSP
    assert _sub([0x0041, 0xFE0F, 0x200B]) == "Compound"
    # tag "AB" + ZWSP
    assert _sub([0xE0041, 0xE0042, 0x200B]) == "Compound"


# ── verdict-shape sanity ─────────────────────────────────────────────


def test_verdict_kind_and_is_clear() -> None:
    from unicode_python.security.calculus import ClassificationKind

    clear = detect([0x41])
    assert clear.is_clear
    assert clear.kind is ClassificationKind.CLEAR

    hazard = detect([0x202E, 0x41])
    assert not hazard.is_clear
    assert hazard.kind is ClassificationKind.HAZARD
