"""RendererDivergence (display-layer detector) — port tests.

Drives the 9 shared context-free fixture vectors
(``fixtures/security/detectors/renderer_divergence.json``) through
:func:`detect`, composing the stable reason code the way the sibling
detectors do (via :func:`policy.reason_code`), plus the 9 Rust reference
spot-checks and 2 structural priority-ladder checks transcribed from
``ports/rust/src/security/display/renderer_divergence.rs``.
"""

import json
from pathlib import Path

from unicode_python.security.calculus import Family
from unicode_python.security.display.renderer_divergence import (
    MIN_COMBINING_STACK,
    ZWJ,
    detect,
    is_fullwidth_halfwidth,
    is_grapheme_extend,
    is_variation_selector,
)
from unicode_python.security.policy import reason_code

_FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "fixtures"
    / "security"
    / "detectors"
    / "renderer_divergence.json"
)


def _tag(input_cps: list[int]) -> str | None:
    return detect(input_cps).classify.tag


def _code(input_cps: list[int]) -> str | None:
    tag = detect(input_cps).classify.tag
    if tag is None:
        return None
    return reason_code(Family.RENDERER_DIVERGENCE, tag)


# ── shared fixture contract ──────────────────────────────────────────


def test_shared_fixture_vectors() -> None:
    fixture = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    assert fixture["schema"] == 1
    assert fixture["family"] == "renderer-divergence"
    for case in fixture["cases"]:
        verdict = detect(case["input"])
        required = case["required_findings"]
        if not required:
            assert verdict.classify.is_clear, case["name"]
            assert verdict.classify.tag is None, case["name"]
        else:
            assert len(required) == 1, case["name"]
            code = reason_code(
                Family.RENDERER_DIVERGENCE, verdict.classify.tag
            )
            assert code == required[0], case["name"]


def test_reason_code_layer_and_slug() -> None:
    # Layer D, slug renderer-divergence — composed like the siblings.
    assert (
        reason_code(Family.RENDERER_DIVERGENCE, "VariationSelectorVariance")
        == "unicode.security.D.renderer-divergence.VariationSelectorVariance"
    )


# ── data-layer sanity (reused port predicates) ───────────────────────


def test_reused_predicates() -> None:
    # Variation-selector set (reuses VariationSelectorPayload).
    assert is_variation_selector(0xFE0F)
    assert not is_variation_selector(0x1F600)
    # Grapheme Extend class (reuses the segmentation table).
    assert is_grapheme_extend(0x0301)  # COMBINING ACUTE ACCENT
    assert not is_grapheme_extend(0x0061)  # LATIN SMALL LETTER A
    # Fullwidth/halfwidth block.
    assert is_fullwidth_halfwidth(0xFF21)  # FULLWIDTH LATIN CAPITAL A
    assert not is_fullwidth_halfwidth(0x0041)
    # Constants match the reference.
    assert MIN_COMBINING_STACK == 4
    assert ZWJ == 0x200D


# ── §5 detect spot checks (one per Rust reference test) ───────────────


def test_detect_empty_clear() -> None:
    assert detect([]).classify.is_clear


def test_detect_ascii_clear() -> None:
    assert detect([0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.is_clear


def test_detect_han_clear() -> None:
    assert detect([0x4E2D, 0x6587]).classify.is_clear


def test_detect_vs_variance() -> None:
    # A single VS (FE0F) after an emoji.
    assert _tag([0x1F600, 0xFE0F]) == "VariationSelectorVariance"
    assert (
        _code([0x1F600, 0xFE0F])
        == "unicode.security.D.renderer-divergence.VariationSelectorVariance"
    )


def test_detect_rgi_family_clear() -> None:
    # A registered RGI family ZWJ sequence (reuses EmojiZwjIntegrity's
    # is_registered_zwj_sequence).
    v = detect([0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466])
    assert v.classify.is_clear
    assert v.has_zwj


def test_detect_unregistered_zwj_variance() -> None:
    # man + ZWJ + woman, not in the RGI set.
    assert _tag([0x1F468, 0x200D, 0x1F469]) == "UnregisteredZwjVariance"


def test_detect_zalgo_variance() -> None:
    # A 4-deep combining stack.
    v = detect([0x0061, 0x0301, 0x0302, 0x0303, 0x0304])
    assert v.classify.tag == "CombiningStackOverflow"
    assert v.classify.positions == [0]
    assert v.combining_count == 4


def test_detect_fullwidth_variance() -> None:
    # Fullwidth 'A'.
    assert _tag([0xFF21]) == "FullwidthVariance"


def test_detect_mixed_direction() -> None:
    # Latin + Hebrew in one input.
    v = detect([0x41, 0x42, 0x05D0, 0x05D1])
    assert v.classify.tag == "MixedDirectionVariance"
    assert v.strong_ltr_count > 0 and v.strong_rtl_count > 0


# ── structural checks (follow from the priority ladder) ──────────────


def test_combining_stack_beats_vs() -> None:
    # A combining stack outranks a variation selector present later.
    v = detect([0x0061, 0x0301, 0x0302, 0x0303, 0x0304, 0xFE0F])
    assert v.classify.tag == "CombiningStackOverflow"


def test_three_marks_below_threshold() -> None:
    # Exactly three combining marks is below the stack threshold.
    v = detect([0x0061, 0x0301, 0x0302, 0x0303])
    assert v.classify.tag != "CombiningStackOverflow"
