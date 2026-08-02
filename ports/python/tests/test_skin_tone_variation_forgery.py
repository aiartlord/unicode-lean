"""SkinToneVariationForgery (identity-layer detector) — port tests.

Drives the 8 shared context-free fixture vectors
(``fixtures/security/detectors/skin_tone_variation_forgery.json``) through
:func:`detect`, composing the stable reason code the way the sibling
identity detectors do (via :func:`policy.reason_code`), plus the Rust
reference spot-checks transcribed from
``ports/rust/src/security/identity/skin_tone_variation_forgery.rs``.
"""

import json
from pathlib import Path

from unicode_python.security.calculus import Family
from unicode_python.security.identity.skin_tone_variation_forgery import (
    detect,
    is_emoji_presentation,
    is_skin_tone,
    is_skin_tone_base,
    is_vs15,
    is_vs16,
)
from unicode_python.security.policy import reason_code

_FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "fixtures"
    / "security"
    / "detectors"
    / "skin_tone_variation_forgery.json"
)


def _tag(input_cps: list[int]) -> str | None:
    return detect(input_cps).classify.tag


# ── shared fixture contract ──────────────────────────────────────────


def test_shared_fixture_vectors() -> None:
    fixture = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    assert fixture["schema"] == 1
    assert fixture["family"] == "skin-tone-variation-forgery"
    for case in fixture["cases"]:
        verdict = detect(case["input"])
        required = case["required_findings"]
        if not required:
            assert verdict.classify.is_clear, case["name"]
            assert verdict.classify.tag is None, case["name"]
        else:
            assert len(required) == 1, case["name"]
            code = reason_code(
                Family.SKIN_TONE_VARIATION_FORGERY, verdict.classify.tag
            )
            assert code == required[0], case["name"]


def test_reason_code_layer_and_slug() -> None:
    # Layer I, slug skin-tone-variation-forgery — composed like siblings.
    assert (
        reason_code(
            Family.SKIN_TONE_VARIATION_FORGERY, "StackedSkinTones"
        )
        == "unicode.security.I.skin-tone-variation-forgery.StackedSkinTones"
    )
    assert (
        reason_code(Family.SKIN_TONE_VARIATION_FORGERY, "ForcedTextStyle")
        == "unicode.security.I.skin-tone-variation-forgery.ForcedTextStyle"
    )


# ── data-layer sanity ────────────────────────────────────────────────


def test_is_skin_tone_reuses_emoji_modifier() -> None:
    assert is_skin_tone(0x1F3FB)
    assert is_skin_tone(0x1F3FF)
    assert not is_skin_tone(0x1F3FA)
    assert not is_skin_tone(0x1F600)


def test_is_skin_tone_base_from_emoji_data() -> None:
    # Waving hand (U+1F44B) bears Emoji_Modifier_Base.
    assert is_skin_tone_base(0x1F44B)
    # Grinning face (U+1F600) does not.
    assert not is_skin_tone_base(0x1F600)
    # ASCII 'A' does not.
    assert not is_skin_tone_base(0x0041)


def test_is_emoji_presentation_from_emoji_data() -> None:
    # Grinning face has Emoji_Presentation.
    assert is_emoji_presentation(0x1F600)
    # ASCII 'A' does not.
    assert not is_emoji_presentation(0x0041)


def test_variation_selector_predicates() -> None:
    assert is_vs15(0xFE0E)
    assert not is_vs15(0xFE0F)
    assert is_vs16(0xFE0F)
    assert not is_vs16(0xFE0E)


# ── §5 detect spot checks (one per Rust reference test) ───────────────


def test_detect_empty_clear() -> None:
    v = detect([])
    assert v.classify.is_clear
    assert v.classify.tag is None
    assert v.skin_tone_count == 0
    assert v.variation_selector15_count == 0
    assert v.variation_selector16_count == 0


def test_detect_ascii_clear() -> None:
    assert detect([0x48, 0x65]).classify.is_clear


def test_detect_plain_emoji_clear() -> None:
    assert detect([0x1F600]).classify.is_clear


def test_detect_wave_skin_tone_clear() -> None:
    v = detect([0x1F44B, 0x1F3FB])
    assert v.classify.is_clear
    assert v.skin_tone_count == 1


def test_detect_stacked_skin_tones() -> None:
    v = detect([0x1F44B, 0x1F3FB, 0x1F3FC])
    assert v.classify.tag == "StackedSkinTones"
    assert v.classify.positions == [1, 2]


def test_detect_invalid_target_ascii() -> None:
    v = detect([0x0041, 0x1F3FB])
    assert v.classify.tag == "InvalidSkinToneTarget"
    assert v.classify.positions == [1]


def test_detect_invalid_target_smiley() -> None:
    assert _tag([0x1F600, 0x1F3FB]) == "InvalidSkinToneTarget"


def test_detect_forced_text_style() -> None:
    v = detect([0x1F600, 0xFE0E])
    assert v.classify.tag == "ForcedTextStyle"
    assert v.classify.positions == [1]
    assert v.variation_selector15_count == 1
