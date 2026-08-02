"""EmojiZwjIntegrity (identity-layer detector I3) — port tests.

Drives the 12 shared context-free fixture vectors
(``fixtures/security/detectors/emoji_zwj_integrity.json``) through
:func:`detect`, composing the stable reason code the way the sibling
identity detectors do (via :func:`policy.reason_code`), plus the 11 Rust
reference spot-checks and 3 structural priority-ladder checks transcribed
from ``ports/rust/src/security/identity/emoji_zwj_integrity.rs``.
"""

import json
from pathlib import Path

from unicode_python.security.calculus import Family
from unicode_python.security.identity.emoji_zwj_integrity import (
    ZWJ,
    Classification,
    NonEmojiInjection,
    OverLength,
    detect,
    is_emoji_modifier,
    is_emoji_target,
    is_registered_zwj_sequence,
)
from unicode_python.security.policy import reason_code

_FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "fixtures"
    / "security"
    / "detectors"
    / "emoji_zwj_integrity.json"
)


def _tag(input_cps: list[int]) -> str | None:
    return detect(input_cps).classify.tag


def _code(input_cps: list[int]) -> str | None:
    tag = detect(input_cps).classify.tag
    if tag is None:
        return None
    return reason_code(Family.EMOJI_ZWJ_INTEGRITY, tag)


# ── shared fixture contract ──────────────────────────────────────────


def test_shared_fixture_vectors() -> None:
    fixture = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    assert fixture["schema"] == 1
    assert fixture["family"] == "emoji-zwj-integrity"
    for case in fixture["cases"]:
        verdict = detect(case["input"])
        required = case["required_findings"]
        if not required:
            assert verdict.classify.is_clear, case["name"]
            assert verdict.classify.tag is None, case["name"]
        else:
            assert len(required) == 1, case["name"]
            code = reason_code(
                Family.EMOJI_ZWJ_INTEGRITY, verdict.classify.tag
            )
            assert code == required[0], case["name"]


def test_reason_code_layer_and_slug() -> None:
    # Layer I, slug emoji-zwj-integrity — composed like the siblings.
    assert (
        reason_code(Family.EMOJI_ZWJ_INTEGRITY, "DoubleZWJ")
        == "unicode.security.I.emoji-zwj-integrity.DoubleZWJ"
    )


# ── data-layer sanity ────────────────────────────────────────────────


def test_is_emoji_modifier_checks() -> None:
    assert is_emoji_modifier(0x1F3FB)
    assert is_emoji_modifier(0x1F3FF)
    assert not is_emoji_modifier(0x1F3FA)
    assert not is_emoji_modifier(0x1F600)


def test_zwj_alphabet_admits_heart_rejects_grinning() -> None:
    # U+2764 HEAVY BLACK HEART appears in couple-with-heart RGI sequences.
    assert is_emoji_target(0x2764)
    # U+1F468 MAN appears in family/couple RGI sequences.
    assert is_emoji_target(0x1F468)
    # U+1F600 GRINNING FACE is in no registered RGI ZWJ sequence.
    assert not is_emoji_target(0x1F600)
    # The joiner itself is excluded from the alphabet.
    assert not is_emoji_target(ZWJ)


def test_registered_membership_is_exact() -> None:
    # MAN + ZWJ + LAPTOP (man technologist) is registered.
    assert is_registered_zwj_sequence([0x1F468, 0x200D, 0x1F4BB])
    # MAN + ZWJ + WOMAN is not registered.
    assert not is_registered_zwj_sequence([0x1F468, 0x200D, 0x1F469])


# ── §5 detect spot checks (one per Rust reference test) ───────────────


def test_detect_empty_clear() -> None:
    v = detect([])
    assert v.classify.is_clear
    assert v.classify.tag is None
    assert v.zwj_positions == []
    assert v.chain_length == 0
    assert v.skin_tone_count == 0


def test_detect_ascii_clear() -> None:
    assert detect([0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.is_clear


def test_detect_plain_emoji_clear() -> None:
    assert detect([0x1F600]).classify.is_clear


def test_detect_one_skintone_clear() -> None:
    v = detect([0x1F44B, 0x1F3FB])
    assert v.classify.is_clear
    assert v.skin_tone_count == 1


def test_detect_family_rgi_clear() -> None:
    v = detect(
        [0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466]
    )
    assert v.classify.is_clear
    assert v.is_registered_rgi


def test_detect_double_zwj() -> None:
    v = detect([0x1F600, 0x200D, 0x200D, 0x1F600])
    assert v.classify.tag == "DoubleZWJ"
    assert v.classify.positions == [1]


def test_detect_non_emoji_injection() -> None:
    v = detect([0x1F600, 0x200D, 0x0061])
    assert v.classify.tag == "NonEmojiInjection"


def test_detect_skin_tone_overflow() -> None:
    v = detect([0x1F44B, 0x1F3FB, 0x1F3FC, 0x1F3FD, 0x1F3FE, 0x1F3FF])
    assert v.classify.tag == "SkinToneOverflow"
    assert v.skin_tone_count == 5


def test_detect_man_laptop_registered_clear() -> None:
    assert detect([0x1F468, 0x200D, 0x1F4BB]).classify.is_clear


def test_detect_unregistered() -> None:
    # man + ZWJ + woman: both flanks are in the RGI alphabet but the
    # joined sequence is not registered.
    v = detect([0x1F468, 0x200D, 0x1F469])
    assert v.classify.tag == "UnregisteredSequence"


def test_detect_grinning_laptop_non_emoji_injection() -> None:
    # grinning face is not a valid ZWJ-join target, so this surfaces as
    # NonEmojiInjection.
    assert _tag([0x1F600, 0x200D, 0x1F4BB]) == "NonEmojiInjection"


# ── structural checks (follow from the priority ladder) ──────────────


def test_over_length_fires_past_cap() -> None:
    # 9 men joined by 8 ZWJs = 17 codepoints (> MAX_RGI_LENGTH).
    input_cps: list[int] = []
    for i in range(9):
        if i > 0:
            input_cps.append(0x200D)
        input_cps.append(0x1F468)
    assert len(input_cps) == 17
    v = detect(input_cps)
    assert v.classify.tag == "OverLength"
    assert v.classify == Classification(
        is_clear=False,
        sub=OverLength(length=17, max_length=16),
        positions=[],
    )
    assert (
        _code(input_cps)
        == "unicode.security.I.emoji-zwj-integrity.OverLength"
    )


def test_trailing_zwj_is_injection() -> None:
    v = detect([0x1F468, 0x200D])
    assert v.classify.tag == "NonEmojiInjection"
    assert v.classify.positions == [1]
    assert v.classify.sub == NonEmojiInjection(zwj_pos=1, non_emoji_cp=0)


def test_double_zwj_beats_unregistered() -> None:
    # man ZWJ ZWJ boy — adjacent ZWJs present; double-ZWJ wins.
    v = detect([0x1F468, 0x200D, 0x200D, 0x1F466])
    assert v.classify.tag == "DoubleZWJ"
