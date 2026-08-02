"""ai-watermark-detectability detector tests.

Ground truth: every probe spot-check, ``detect_*``, priority, tolerance, and
cue-class theorem in ``Unicode.Security.Crypto.AiWatermarkDetectability``,
transliterated from the verified Rust reference
``ports/rust/src/security/crypto/ai_watermark_detectability.rs``.

Two suites:

* the shared context-free fixture
  (``fixtures/security/detectors/ai_watermark_detectability.json``) run through
  :func:`detect`, mapping each classification tag to its stable reason code the
  same way the policy layer does; and
* the two ``Context``-tolerance vectors transcribed from the Rust reference's
  ``#[test]`` module (``detect_zwsp_jittered_strict_clear`` /
  ``detect_zwsp_jittered_tolerant_fires``); the shared detector-fixture schema
  cannot express a ``Context``, so those vectors live only here.
"""

import json
from pathlib import Path

from unicode_python.security.calculus import Family
from unicode_python.security.crypto.ai_watermark_detectability import (
    Context,
    CueClass,
    SubThreat,
    SubThreatTag,
    contains_sublist,
    detect,
    detect_with_context,
    is_adjacent_to_emoji,
    is_default_ignorable,
    is_emoji,
    is_nnbsp,
    is_variation_selector,
    is_zwj,
)
from unicode_python.security.policy import reason_code

DETECTORS_DIR = (
    Path(__file__).resolve().parents[3] / "fixtures" / "security" / "detectors"
)


def _tag(cps: list[int]) -> str | None:
    return detect(cps).classify.tag


# ── §4 probe spot checks ───────────────────────────────────────────────


def test_is_nnbsp_checks() -> None:
    assert is_nnbsp(0x202F)
    assert not is_nnbsp(0x20)
    assert not is_nnbsp(0x3000)


def test_is_zwj_checks() -> None:
    assert is_zwj(0x200D)
    assert not is_zwj(0x200B)
    assert not is_zwj(0x200C)


def test_is_vs_checks() -> None:
    assert is_variation_selector(0xFE00)
    assert is_variation_selector(0xFE0F)
    assert is_variation_selector(0xE0100)
    assert not is_variation_selector(0x61)
    assert not is_variation_selector(0x200D)


def test_is_default_ignorable_checks() -> None:
    assert is_default_ignorable(0x200B)
    assert is_default_ignorable(0x200D)
    assert is_default_ignorable(0x00AD)
    assert not is_default_ignorable(0x202F)
    assert not is_default_ignorable(0x61)


def test_is_emoji_checks() -> None:
    assert is_emoji(0x1F600)
    assert not is_emoji(0x200D)
    assert not is_emoji(0x61)


def test_is_adjacent_to_emoji_negative() -> None:
    assert not is_adjacent_to_emoji([0x61, 0xFE0F, 0x62], 1)


def test_is_adjacent_to_emoji_after_smiley() -> None:
    assert is_adjacent_to_emoji([0x1F600, 0xFE0F], 1)


def test_is_adjacent_to_emoji_before_smiley() -> None:
    assert is_adjacent_to_emoji([0xFE0F, 0x1F600], 0)


def test_contains_sublist() -> None:
    assert contains_sublist([0x62, 0x63], [0x61, 0x62, 0x63]) == 1
    assert contains_sublist([], [0x61]) is None
    assert contains_sublist([0x61, 0x62], [0x61]) is None


# ── §6 detect spot checks ──────────────────────────────────────────────


def test_detect_empty_clear() -> None:
    assert detect([]).classify.is_clear


def test_detect_ascii_clear() -> None:
    assert detect([0x61, 0x62, 0x63]).classify.is_clear


def test_detect_han_clear() -> None:
    assert detect([0x4E2D, 0x6587]).classify.is_clear


def test_detect_nnbsp_fires() -> None:
    v = detect([0x61, 0x202F, 0x62])
    assert v.classify.tag == "NnbspBoundary"
    assert v.classify.positions == [1]
    assert v.marker_count == 1


def test_detect_vs_in_plain_text_fires() -> None:
    v = detect([0x61, 0xFE0F, 0x62])
    assert v.classify.tag == "VariationSelectorCarrier"
    assert v.marker_count == 1


def test_detect_vs_after_emoji_clear() -> None:
    assert detect([0x1F600, 0xFE0F]).classify.is_clear


def test_detect_zwj_in_plain_text_fires() -> None:
    v = detect([0x61, 0x200D, 0x62])
    assert v.classify.tag == "ZwjNonEmoji"
    assert v.marker_count == 1


def test_detect_zwj_emoji_sequence_clear() -> None:
    assert detect([0x1F469, 0x200D, 0x1F52C]).classify.is_clear


def test_detect_soft_hyphen_fires() -> None:
    v = detect([0x61, 0x00AD, 0x62])
    assert v.classify.tag == "DefaultIgnorableCarrier"
    assert v.marker_count == 1


def test_detect_zwsp_fires() -> None:
    v = detect([0x61, 0x200B, 0x62])
    assert v.classify.tag == "DefaultIgnorableCarrier"
    assert v.marker_count == 1


def test_detect_priority_unknown_over_nnbsp_with_di() -> None:
    assert _tag([0x61, 0x202F, 0x00AD, 0x62]) == "Unknown"


def test_detect_priority_unknown_over_vs_with_zwj() -> None:
    assert _tag([0x61, 0xFE0F, 0x200D, 0x62]) == "Unknown"


def test_detect_multiple_nnbsp_aggregates() -> None:
    v = detect([0x61, 0x202F, 0x62, 0x202F, 0x63])
    assert v.classify.tag == "NnbspBoundary"
    assert v.marker_count == 2
    assert v.classify.positions == [1, 3]


# ── §7 refinement-probe spot checks ────────────────────────────────────


def test_detect_adversarial_arithmetic_nnbsp() -> None:
    v = detect([0x61, 0x202F, 0x62, 0x202F, 0x63, 0x202F, 0x64])
    assert v.classify.tag == "Adversarial"
    assert v.marker_count == 3


def test_detect_nnbsp_two_below_adversarial_threshold() -> None:
    assert _tag([0x61, 0x202F, 0x62, 0x202F, 0x63]) == "NnbspBoundary"


def test_detect_gpt5_zwsp_modulo() -> None:
    v = detect([0x61, 0x200B, 0x62, 0x200B, 0x63, 0x200B, 0x64])
    assert v.classify.tag == "Gpt5ZwspModulo"
    assert v.marker_count == 3


def test_detect_zwsp_two_below_modulo_threshold() -> None:
    assert _tag([0x61, 0x200B, 0x62, 0x200B, 0x63]) == "DefaultIgnorableCarrier"


def test_detect_smart_quote_alternation() -> None:
    v = detect([0x201C, 0x61, 0x62, 0x63, 0x201D])
    assert v.classify.tag == "SmartQuoteAlternation"
    assert v.marker_count == 2


def test_detect_smart_quote_with_straight_clear() -> None:
    assert detect([0x201C, 0x61, 0x22, 0x201D]).classify.is_clear


def test_detect_em_dash_pattern() -> None:
    v = detect(
        [0x61, 0x62, 0x20, 0x2014, 0x20, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66]
    )
    assert v.classify.tag == "EmDashPattern"
    assert v.marker_count == 2


def test_detect_em_dash_with_hyphen_clear() -> None:
    assert detect(
        [0x61, 0x62, 0x2D, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66]
    ).classify.is_clear


def test_detect_statistical_token_delve() -> None:
    v = detect([0x64, 0x65, 0x6C, 0x76, 0x65])
    assert v.classify.tag == "StatisticalTokenChoice"
    assert v.marker_count == 1


def test_detect_statistical_token_moreover_embedded() -> None:
    v = detect(
        [0x3B, 0x20, 0x6D, 0x6F, 0x72, 0x65, 0x6F, 0x76, 0x65, 0x72, 0x2C, 0x20]
    )
    assert v.classify.tag == "StatisticalTokenChoice"
    assert v.classify.positions == [2]


def test_detect_unknown_nnbsp_plus_di() -> None:
    v = detect([0x61, 0x202F, 0x00AD, 0x62])
    assert v.classify.tag == "Unknown"
    assert v.marker_count == 2


def test_detect_unknown_vs_plus_zwj() -> None:
    v = detect([0x61, 0xFE0F, 0x200D, 0x62])
    assert v.classify.tag == "Unknown"
    assert v.marker_count == 2


def test_detect_unknown_nnbsp_plus_zwj() -> None:
    v = detect([0x61, 0x202F, 0x200D, 0x62])
    assert v.classify.tag == "Unknown"
    assert v.marker_count == 2


def test_detect_single_category_skips_unknown() -> None:
    assert _tag([0x61, 0x202F, 0x62]) == "NnbspBoundary"


def test_detect_priority_adversarial_over_nnbsp() -> None:
    assert (
        _tag([0x61, 0x202F, 0x62, 0x202F, 0x63, 0x202F, 0x64]) == "Adversarial"
    )


def test_detect_priority_zwsp_modulo_over_di() -> None:
    assert (
        _tag([0x61, 0x200B, 0x62, 0x200B, 0x63, 0x200B, 0x64]) == "Gpt5ZwspModulo"
    )


# ── §8 tolerance-parameterised probes ──────────────────────────────────


def test_detect_zwsp_jittered_strict_clear() -> None:
    # ZWSPs at 1, 3, 6 (gaps 2, 3). Bare detect (tolerance 0) does not fire
    # gpt5ZwspModulo; falls through to defaultIgnorableCarrier.
    input_cps = [0x61, 0x200B, 0x62, 0x200B, 0x63, 0x64, 0x200B, 0x65]
    assert _tag(input_cps) == "DefaultIgnorableCarrier"


def test_detect_zwsp_jittered_tolerant_fires() -> None:
    input_cps = [0x61, 0x200B, 0x62, 0x200B, 0x63, 0x64, 0x200B, 0x65]
    ctx = Context(zwsp_modulo_tolerance=1)
    v = detect_with_context(ctx, input_cps)
    assert v.classify.tag == "Gpt5ZwspModulo"


def test_detect_with_context_default_matches_detect() -> None:
    d = detect([0x61, 0x202F, 0x62])
    c = detect_with_context(Context(), [0x61, 0x202F, 0x62])
    assert c.classify == d.classify


# ── §7 cue-class coverage ──────────────────────────────────────────────


def test_every_cue_class_is_probed() -> None:
    classes = [
        CueClass.GREEN_LIST_BIAS,
        CueClass.PSEUDORANDOM_SEQ,
        CueClass.SEMANTIC_DRIFT,
    ]
    sub_threats = [
        SubThreat(tag=SubThreatTag.NNBSP_BOUNDARY, marker_count=0),
        SubThreat(tag=SubThreatTag.VARIATION_SELECTOR_CARRIER, marker_count=0),
        SubThreat(tag=SubThreatTag.ZWJ_NON_EMOJI, marker_count=0),
        SubThreat(tag=SubThreatTag.DEFAULT_IGNORABLE_CARRIER, marker_count=0),
        SubThreat(tag=SubThreatTag.GPT5_ZWSP_MODULO, first_pos=0),
        SubThreat(tag=SubThreatTag.EM_DASH_PATTERN, first_pos=0),
        SubThreat(tag=SubThreatTag.SMART_QUOTE_ALTERNATION, first_pos=0),
        SubThreat(tag=SubThreatTag.STATISTICAL_TOKEN_CHOICE, first_pos=0),
        SubThreat(
            tag=SubThreatTag.ADVERSARIAL, impersonated_scheme="", first_pos=0
        ),
    ]
    for cls in classes:
        assert any(st.cue_class() == cls for st in sub_threats), (
            f"cue class {cls} is not probed by any sub-threat"
        )


def test_unknown_has_no_cue_class() -> None:
    assert SubThreat(tag=SubThreatTag.UNKNOWN, anomaly_marker=0).cue_class() is None


# ── Shared context-free fixture, run through detect ────────────────────


def test_shared_fixture_cases() -> None:
    fixture = json.loads(
        (DETECTORS_DIR / "ai_watermark_detectability.json").read_text(
            encoding="utf-8"
        )
    )
    assert fixture["schema"] == 1
    assert fixture["family"] == "ai-watermark-detectability"
    for case in fixture["cases"]:
        classify = detect(case["input"]).classify
        required = case["required_findings"]
        if not required:
            assert classify.tag is None, (
                f"{case['name']}: expected clear, got {classify.tag}"
            )
            continue
        code = reason_code(Family.AI_WATERMARK_DETECTABILITY, classify.tag)
        assert code in required, (
            f"{case['name']}: {code} not in required {required}"
        )
