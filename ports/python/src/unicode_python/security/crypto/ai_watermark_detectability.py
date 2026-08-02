"""ai-watermark-detectability — character-level detector for inputs carrying
codepoint patterns consistent with a known AI watermark scheme. Answers the
question: does this input contain markers attributable to a watermarking
protocol?

Direct port of ``Unicode.Security.Crypto.AiWatermarkDetectability`` (and a
faithful transliteration of the verified Rust reference
``ports/rust/src/security/crypto/ai_watermark_detectability.rs``).

Threat model — provenance-attribution attacker. An input either (a) carries an
AI provider's watermark codepoints (a legitimate provenance marker) or (b)
carries injected markers that impersonate a provider's scheme to discredit the
content as AI-generated. Character-level detection alone cannot distinguish (a)
from (b); the detector reports the matched scheme and leaves provider-specific
authentication to downstream code.

Probe inventory (priority order, first match wins):

    1. ``adversarial``              — NNBSP count >= 3 at arithmetic-progression positions.
    2. ``gpt5ZwspModulo``           — ZWSP count >= 3 at arithmetic-progression positions.
    3. ``unknown``                  — invisible markers from >= 2 distinct categories.
    4. ``nnbspBoundary``            — single-category NNBSP.
    5. ``variationSelectorCarrier`` — VS NOT adjacent to an emoji codepoint.
    6. ``zwjNonEmoji``              — ZWJ NOT adjacent to an emoji codepoint.
    7. ``smartQuoteAlternation``    — paired curly quotes, no ASCII straight quotes.
    8. ``emDashPattern``            — em-dashes, no ASCII hyphen-minus.
    9. ``statisticalTokenChoice``   — input contains an AI-favored lexical pattern.
   10. ``defaultIgnorableCarrier``  — single-category residual Default_Ignorable.

The Emoji property table is bundled in the port's own ``data/emoji-data.txt``
(UTS #51 17.0, byte-identical to the UCD source the Lean spec cites); the
adjacency probe parses the ``Emoji`` rows from it, never a host emoji library.
The residual-default-ignorable probe reuses the port's own UCD
``is_default_ignorable`` table, never a host normalizer.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from ..identity.ucd import is_default_ignorable

# ─────────────────────────────────────────────────────────────────────
# §1 Types
# ─────────────────────────────────────────────────────────────────────


class CueClass(Enum):
    """The conceptual watermark cue class a sub-threat probes for, drawn from
    the fixed vocabulary in ``Unicode.Generated.WatermarkSchemes.CueClass``.
    Ported here because the port exposes no generated watermark-schemes
    module."""

    # A codepoint-frequency bias toward a pinned "green list" of tokens.
    GREEN_LIST_BIAS = "GreenListBias"
    # A fixed-period or carrier-byte channel surfacing a pseudorandom function.
    PSEUDORANDOM_SEQ = "PseudorandomSeq"
    # A stylistic-distribution drift away from natural human writing.
    SEMANTIC_DRIFT = "SemanticDrift"


class SubThreatTag(Enum):
    """Sub-threats this detector can fire. Each variant has a corresponding
    probe in :func:`detect_with_context`; the tag strings match the Lean/Rust
    reference exactly."""

    NNBSP_BOUNDARY = "NnbspBoundary"
    VARIATION_SELECTOR_CARRIER = "VariationSelectorCarrier"
    ZWJ_NON_EMOJI = "ZwjNonEmoji"
    DEFAULT_IGNORABLE_CARRIER = "DefaultIgnorableCarrier"
    GPT5_ZWSP_MODULO = "Gpt5ZwspModulo"
    EM_DASH_PATTERN = "EmDashPattern"
    SMART_QUOTE_ALTERNATION = "SmartQuoteAlternation"
    STATISTICAL_TOKEN_CHOICE = "StatisticalTokenChoice"
    ADVERSARIAL = "Adversarial"
    UNKNOWN = "Unknown"


@dataclass(frozen=True, slots=True)
class SubThreat:
    """A fired sub-threat together with the payload fields the Lean/Rust variant
    carries. ``tag`` selects the variant; the remaining fields carry that
    variant's payload (``None`` when not applicable to the variant).

    * ``marker_count`` — NnbspBoundary / VariationSelectorCarrier / ZwjNonEmoji
      / DefaultIgnorableCarrier: how many markers matched.
    * ``first_pos`` — Gpt5ZwspModulo / EmDashPattern / SmartQuoteAlternation /
      StatisticalTokenChoice / Adversarial: the first / start position.
    * ``impersonated_scheme`` — Adversarial: the scheme the over-regular
      placement impersonates.
    * ``anomaly_marker`` — Unknown: total invisible-marker count across all
      categories (attribution to a single scheme fails)."""

    tag: SubThreatTag
    marker_count: int | None = None
    first_pos: int | None = None
    impersonated_scheme: str | None = None
    anomaly_marker: int | None = None

    def tag_str(self) -> str:
        """Human-facing classification tag for this sub-threat."""
        return self.tag.value

    def cue_class(self) -> CueClass | None:
        """Map this sub-threat to the conceptual watermark cue class it probes
        for. Marker-encoded sub-threats route to ``PseudorandomSeq``;
        vocabulary-bias to ``GreenListBias``; stylistic-distribution to
        ``SemanticDrift``; ``Unknown`` (multi-category mixing) implicates no
        single scheme."""
        if self.tag in (
            SubThreatTag.NNBSP_BOUNDARY,
            SubThreatTag.VARIATION_SELECTOR_CARRIER,
            SubThreatTag.ZWJ_NON_EMOJI,
            SubThreatTag.DEFAULT_IGNORABLE_CARRIER,
            SubThreatTag.GPT5_ZWSP_MODULO,
        ):
            return CueClass.PSEUDORANDOM_SEQ
        if self.tag is SubThreatTag.EM_DASH_PATTERN:
            return CueClass.SEMANTIC_DRIFT
        if self.tag is SubThreatTag.SMART_QUOTE_ALTERNATION:
            return CueClass.SEMANTIC_DRIFT
        if self.tag is SubThreatTag.STATISTICAL_TOKEN_CHOICE:
            return CueClass.GREEN_LIST_BIAS
        if self.tag is SubThreatTag.ADVERSARIAL:
            return CueClass.PSEUDORANDOM_SEQ
        return None


@dataclass(frozen=True, slots=True)
class Classification:
    """Top-level AiWatermarkDetectability classification. ``is_clear``
    distinguishes the ``Clear`` variant (``noWatermark``) from the ``Hazard``
    variant; a hazard carries its sub-threat and the codepoint positions it
    implicates."""

    is_clear: bool
    sub: SubThreat | None = None
    positions: list[int] = field(default_factory=list)

    @property
    def tag(self) -> str | None:
        """Human-facing tag for a hazard, or ``None`` when clear."""
        if self.is_clear or self.sub is None:
            return None
        return self.sub.tag.value


@dataclass(frozen=True, slots=True)
class Verdict:
    """AiWatermarkDetectability verdict — the structured output of
    :func:`detect`. ``marker_count`` is the count of codepoints matching the
    fired scheme's probe (0 when clear)."""

    input: list[int]
    classify: Classification
    marker_count: int


@dataclass(frozen=True, slots=True)
class Context:
    """Optional context for the modulo-probe tolerances. Each field controls how
    strictly the corresponding probe checks its arithmetic-progression
    condition; the defaults of ``0`` require exact equality of consecutive
    gaps."""

    # ZWSP-modulo tolerance. ``0`` requires the ZWSP-position arithmetic
    # progression to be exact. ``k > 0`` accepts position gaps within +/- k of
    # the first gap, catching modulo schedules with light jitter.
    zwsp_modulo_tolerance: int = 0
    # NNBSP-arithmetic tolerance (the ``adversarial`` probe). Same semantic as
    # ``zwsp_modulo_tolerance`` but for the NNBSP positions.
    adversarial_tolerance: int = 0


# ─────────────────────────────────────────────────────────────────────
# §2 Emoji property table (bundled data/emoji-data.txt, Emoji rows)
# ─────────────────────────────────────────────────────────────────────

_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"


def _parse_emoji_ranges() -> list[tuple[int, int]]:
    """Parse the ``Emoji`` (``Emoji=Yes``) closed intervals from
    emoji-data.txt. Each non-comment row is ``<range> ; <property> #
    <comment>``; we keep only rows whose property is exactly ``Emoji``."""
    with (_DATA_DIR / "emoji-data.txt").open("r", encoding="utf-8") as f:
        raw = f.read()
    out: list[tuple[int, int]] = []
    for raw_line in raw.splitlines():
        hash_idx = raw_line.find("#")
        body = raw_line if hash_idx < 0 else raw_line[:hash_idx]
        stripped = body.strip()
        if not stripped:
            continue
        fields = stripped.split(";")
        if len(fields) < 2:
            continue
        range_field, prop_field = fields[0], fields[1]
        if prop_field.strip() != "Emoji":
            continue
        rng = range_field.strip()
        dots = rng.find("..")
        if dots < 0:
            try:
                single = int(rng, 16)
            except ValueError:
                continue
            out.append((single, single))
        else:
            try:
                lo = int(rng[:dots].strip(), 16)
                hi = int(rng[dots + 2 :].strip(), 16)
            except ValueError:
                continue
            out.append((lo, hi))
    return out


_EMOJI_RANGES: list[tuple[int, int]] | None = None


def _emoji_ranges() -> list[tuple[int, int]]:
    global _EMOJI_RANGES
    if _EMOJI_RANGES is None:
        _EMOJI_RANGES = _parse_emoji_ranges()
    return _EMOJI_RANGES


def is_emoji(cp: int) -> bool:
    """True iff ``cp`` has the ``Emoji = Yes`` property per emoji-data.txt."""
    return any(lo <= cp <= hi for lo, hi in _emoji_ranges())


# ─────────────────────────────────────────────────────────────────────
# §3 Codepoint probes
# ─────────────────────────────────────────────────────────────────────


def is_nnbsp(cp: int) -> bool:
    """True iff ``cp`` is U+202F NARROW NO-BREAK SPACE."""
    return cp == 0x202F


def is_zwj(cp: int) -> bool:
    """True iff ``cp`` is U+200D ZERO WIDTH JOINER."""
    return cp == 0x200D


def is_variation_selector(cp: int) -> bool:
    """True iff ``cp`` is a Variation Selector — the basic block U+FE00..U+FE0F
    (VS1..VS16) or the Plane-14 IVS block U+E0100..U+E01EF (VS17..VS256)."""
    return (0xFE00 <= cp <= 0xFE0F) or (0xE0100 <= cp <= 0xE01EF)


def is_zwsp(cp: int) -> bool:
    """True iff ``cp`` is U+200B ZERO WIDTH SPACE."""
    return cp == 0x200B


def is_em_dash(cp: int) -> bool:
    """True iff ``cp`` is U+2014 EM DASH."""
    return cp == 0x2014


def is_hyphen_minus(cp: int) -> bool:
    """True iff ``cp`` is U+002D HYPHEN-MINUS (ASCII)."""
    return cp == 0x002D


def is_curly_quote(cp: int) -> bool:
    """True iff ``cp`` is one of the four "curly" quotation marks: U+2018 /
    U+2019 (single open/close) and U+201C / U+201D (double open/close)."""
    return cp == 0x2018 or cp == 0x2019 or cp == 0x201C or cp == 0x201D


def is_straight_quote(cp: int) -> bool:
    """True iff ``cp`` is an ASCII straight quote — U+0022 (double) or U+0027
    (single / apostrophe)."""
    return cp == 0x0022 or cp == 0x0027


def is_adjacent_to_emoji(input_cps: list[int], i: int) -> bool:
    """True iff ``input[i]`` is adjacent (immediate predecessor OR immediate
    successor) to an emoji codepoint. Two-sided check, single pass. Used by the
    VS and ZWJ probes to exclude legitimate emoji-context occurrences."""
    prev_is_emoji = i > 0 and is_emoji(input_cps[i - 1])
    next_is_emoji = i + 1 < len(input_cps) and is_emoji(input_cps[i + 1])
    return prev_is_emoji or next_is_emoji


def all_positions(p: Callable[[int], bool], input_cps: list[int]) -> list[int]:
    """All positions in ``input`` matching predicate ``p``."""
    return [idx for idx, cp in enumerate(input_cps) if p(cp)]


def positions_are_arithmetic_within(positions: list[int], tolerance: int) -> bool:
    """True iff ``positions`` forms an arithmetic progression with all
    consecutive gaps within ``tolerance`` of the first gap. Empty + singleton
    lists are vacuously arithmetic. ``positions`` is assumed ascending (produced
    by :func:`all_positions`), so gaps are non-negative."""
    if len(positions) < 2:
        return True
    first_gap = positions[1] - positions[0]
    for i in range(len(positions) - 1):
        gap = positions[i + 1] - positions[i]
        if not (gap <= first_gap + tolerance and first_gap <= gap + tolerance):
            return False
    return True


def contains_sublist(pattern: list[int], input_cps: list[int]) -> int | None:
    """First start-position at which ``pattern`` appears as a contiguous
    sub-slice of ``input``, or ``None`` if absent."""
    if not pattern or len(pattern) > len(input_cps):
        return None
    max_start = len(input_cps) - len(pattern)
    for start in range(max_start + 1):
        if input_cps[start : start + len(pattern)] == pattern:
            return start
    return None


# The "AI-favored" lexical-pattern catalog (each word as its codepoint
# sequence), transcribed verbatim from the pinned ``aiFavoredVocabulary``
# literal in the Lean spec (parsed from ``Ucd/Security/AiFavoredVocabulary.txt``
# and drift-gated there against a fresh parse).
AI_FAVORED_VOCABULARY: list[list[int]] = [
    [100, 101, 108, 118, 101],
    [100, 101, 108, 118, 105, 110, 103],
    [116, 97, 112, 101, 115, 116, 114, 121],
    [105, 110, 116, 114, 105, 99, 97, 116, 101],
    [110, 117, 97, 110, 99, 101, 100],
    [109, 111, 114, 101, 111, 118, 101, 114],
    [102, 117, 114, 116, 104, 101, 114, 109, 111, 114, 101],
    [114, 101, 97, 108, 109],
    [101, 108, 117, 99, 105, 100, 97, 116, 101],
    [115, 104, 111, 119, 99, 97, 115, 105, 110, 103],
    [117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 115],
    [117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 100],
    [112, 105, 118, 111, 116, 97, 108],
    [98, 111, 108, 115, 116, 101, 114],
    [109, 117, 108, 116, 105, 102, 97, 99, 101, 116, 101, 100],
    [116, 101, 115, 116, 97, 109, 101, 110, 116],
    [102, 111, 115, 116, 101, 114],
    [104, 111, 108, 105, 115, 116, 105, 99],
    [112, 97, 114, 97, 100, 105, 103, 109],
    [116, 114, 97, 110, 115, 102, 111, 114, 109, 97, 116, 105, 118, 101],
    [115, 112, 101, 97, 114, 104, 101, 97, 100],
    [109, 101, 116, 105, 99, 117, 108, 111, 117, 115],
    [109, 101, 116, 105, 99, 117, 108, 111, 117, 115, 108, 121],
    [101, 109, 112, 111, 119, 101, 114],
    [101, 109, 112, 111, 119, 101, 114, 105, 110, 103],
    [112, 114, 111, 102, 111, 117, 110, 100],
    [112, 114, 111, 102, 111, 117, 110, 100, 108, 121],
    [99, 111, 109, 112, 101, 108, 108, 105, 110, 103],
    [99, 111, 109, 112, 114, 101, 104, 101, 110, 115, 105, 118, 101],
    [99, 114, 117, 99, 105, 97, 108],
    [100, 97, 117, 110, 116, 105, 110, 103],
    [114, 111, 98, 117, 115, 116],
    [115, 116, 114, 101, 97, 109, 108, 105, 110, 101],
    [101, 110, 114, 105, 99, 104],
    [101, 120, 101, 109, 112, 108, 105, 102, 121],
    [99, 97, 112, 116, 105, 118, 97, 116, 105, 110, 103],
    [100, 105, 115, 99, 101, 114, 110, 105, 110, 103],
    [109, 101, 115, 109, 101, 114, 105, 122, 101],
    [105, 110, 116, 114, 105, 99, 97, 116, 101, 108, 121],
    [105, 109, 98, 117, 101],
    [
        112, 108, 97, 121, 115, 32, 97, 32, 99, 114, 117, 99, 105, 97, 108, 32,
        114, 111, 108, 101,
    ],
    [
        112, 108, 97, 121, 115, 32, 97, 32, 112, 105, 118, 111, 116, 97, 108, 32,
        114, 111, 108, 101,
    ],
    [
        105, 116, 32, 105, 115, 32, 105, 109, 112, 111, 114, 116, 97, 110, 116,
        32, 116, 111, 32, 110, 111, 116, 101,
    ],
    [
        105, 116, 32, 105, 115, 32, 119, 111, 114, 116, 104, 32, 110, 111, 116,
        105, 110, 103,
    ],
    [105, 110, 32, 99, 111, 110, 99, 108, 117, 115, 105, 111, 110],
    [105, 110, 32, 101, 115, 115, 101, 110, 99, 101],
    [100, 101, 108, 118, 101, 32, 105, 110, 116, 111],
    [100, 101, 108, 118, 105, 110, 103, 32, 105, 110, 116, 111],
    [116, 97, 112, 101, 115, 116, 114, 121, 32, 111, 102],
    [114, 101, 97, 108, 109, 32, 111, 102],
]


# ─────────────────────────────────────────────────────────────────────
# §4 Top-level detection
# ─────────────────────────────────────────────────────────────────────


def detect_with_context(ctx: Context, input_cps: list[int]) -> Verdict:
    """The detection function. Runs every probe in the fixed priority order
    (most-specific first); the first hit wins. See the module header for the
    probe inventory and the ordering rationale."""
    nnbsp_positions = all_positions(is_nnbsp, input_cps)
    nnbsp_count = len(nnbsp_positions)

    # Probe 1: adversarial — NNBSP too-regular.
    adversarial_fires = nnbsp_count >= 3 and positions_are_arithmetic_within(
        nnbsp_positions, ctx.adversarial_tolerance
    )

    # Probe 2: gpt5ZwspModulo — ZWSP arithmetic progression.
    zwsp_positions = all_positions(is_zwsp, input_cps)
    zwsp_count = len(zwsp_positions)
    zwsp_modulo_fires = zwsp_count >= 3 and positions_are_arithmetic_within(
        zwsp_positions, ctx.zwsp_modulo_tolerance
    )

    vs_all_pos = all_positions(is_variation_selector, input_cps)
    vs_non_emoji_pos = [
        i for i in vs_all_pos if not is_adjacent_to_emoji(input_cps, i)
    ]
    vs_non_emoji_count = len(vs_non_emoji_pos)

    zwj_all_pos = all_positions(is_zwj, input_cps)
    zwj_non_emoji_pos = [
        i for i in zwj_all_pos if not is_adjacent_to_emoji(input_cps, i)
    ]
    zwj_non_emoji_count = len(zwj_non_emoji_pos)

    # Probe 7: smartQuoteAlternation — curly quotes only.
    curly_positions = all_positions(is_curly_quote, input_cps)
    curly_count = len(curly_positions)
    has_straight_quote = any(is_straight_quote(cp) for cp in input_cps)
    smart_quote_fires = curly_count >= 2 and not has_straight_quote

    # Probe 8: emDashPattern — em-dashes without hyphen-minus.
    em_dash_positions = all_positions(is_em_dash, input_cps)
    em_dash_count = len(em_dash_positions)
    has_hyphen_minus = any(is_hyphen_minus(cp) for cp in input_cps)
    em_dash_fires = em_dash_count >= 2 and not has_hyphen_minus

    # Probe 9: statisticalTokenChoice — scan the pinned vocabulary. Each word is
    # compared as a contiguous sub-slice of the input.
    vocab_hit: int | None = None
    for pattern in AI_FAVORED_VOCABULARY:
        hit = contains_sublist(pattern, input_cps)
        if hit is not None:
            vocab_hit = hit
            break

    # Residual default-ignorables (excluding VS and ZWJ, handled above).
    def is_residual_di(cp: int) -> bool:
        return (
            is_default_ignorable(cp)
            and not is_variation_selector(cp)
            and not is_zwj(cp)
        )

    di_positions = all_positions(is_residual_di, input_cps)
    di_count = len(di_positions)

    # Probe 3: unknown — invisible markers from >= 2 distinct categories.
    category_count = (
        int(nnbsp_count > 0)
        + int(vs_non_emoji_count > 0)
        + int(zwj_non_emoji_count > 0)
        + int(di_count > 0)
    )
    unknown_fires = category_count >= 2
    total_invisible_count = (
        nnbsp_count + vs_non_emoji_count + zwj_non_emoji_count + di_count
    )

    if adversarial_fires:
        first_pos = nnbsp_positions[0] if nnbsp_positions else 0
        classification = Classification(
            is_clear=False,
            sub=SubThreat(
                tag=SubThreatTag.ADVERSARIAL,
                impersonated_scheme="nnbspBoundary",
                first_pos=first_pos,
            ),
            positions=nnbsp_positions,
        )
        fired_count = nnbsp_count
    elif zwsp_modulo_fires:
        first_pos = zwsp_positions[0] if zwsp_positions else 0
        classification = Classification(
            is_clear=False,
            sub=SubThreat(tag=SubThreatTag.GPT5_ZWSP_MODULO, first_pos=first_pos),
            positions=zwsp_positions,
        )
        fired_count = zwsp_count
    elif unknown_fires:
        all_invisible_pos = [
            idx
            for idx, cp in enumerate(input_cps)
            if is_nnbsp(cp)
            or is_variation_selector(cp)
            or is_zwj(cp)
            or is_default_ignorable(cp)
        ]
        classification = Classification(
            is_clear=False,
            sub=SubThreat(
                tag=SubThreatTag.UNKNOWN, anomaly_marker=total_invisible_count
            ),
            positions=all_invisible_pos,
        )
        fired_count = total_invisible_count
    elif nnbsp_count > 0:
        classification = Classification(
            is_clear=False,
            sub=SubThreat(
                tag=SubThreatTag.NNBSP_BOUNDARY, marker_count=nnbsp_count
            ),
            positions=nnbsp_positions,
        )
        fired_count = nnbsp_count
    elif vs_non_emoji_count > 0:
        classification = Classification(
            is_clear=False,
            sub=SubThreat(
                tag=SubThreatTag.VARIATION_SELECTOR_CARRIER,
                marker_count=vs_non_emoji_count,
            ),
            positions=vs_non_emoji_pos,
        )
        fired_count = vs_non_emoji_count
    elif zwj_non_emoji_count > 0:
        classification = Classification(
            is_clear=False,
            sub=SubThreat(
                tag=SubThreatTag.ZWJ_NON_EMOJI, marker_count=zwj_non_emoji_count
            ),
            positions=zwj_non_emoji_pos,
        )
        fired_count = zwj_non_emoji_count
    elif smart_quote_fires:
        first_pos = curly_positions[0] if curly_positions else 0
        classification = Classification(
            is_clear=False,
            sub=SubThreat(
                tag=SubThreatTag.SMART_QUOTE_ALTERNATION, first_pos=first_pos
            ),
            positions=curly_positions,
        )
        fired_count = curly_count
    elif em_dash_fires:
        first_pos = em_dash_positions[0] if em_dash_positions else 0
        classification = Classification(
            is_clear=False,
            sub=SubThreat(tag=SubThreatTag.EM_DASH_PATTERN, first_pos=first_pos),
            positions=em_dash_positions,
        )
        fired_count = em_dash_count
    elif vocab_hit is not None:
        classification = Classification(
            is_clear=False,
            sub=SubThreat(
                tag=SubThreatTag.STATISTICAL_TOKEN_CHOICE, first_pos=vocab_hit
            ),
            positions=[vocab_hit],
        )
        fired_count = 1
    elif di_count > 0:
        classification = Classification(
            is_clear=False,
            sub=SubThreat(
                tag=SubThreatTag.DEFAULT_IGNORABLE_CARRIER, marker_count=di_count
            ),
            positions=di_positions,
        )
        fired_count = di_count
    else:
        classification = Classification(is_clear=True, sub=None, positions=[])
        fired_count = 0

    return Verdict(
        input=list(input_cps),
        classify=classification,
        marker_count=fired_count,
    )


def detect(input_cps: list[int]) -> Verdict:
    """Convenience wrapper over :func:`detect_with_context` with the empty
    context — exact-arithmetic settings (``zwsp_modulo_tolerance = 0``,
    ``adversarial_tolerance = 0``)."""
    return detect_with_context(Context(), input_cps)
