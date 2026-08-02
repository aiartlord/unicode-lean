"""RendererDivergence — detection of codepoint/sequence shapes known to
render differently across font + terminal + browser stacks (the
display-layer detector).

Byte-faithful transliteration of the verified Rust reference
implementation (itself a transliteration of
``Unicode.Security.Display.RendererDivergence``).

Threat model. An adversary crafts content that renders one way in the
auditor's renderer (a benign glyph or an empty span) and a different way
in the consumer's renderer (a misleading glyph, a wider glyph, or a
different sequence). This is the "fingerprint stability" family — clear
inputs render the same across the renderer cohort the Standard documents
as stable.

What the detector draws. A heuristic three-value split, surfaced through
the universal clear/hazard carrier: an input is clear when none of the
documented variance triggers fire, and otherwise is classified by the
first trigger in priority order — combining-mark stack overflow,
variation-selector presence, an unregistered ZWJ shape,
fullwidth/halfwidth display, or mixed direction. It reuses the port's own
tables (the variation-selector set, the grapheme Extend class, the RGI
ZWJ registry, and the strong-bidi classes), never a host rendering or
shaping library.

Sub-threats (priority order):
    1. ``CombiningStackOverflow``    Zalgo-like combining-mark stack >= 4 on a base.
    2. ``VariationSelectorVariance`` any variation selector present.
    3. ``UnregisteredZwjVariance``   ZWJ-containing input not in the RGI ZWJ set.
    4. ``FullwidthVariance``         a fullwidth/halfwidth codepoint present.
    5. ``MixedDirectionVariance``    both strong-LTR and strong-RTL codepoints.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Union

from ..calculus import ClassificationKind
from ..covert import variation_selector_payload
from ..identity import emoji_zwj_integrity, ucd
from ...segmentation import grapheme

# ─────────────────────────────────────────────────────────────────────
# §1 Constants
# ─────────────────────────────────────────────────────────────────────

# The combining-mark stack depth (on a single base) at or beyond which
# the input is treated as a Zalgo-style rendering-variance hazard.
MIN_COMBINING_STACK = 4

# The ZERO WIDTH JOINER codepoint.
ZWJ = 0x200D


# ─────────────────────────────────────────────────────────────────────
# §2 Sub-threat ADT + verdict
# ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class CombiningStackOverflow:
    """A combining-mark stack of ``stack_len`` marks on the base at
    ``base_pos`` (``stack_len >= MIN_COMBINING_STACK``)."""

    base_pos: int
    stack_len: int


@dataclass(frozen=True, slots=True)
class VariationSelectorVariance:
    """A variation selector at ``first_vs_pos`` (codepoint
    ``first_vs_cp``)."""

    first_vs_pos: int
    first_vs_cp: int


@dataclass(frozen=True, slots=True)
class UnregisteredZwjVariance:
    """A ZWJ-containing input not present in the registered RGI ZWJ set;
    ``first_zwj_pos`` is the position of the first ZWJ."""

    first_zwj_pos: int


@dataclass(frozen=True, slots=True)
class FullwidthVariance:
    """A fullwidth/halfwidth codepoint at ``first_fw_pos`` (codepoint
    ``first_fw_cp``)."""

    first_fw_pos: int
    first_fw_cp: int


@dataclass(frozen=True, slots=True)
class MixedDirectionVariance:
    """Both strong-LTR and strong-RTL codepoints in one input."""

    ltr_count: int
    rtl_count: int


SubThreat = Union[
    CombiningStackOverflow,
    VariationSelectorVariance,
    UnregisteredZwjVariance,
    FullwidthVariance,
    MixedDirectionVariance,
]


def sub_threat_tag(sub: SubThreat) -> str:
    """Fixture-row tag string for a sub-threat (matches ``SubThreat.tag``
    in the Lean/Rust reference)."""
    if isinstance(sub, CombiningStackOverflow):
        return "CombiningStackOverflow"
    if isinstance(sub, VariationSelectorVariance):
        return "VariationSelectorVariance"
    if isinstance(sub, UnregisteredZwjVariance):
        return "UnregisteredZwjVariance"
    if isinstance(sub, FullwidthVariance):
        return "FullwidthVariance"
    if isinstance(sub, MixedDirectionVariance):
        return "MixedDirectionVariance"
    raise TypeError(f"sub_threat_tag: unknown SubThreat variant {sub!r}")


@dataclass(frozen=True, slots=True)
class Classification:
    """Top-level RendererDivergence classification. ``is_clear``
    distinguishes the ``Clear`` variant from the ``Hazard`` variant; a
    hazard carries its sub-threat, the codepoint positions it implicates,
    and the decoded-byte projection (always empty here, kept for shape
    parity with the Lean ``Classification.hazard``)."""

    is_clear: bool
    sub: SubThreat | None = None
    positions: list[int] = field(default_factory=list)
    decoded: list[int] = field(default_factory=list)

    @property
    def tag(self) -> str | None:
        """Human-facing tag for a hazard, or ``None`` when clear."""
        if self.is_clear or self.sub is None:
            return None
        return sub_threat_tag(self.sub)

    @property
    def kind(self) -> ClassificationKind:
        """The classification kind (``CLEAR`` or ``HAZARD``)."""
        return (
            ClassificationKind.CLEAR
            if self.is_clear
            else ClassificationKind.HAZARD
        )


@dataclass(frozen=True, slots=True)
class Verdict:
    """The structured output of :func:`detect` (mirrors the Lean
    ``Verdict``)."""

    input: list[int]
    classify: Classification
    vs_count: int
    combining_count: int
    fullwidth_count: int
    has_zwj: bool
    strong_ltr_count: int
    strong_rtl_count: int


# ─────────────────────────────────────────────────────────────────────
# §3 Core predicates
# ─────────────────────────────────────────────────────────────────────


def is_variation_selector(cp: int) -> bool:
    """True iff ``cp`` is a variation selector (reuses the port's own
    :func:`variation_selector_payload.is_variation_selector`)."""
    return variation_selector_payload.is_variation_selector(cp)


def is_zwj(cp: int) -> bool:
    """True iff ``cp`` is the ZWJ codepoint."""
    return cp == ZWJ


def is_fullwidth_halfwidth(cp: int) -> bool:
    """True iff ``cp`` is in the Halfwidth/Fullwidth Forms block."""
    return 0xFF01 <= cp <= 0xFFEF


def is_grapheme_extend(cp: int) -> bool:
    """True iff ``cp`` has ``Grapheme_Cluster_Break = Extend`` (reuses the
    port's grapheme table via :func:`grapheme.is_grapheme_extend`)."""
    return grapheme.is_grapheme_extend(cp)


# ─────────────────────────────────────────────────────────────────────
# §4 Sub-detectors
# ─────────────────────────────────────────────────────────────────────


def _count_vs(input_cps: list[int]) -> int:
    return sum(1 for cp in input_cps if is_variation_selector(cp))


def _count_combining(input_cps: list[int]) -> int:
    return sum(1 for cp in input_cps if is_grapheme_extend(cp))


def _count_fullwidth(input_cps: list[int]) -> int:
    return sum(1 for cp in input_cps if is_fullwidth_halfwidth(cp))


def _input_has_zwj(input_cps: list[int]) -> bool:
    return any(is_zwj(cp) for cp in input_cps)


def _count_strong_ltr(input_cps: list[int]) -> int:
    return sum(1 for cp in input_cps if ucd.is_strong_ltr(cp))


def _count_strong_rtl(input_cps: list[int]) -> int:
    return sum(1 for cp in input_cps if ucd.is_strong_rtl(cp))


def _first_vs_pos(input_cps: list[int]) -> tuple[int, int] | None:
    """Position and codepoint of the first variation selector."""
    for index, cp in enumerate(input_cps):
        if is_variation_selector(cp):
            return (index, cp)
    return None


def _first_zwj_pos(input_cps: list[int]) -> int | None:
    """Position of the first ZWJ."""
    for index, cp in enumerate(input_cps):
        if is_zwj(cp):
            return index
    return None


def _first_fullwidth_pos(input_cps: list[int]) -> tuple[int, int] | None:
    """Position and codepoint of the first fullwidth/halfwidth codepoint."""
    for index, cp in enumerate(input_cps):
        if is_fullwidth_halfwidth(cp):
            return (index, cp)
    return None


def _first_combining_stack(
    input_cps: list[int], min_stack: int
) -> tuple[int, int] | None:
    """The first base position (a non-Extend codepoint) immediately
    followed by exactly ``min_stack`` consecutive Extend codepoints.
    Returns ``(base_pos, min_stack)`` on hit."""
    for idx, cp in enumerate(input_cps):
        if not is_grapheme_extend(cp):
            following = input_cps[idx + 1 : idx + 1 + min_stack]
            if len(following) == min_stack and all(
                is_grapheme_extend(c) for c in following
            ):
                return (idx, min_stack)
    return None


# ─────────────────────────────────────────────────────────────────────
# §5 Top-level detection
# ─────────────────────────────────────────────────────────────────────


def detect(input_cps: list[int]) -> Verdict:
    """The RendererDivergence detection function."""
    vs_count = _count_vs(input_cps)
    combining_count = _count_combining(input_cps)
    fullwidth_count = _count_fullwidth(input_cps)
    has_zwj = _input_has_zwj(input_cps)
    ltr_count = _count_strong_ltr(input_cps)
    rtl_count = _count_strong_rtl(input_cps)

    # Priority 1: combining-mark stack overflow (Zalgo).
    stack = _first_combining_stack(input_cps, MIN_COMBINING_STACK)
    if stack is not None:
        base_pos, stack_len = stack
        classification = Classification(
            is_clear=False,
            sub=CombiningStackOverflow(base_pos=base_pos, stack_len=stack_len),
            positions=[base_pos],
        )
    else:
        # Priority 2: any variation selector triggers presentation variance.
        vs_hit = _first_vs_pos(input_cps)
        if vs_hit is not None:
            pos, cp = vs_hit
            classification = Classification(
                is_clear=False,
                sub=VariationSelectorVariance(first_vs_pos=pos, first_vs_cp=cp),
                positions=[pos],
            )
        elif has_zwj and not emoji_zwj_integrity.is_registered_zwj_sequence(
            input_cps
        ):
            # Priority 3: ZWJ-containing input not in the registered RGI set.
            zwj_pos = _first_zwj_pos(input_cps)
            if zwj_pos is not None:
                classification = Classification(
                    is_clear=False,
                    sub=UnregisteredZwjVariance(first_zwj_pos=zwj_pos),
                    positions=[zwj_pos],
                )
            else:
                # Unreachable: has_zwj guarantees a ZWJ position exists.
                classification = Classification(is_clear=True)
        else:
            # Priority 4: fullwidth/halfwidth.
            fw_hit = _first_fullwidth_pos(input_cps)
            if fw_hit is not None:
                pos, cp = fw_hit
                classification = Classification(
                    is_clear=False,
                    sub=FullwidthVariance(first_fw_pos=pos, first_fw_cp=cp),
                    positions=[pos],
                )
            elif ltr_count > 0 and rtl_count > 0:
                # Priority 5: mixed direction.
                classification = Classification(
                    is_clear=False,
                    sub=MixedDirectionVariance(
                        ltr_count=ltr_count, rtl_count=rtl_count
                    ),
                    positions=[],
                )
            else:
                classification = Classification(is_clear=True)

    return Verdict(
        input=list(input_cps),
        classify=classification,
        vs_count=vs_count,
        combining_count=combining_count,
        fullwidth_count=fullwidth_count,
        has_zwj=has_zwj,
        strong_ltr_count=ltr_count,
        strong_rtl_count=rtl_count,
    )
