"""FilenameDisguise — detection of filename/extension disguise attacks
where the visible extension differs from the byte extension (the
display-layer detector).

Byte-faithful transliteration of the verified Rust reference
implementation (itself a transliteration of
``Unicode.Security.Display.FilenameDisguise``).

Threat model. An adversary delivers a file whose rendered name looks like
a benign type (``document.txt``) but whose actual byte extension is
executable — the canonical attack inserts ``U+202E`` RIGHT-TO-LEFT
OVERRIDE so ``document<RLO>txt.exe`` renders as ``document exe.txt``.

Detection is presentation- and language-agnostic: it surfaces every
codepoint that could cause display-vs-byte divergence in the filename —
any bidi format-control anywhere, and any fullwidth/halfwidth or
combining (grapheme Extend) codepoint in the extension region (after the
last ``.``). Native-RTL names with no bidi controls clear. It reuses the
port's own predicates (the bidi-format-control set, the grapheme Extend
class, the fullwidth range), never a host filesystem or rendering library.

Sub-threats (priority order):
    1. ``RloFlip``            any bidi format-control in the input.
    2. ``WidthClassExt``      a fullwidth/halfwidth codepoint in the extension.
    3. ``CombiningInExt``     a combining (Extend) codepoint in the extension.
    4. ``MultipleExtensions`` >= 3 dots (advisory; e.g. ``.tar.gz.sig``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Union

from ..calculus import ClassificationKind
from ..covert import bidi_control_balance
from ...segmentation import grapheme

# ─────────────────────────────────────────────────────────────────────
# §1 Constants
# ─────────────────────────────────────────────────────────────────────

# The number of ``.`` separators at or beyond which a name is treated as
# an advisory MultipleExtensions hazard.
MIN_MULTIPLE_EXTENSIONS = 3


# ─────────────────────────────────────────────────────────────────────
# §2 Sub-threat ADT + verdict
# ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RloFlip:
    """A bidi format-control at ``position`` (codepoint ``control_cp``)."""

    position: int
    control_cp: int


@dataclass(frozen=True, slots=True)
class WidthClassExt:
    """A fullwidth/halfwidth codepoint in the extension, at ``position``
    (codepoint ``cp``)."""

    position: int
    cp: int


@dataclass(frozen=True, slots=True)
class CombiningInExt:
    """A combining (grapheme Extend) codepoint in the extension, at
    ``position`` (codepoint ``cp``)."""

    position: int
    cp: int


@dataclass(frozen=True, slots=True)
class MultipleExtensions:
    """Three or more ``.`` separators (advisory); ``dot_count`` is the
    number of separators."""

    dot_count: int


SubThreat = Union[
    RloFlip,
    WidthClassExt,
    CombiningInExt,
    MultipleExtensions,
]


def sub_threat_tag(sub: SubThreat) -> str:
    """Fixture-row tag string for a sub-threat (matches ``SubThreat.tag``
    in the Lean/Rust reference)."""
    if isinstance(sub, RloFlip):
        return "RloFlip"
    if isinstance(sub, WidthClassExt):
        return "WidthClassExt"
    if isinstance(sub, CombiningInExt):
        return "CombiningInExt"
    if isinstance(sub, MultipleExtensions):
        return "MultipleExtensions"
    raise TypeError(f"sub_threat_tag: unknown SubThreat variant {sub!r}")


@dataclass(frozen=True, slots=True)
class Classification:
    """Top-level FilenameDisguise classification. ``is_clear``
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
    dot_positions: list[int]
    last_dot_pos: int | None
    bidi_control_count: int
    fullwidth_in_ext: int
    combining_in_ext: int


# ─────────────────────────────────────────────────────────────────────
# §3 Core predicates
# ─────────────────────────────────────────────────────────────────────


def is_ascii_dot(cp: int) -> bool:
    """True iff ``cp`` is ``U+002E FULL STOP`` (the extension separator)."""
    return cp == 0x002E


def is_fullwidth_halfwidth(cp: int) -> bool:
    """True iff ``cp`` is in the Halfwidth and Fullwidth Forms block."""
    return 0xFF01 <= cp <= 0xFFEF


def is_bidi_format_control(cp: int) -> bool:
    """True iff ``cp`` is a bidi format-control (reuses the port's own
    :func:`bidi_control_balance.is_bidi_format_control`)."""
    return bidi_control_balance.is_bidi_format_control(cp)


def is_grapheme_extend(cp: int) -> bool:
    """True iff ``cp`` has ``Grapheme_Cluster_Break = Extend`` (reuses the
    port's grapheme table via :func:`grapheme.is_grapheme_extend`)."""
    return grapheme.is_grapheme_extend(cp)


# ─────────────────────────────────────────────────────────────────────
# §4 Sub-detectors
# ─────────────────────────────────────────────────────────────────────


def _dot_positions(input_cps: list[int]) -> list[int]:
    """Positions of every ``.`` in ``input_cps``."""
    return [index for index, cp in enumerate(input_cps) if is_ascii_dot(cp)]


def _first_bidi_control(input_cps: list[int]) -> tuple[int, int] | None:
    """Position and codepoint of the first bidi format-control."""
    for index, cp in enumerate(input_cps):
        if is_bidi_format_control(cp):
            return (index, cp)
    return None


def _first_fullwidth_from(
    input_cps: list[int], start: int
) -> tuple[int, int] | None:
    """Position and codepoint of the first fullwidth/halfwidth codepoint
    at or after ``start``."""
    for index, cp in enumerate(input_cps):
        if index >= start and is_fullwidth_halfwidth(cp):
            return (index, cp)
    return None


def _first_extend_from(
    input_cps: list[int], start: int
) -> tuple[int, int] | None:
    """Position and codepoint of the first Extend codepoint at or after
    ``start``."""
    for index, cp in enumerate(input_cps):
        if index >= start and is_grapheme_extend(cp):
            return (index, cp)
    return None


def _count_fullwidth_from(input_cps: list[int], start: int) -> int:
    """Count of fullwidth/halfwidth codepoints at or after ``start``."""
    return sum(
        1
        for index, cp in enumerate(input_cps)
        if index >= start and is_fullwidth_halfwidth(cp)
    )


def _count_extend_from(input_cps: list[int], start: int) -> int:
    """Count of Extend codepoints at or after ``start``."""
    return sum(
        1
        for index, cp in enumerate(input_cps)
        if index >= start and is_grapheme_extend(cp)
    )


# ─────────────────────────────────────────────────────────────────────
# §5 Top-level detection
# ─────────────────────────────────────────────────────────────────────


def detect(input_cps: list[int]) -> Verdict:
    """The FilenameDisguise detection function."""
    dots = _dot_positions(input_cps)
    last_dot = dots[-1] if dots else None
    ext_start = last_dot + 1 if last_dot is not None else len(input_cps)

    bidi_count = sum(1 for cp in input_cps if is_bidi_format_control(cp))
    fw_in_ext = _count_fullwidth_from(input_cps, ext_start)
    ext_in_ext = _count_extend_from(input_cps, ext_start)

    bidi_hit = _first_bidi_control(input_cps)
    if bidi_hit is not None:
        # Priority 1: any bidi format-control.
        pos, ctl_cp = bidi_hit
        classification = Classification(
            is_clear=False,
            sub=RloFlip(position=pos, control_cp=ctl_cp),
            positions=[pos],
        )
    else:
        fw_hit = _first_fullwidth_from(input_cps, ext_start)
        if fw_hit is not None:
            # Priority 2: fullwidth/halfwidth in the extension.
            pos, cp = fw_hit
            classification = Classification(
                is_clear=False,
                sub=WidthClassExt(position=pos, cp=cp),
                positions=[pos],
            )
        else:
            ext_hit = _first_extend_from(input_cps, ext_start)
            if ext_hit is not None:
                # Priority 3: combining mark in the extension.
                pos, cp = ext_hit
                classification = Classification(
                    is_clear=False,
                    sub=CombiningInExt(position=pos, cp=cp),
                    positions=[pos],
                )
            elif len(dots) >= MIN_MULTIPLE_EXTENSIONS:
                # Priority 4: three or more extensions (advisory).
                classification = Classification(
                    is_clear=False,
                    sub=MultipleExtensions(dot_count=len(dots)),
                    positions=list(dots),
                )
            else:
                classification = Classification(is_clear=True)

    return Verdict(
        input=list(input_cps),
        classify=classification,
        dot_positions=dots,
        last_dot_pos=last_dot,
        bidi_control_count=bidi_count,
        fullwidth_in_ext=fw_in_ext,
        combining_in_ext=ext_in_ext,
    )
