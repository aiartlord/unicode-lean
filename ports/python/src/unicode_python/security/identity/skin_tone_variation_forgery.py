"""skin-tone-variation-forgery — skin-tone modifier and variation-selector
abuse on emoji bases per UTS #51 (the identity-layer detector).

Byte-faithful transliteration of the verified Rust reference
implementation (itself a transliteration of
``Unicode.Security.Identity.SkinToneVariationForgery``).

Threat model. Tier A₁. An adversary places a skin-tone modifier on a
codepoint that does NOT bear ``Emoji_Modifier_Base``, stacks multiple
skin-tones on one base, or forces a text-style render on an
emoji-default codepoint via ``U+FE0E`` (VS15) — sometimes to hide a
payload-bearing glyph in plain sight.

Distinct from VariationSelectorPayload (pair-aligned VS runs that decode
to bytes): this catches the orthogonal case of *semantic* VS / skin-tone
misuse on a single base. Both can fire on the same input;
SourceDisplayDivergence aggregates.

It reuses the port's own emoji property tables (the bundled
``emoji-data.txt``), never a host emoji library. The skin-tone modifier
predicate is the port's own :func:`emoji_zwj_integrity.is_emoji_modifier`;
the ``Emoji_Modifier_Base`` and ``Emoji_Presentation`` intervals are
parsed from the already-bundled ``emoji-data.txt`` by the same
property-interval parser shape the port's other emoji detectors use.

Sub-threats (priority order):

    1. ``StackedSkinTones``      a base immediately followed by >= 2
                                 skin-tone modifiers.
    2. ``InvalidSkinToneTarget`` a skin-tone modifier on a
                                 non-``Emoji_Modifier_Base``.
    3. ``ForcedTextStyle``       ``U+FE0E`` on an ``Emoji_Presentation``
                                 codepoint.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Union

from ..calculus import ClassificationKind
from .emoji_zwj_integrity import is_emoji_modifier

# ─────────────────────────────────────────────────────────────────────
# §1 Sub-threat ADT + verdict
# ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class StackedSkinTones:
    """A base at ``base_pos`` followed by >= 2 skin-tone modifiers
    (``modifiers``, the first two stacked modifiers)."""

    base_pos: int
    modifiers: list[int]


@dataclass(frozen=True, slots=True)
class InvalidSkinToneTarget:
    """A skin-tone ``modifier_cp`` at ``base_pos + 1`` on a
    non-``Emoji_Modifier_Base`` ``base_cp``."""

    base_pos: int
    base_cp: int
    modifier_cp: int


@dataclass(frozen=True, slots=True)
class ForcedTextStyle:
    """A ``U+FE0E`` at ``base_pos + 1`` forcing text-style on an
    ``Emoji_Presentation`` ``base_cp``."""

    base_pos: int
    base_cp: int


SubThreat = Union[
    StackedSkinTones,
    InvalidSkinToneTarget,
    ForcedTextStyle,
]


def sub_threat_tag(sub: SubThreat) -> str:
    """Fixture-row tag string for a sub-threat (matches ``SubThreat.tag``
    in the Lean/Rust reference)."""
    if isinstance(sub, StackedSkinTones):
        return "StackedSkinTones"
    if isinstance(sub, InvalidSkinToneTarget):
        return "InvalidSkinToneTarget"
    if isinstance(sub, ForcedTextStyle):
        return "ForcedTextStyle"
    raise TypeError(
        f"sub_threat_tag: unknown SubThreat variant {sub!r}"
    )


@dataclass(frozen=True, slots=True)
class Classification:
    """Top-level SkinToneVariationForgery classification. ``is_clear``
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
    skin_tone_count: int
    variation_selector15_count: int
    variation_selector16_count: int


# ─────────────────────────────────────────────────────────────────────
# §2 Emoji property tables (bundled data/emoji-data.txt)
# ─────────────────────────────────────────────────────────────────────

_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"


def _parse_emoji_property(prop: str) -> list[tuple[int, int]]:
    """Parse the closed intervals for a single emoji property from
    emoji-data.txt. Each non-comment row is ``<range> ; <property> #
    <comment>``; we keep only rows whose property field is exactly
    ``prop``."""
    with (_DATA_DIR / "emoji-data.txt").open(
        "r", encoding="utf-8"
    ) as f:
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
        if prop_field.strip() != prop:
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


_MODIFIER_BASE_RANGES: list[tuple[int, int]] | None = None
_PRESENTATION_RANGES: list[tuple[int, int]] | None = None


def _emoji_modifier_base_ranges() -> list[tuple[int, int]]:
    global _MODIFIER_BASE_RANGES
    if _MODIFIER_BASE_RANGES is None:
        _MODIFIER_BASE_RANGES = _parse_emoji_property(
            "Emoji_Modifier_Base"
        )
    return _MODIFIER_BASE_RANGES


def _emoji_presentation_ranges() -> list[tuple[int, int]]:
    global _PRESENTATION_RANGES
    if _PRESENTATION_RANGES is None:
        _PRESENTATION_RANGES = _parse_emoji_property("Emoji_Presentation")
    return _PRESENTATION_RANGES


# ─────────────────────────────────────────────────────────────────────
# §3 Core predicates
# ─────────────────────────────────────────────────────────────────────


def is_skin_tone(cp: int) -> bool:
    """True iff ``cp`` is an emoji skin-tone modifier (reuses the port's
    own :func:`emoji_zwj_integrity.is_emoji_modifier`,
    U+1F3FB..U+1F3FF)."""
    return is_emoji_modifier(cp)


def is_skin_tone_base(cp: int) -> bool:
    """True iff ``cp`` has ``Emoji_Modifier_Base`` per emoji-data.txt."""
    return any(lo <= cp <= hi for lo, hi in _emoji_modifier_base_ranges())


def is_emoji_presentation(cp: int) -> bool:
    """True iff ``cp`` has ``Emoji_Presentation`` per emoji-data.txt."""
    return any(lo <= cp <= hi for lo, hi in _emoji_presentation_ranges())


def is_vs15(cp: int) -> bool:
    """True iff ``cp`` is ``U+FE0E`` (VS15, text-style variation
    selector)."""
    return cp == 0xFE0E


def is_vs16(cp: int) -> bool:
    """True iff ``cp`` is ``U+FE0F`` (VS16, emoji-style variation
    selector)."""
    return cp == 0xFE0F


# ─────────────────────────────────────────────────────────────────────
# §4 Sub-detectors
# ─────────────────────────────────────────────────────────────────────


def first_stacked_skin_tones(
    input_cps: list[int],
) -> tuple[int, list[int]] | None:
    """First position whose next two codepoints are both skin-tone
    modifiers, as ``(base_pos, [mod1, mod2])``."""
    for i in range(len(input_cps)):
        if i + 2 < len(input_cps):
            m1 = input_cps[i + 1]
            m2 = input_cps[i + 2]
            if is_skin_tone(m1) and is_skin_tone(m2):
                return (i, [m1, m2])
    return None


def first_invalid_skin_tone_target(
    input_cps: list[int],
) -> tuple[int, int, int] | None:
    """First skin-tone modifier whose preceding codepoint is NOT
    ``Emoji_Modifier_Base``, as ``(base_pos, base_cp, modifier_cp)``."""
    for i in range(len(input_cps)):
        if i + 1 < len(input_cps):
            cp = input_cps[i + 1]
            if is_skin_tone(cp) and not is_skin_tone_base(input_cps[i]):
                return (i, input_cps[i], cp)
    return None


def first_forced_text_style(
    input_cps: list[int],
) -> tuple[int, int] | None:
    """First ``U+FE0E`` whose preceding codepoint has
    ``Emoji_Presentation``, as ``(base_pos, base_cp)``."""
    for i in range(len(input_cps)):
        if i + 1 < len(input_cps):
            cp = input_cps[i + 1]
            if is_vs15(cp) and is_emoji_presentation(input_cps[i]):
                return (i, input_cps[i])
    return None


def skin_tone_count(input_cps: list[int]) -> int:
    """Count of skin-tone modifier codepoints."""
    return sum(1 for cp in input_cps if is_skin_tone(cp))


def vs15_count(input_cps: list[int]) -> int:
    """Count of ``U+FE0E`` (VS15) codepoints."""
    return sum(1 for cp in input_cps if is_vs15(cp))


def vs16_count(input_cps: list[int]) -> int:
    """Count of ``U+FE0F`` (VS16) codepoints."""
    return sum(1 for cp in input_cps if is_vs16(cp))


# ─────────────────────────────────────────────────────────────────────
# §5 Top-level detection
# ─────────────────────────────────────────────────────────────────────


def detect(input_cps: list[int]) -> Verdict:
    """The SkinToneVariationForgery detection function."""
    stc = skin_tone_count(input_cps)
    v15 = vs15_count(input_cps)
    v16 = vs16_count(input_cps)

    stacked = first_stacked_skin_tones(input_cps)
    if stacked is not None:
        # Priority 1: a base followed by two stacked skin tones.
        base_pos, modifiers = stacked
        positions = [base_pos + 1 + i for i in range(len(modifiers))]
        classification = Classification(
            is_clear=False,
            sub=StackedSkinTones(base_pos=base_pos, modifiers=modifiers),
            positions=positions,
        )
    else:
        invalid = first_invalid_skin_tone_target(input_cps)
        if invalid is not None:
            # Priority 2: a skin tone on a non-modifier-base.
            base_pos, base_cp, modifier_cp = invalid
            classification = Classification(
                is_clear=False,
                sub=InvalidSkinToneTarget(
                    base_pos=base_pos,
                    base_cp=base_cp,
                    modifier_cp=modifier_cp,
                ),
                positions=[base_pos + 1],
            )
        else:
            forced = first_forced_text_style(input_cps)
            if forced is not None:
                # Priority 3: VS15 forcing text style on an
                # emoji-presentation cp.
                base_pos, base_cp = forced
                classification = Classification(
                    is_clear=False,
                    sub=ForcedTextStyle(
                        base_pos=base_pos, base_cp=base_cp
                    ),
                    positions=[base_pos + 1],
                )
            else:
                classification = Classification(is_clear=True)

    return Verdict(
        input=list(input_cps),
        classify=classification,
        skin_tone_count=stc,
        variation_selector15_count=v15,
        variation_selector16_count=v16,
    )
