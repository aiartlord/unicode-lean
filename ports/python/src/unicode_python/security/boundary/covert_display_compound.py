"""Covert-display compound detector (bidi control co-located with a hidden
covert channel).

Threat model.  Tier compound.  A bidi format-control that reorders the
visible glyphs is materially more dangerous when the same input also
carries a covert channel — an unregistered variation selector or a
tag-block character — because the reorder hides where the covert payload
sits.  This detector fires only when a bidi control coincides with one of
those covert classes.

Direct port of ``Unicode.Security.Boundary.CovertDisplayCompound``.
A "suspicious VS" is a variation selector that does not form a registered
(base, VS) pair (StandardizedVariants / emoji-variation-sequences), the
``.suspicious`` case of the variation-selector classifier.

Sub-threats (priority order, both reachable):

  - ``BidiPlusUnregisteredVs`` — bidi control + a suspicious variation
    selector that does not form a registered (base, VS) pair.
  - ``BidiPlusTagBlock`` — bidi control + a tag-block character
    (U+E0000..U+E007F).  Reached when no suspicious VS fires first.
"""

from dataclasses import dataclass, field

from ..covert.bidi_control_balance import is_bidi_format_control
from ..covert.variation_selector_payload import (
    is_registered_variation_pair,
    is_variation_selector,
)


@dataclass(frozen=True, slots=True)
class Detection:
    """One covert-display-compound scan result.  ``sub`` is ``None`` for a
    clear input; otherwise it is the sub-threat tag with the offending
    positions ``[bidi_pos, covert_pos]``."""

    sub: str | None = None
    positions: list[int] = field(default_factory=list)


def is_tag_block_char(cp: int) -> bool:
    """True iff ``cp`` is in the tag-block range U+E0000..U+E007F."""
    return 0xE0000 <= cp <= 0xE007F


def _first_bidi_pos(input_cps: list[int]) -> int | None:
    for index, cp in enumerate(input_cps):
        if is_bidi_format_control(cp):
            return index
    return None


def _first_suspicious_vs_pos(input_cps: list[int]) -> int | None:
    """First position holding a suspicious variation selector — a VS that
    does not form a registered (base, VS) pair with its predecessor.
    Mirrors the ``.suspicious`` case of the Lean ``classifyPositions``."""
    for index, cp in enumerate(input_cps):
        if is_variation_selector(cp) and not (
            index > 0 and is_registered_variation_pair(input_cps[index - 1], cp)
        ):
            return index
    return None


def _first_tag_block_pos(input_cps: list[int]) -> int | None:
    for index, cp in enumerate(input_cps):
        if is_tag_block_char(cp):
            return index
    return None


def detect(input_cps: list[int]) -> Detection:
    """Detect a bidi control co-located with a covert channel.  Priority
    mirrors the spec: a bidi control must be present; then a suspicious VS
    fires ``BidiPlusUnregisteredVs``; otherwise a tag-block character fires
    ``BidiPlusTagBlock``; otherwise clear."""
    bidi_pos = _first_bidi_pos(input_cps)
    if bidi_pos is None:
        return Detection(sub=None, positions=[])

    vs_pos = _first_suspicious_vs_pos(input_cps)
    if vs_pos is not None:
        return Detection(
            sub="BidiPlusUnregisteredVs",
            positions=[bidi_pos, vs_pos],
        )

    tag_pos = _first_tag_block_pos(input_cps)
    if tag_pos is not None:
        return Detection(
            sub="BidiPlusTagBlock",
            positions=[bidi_pos, tag_pos],
        )

    return Detection(sub=None, positions=[])


__all__ = [
    "Detection",
    "detect",
    "is_tag_block_char",
]
