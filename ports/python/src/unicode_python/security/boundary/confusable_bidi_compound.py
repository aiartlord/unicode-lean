"""Confusable-in-bidi-context compound detector (CVE-2021-42574 class).

Threat model.  Cross-Layer Identity x Display compound.  A confusable
(homoglyph) codepoint co-located with a bidi format-control is
materially more dangerous than either alone: the homoglyph disguises an
identifier while the bidi control reorders how a reviewer reads it.
This detector fires only when both are present.

Direct port of ``Unicode/Security/Boundary/ConfusableBidiCompound.lean``.
The confusable-source predicate reads confusables.txt (via
:func:`unicode_python.security.identity.homoglyph_confusable.is_confusable_source`);
the bidi predicates split the format-controls into the override class
(LRE / RLE / LRO / RLO / PDF) and the isolate class (LRI / RLI / FSI /
PDI), matching ``Unicode.TrojanSource``.

Sub-threats (priority order, both reachable):

  - ``ConfusableInOverride`` — confusable cp + override-class bidi
    control.  The high-severity Trojan-Source CVE-2021-42574 class.
  - ``ConfusableInIsolate``  — confusable cp + isolate-class bidi
    control.  Reached when no override control fires first; a softer
    attack class but still a compound hazard.
"""

from collections.abc import Callable
from dataclasses import dataclass, field

from ..covert.bidi_control_balance import (
    is_pdf,
    is_pdi,
    opens_embedding,
    opens_isolate,
)
from ..identity.homoglyph_confusable import is_confusable_source


@dataclass(frozen=True, slots=True)
class Detection:
    """One confusable-bidi-compound scan result.  ``sub`` is ``None``
    for a clear input; otherwise it is the sub-threat tag with the
    offending positions ``[confusable_pos, bidi_pos]``."""

    sub: str | None = None
    positions: list[int] = field(default_factory=list)


def is_override(cp: int) -> bool:
    """True iff ``cp`` is an override-class bidi control
    (LRE, RLE, LRO, RLO, PDF)."""
    return opens_embedding(cp) or is_pdf(cp)


def is_isolate(cp: int) -> bool:
    """True iff ``cp`` is an isolate-class bidi control
    (LRI, RLI, FSI, PDI)."""
    return opens_isolate(cp) or is_pdi(cp)


def _first_pos(input_cps: list[int], predicate: Callable[[int], bool]) -> int | None:
    for index, cp in enumerate(input_cps):
        if predicate(cp):
            return index
    return None


def detect(input_cps: list[int]) -> Detection:
    """Detect a confusable codepoint sharing the input with a bidi
    control.  Priority mirrors the spec: with a confusable present, an
    override-class control fires ``ConfusableInOverride``; otherwise an
    isolate-class control fires ``ConfusableInIsolate``; otherwise
    clear."""
    confusable_pos = _first_pos(input_cps, is_confusable_source)
    if confusable_pos is None:
        return Detection(sub=None, positions=[])

    override_pos = _first_pos(input_cps, is_override)
    if override_pos is not None:
        return Detection(
            sub="ConfusableInOverride",
            positions=[confusable_pos, override_pos],
        )

    isolate_pos = _first_pos(input_cps, is_isolate)
    if isolate_pos is not None:
        return Detection(
            sub="ConfusableInIsolate",
            positions=[confusable_pos, isolate_pos],
        )

    return Detection(sub=None, positions=[])


__all__ = [
    "Detection",
    "detect",
    "is_isolate",
    "is_override",
]
