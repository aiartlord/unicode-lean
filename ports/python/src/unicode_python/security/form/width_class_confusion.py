"""Width-class-confusion detector.

Mirrors ``Unicode.Security.Form.WidthClassConfusion``. Detects UAX #11 East
Asian Width class confusion: inputs containing Fullwidth (EAW = F) or
Halfwidth (EAW = H) codepoints whose NFKD form has a different EAW class.
These are the canonical compatibility-fold homograph shapes::

    U+FF21 'Ａ' (F)  ->  U+0041 'A' (Na)
    U+FF11 '１' (F)  ->  U+0031 '1' (Na)
    U+FF71 'ｱ' (H)  ->  U+30A2 'ア' (W)

The two-system bypass: a validator that whitelists ASCII rejects ``Ａ``, while
a downstream NFKC step at storage or comparison time folds it to plain ``A``.
The attacker claims the username ``ADMIN`` with ``ＡＤＭＩＮ`` against a system
that did not normalise before whitelisting.

Distinct from ``renderer_divergence``'s ``FullwidthVariance``, which fires on
F-class codepoints for renderer-cohort reasons; this is the NFKC-fold verdict,
and both can fire on one input independently.

Detection is per input position and uses NFKD, because every compatibility
decomposition path goes through it. Hangul syllables decompose to jamos that
are still W class, so pure Hangul stays clear.
"""

from dataclasses import dataclass

from ..identity.ucd import EastAsianWidthClass, east_asian_width, to_nfkd

__all__ = ["Detection", "detect"]


@dataclass(frozen=True, slots=True)
class Detection:
    """One width-class-confusion scan result. ``sub`` is ``None`` for a clear
    input, else the fold tag with the single position it was found at."""

    sub: str | None
    positions: tuple[int, ...]
    fullwidth_fold_count: int
    halfwidth_fold_count: int


def _has_width_fold(cp: int) -> bool:
    """True iff the NFKD head of ``cp`` has a different EAW class."""
    folded = to_nfkd([cp])
    if not folded:
        return False
    return east_asian_width(folded[0]) is not east_asian_width(cp)


def _first_fold(input_cps: list[int], want: EastAsianWidthClass) -> int | None:
    for index, cp in enumerate(input_cps):
        if east_asian_width(cp) is want and _has_width_fold(cp):
            return index
    return None


def _fold_count(input_cps: list[int], want: EastAsianWidthClass) -> int:
    return sum(
        1 for cp in input_cps if east_asian_width(cp) is want and _has_width_fold(cp)
    )


def detect(input_cps: list[int]) -> Detection:
    """Detect a width-class fold. A Fullwidth fold takes priority over a
    Halfwidth one, matching the reference's sub-threat order."""
    fullwidth_count = _fold_count(input_cps, EastAsianWidthClass.F)
    halfwidth_count = _fold_count(input_cps, EastAsianWidthClass.H)

    position = _first_fold(input_cps, EastAsianWidthClass.F)
    if position is not None:
        return Detection("FullwidthFold", (position,), fullwidth_count, halfwidth_count)

    position = _first_fold(input_cps, EastAsianWidthClass.H)
    if position is not None:
        return Detection("HalfwidthFold", (position,), fullwidth_count, halfwidth_count)

    return Detection(None, (), fullwidth_count, halfwidth_count)
