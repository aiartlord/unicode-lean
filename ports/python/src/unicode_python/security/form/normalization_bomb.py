"""Normalization-bomb detector (F1).

Mirrors ``Unicode.Security.Form.NormalizationBomb``. Detects inputs whose NFD
or NFKD expansion exceeds documented bounds — the classic
normalization-expansion DoS, where a small input expands to a very large
normalized form and exhausts memory/CPU at the receiving layer (the Arabic
ligature U+FDFA expands to 18 codepoints under NFKD, etc.).

Pure functional: compute NFD and NFKD lengths, then three priority-ordered
checks — a per-codepoint blow-up scan, an overall NFKD ratio, an overall NFD
ratio. Ratios are expressed in hundredths to avoid floats.
"""

from dataclasses import dataclass

from ..identity.ucd import to_nfd, to_nfkd

__all__ = ["Detection", "detect"]

# Maximum allowed NFKD expansion per single codepoint. Hangul <= 3, Greek
# extended forms 4, the largest non-FDFA Arabic ligature (FDFB) 8; anything
# greater than 8 is flagged.
MAX_NFKD_PER_CP = 8

# Overall-sequence NFD expansion ratio threshold, in hundredths (300 = 3x).
# Pure Hangul sits at exactly 300 and stays clear under strict ``>``.
NFD_RATIO_PCT = 300

# Overall-sequence NFKD expansion ratio threshold, in hundredths (400 = 4x).
NFKD_RATIO_PCT = 400


@dataclass(frozen=True, slots=True)
class Detection:
    """One normalization-bomb scan result. ``sub`` is ``None`` for a clear
    input; a per-codepoint blow-up carries the offending position, the ratio
    hazards carry no position."""

    sub: str | None
    positions: tuple[int, ...]


def _first_blowup_cp(input_cps: list[int]) -> tuple[int, int, int] | None:
    """First position whose single-codepoint NFKD expansion exceeds
    ``MAX_NFKD_PER_CP``, with the codepoint and its expansion length."""
    for index, cp in enumerate(input_cps):
        expand = len(to_nfkd([cp]))
        if expand > MAX_NFKD_PER_CP:
            return (index, cp, expand)
    return None


def _nfd_ratio_pct(input_cps: list[int]) -> int:
    """NFD ratio percentage (``100 * nfdLen // inputLen``); 0 on empty input."""
    if not input_cps:
        return 0
    return len(to_nfd(input_cps)) * 100 // len(input_cps)


def _nfkd_ratio_pct(input_cps: list[int]) -> int:
    """NFKD ratio percentage (``100 * nfkdLen // inputLen``); 0 on empty input."""
    if not input_cps:
        return 0
    return len(to_nfkd(input_cps)) * 100 // len(input_cps)


def detect(input_cps: list[int]) -> Detection:
    """Detect a normalization-expansion bomb. Priority: per-codepoint blow-up,
    then overall NFKD ratio, then overall NFD ratio."""
    blowup = _first_blowup_cp(input_cps)
    if blowup is not None:
        pos, _cp, _expand = blowup
        return Detection(sub="SingleCpBlowup", positions=(pos,))
    if _nfkd_ratio_pct(input_cps) > NFKD_RATIO_PCT:
        return Detection(sub="NfkdHighExpansion", positions=())
    if _nfd_ratio_pct(input_cps) > NFD_RATIO_PCT:
        return Detection(sub="NfdHighExpansion", positions=())
    return Detection(sub=None, positions=())
