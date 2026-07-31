"""Right-to-left injection detection for left-to-right-declared fields.

Threat model.  Tier A1.  An adversary places strong-RTL codepoints
(Hebrew, Arabic, ...) or bidi format-controls (RLO, LRO, PDF, the
isolates) into a field the surrounding UI declares left-to-right — a
username box, a filename, a source-code token.  A bidi-aware renderer
reorders the visible glyphs, so what the reviewer reads differs from
the logical byte order the machine acts on.

Direct port of ``Unicode.Security.Display.RtlInjection``.  The four
sub-threats, their priority, and the reported positions match that
module's ``detect`` exactly; the strong-RTL / strong-LTR predicates read
``Bidi_Class`` from the bundled ``DerivedBidiClass.txt`` (see
:func:`ucd.is_strong_rtl`), mirroring
``Unicode.Generated.DerivedBidiClass.lookup``.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..covert.bidi_control_balance import is_bidi_format_control
from ..identity import ucd

__all__ = ["Detection", "detect"]


@dataclass(frozen=True, slots=True)
class Detection:
    """One RTL-injection scan result.

    ``sub`` is ``None`` for a clear input; otherwise it carries the
    fixture-row tag of the single highest-priority sub-threat that fired,
    with the offending positions.
    """

    sub: str | None
    positions: tuple[int, ...]


_CLEAR = Detection(sub=None, positions=())


def _count_strong_rtl(input_cps: list[int]) -> int:
    return sum(1 for cp in input_cps if ucd.is_strong_rtl(cp))


def _first_bidi_control_pos(input_cps: list[int]) -> int | None:
    for index, cp in enumerate(input_cps):
        if is_bidi_format_control(cp):
            return index
    return None


def _first_strong_char(input_cps: list[int]) -> tuple[int, bool] | None:
    for index, cp in enumerate(input_cps):
        if ucd.is_strong_rtl(cp):
            return (index, True)
        if ucd.is_strong_ltr(cp):
            return (index, False)
    return None


def _first_strong_rtl_pos(input_cps: list[int]) -> int | None:
    for index, cp in enumerate(input_cps):
        if ucd.is_strong_rtl(cp):
            return index
    return None


def _longest_rtl_run(input_cps: list[int]) -> tuple[int, int]:
    longest = 0
    longest_start = 0
    current = 0
    current_start = 0
    for index, cp in enumerate(input_cps):
        if ucd.is_strong_rtl(cp):
            new_start = index if current == 0 else current_start
            current += 1
            current_start = new_start
            if current > longest:
                longest = current
                longest_start = new_start
        else:
            current = 0
    return (longest, longest_start)


def _phase3(
    input_cps: list[int], strong_rtl: int, run_len: int, run_start: int
) -> Detection:
    """Mid-stream strong-RTL in a field that did not lead with one.

    A run of four or more is a mixed-overflow takeover; a shorter run is
    a single mid-stream strong-RTL hazard.
    """
    if strong_rtl == 0:
        return _CLEAR
    if run_len >= 4:
        return Detection(sub="MixedOverflow", positions=(run_start,))
    pos = _first_strong_rtl_pos(input_cps)
    if pos is not None:
        return Detection(sub="StrongRTLInLTR", positions=(pos,))
    # Unreachable when strong_rtl > 0.
    return _CLEAR


def detect(input_cps: list[int]) -> Detection:
    """Detect right-to-left injection in an LTR-declared field.

    Priority mirrors the spec exactly: (1) any bidi format-control
    anywhere fires ``RloInLTRField``; otherwise (2) a leading strong-RTL
    codepoint fires ``FieldTakeover``; otherwise (3) mid-stream strong-RTL
    is classified by run length.
    """
    strong_rtl = _count_strong_rtl(input_cps)
    run_len, run_start = _longest_rtl_run(input_cps)

    ctl_pos = _first_bidi_control_pos(input_cps)
    if ctl_pos is not None:
        return Detection(sub="RloInLTRField", positions=(ctl_pos,))

    strong = _first_strong_char(input_cps)
    if strong is not None:
        pos, is_rtl = strong
        if is_rtl:
            return Detection(sub="FieldTakeover", positions=(pos,))
    return _phase3(input_cps, strong_rtl, run_len, run_start)
