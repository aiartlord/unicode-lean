"""UAX #29 default extended grapheme cluster segmentation.

A port of the Lean algorithm
``Unicode.Segmentation.GraphemeBreak.graphemeBreaks``. The active Lean tree
proves ``graphemeBreaks_eq_spec``, relating that algorithm to the declarative
UAX #29 GB1-GB999 specification. The state fields, rule order, and transition
below mirror that reference.

The property tables are grouped by property value (as in the UCD source), not
globally sorted by code point, so lookups scan linearly for the covering range,
mirroring the verified Lean ``find?``. Each class is a partition, so the first
covering range is the only one.
"""

from __future__ import annotations

from dataclasses import dataclass

from unicode_python.segmentation.grapheme_tables import (
    EXTPICT_RANGES,
    GCB_RANGES,
    INCB_RANGES,
)


def lookup_gcb(cp: int) -> str:
    """Grapheme_Cluster_Break class of ``cp``, ``"Other"`` when uncovered."""
    for lo, hi, cls in GCB_RANGES:
        if lo <= cp <= hi:
            return cls
    return "Other"


def lookup_incb(cp: int) -> str:
    """Indic_Conjunct_Break class of ``cp``, ``"None"`` when uncovered."""
    for lo, hi, cls in INCB_RANGES:
        if lo <= cp <= hi:
            return cls
    return "None"


def is_ext_pict(cp: int) -> bool:
    """Whether ``cp`` has the Extended_Pictographic property."""
    return any(lo <= cp <= hi for lo, hi in EXTPICT_RANGES)


@dataclass
class _State:
    """Running scan state, mirroring the Lean ``State``."""

    prev_class: str | None
    epic_state: str  # "none" | "after_ep" | "after_ep_zwj"  (GB11)
    incb_state: str  # "none" | "consonant" | "linker"        (GB9c)
    ri_run: int


def _initial() -> _State:
    return _State(prev_class=None, epic_state="none", incb_state="none", ri_run=0)


def _should_break_before(cp: int, s: _State) -> bool:
    """Whether a grapheme cluster break occurs immediately before ``cp``.

    Implements UAX #29 GB1-GB999 in canonical order; first match wins, the
    trailing GB999 breaks every otherwise-unmatched pair.
    """
    bc = lookup_gcb(cp)
    incb = lookup_incb(cp)
    is_ep = is_ext_pict(cp)
    pc = s.prev_class
    if pc is None:
        return True  # GB1: sot break
    if pc == "CR" and bc == "LF":
        return False  # GB3
    if pc in ("Control", "CR", "LF"):
        return True  # GB4
    if bc in ("Control", "CR", "LF"):
        return True  # GB5
    if pc == "L" and bc in ("L", "V", "LV", "LVT"):
        return False  # GB6
    if pc in ("LV", "V") and bc in ("V", "T"):
        return False  # GB7
    if pc in ("LVT", "T") and bc == "T":
        return False  # GB8
    if bc in ("Extend", "ZWJ"):
        return False  # GB9
    if bc == "SpacingMark":
        return False  # GB9a
    if pc == "Prepend":
        return False  # GB9b
    if s.incb_state == "linker" and incb == "Consonant":
        return False  # GB9c
    if s.epic_state == "after_ep_zwj" and is_ep:
        return False  # GB11
    if bc == "Regional_Indicator" and s.ri_run % 2 == 1:
        return False  # GB12/GB13
    return True  # GB999


def _advance(cp: int, s: _State) -> _State:
    """Update the running state after consuming ``cp``. Mirrors ``advance``."""
    bc = lookup_gcb(cp)
    incb = lookup_incb(cp)
    is_ep = is_ext_pict(cp)
    if is_ep:
        epic = "after_ep"
    elif s.epic_state == "after_ep" and bc == "Extend":
        epic = "after_ep"
    elif s.epic_state == "after_ep" and bc == "ZWJ":
        epic = "after_ep_zwj"
    else:
        epic = "none"
    if incb == "Consonant":
        incb_s = "consonant"
    elif s.incb_state == "consonant" and incb == "Linker":
        incb_s = "linker"
    elif s.incb_state == "consonant" and incb == "Extend":
        incb_s = "consonant"
    elif s.incb_state == "linker" and incb == "Linker":
        incb_s = "linker"
    elif s.incb_state == "linker" and incb == "Extend":
        incb_s = "linker"
    else:
        incb_s = "none"
    ri = s.ri_run + 1 if bc == "Regional_Indicator" else 0
    return _State(prev_class=bc, epic_state=epic, incb_state=incb_s, ri_run=ri)


def grapheme_breaks(cps: list[int]) -> list[bool]:
    """Boundary mask of length ``len(cps) + 1``.

    Entry ``i`` is ``True`` when a grapheme cluster break occurs immediately
    before position ``i`` -- entry ``0`` is the GB1 start-of-text break, entry
    ``len(cps)`` the GB2 end-of-text break, both always ``True``. Mirrors the
    Lean ``graphemeBreaks``.
    """
    breaks: list[bool] = []
    s = _initial()
    for cp in cps:
        breaks.append(_should_break_before(cp, s))
        s = _advance(cp, s)
    breaks.append(True)  # GB2: eot break
    return breaks


def grapheme_clusters(cps: list[int]) -> list[list[int]]:
    """Split ``cps`` into grapheme clusters (code points between boundaries)."""
    breaks = grapheme_breaks(cps)
    out: list[list[int]] = []
    cur: list[int] = []
    for i, cp in enumerate(cps):
        if breaks[i] and cur:
            out.append(cur)
            cur = []
        cur.append(cp)
    if cur:
        out.append(cur)
    return out
