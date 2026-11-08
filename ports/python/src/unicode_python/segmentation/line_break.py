"""UAX #14 default line breaking.

A port of the Lean algorithm ``Unicode.Segmentation.LineBreak.lineBreaks``,
whose ``lineBreaks_length`` theorem fixes the output shape: one
break-opportunity flag per boundary position. The rule order, rule bodies, and
snapshot fields below mirror that reference -- LB2 through LB31 in UAX #14 R7's
canonical order, first match winning, the trailing LB31 breaking every
otherwise-unmatched pair.

Where a line may break is a property of a sequence rather than of a code point,
so the entry point returns a flag per boundary instead of a predicate over code
points.

Three mechanisms carry the context the rules read:

* LB1 is applied at lookup time by :func:`resolved_class`, which folds the
  tailorable ``AI``, ``CJ``, ``SA``, ``SG`` and ``XX`` into the algorithm's
  working alphabet. ``SA`` needs General_Category to choose between ``CM`` and
  ``AL``.
* LB9 -- treat ``X CM*`` / ``X ZWJ*`` as ``X`` -- is realised through
  ``_Snapshot``, whose fields hold the most recent class that was not ``CM`` or
  ``ZWJ``. LB10, treating a leftover ``CM`` or ``ZWJ`` as ``AL``, is the
  fallback taken when no such class exists.
* The rules naming a third character -- LB15b, LB15c, the LB25 bracket and the
  fourth LB28a sub-rule -- read the suffix beginning at the position being
  decided, so a lookahead needs no index arithmetic.

Two departures from the Lean. Its positional reads are ``lits[i]!`` and
``cps[i]!``; here every read comes from a slice the caller already holds, so no
access can leave the sequence. And its ``spSinceNoSp`` snapshot field is
written by its fold and read by no rule, so this port omits it.

The two properties this algorithm needs beyond the Line_Break class --
General_Category for the LB1 ``SA`` resolution, the Pi/Pf quote refinement and
LB30b, and East_Asian_Width for LB19a, LB25 and LB30 -- come from the generated
modules above both this layer and the security layer, so one table serves both.
"""

from __future__ import annotations

from dataclasses import dataclass

from unicode_python.east_asian_width import east_asian_width_value
from unicode_python.general_category import general_category
from unicode_python.segmentation.grapheme import is_ext_pict
from unicode_python.segmentation.line_break_tables import raw_class


def resolved_class(cp: int) -> str:
    """The ``Line_Break`` class ``cp`` carries once LB1 has tailored it.

    ``AI``, ``SG`` and ``XX`` resolve to ``AL``; ``CJ`` to ``NS``; ``SA`` to
    ``CM`` when the code point is a non-spacing or spacing combining mark and
    to ``AL`` otherwise. Every other class is already in the working alphabet.
    """
    cls = raw_class(cp)
    if cls in ("AI", "SG", "XX"):
        return "AL"
    if cls == "CJ":
        return "NS"
    if cls == "SA":
        # LB1 reads only the two combining-mark categories here; an enclosing
        # mark is not among them.
        return "CM" if general_category(cp) in ("Mn", "Mc") else "AL"
    return cls


def _is_cm_zwj(cls: str) -> bool:
    """Whether LB9 absorbs this class into the character before it."""
    return cls in ("CM", "ZWJ")


def _blocks_absorb(cls: str) -> bool:
    """Whether a preceding class blocks LB9's absorption, so a following ``CM``
    or ``ZWJ`` stands on its own and LB10 reads it as ``AL``."""
    return cls in ("BK", "CR", "LF", "NL", "SP", "ZW")


def _is_pi_quote(cp: int, cls: str) -> bool:
    """Whether the class is ``QU`` and the code point is initial punctuation,
    the refinement LB15a reads."""
    return cls == "QU" and general_category(cp) == "Pi"


def _is_pf_quote(cp: int, cls: str) -> bool:
    """Whether the class is ``QU`` and the code point is final punctuation, the
    refinement LB15b reads."""
    return cls == "QU" and general_category(cp) == "Pf"


def _is_hyphen_u2010(cp: int) -> bool:
    """Whether the code point is U+2010 HYPHEN, which LB20a and LB21a name
    explicitly because UCD 17.0 moved it from class ``HY`` to class ``HH``."""
    return cp == 0x2010


def _is_east_asian_full_wide(cp: int) -> bool:
    """Whether ``cp`` is East_Asian_Width ``F``, ``W`` or ``H``, the set LB25
    and LB30 read."""
    return east_asian_width_value(cp) in ("F", "W", "H")


def _is_east_asian_or_ambiguous(cp: int) -> bool:
    """Whether ``cp`` counts as East Asian for LB19a's tailoring, which treats
    ``Ambiguous`` as East Asian alongside ``Fullwidth``, ``Wide`` and
    ``Halfwidth``. Wider than :func:`_is_east_asian_full_wide`."""
    return east_asian_width_value(cp) in ("F", "W", "H", "A")


@dataclass(frozen=True, slots=True)
class _Snapshot:
    """The left-hand context a boundary decision reads: the classes and code
    points of the most recent characters LB9 did not absorb, plus the running
    counters the rules keep. Mirrors the Lean ``EffSnapshot``."""

    # Class of the most recent character that was not ``CM`` or ``ZWJ``.
    eff_prev: str | None
    # Its code point -- LB20a, LB21a and LB28a name U+2010 and U+25CC.
    eff_prev_cp: int | None
    # Class of the most recent character that was not ``CM``, ``ZWJ`` or
    # ``SP``.
    eff_prev_no_sp: str | None
    # Class of the second most recent such character.
    eff_prev_prev: str | None
    # Its code point.
    eff_prev_prev_cp: int | None
    # Whether an LB15a initial-punctuation quote window is open.
    in_pi_quote_window: bool
    # Length of the current regional-indicator run, for LB30a.
    ri_run: int
    # Whether an LB25 numeric chain is open.
    in_nu_chain: bool


def _initial() -> _Snapshot:
    """The context before any character has been read."""
    return _Snapshot(
        eff_prev=None,
        eff_prev_cp=None,
        eff_prev_no_sp=None,
        eff_prev_prev=None,
        eff_prev_prev_cp=None,
        in_pi_quote_window=False,
        ri_run=0,
        in_nu_chain=False,
    )


def _effective_class(cls: str, eff_prev: str | None) -> str:
    """The class a ``CM`` or ``ZWJ`` takes from what it attaches to under LB9,
    or ``AL`` under LB10 when nothing absorbs it."""
    if not _is_cm_zwj(cls):
        return cls
    if eff_prev is None:
        return "AL"
    return "AL" if _blocks_absorb(eff_prev) else cls


def _advance(s: _Snapshot, cp: int, cls: str) -> _Snapshot:
    """Fold one character into the context.

    A character LB9 absorbs leaves the context untouched, which is what makes
    the neighbours it records effective rather than literal. Mirrors the Lean
    ``buildSnapshots`` step.
    """
    effective = _effective_class(cls, s.eff_prev)
    if _is_cm_zwj(effective):
        return s

    # LB15a opens its window only where an initial-punctuation quote stands
    # outside a word; a space carries an open window forward.
    if s.eff_prev is None:
        left_context_opens = True
    else:
        left_context_opens = s.eff_prev in (
            "BK", "CR", "LF", "NL", "OP", "QU", "GL", "SP", "ZW"
        )
    if _is_pi_quote(cp, effective) and left_context_opens:
        in_pi_quote_window = True
    elif effective == "SP":
        in_pi_quote_window = s.in_pi_quote_window
    else:
        in_pi_quote_window = False

    if effective == "NU":
        in_nu_chain = True
    else:
        in_nu_chain = s.in_nu_chain and effective in (
            "SY", "IS", "CL", "CP", "PR"
        )

    return _Snapshot(
        eff_prev=effective,
        eff_prev_cp=cp,
        eff_prev_no_sp=s.eff_prev_no_sp if effective == "SP" else effective,
        eff_prev_prev=s.eff_prev,
        eff_prev_prev_cp=s.eff_prev_cp,
        in_pi_quote_window=in_pi_quote_window,
        ri_run=s.ri_run + 1 if effective == "RI" else 0,
        in_nu_chain=in_nu_chain,
    )


def _final_quote_closes(ahead: list[tuple[int, str]]) -> bool:
    """LB15b holds when the final quote is last, or when what follows it cannot
    itself open a line."""
    if not ahead:
        return True
    return ahead[0][1] in (
        "SP", "GL", "WJ", "CL", "QU", "CP", "EX", "IS",
        "SY", "BK", "CR", "LF", "NL", "ZW",
    )


def _next_significant_is_vf(ahead: list[tuple[int, str]]) -> bool:
    """The fourth LB28a sub-rule looks past any ``CM`` or ``ZWJ`` the cluster
    absorbs, so the character it tests is the first significant one ahead."""
    for _cp, cls in ahead:
        if not _is_cm_zwj(cls):
            return cls == "VF"
    return False


def _class_at(ahead: list[tuple[int, str]], offset: int) -> str | None:
    """The class at an offset into a suffix, or ``None`` past its end."""
    if offset < len(ahead):
        return ahead[offset][1]
    return None


def _breaks_before(
    prev: tuple[int, str],
    suffix: list[tuple[int, str]],
    s: _Snapshot,
) -> bool:
    """Whether a line break opportunity falls immediately before the head of
    ``suffix``, given the character before it and the context accumulated from
    everything earlier.

    ``suffix`` begins at the position being decided, so its head is the current
    character and its tail supplies every lookahead the rules take.
    """
    if not suffix:
        return True  # LB3
    prev_cp, prev_class = prev
    current_cp, current_class = suffix[0]
    ahead = suffix[1:]

    eff = _effective_class(current_class, s.eff_prev)
    left = s.eff_prev if _is_cm_zwj(prev_class) else prev_class

    # LB4
    if prev_class == "BK":
        return True
    # LB5
    if prev_class == "CR" and current_class == "LF":
        return False
    if prev_class in ("CR", "LF", "NL"):
        return True
    # LB6
    if current_class in ("BK", "CR", "LF", "NL"):
        return False
    # LB7
    if current_class in ("SP", "ZW"):
        return False
    # LB8
    if s.eff_prev_no_sp == "ZW":
        return True
    # LB8a
    if prev_class == "ZWJ":
        return False
    # LB9
    if _is_cm_zwj(current_class) and s.eff_prev is not None:
        if not _blocks_absorb(s.eff_prev):
            return False
    # LB11
    if eff == "WJ" or left == "WJ":
        return False
    # LB12
    if left == "GL":
        return False
    # LB12a
    if eff == "GL":
        if left is None or left not in ("SP", "BA", "HY", "HH"):
            return False
    # LB15c, which UCD 17.0 orders above LB13 and LB15d: break before an ``IS``
    # that opens a number and follows a space, as in "equals .35".
    if prev_class == "SP" and eff == "IS" and _class_at(ahead, 0) == "NU":
        return True
    # LB13
    if eff in ("CL", "CP", "EX", "IS", "SY"):
        return False
    # LB14
    if s.eff_prev_no_sp == "OP":
        return False
    # LB15a
    if s.in_pi_quote_window:
        return False
    # LB15b
    if _is_pf_quote(current_cp, eff) and _final_quote_closes(ahead):
        return False
    # LB15d
    if eff == "IS":
        return False
    # LB16
    if eff == "NS" and s.eff_prev_no_sp in ("CL", "CP"):
        return False
    # LB17
    if eff == "B2" and s.eff_prev_no_sp == "B2":
        return False
    # LB18
    if prev_class == "SP":
        return True
    # LB19 and LB19a. A quote neither breaks before nor after, except on the
    # OUTER side of an initial or final punctuation quote standing in
    # contiguous East Asian content -- there the default break applies, so a
    # line may break at the quote boundary. The inner side stays unbroken,
    # being the boundary inside the quote's own scope.
    if eff == "QU":
        next_cp = ahead[0][0] if ahead else None
        open_quote_in_east_asian = (
            _is_pi_quote(current_cp, eff)
            and _is_east_asian_or_ambiguous(prev_cp)
            and _is_east_asian_or_ambiguous(current_cp)
            and next_cp is not None
            and _is_east_asian_or_ambiguous(next_cp)
        )
        if not open_quote_in_east_asian:
            return False
    if left == "QU":
        quote_cp = s.eff_prev_cp
        close_quote_in_east_asian = (
            quote_cp is not None
            and _is_pf_quote(quote_cp, "QU")
            and s.eff_prev_prev_cp is not None
            and _is_east_asian_or_ambiguous(s.eff_prev_prev_cp)
            and _is_east_asian_or_ambiguous(quote_cp)
            and _is_east_asian_or_ambiguous(current_cp)
        )
        if not close_quote_in_east_asian:
            return False
    # LB20
    if eff == "CB" or left == "CB":
        return True

    # LB20.1 and LB20a both require the hyphen's own left context to be outside
    # a word, the same start-of-segment set.
    if s.eff_prev_prev is None:
        hyphen_left_context_opens = True
    else:
        hyphen_left_context_opens = s.eff_prev_prev in (
            "BK", "CR", "LF", "NL", "SP", "ZW", "CB", "GL"
        )
    # LB20.1, UCD 17.0: an explicit hyphen joins a following letter only where
    # its own left context is outside a word. A mid-word ``HH`` falls through
    # to LB31.
    if left == "HH" and eff in ("AL", "HL") and hyphen_left_context_opens:
        return False
    # LB20a, with UCD 17.0's right side broadened to ``HL`` beside ``AL``.
    if eff in ("AL", "HL"):
        hyphen_carries_left = s.eff_prev is not None and (
            s.eff_prev in ("HY", "HH")
            or (s.eff_prev_cp is not None and _is_hyphen_u2010(s.eff_prev_cp))
        )
        if hyphen_carries_left and hyphen_left_context_opens:
            return False
    # LB21
    if eff in ("BA", "HY", "HH", "NS"):
        return False
    if left == "BB":
        return False
    # LB21a: an ``HL`` letter followed by an ``HY`` hyphen or U+2010 glues to
    # what comes next unless that is itself ``HL``. A ``BA`` does not glue.
    if s.eff_prev_prev == "HL" and eff != "HL":
        hyphen_is_hy_or_2010 = s.eff_prev is not None and (
            s.eff_prev == "HY"
            or (s.eff_prev_cp is not None and _is_hyphen_u2010(s.eff_prev_cp))
        )
        if hyphen_is_hy_or_2010:
            return False
    # LB21b
    if eff == "HL" and left == "SY":
        return False
    # LB22
    if eff == "IN":
        return False
    # LB23
    if eff == "NU" and left in ("AL", "HL"):
        return False
    if eff in ("AL", "HL") and left == "NU":
        return False
    # LB23a
    if eff in ("ID", "EB", "EM") and left == "PR":
        return False
    if eff == "PO" and left in ("ID", "EB", "EM"):
        return False
    # LB24
    if eff in ("AL", "HL") and left in ("PR", "PO"):
        return False
    if eff in ("PR", "PO") and left in ("AL", "HL"):
        return False
    # LB25, closing an open numeric chain with a ``CL`` or ``CP`` suffix and a
    # following ``PO`` or ``PR``.
    if s.in_nu_chain and eff in ("CL", "CP", "PO", "PR"):
        return False
    # LB25, opening a chain
    if eff == "NU" and left in ("PR", "PO", "HY", "OP", "IS"):
        return False
    # LB25, chain body
    if eff == "NU" and left == "NU":
        return False
    # LB25, extending an open chain across a ``SY``
    if eff == "NU" and left == "SY" and s.in_nu_chain:
        return False
    # LB25, bracketed prefix: a ``PR`` joins an ``OP`` only when the ``OP``
    # itself opens a number, and neither is East Asian Fullwidth, Wide or
    # Halfwidth.
    if (
        eff == "OP"
        and left == "PR"
        and not _is_east_asian_full_wide(current_cp)
        and s.eff_prev_cp is not None
        and not _is_east_asian_full_wide(s.eff_prev_cp)
        and _class_at(ahead, 0) == "NU"
    ):
        return False
    # LB26
    if left == "JL" and eff in ("JL", "JV", "H2", "H3"):
        return False
    if left in ("JV", "H2") and eff in ("JV", "JT"):
        return False
    if left in ("JT", "H3") and eff == "JT":
        return False
    # LB27
    if left in ("JL", "JV", "JT", "H2", "H3") and eff in ("IN", "PO"):
        return False
    if left == "PR" and eff in ("JL", "JV", "JT", "H2", "H3"):
        return False
    # LB28
    if eff in ("AL", "HL") and left in ("AL", "HL"):
        return False

    # LB28a, the aksara cluster rules. U+25CC DOTTED CIRCLE carries class
    # ``AL`` and stands in for a cluster base throughout.
    left_is_aksara_base = left in ("AK", "AS") or (
        s.eff_prev_cp == 0x25CC and s.eff_prev == "AL"
    )
    if left == "AP" and (eff in ("AK", "AS") or current_cp == 0x25CC):
        return False
    if left_is_aksara_base and eff in ("VF", "VI"):
        return False
    if (
        s.eff_prev == "VI"
        and (
            s.eff_prev_prev in ("AK", "AS")
            or s.eff_prev_prev_cp == 0x25CC
        )
        and (eff == "AK" or current_cp == 0x25CC)
    ):
        return False
    if (
        left_is_aksara_base
        and (eff in ("AK", "AS") or current_cp == 0x25CC)
        and _next_significant_is_vf(ahead)
    ):
        return False
    # LB29
    if eff in ("AL", "HL") and left == "IS":
        return False
    # LB30, where the bracket must not be East Asian Fullwidth, Wide or
    # Halfwidth.
    if (
        eff == "OP"
        and left in ("AL", "HL", "NU")
        and not _is_east_asian_full_wide(current_cp)
    ):
        return False
    if (
        eff in ("AL", "HL", "NU")
        and left == "CP"
        and not _is_east_asian_full_wide(prev_cp)
    ):
        return False
    # LB30a
    if eff == "RI" and s.ri_run % 2 == 1:
        return False
    # LB30b
    if eff == "EM" and left == "EB":
        return False
    if eff == "EM" and s.eff_prev_cp is not None:
        previous_is_unassigned_pictograph = (
            is_ext_pict(s.eff_prev_cp)
            and general_category(s.eff_prev_cp) == "Cn"
        )
        if previous_is_unassigned_pictograph:
            return False
    # LB31
    return True


def line_breaks(cps: list[int]) -> list[bool]:
    """One break-opportunity flag per boundary of the code point sequence, so a
    sequence of ``n`` code points yields ``n + 1`` flags -- the shape the Lean
    ``lineBreaks_length`` theorem fixes.

    Entry ``0`` is ``False`` -- LB2 forbids a break at the start of text -- and
    entry ``n`` is ``True`` per LB3, which requires one at the end.
    """
    pairs = [(cp, resolved_class(cp)) for cp in cps]
    out: list[bool] = []
    s = _initial()
    for index, (cp, cls) in enumerate(pairs):
        if index == 0:
            out.append(False)  # LB2
        else:
            out.append(_breaks_before(pairs[index - 1], pairs[index:], s))
        s = _advance(s, cp, cls)
    out.append(True)  # LB3
    return out


def line_runs(cps: list[int]) -> list[list[int]]:
    """The code point sequence split at every break opportunity -- the runs a
    renderer may place on separate lines."""
    breaks = line_breaks(cps)
    out: list[list[int]] = []
    current: list[int] = []
    for index, cp in enumerate(cps):
        current.append(cp)
        if breaks[index + 1]:
            out.append(current)
            current = []
    if current:
        out.append(current)
    return out
