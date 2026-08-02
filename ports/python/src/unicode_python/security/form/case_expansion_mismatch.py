"""CaseExpansionMismatch detector (UAX #21 / Tier A1–A2).

Mirrors ``Unicode.Security.Form.CaseExpansionMismatch`` (direct port of the
verified Rust reference ``security/form/case_expansion_mismatch.rs``). Detects
inputs a codepoint of which case-maps, under the default locale, to a sequence
of a *different* length than the input — a length-changing case mapping.

Threat model. An attacker submits text whose case-mapped form has a different
codepoint count than the input. A receiver that fixes a 16-byte username column
and stores ``toUpper(username)`` overflows when the user picks "ßßßßßßßß"
(8 in → 16 stored); a receiver that checks ``len(stored) == len(input)`` rejects
valid case-insensitive logins whose names expand under folding. Examples:
U+00DF ß → "SS", U+FB01 ﬁ → "FI", U+0130 İ → toLower "i̇" (i + U+0307).

Distinct from LocaleCaseInversion (case mapping that changes *across* locales):
this fires on shapes whose mapping is locale-stable but length-changing under
the default locale itself.

It reuses the port's own UAX #21 case mapping — :func:`casing.upper_codepoint`
and :func:`casing.lower_codepoint`, which evaluate the SpecialCasing context
predicates — never a host casing library.

Sub-threats (priority order):
  1. ``UpperExpansion`` — first position whose default ``upper_codepoint``
     yields more than one codepoint.
  2. ``LowerExpansion`` — first position whose default ``lower_codepoint``
     yields more than one codepoint (reached only when no upper expansion
     fires first).
"""

from dataclasses import dataclass, field
from typing import Union

from ..casing import Locale, lower_codepoint, upper_codepoint

__all__ = [
    "UpperExpansion",
    "LowerExpansion",
    "SubThreat",
    "sub_threat_tag",
    "Classification",
    "Verdict",
    "detect",
]


# ─────────────────────────────────────────────────────────────────────
# §1 Types
# ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class UpperExpansion:
    """A codepoint whose default uppercase mapping expands to more than one
    codepoint, at ``base_pos``. ``cp`` is the expanding codepoint and
    ``expansion_len`` the length (> 1) of its uppercase expansion."""

    base_pos: int
    cp: int
    expansion_len: int


@dataclass(frozen=True, slots=True)
class LowerExpansion:
    """A codepoint whose default lowercase mapping expands to more than one
    codepoint, at ``base_pos``. ``cp`` is the expanding codepoint and
    ``expansion_len`` the length (> 1) of its lowercase expansion."""

    base_pos: int
    cp: int
    expansion_len: int


SubThreat = Union[UpperExpansion, LowerExpansion]


def sub_threat_tag(sub: SubThreat) -> str:
    """Fixture-row tag string for a sub-threat (matches ``SubThreat.tag`` in
    the Lean/Rust reference)."""
    if isinstance(sub, UpperExpansion):
        return "UpperExpansion"
    if isinstance(sub, LowerExpansion):
        return "LowerExpansion"
    raise TypeError(f"sub_threat_tag: unknown SubThreat variant {sub!r}")


@dataclass(frozen=True, slots=True)
class Classification:
    """Top-level CaseExpansionMismatch classification. ``sub`` is ``None`` for
    a clear input (no case-mapped expansion present), else the sub-threat that
    fired together with its implicated positions. ``decoded`` mirrors the
    spec's ``Classification.hazard`` byte-context field and is always empty for
    this detector."""

    sub: SubThreat | None = None
    positions: tuple[int, ...] = ()
    decoded: tuple[int, ...] = ()

    @staticmethod
    def clear() -> "Classification":
        """The clear classification — no case-mapped expansion present."""
        return Classification(sub=None, positions=(), decoded=())

    @staticmethod
    def hazard(
        sub: SubThreat,
        positions: tuple[int, ...],
        decoded: tuple[int, ...],
    ) -> "Classification":
        """A hazard classification carrying the sub-threat, implicated
        positions, and (always empty) decoded byte context."""
        return Classification(sub=sub, positions=positions, decoded=decoded)

    def is_clear(self) -> bool:
        """True iff the input is clear."""
        return self.sub is None

    def tag(self) -> str | None:
        """Human-facing tag for a hazard, or ``None`` when clear."""
        if self.sub is None:
            return None
        return sub_threat_tag(self.sub)


@dataclass(frozen=True, slots=True)
class Verdict:
    """The structured output of :func:`detect` (mirrors the Lean/Rust
    ``Verdict``). The expansion summaries are exposed so downstream callers can
    size the buffer growth a case-mapping stage would see:
    ``max_expansion_len`` is the largest per-position case-mapped length (upper
    or lower) across the input, ``1`` when every codepoint maps 1→1 and ``0``
    for empty input."""

    input: tuple[int, ...]
    classify: Classification
    upper_expansion_count: int
    lower_expansion_count: int
    max_expansion_len: int = field(default=0)


# ─────────────────────────────────────────────────────────────────────
# §2 Per-position expansion scan
# ─────────────────────────────────────────────────────────────────────


def _upper_len_at(input_cps: list[int], i: int) -> int:
    """The default-locale uppercase expansion length at position ``i``,
    evaluating the SpecialCasing context (preceding codepoints nearest-first,
    following ones)."""
    rev_prefix = list(reversed(input_cps[:i]))
    suffix = input_cps[i + 1 :]
    return len(upper_codepoint(Locale.DEFAULT, rev_prefix, suffix, input_cps[i]))


def _lower_len_at(input_cps: list[int], i: int) -> int:
    """The default-locale lowercase expansion length at position ``i``."""
    rev_prefix = list(reversed(input_cps[:i]))
    suffix = input_cps[i + 1 :]
    return len(lower_codepoint(Locale.DEFAULT, rev_prefix, suffix, input_cps[i]))


def _first_upper_expansion(input_cps: list[int]) -> tuple[int, int, int] | None:
    """First position whose default uppercase mapping expands to more than one
    codepoint, as ``(base_pos, cp, expansion_len)``; ``None`` when none does."""
    for i, cp in enumerate(input_cps):
        length = _upper_len_at(input_cps, i)
        if length > 1:
            return (i, cp, length)
    return None


def _first_lower_expansion(input_cps: list[int]) -> tuple[int, int, int] | None:
    """First position whose default lowercase mapping expands to more than one
    codepoint, as ``(base_pos, cp, expansion_len)``; ``None`` when none does."""
    for i, cp in enumerate(input_cps):
        length = _lower_len_at(input_cps, i)
        if length > 1:
            return (i, cp, length)
    return None


def _upper_expansion_count(input_cps: list[int]) -> int:
    """Count of positions whose default uppercase mapping expands."""
    return sum(1 for i in range(len(input_cps)) if _upper_len_at(input_cps, i) > 1)


def _lower_expansion_count(input_cps: list[int]) -> int:
    """Count of positions whose default lowercase mapping expands."""
    return sum(1 for i in range(len(input_cps)) if _lower_len_at(input_cps, i) > 1)


def _max_expansion_len(input_cps: list[int]) -> int:
    """Maximum case-mapped expansion length across all positions (the larger of
    the upper and lower mapped lengths per position), ``0`` for empty input."""
    acc = 0
    for i in range(len(input_cps)):
        here = max(_upper_len_at(input_cps, i), _lower_len_at(input_cps, i))
        if here > acc:
            acc = here
    return acc


# ─────────────────────────────────────────────────────────────────────
# §3 Top-level detection
# ─────────────────────────────────────────────────────────────────────


def detect(input_cps: list[int]) -> Verdict:
    """The CaseExpansionMismatch detection function. Fires ``UpperExpansion``
    on the first position whose default uppercase mapping expands; failing
    that, ``LowerExpansion`` on the first position whose default lowercase
    mapping expands; otherwise clear."""
    upper = _first_upper_expansion(input_cps)
    if upper is not None:
        pos, cp, length = upper
        classification = Classification.hazard(
            sub=UpperExpansion(base_pos=pos, cp=cp, expansion_len=length),
            positions=(pos,),
            decoded=(),
        )
    else:
        lower = _first_lower_expansion(input_cps)
        if lower is not None:
            pos, cp, length = lower
            classification = Classification.hazard(
                sub=LowerExpansion(base_pos=pos, cp=cp, expansion_len=length),
                positions=(pos,),
                decoded=(),
            )
        else:
            classification = Classification.clear()
    return Verdict(
        input=tuple(input_cps),
        classify=classification,
        upper_expansion_count=_upper_expansion_count(input_cps),
        lower_expansion_count=_lower_expansion_count(input_cps),
        max_expansion_len=_max_expansion_len(input_cps),
    )
