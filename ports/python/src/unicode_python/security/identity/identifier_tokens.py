"""The identifier-shaped tokens of running text.

Direct port of ``Unicode/Security/Identity/IdentifierTokens.lean``. A source
file or a message is not one identifier, and the identifier detectors judge a
whole document wrongly when handed one; switching them off for running text is
wrong the other way, because ``scоpe`` with a Cyrillic о inside a source file is
exactly the homograph they exist to catch. The reading that is right for both is
per token: a maximal run of codepoints with the UAX #31 ``XID_Continue``
property, judged as the identifier it is. No language is assumed and no region
is exempt.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import ucd


@dataclass(frozen=True, slots=True)
class Token:
    """One token: where it starts in the input, and its codepoints. Mirrors
    ``Token``."""

    start: int
    cps: tuple[int, ...]


def is_token_char(cp: int) -> bool:
    """True iff ``cp`` may continue an identifier: UAX #31 ``XID_Continue``.
    Mirrors ``isTokenChar``."""
    return ucd.is_xid_continue(cp)


def tokens(input_cps: list[int]) -> list[Token]:
    """The identifier-shaped tokens of ``input_cps``, in input order: maximal
    runs of ``XID_Continue`` codepoints, each with the position it starts at.
    Mirrors ``tokens``."""
    out: list[Token] = []
    start: int | None = None
    current: list[int] = []
    for idx, cp in enumerate(input_cps):
        if is_token_char(cp):
            if start is None:
                start = idx
            current.append(cp)
        elif start is not None:
            out.append(Token(start=start, cps=tuple(current)))
            start = None
            current = []
    if start is not None:
        out.append(Token(start=start, cps=tuple(current)))
    return out


def shift_positions(start: int, positions: list[int]) -> list[int]:
    """Shift a position list from token-relative to input-relative. Mirrors
    ``shiftPositions``."""
    return [p + start for p in positions]


__all__ = ["Token", "is_token_char", "shift_positions", "tokens"]
