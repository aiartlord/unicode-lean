"""IdentifierFormDrift — cross-layer identifier x form drift (boundary detector).

Byte-faithful transliteration of the verified Rust reference implementation
(``Unicode.Security.Boundary.IdentifierFormDrift``).

Threat model.  Tier A2 two-system bypass.  An identity validator and a form
normalizer disagree about a codepoint: stage A runs the UTS #39
``Identifier_Status`` check before normalisation and rejects, say, U+1D44E
MATHEMATICAL ITALIC SMALL A (Restricted); stage B normalises first and then
runs the same check, seeing U+0061 'a' (Allowed) and accepting.  The attacker
controls which stage processes the input and exploits the disagreement.  The
same shape covers fullwidth (U+FF21), circled (U+24B6), ligature (U+FB01), and
Roman-numeral (U+2163) compatibility forms.

The detector fires on the *form transition* itself — it reports every input
position whose ``Identifier_Status`` differs from the ``Identifier_Status`` of
that codepoint's NFKD head.  This is orthogonal to the single-form identity-
spoofing detectors (which examine the input under one form) and stronger than a
form-of-input fold (it asks whether the identifier verdict changes, not whether
any output bit changes).

Note on Hangul: precomposed syllables are Allowed while their NFKD-head jamos
are Restricted, so pure Korean text fires; callers intending to accept Korean
identifiers should apply NFC before evaluating admissibility.

It reuses the port's own UTS #39 ``Identifier_Status`` predicate
(``is_id_allowed``) and NFKD pipeline (``to_nfkd``), never a host normalization
or identifier library.

Sub-threat (direction-agnostic):

  - ``IdentifierStatusShift`` — the first input position whose
    ``Identifier_Status`` differs from its NFKD-head's.  The verdict carries the
    total shift count.
"""

from dataclasses import dataclass, field
from enum import Enum

from ..identity.ucd import is_id_allowed, to_nfkd


# ─────────────────────────────────────────────────────────────────────
# §1 Types
# ─────────────────────────────────────────────────────────────────────


class SubThreatKind(Enum):
    """Sub-threat enumeration for IdentifierFormDrift (a single member)."""

    IDENTIFIER_STATUS_SHIFT = "IdentifierStatusShift"


@dataclass(frozen=True, slots=True)
class SubThreat:
    """A codepoint at ``base_pos`` whose ``Identifier_Status`` differs from its
    NFKD-head's (codepoint ``cp``)."""

    kind: SubThreatKind
    base_pos: int
    cp: int

    def tag(self) -> str:
        """Fixture-row tag string for this sub-threat.  Dispatch is explicit
        with an error on the unreachable arm — no catch-all default."""
        if self.kind is SubThreatKind.IDENTIFIER_STATUS_SHIFT:
            return "IdentifierStatusShift"
        raise ValueError(f"unreachable SubThreat kind: {self.kind!r}")


@dataclass(frozen=True, slots=True)
class Classification:
    """Top-level classification for IdentifierFormDrift.  ``sub`` is ``None`` for
    a clear input; otherwise it holds the sub-threat that fired, ``positions``
    the implicated positions, and ``decoded`` the decoded-byte projection
    (always empty here; shape parity with the reference)."""

    sub: SubThreat | None = None
    positions: list[int] = field(default_factory=list)
    decoded: list[int] = field(default_factory=list)

    def is_clear(self) -> bool:
        """True iff the classification is clear."""
        return self.sub is None

    def tag(self) -> str | None:
        """Human-facing tag for a hazard, or ``None`` when clear."""
        if self.sub is None:
            return None
        return self.sub.tag()


@dataclass(frozen=True, slots=True)
class Verdict:
    """The structured output of ``detect``.  Mirrors the reference verdict:
    the scanned input, the classification, and the total status-shift count."""

    input_cps: list[int]
    classify: Classification
    shift_count: int


# ─────────────────────────────────────────────────────────────────────
# §2 Core predicates
# ─────────────────────────────────────────────────────────────────────


def nfkd_head_allowed(cp: int) -> bool:
    """``Identifier_Status = Allowed`` of the first codepoint of ``cp``'s NFKD
    form, or ``cp``'s own status when NFKD is empty (defensive — ``to_nfkd`` is
    total and returns at least ``[cp]``).  Reuses the port's own UTS #39
    predicate and NFKD pipeline."""
    head = to_nfkd([cp])
    if head:
        return is_id_allowed(head[0])
    return is_id_allowed(cp)


# ─────────────────────────────────────────────────────────────────────
# §3 Sub-detectors
# ─────────────────────────────────────────────────────────────────────


def _first_status_shift(input_cps: list[int]) -> tuple[int, int] | None:
    """First input position whose ``is_id_allowed`` differs from its NFKD-head's."""
    for index, cp in enumerate(input_cps):
        if not is_id_allowed(cp) and nfkd_head_allowed(cp):
            return (index, cp)
    return None


def _status_shift_count(input_cps: list[int]) -> int:
    """Total count of input positions where the per-cp status shifts under NFKD."""
    return sum(
        1 for cp in input_cps if not is_id_allowed(cp) and nfkd_head_allowed(cp)
    )


# ─────────────────────────────────────────────────────────────────────
# §4 Top-level detection
# ─────────────────────────────────────────────────────────────────────


def detect(input_cps: list[int]) -> Verdict:
    """The IdentifierFormDrift detection function.  If a status shift is present
    the verdict is a hazard carrying the first shifting position and codepoint;
    otherwise it is clear.  The shift count is always the total over the input."""
    shift = _first_status_shift(input_cps)
    if shift is not None:
        pos, cp = shift
        classification = Classification(
            sub=SubThreat(
                kind=SubThreatKind.IDENTIFIER_STATUS_SHIFT,
                base_pos=pos,
                cp=cp,
            ),
            positions=[pos],
            decoded=[],
        )
    else:
        classification = Classification(sub=None, positions=[], decoded=[])

    return Verdict(
        input_cps=list(input_cps),
        classify=classification,
        shift_count=_status_shift_count(input_cps),
    )


__all__ = [
    "Classification",
    "SubThreat",
    "SubThreatKind",
    "Verdict",
    "detect",
    "nfkd_head_allowed",
]
