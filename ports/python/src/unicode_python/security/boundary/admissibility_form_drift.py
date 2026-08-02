"""AdmissibilityFormDrift — cross-layer identifier-admissibility x form drift
(boundary-layer detector).

Byte-faithful transliteration of the verified Rust reference implementation
(``Unicode.Security.Boundary.AdmissibilityFormDrift``).

Fires on inputs whose UTS #39 whole-string ``is_allowed_identifier`` verdict
differs between the input and its NFKC form.  This is the string-level
complement of IdentifierFormDrift (which scans ``Identifier_Status`` against the
per-codepoint NFKD head): here the whole-string admissibility predicate is
evaluated twice — once on the input, once on ``to_nfkc(input)``.  The two are
not redundant.  In particular, a sequence of decomposed Hangul jamos passes the
per-codepoint scan cleanly (each jamo has identity NFKD and Restricted status on
both sides) but fires here: the jamo sequence is rejected by
``is_allowed_identifier``, while its NFKC composition into a precomposed Hangul
syllable is accepted.

It reuses the port's own UTS #39 admissibility predicate
(``ucd.is_allowed_identifier`` = UAX #31 default identifier AND every codepoint
Allowed) and NFKC pipeline (``ucd.to_nfkc``), never a host normalization or
identifier library.

Sub-threat (direction-agnostic):

  - ``AdmissibilityFormDrift`` — ``is_allowed_identifier(input) !=
    is_allowed_identifier(to_nfkc(input))``.  The pair of booleans is carried so
    the verdict records which direction the drift goes; no position is reported
    because the predicate is whole-string.
"""

from dataclasses import dataclass, field
from enum import Enum

from ..identity.ucd import is_allowed_identifier, to_nfkc


# ─────────────────────────────────────────────────────────────────────
# §1 Types
# ─────────────────────────────────────────────────────────────────────


class SubThreatKind(Enum):
    """Sub-threat enumeration for AdmissibilityFormDrift (a single member)."""

    ADMISSIBILITY_FORM_DRIFT = "AdmissibilityFormDrift"


@dataclass(frozen=True, slots=True)
class SubThreat:
    """The whole-string admissibility verdict differs between the input and its
    NFKC form.  ``input_admissible`` is ``is_allowed_identifier(input)``;
    ``nfkc_admissible`` is ``is_allowed_identifier(to_nfkc(input))``."""

    kind: SubThreatKind
    input_admissible: bool
    nfkc_admissible: bool

    def tag(self) -> str:
        """Fixture-row tag string for this sub-threat.  Dispatch is explicit
        with an error on the unreachable arm — no catch-all default."""
        if self.kind is SubThreatKind.ADMISSIBILITY_FORM_DRIFT:
            return "AdmissibilityFormDrift"
        raise ValueError(f"unreachable SubThreat kind: {self.kind!r}")


@dataclass(frozen=True, slots=True)
class Classification:
    """Top-level classification for AdmissibilityFormDrift.  ``sub`` is ``None``
    for a clear input (the admissibility verdict agrees across forms); otherwise
    it holds the sub-threat that fired, ``positions`` the implicated positions
    (always empty — the predicate is whole-string), and ``decoded`` the
    decoded-byte projection (always empty here; shape parity with the
    reference)."""

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
    """The structured output of ``detect``.  Mirrors the reference verdict: the
    scanned input, the classification, and the two whole-string admissibility
    booleans (input and its NFKC form)."""

    input_cps: list[int]
    classify: Classification
    input_admissible: bool
    nfkc_admissible: bool


# ─────────────────────────────────────────────────────────────────────
# §2 Top-level detection
# ─────────────────────────────────────────────────────────────────────


def detect(input_cps: list[int]) -> Verdict:
    """The AdmissibilityFormDrift detection function.  Evaluates the whole-string
    admissibility predicate on the input and on its NFKC form; when the two
    verdicts disagree the result is a hazard carrying both booleans, otherwise it
    is clear."""
    nfkc = to_nfkc(input_cps)
    in_ok = is_allowed_identifier(input_cps)
    nfkc_ok = is_allowed_identifier(nfkc)

    if in_ok == nfkc_ok:
        classification = Classification(sub=None, positions=[], decoded=[])
    else:
        classification = Classification(
            sub=SubThreat(
                kind=SubThreatKind.ADMISSIBILITY_FORM_DRIFT,
                input_admissible=in_ok,
                nfkc_admissible=nfkc_ok,
            ),
            positions=[],
            decoded=[],
        )

    return Verdict(
        input_cps=list(input_cps),
        classify=classification,
        input_admissible=in_ok,
        nfkc_admissible=nfkc_ok,
    )


__all__ = [
    "Classification",
    "SubThreat",
    "SubThreatKind",
    "Verdict",
    "detect",
]
