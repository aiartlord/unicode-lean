"""Surrogate-reassembly / malformed-byte-stream detection.

Threat model.  Tier C.  An adversary hides intent in a byte stream
that is not well-formed UTF-8 — an overlong encoding, a CESU-8 /
surrogate codepoint, a truncated sequence, an invalid start or
continuation byte, or a value beyond U+10FFFF — betting a lenient
decoder will "reassemble" it into something the security scanner
never saw in codepoint form.

Direct port of ``Unicode/Security/Covert/SurrogateReassembly.lean``.
The input codepoint list is treated as a byte stream (one octet per
entry); the family only applies when every entry is a byte
(``< 0x100``), matching the ``looksLikeByteStream`` gate in
``Unicode/Security/RunAll.lean``.  The verdict projects the first
UTF-8 violation found by the shared strict decoder
(:func:`unicode_python.utf8.first_invalid_utf8_offset`) onto a
covert-layer sub-threat.

Sub-threat tags differ from the malformed-utf8 family's tags: a
surrogate codepoint maps to ``"Cesu8"`` (CESU-8 / Java-modified-UTF-8
indicator) and a truncated sequence to ``"Truncated"``.
"""

from dataclasses import dataclass, field

from ...strict import Utf8RejectKind
from ...utf8 import first_invalid_utf8_offset
from ..calculus import ClassificationKind


def looks_like_byte_stream(input_cps: list[int]) -> bool:
    """True iff every entry fits in one octet — the
    ``looksLikeByteStream`` gate.  A codepoint list containing any
    value ``>= 0x100`` is not a byte stream, and running the UTF-8
    decoder on it would be meaningless.
    """
    return all(cp < 0x100 for cp in input_cps)


def sub_threat_of_reject_kind(kind: Utf8RejectKind) -> str:
    """Project a :class:`Utf8RejectKind` to its surrogate-reassembly
    sub-threat tag, mirroring ``subThreatOfRejectKind`` in the Lean
    spec.  These tags DIFFER from the malformed-utf8 family's tags.
    """
    if kind is Utf8RejectKind.OVERLONG_ENCODING:
        return "Overlong"
    if kind is Utf8RejectKind.SURROGATE_CODEPOINT:
        return "Cesu8"
    if kind is Utf8RejectKind.TRUNCATED_SEQUENCE:
        return "Truncated"
    if kind is Utf8RejectKind.INVALID_START_BYTE:
        return "InvalidStartByte"
    if kind is Utf8RejectKind.INVALID_CONTINUATION_BYTE:
        return "InvalidContinuation"
    return "CodepointBeyondMax"


@dataclass(slots=True)
class Verdict:
    """One surrogate-reassembly scan result.

    ``sub`` is ``None`` for a clear input (well-formed UTF-8, or not
    a byte stream); otherwise it carries the sub-threat tag of the
    first UTF-8 violation and ``positions`` carries its byte offset.
    """

    kind: ClassificationKind
    sub: str | None = None
    positions: list[int] = field(default_factory=list)


def sub_threat_tag(sub: str) -> str:
    """Identity projection kept for wiring symmetry with the sibling
    covert detectors, whose ``sub`` payloads are structured objects.
    Here the sub-threat is already the tag string."""
    return sub


def detect(input_cps: list[int]) -> Verdict:
    """Detect a malformed UTF-8 byte stream hidden in a codepoint
    list.  Only applies to byte-stream-shaped input (every entry
    ``< 0x100``); otherwise clear.  Reports the sub-threat of the
    first violation at its byte offset.
    """
    if not looks_like_byte_stream(input_cps):
        return Verdict(kind=ClassificationKind.CLEAR)
    invalid = first_invalid_utf8_offset(bytes(input_cps))
    if invalid is None:
        return Verdict(kind=ClassificationKind.CLEAR)
    offset, kind = invalid
    return Verdict(
        kind=ClassificationKind.HAZARD,
        sub=sub_threat_of_reject_kind(kind),
        positions=[offset],
    )


__all__ = [
    "Verdict",
    "detect",
    "looks_like_byte_stream",
    "sub_threat_of_reject_kind",
    "sub_threat_tag",
]
