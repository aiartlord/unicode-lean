"""NFC-idempotence-witness detector (F6).

Mirrors ``Unicode.Security.Form.NfcIdempotenceWitness``. Detects inputs that
are not already in NFC (or, failing that, not in NFKC) — the silent
normalization-drift class where a signer and verifier pick different canonical
forms and their hashes diverge.

Compares ``input`` element-wise against ``to_nfc(input)`` and ``to_nfkc(input)``,
reporting the first divergent position: a mismatch against NFC is
``NonNfcForm``; a sequence already in NFC but not NFKC is ``NonNfkcCompatForm``.
"""

from dataclasses import dataclass

from ..identity.ucd import to_nfc, to_nfkc

__all__ = ["Detection", "detect"]


@dataclass(frozen=True, slots=True)
class Detection:
    """One NFC-idempotence-witness scan result. ``sub`` is ``None`` for a clear
    input (already in NFC and NFKC), else the divergence tag with its first
    position."""

    sub: str | None
    positions: tuple[int, ...]


def _first_divergence(a: list[int], b: list[int]) -> int | None:
    """First index at which two sequences diverge (in element, or one ends);
    ``None`` when identical."""
    common = min(len(a), len(b))
    for i in range(common):
        if a[i] != b[i]:
            return i
    if len(a) != len(b):
        return common
    return None


def detect(input_cps: list[int]) -> Detection:
    """Detect an input that is not in canonical (NFC), or not in compatibility
    (NFKC), form. NFC divergence takes priority over NFKC."""
    nfc = to_nfc(input_cps)
    pos = _first_divergence(input_cps, nfc)
    if pos is not None:
        return Detection(sub="NonNfcForm", positions=(pos,))
    nfkc = to_nfkc(input_cps)
    pos = _first_divergence(input_cps, nfkc)
    if pos is not None:
        return Detection(sub="NonNfkcCompatForm", positions=(pos,))
    return Detection(sub=None, positions=())
