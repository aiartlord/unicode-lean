"""NFC-idempotence-witness detector contract tests.

Mirrors the ``detect_*`` ground-truth theorems in
``Unicode/Security/Form/NfcIdempotenceWitness.lean``.
"""

from unicode_python.security.form.nfc_idempotence_witness import detect


def _sub(input_cps: list[int]) -> str | None:
    return detect(input_cps).sub


def test_empty_is_clear() -> None:
    assert _sub([]) is None


def test_ascii_is_clear() -> None:
    assert _sub([0x48, 0x65, 0x6C, 0x6C, 0x6F]) is None


def test_precomposed_e_acute_is_clear() -> None:
    assert _sub([0x00E9]) is None


def test_decomposed_e_acute_fires_non_nfc() -> None:
    assert _sub([0x0065, 0x0301]) == "NonNfcForm"
    assert detect([0x0065, 0x0301]).positions == (0,)


def test_fi_ligature_fires_non_nfkc() -> None:
    assert _sub([0xFB01]) == "NonNfkcCompatForm"
