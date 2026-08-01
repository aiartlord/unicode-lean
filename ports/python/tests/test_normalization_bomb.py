"""Normalization-bomb detector contract tests.

Mirrors the ``detect_*`` ground-truth theorems in
``Unicode/Security/Form/NormalizationBomb.lean``, plus the two ratio-branch
shapes the module docstring guarantees (FDFB -> NFKD ratio; a Greek extended
form -> NFD ratio).
"""

from unicode_python.security.form.normalization_bomb import detect


def _sub(input_cps: list[int]) -> str | None:
    return detect(input_cps).sub


def test_empty_is_clear() -> None:
    assert _sub([]) is None


def test_ascii_is_clear() -> None:
    assert _sub([0x48, 0x65, 0x6C, 0x6C, 0x6F]) is None


def test_korean_stays_clear() -> None:
    assert _sub([0xD55C]) is None


def test_circled_one_stays_clear() -> None:
    assert _sub([0x2460]) is None


def test_arabic_ligature_fires_single_cp_blowup() -> None:
    assert _sub([0xFDFA]) == "SingleCpBlowup"
    assert detect([0xFDFA]).positions == (0,)


def test_fdfb_fires_nfkd_high_expansion() -> None:
    assert _sub([0xFDFB]) == "NfkdHighExpansion"


def test_greek_extended_fires_nfd_high_expansion() -> None:
    assert _sub([0x1F82]) == "NfdHighExpansion"
