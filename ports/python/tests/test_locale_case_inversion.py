"""Locale-case-inversion detector contract tests.

Mirrors the ``detect_*`` ground-truth theorems in
``Unicode/Security/Form/LocaleCaseInversion.lean``.
"""

from unicode_python.security.form.locale_case_inversion import detect


def _sub(input_cps: list[int]) -> str | None:
    return detect(input_cps).sub


def test_empty_is_clear() -> None:
    assert _sub([]) is None


def test_ascii_without_i_is_clear() -> None:
    assert _sub([0x48, 0x65, 0x6C, 0x6C, 0x6F]) is None


def test_capital_i_fires_turkish() -> None:
    assert _sub([0x0049]) == "TurkishCaseDivergence"
    assert detect([0x0049]).positions == (0,)


def test_dotted_i_fires_turkish() -> None:
    assert _sub([0x0130]) == "TurkishCaseDivergence"


def test_i_with_grave_picks_turkish_first() -> None:
    assert _sub([0x0049, 0x0300]) == "TurkishCaseDivergence"


def test_j_with_grave_fires_lithuanian() -> None:
    assert _sub([0x004A, 0x0300]) == "LithuanianCaseDivergence"
