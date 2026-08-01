"""Locale-case-inversion detector (UAX #21 / Tier A2).

Mirrors ``Unicode.Security.Form.LocaleCaseInversion``. Detects inputs whose
lowercase fold inverts across locales — the homograph-via-locale attack
(CVE-2007-6692, CVE-2021-30245, the Spotify "İSTANBUL" / "iSTANBUL" incident
class). One stage folds the input under the default locale to compare against a
stored credential while another folds it under Turkish or Lithuanian; the two
folds diverge and the attacker controls which is used where.

Detection compares per-position :func:`lower_codepoint` under each locale
against the default, rather than diffing whole-string :func:`to_lower`, because
``lower_codepoint`` evaluates the SpecialCasing context predicates (After_I,
More_Above, Not_Before_Dot, After_Soft_Dotted, Final_Sigma) with the full
surrounding context. Turkish divergence takes priority over Lithuanian
(SpecialCasing has no ``az``-only codepoint, so Turkish covers Azeri).
"""

from dataclasses import dataclass

from ..casing import Locale, lower_codepoint

__all__ = ["Detection", "detect"]


@dataclass(frozen=True, slots=True)
class Detection:
    """One locale-case-inversion scan result. ``sub`` is ``None`` for a clear
    input, else the divergent locale's tag, with the first divergent position."""

    sub: str | None
    positions: tuple[int, ...]


def _first_locale_divergence(loc: Locale, input_cps: list[int]) -> tuple[int, int] | None:
    """First input position whose ``lower_codepoint`` under ``loc`` differs from
    the default-locale result, with the codepoint there."""
    rev_prefix: list[int] = []
    for index, cp in enumerate(input_cps):
        suffix = input_cps[index + 1 :]
        default_lower = lower_codepoint(Locale.DEFAULT, rev_prefix, suffix, cp)
        locale_lower = lower_codepoint(loc, rev_prefix, suffix, cp)
        if default_lower != locale_lower:
            return (index, cp)
        rev_prefix.insert(0, cp)
    return None


def detect(input_cps: list[int]) -> Detection:
    """Detect an input whose lowercase fold inverts across locales. Turkish
    divergence takes priority; Lithuanian is reached only when no Turkish
    divergence is found."""
    turkish = _first_locale_divergence(Locale.TURKISH, input_cps)
    if turkish is not None:
        pos, _cp = turkish
        return Detection(sub="TurkishCaseDivergence", positions=(pos,))
    lithuanian = _first_locale_divergence(Locale.LITHUANIAN, input_cps)
    if lithuanian is not None:
        pos, _cp = lithuanian
        return Detection(sub="LithuanianCaseDivergence", positions=(pos,))
    return Detection(sub=None, positions=())
