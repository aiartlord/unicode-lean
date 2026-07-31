"""UAX #21 case mapping (``toLower`` / ``toUpper``), mirroring
``Unicode.Casing``.

Full case mappings from ``SpecialCasing.txt`` (one-to-many and
context/locale-dependent rows) combined with the simple case mappings in
``UnicodeData.txt`` field 13 (lowercase) / 12 (uppercase). Context predicates
(Final_Sigma, After_Soft_Dotted, More_Above, Not_Before_Dot, After_I) use
canonical combining class plus the ``Cased`` and ``Soft_Dotted`` properties
from ``DerivedCoreProperties.txt``.

This is a shared primitive: ``bip39-canonical`` uses ``toLower(default)``, and
the ``locale-case-inversion`` / ``case-expansion-mismatch`` form detectors
build on ``toLower`` / ``toUpper``.
"""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .identity.ucd import ccc

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _read_data_file(name: str) -> str:
    with (_DATA_DIR / name).open("r", encoding="utf-8") as handle:
        return handle.read()


class Locale(Enum):
    """The locales SpecialCasing.txt distinguishes. ``DEFAULT`` covers
    everything not tagged Turkish / Azeri / Lithuanian."""

    DEFAULT = "default"
    TURKISH = "turkish"
    AZERI = "azeri"
    LITHUANIAN = "lithuanian"


_LOCALE_CONDITIONS = frozenset({"tr", "az", "lt"})


@dataclass(frozen=True, slots=True)
class _Row:
    code: int
    lower: tuple[int, ...]
    title: tuple[int, ...]
    upper: tuple[int, ...]
    conditions: tuple[str, ...]


# ─────────────────────────────────────────────────────────────────────
# Data tables (SpecialCasing rows, simple case mappings, Cased/Soft_Dotted)
# ─────────────────────────────────────────────────────────────────────


def _parse_special_casing() -> dict[int, list[_Row]]:
    rows: dict[int, list[_Row]] = {}
    for raw in _read_data_file("SpecialCasing.txt").split("\n"):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = [f.strip() for f in line.split(";")]
        if len(fields) < 4:
            continue
        code = int(fields[0], 16)
        lower = tuple(int(tok, 16) for tok in fields[1].split())
        title = tuple(int(tok, 16) for tok in fields[2].split())
        upper = tuple(int(tok, 16) for tok in fields[3].split())
        conditions = tuple(fields[4].split()) if len(fields) > 4 and fields[4] else ()
        rows.setdefault(code, []).append(
            _Row(code=code, lower=lower, title=title, upper=upper, conditions=conditions)
        )
    return rows


def _parse_simple_case_mappings() -> tuple[dict[int, int], dict[int, int]]:
    """Return (lowercase, uppercase) maps from UnicodeData.txt fields 13/12.
    Codepoints absent from a map lowercase / uppercase to themselves."""
    lower: dict[int, int] = {}
    upper: dict[int, int] = {}
    for line in _read_data_file("UnicodeData.txt").split("\n"):
        if not line:
            continue
        fields = line.split(";")
        if len(fields) < 15:
            continue
        cp = int(fields[0], 16)
        if fields[12]:
            upper[cp] = int(fields[12], 16)
        if fields[13]:
            lower[cp] = int(fields[13], 16)
    return lower, upper


def _parse_derived_property(name: str) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for raw in _read_data_file("DerivedCoreProperties.txt").split("\n"):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(";", 1)
        if len(parts) < 2 or parts[1].strip() != name:
            continue
        field = parts[0].strip()
        dots = field.find("..")
        if dots < 0:
            cp = int(field, 16)
            out.append((cp, cp))
        else:
            out.append((int(field[:dots], 16), int(field[dots + 2 :], 16)))
    out.sort(key=lambda r: r[0])
    return out


_SPECIAL_ROWS: dict[int, list[_Row]] | None = None
_SIMPLE_LOWER: dict[int, int] | None = None
_SIMPLE_UPPER: dict[int, int] | None = None
_CASED: list[tuple[int, int]] | None = None
_SOFT_DOTTED: list[tuple[int, int]] | None = None


def _special_rows() -> dict[int, list[_Row]]:
    global _SPECIAL_ROWS
    if _SPECIAL_ROWS is None:
        _SPECIAL_ROWS = _parse_special_casing()
    return _SPECIAL_ROWS


def _simple_maps() -> tuple[dict[int, int], dict[int, int]]:
    global _SIMPLE_LOWER, _SIMPLE_UPPER
    if _SIMPLE_LOWER is None or _SIMPLE_UPPER is None:
        _SIMPLE_LOWER, _SIMPLE_UPPER = _parse_simple_case_mappings()
    return _SIMPLE_LOWER, _SIMPLE_UPPER


def _in_ranges(ranges: list[tuple[int, int]], cp: int) -> bool:
    return any(lo <= cp <= hi for lo, hi in ranges)


def _is_cased(cp: int) -> bool:
    global _CASED
    if _CASED is None:
        _CASED = _parse_derived_property("Cased")
    return _in_ranges(_CASED, cp)


def _is_soft_dotted(cp: int) -> bool:
    global _SOFT_DOTTED
    if _SOFT_DOTTED is None:
        _SOFT_DOTTED = _parse_derived_property("Soft_Dotted")
    return _in_ranges(_SOFT_DOTTED, cp)


def simple_lowercase(cp: int) -> int:
    return _simple_maps()[0].get(cp, cp)


def simple_uppercase(cp: int) -> int:
    return _simple_maps()[1].get(cp, cp)


# ─────────────────────────────────────────────────────────────────────
# Context predicates (UAX #21). ``rev_prefix`` is the preceding codepoints
# nearest-first; ``suffix`` the strictly-following ones.
# ─────────────────────────────────────────────────────────────────────


def _more_above_after(suffix: list[int]) -> bool:
    for cp in suffix:
        c = ccc(cp)
        if c == 230:
            return True
        if c == 0:
            return False
    return False


def _after_soft_dotted(rev_prefix: list[int]) -> bool:
    for cp in rev_prefix:
        if _is_soft_dotted(cp):
            return True
        c = ccc(cp)
        if c in (0, 230):
            return False
    return False


def _after_i(rev_prefix: list[int]) -> bool:
    for cp in rev_prefix:
        if cp == 0x0049:
            return True
        c = ccc(cp)
        if c in (0, 230):
            return False
    return False


def _before_dot(suffix: list[int]) -> bool:
    for cp in suffix:
        if cp == 0x0307:
            return True
        if ccc(cp) == 0:
            return False
    return False


def _has_cased_before(rev_prefix: list[int]) -> bool:
    for cp in rev_prefix:
        if _is_cased(cp):
            return True
        if ccc(cp) == 0:
            return False
    return False


def _has_cased_after(suffix: list[int]) -> bool:
    for cp in suffix:
        if _is_cased(cp):
            return True
        if ccc(cp) == 0:
            return False
    return False


def _final_sigma(rev_prefix: list[int], suffix: list[int]) -> bool:
    return _has_cased_before(rev_prefix) and not _has_cased_after(suffix)


def _locale_matches(loc: Locale, conds: tuple[str, ...]) -> bool:
    if not any(c in _LOCALE_CONDITIONS for c in conds):
        return True
    return any(
        (c == "tr" and loc is Locale.TURKISH)
        or (c == "az" and loc is Locale.AZERI)
        or (c == "lt" and loc is Locale.LITHUANIAN)
        for c in conds
    )


def _conditions_hold(
    loc: Locale, rev_prefix: list[int], suffix: list[int], conds: tuple[str, ...]
) -> bool:
    if not _locale_matches(loc, conds):
        return False
    for c in conds:
        if c in _LOCALE_CONDITIONS:
            continue
        if c == "Final_Sigma":
            ok = _final_sigma(rev_prefix, suffix)
        elif c == "Not_Final_Sigma":
            ok = not _final_sigma(rev_prefix, suffix)
        elif c == "After_Soft_Dotted":
            ok = _after_soft_dotted(rev_prefix)
        elif c == "More_Above":
            ok = _more_above_after(suffix)
        elif c == "Not_Before_Dot":
            ok = not _before_dot(suffix)
        elif c == "After_I":
            ok = _after_i(rev_prefix)
        else:  # unrecognised context token — never matches
            ok = False
        if not ok:
            return False
    return True


def _find_special_row(
    loc: Locale, rev_prefix: list[int], suffix: list[int], cp: int
) -> _Row | None:
    candidates = _special_rows().get(cp)
    if candidates is None:
        return None
    # UAX #21: a conditional row whose conditions hold outranks the
    # unconditional row for the same codepoint.
    for row in candidates:
        if row.conditions and _conditions_hold(loc, rev_prefix, suffix, row.conditions):
            return row
    for row in candidates:
        if not row.conditions:
            return row
    return None


def _lower_codepoint(
    loc: Locale, rev_prefix: list[int], suffix: list[int], cp: int
) -> list[int]:
    row = _find_special_row(loc, rev_prefix, suffix, cp)
    if row is not None:
        return list(row.lower)
    return [simple_lowercase(cp)]


def _upper_codepoint(
    loc: Locale, rev_prefix: list[int], suffix: list[int], cp: int
) -> list[int]:
    row = _find_special_row(loc, rev_prefix, suffix, cp)
    if row is not None:
        return list(row.upper)
    return [simple_uppercase(cp)]


def to_lower(loc: Locale, cps: list[int]) -> list[int]:
    """Lowercase a codepoint sequence under ``loc`` (UAX #21 full mapping)."""
    out: list[int] = []
    rev_prefix: list[int] = []
    for index, cp in enumerate(cps):
        suffix = cps[index + 1 :]
        out.extend(_lower_codepoint(loc, rev_prefix, suffix, cp))
        rev_prefix.insert(0, cp)
    return out


def to_upper(loc: Locale, cps: list[int]) -> list[int]:
    """Uppercase a codepoint sequence under ``loc`` (UAX #21 full mapping)."""
    out: list[int] = []
    rev_prefix: list[int] = []
    for index, cp in enumerate(cps):
        suffix = cps[index + 1 :]
        out.extend(_upper_codepoint(loc, rev_prefix, suffix, cp))
        rev_prefix.insert(0, cp)
    return out
