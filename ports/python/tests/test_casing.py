"""UAX #21 case-mapping tests.

Ground truth: the spot-check theorems in ``Unicode.Casing`` (toLower_hello,
toUpper_hello, toUpper_sharp_s, toLower_I_default / _turkish / _azeri,
toLower_dotted_I_default / _turkish). The differential test pins that the
from-tables ``to_lower`` agrees with the runtime ``str.lower`` on every
codepoint both Unicode versions know — the only allowed differences are
codepoints the (older) runtime has not been assigned yet, mirroring the pinned
UCD 17.0.0 vs runtime-ICU gap the normalization ports have."""

import unicodedata

from unicode_python.security.casing import Locale, to_lower, to_upper


def test_to_lower_spot_checks() -> None:
    assert to_lower(Locale.DEFAULT, [0x48, 0x65, 0x6C, 0x6C, 0x6F]) == [
        0x68, 0x65, 0x6C, 0x6C, 0x6F
    ]
    # Default: I -> i; Turkish/Azeri: I -> dotless i (U+0131).
    assert to_lower(Locale.DEFAULT, [0x0049]) == [0x0069]
    assert to_lower(Locale.TURKISH, [0x0049]) == [0x0131]
    assert to_lower(Locale.AZERI, [0x0049]) == [0x0131]
    # Dotted capital I: default -> i + combining dot above; Turkish -> plain i.
    assert to_lower(Locale.DEFAULT, [0x0130]) == [0x0069, 0x0307]
    assert to_lower(Locale.TURKISH, [0x0130]) == [0x0069]


def test_to_upper_spot_checks() -> None:
    assert to_upper(Locale.DEFAULT, [0x68, 0x65, 0x6C, 0x6C, 0x6F]) == [
        0x48, 0x45, 0x4C, 0x4C, 0x4F
    ]
    # ß uppercases to "SS" (full case mapping).
    assert to_upper(Locale.DEFAULT, [0x00DF]) == [0x0053, 0x0053]


def test_to_lower_matches_runtime_except_version_drift() -> None:
    """Every single-codepoint default lowercasing agrees with the runtime,
    except for codepoints the runtime's older Unicode version has not assigned
    (which the pinned UCD 17.0.0 tables do). A mismatch on a codepoint the
    runtime *does* know would be a real divergence."""
    for cp in range(0x110000):
        if 0xD800 <= cp <= 0xDFFF:
            continue
        tables = to_lower(Locale.DEFAULT, [cp])
        runtime = [ord(c) for c in chr(cp).lower()]
        if tables != runtime:
            # allowed only when the runtime doesn't recognise the codepoint
            assert unicodedata.name(chr(cp), "") == "", (
                f"U+{cp:04X} lowercases to {tables} from tables but "
                f"{runtime} at runtime, and the runtime knows this codepoint"
            )
