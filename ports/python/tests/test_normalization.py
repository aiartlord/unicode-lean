"""NFKD / NFKC normalization tests for the UCD-table-backed
compatibility-decomposition pipeline (mirrors the Rust port's
``nfkc_nfkd_tests`` in ``security/identity/ucd.rs``).

All expected values are built from the vendored UCD 17.0.0 tables,
never Python's stdlib ``unicodedata`` (which may track a different
Unicode version)."""

from unicode_python.security.identity import ucd


def test_to_nfkc_known_vectors() -> None:
    # ﬁ ligature (U+FB01) → "fi"
    assert ucd.to_nfkc([0xFB01]) == [0x66, 0x69]
    # ① circled digit one (U+2460) → "1"
    assert ucd.to_nfkc([0x2460]) == [0x31]
    # Fullwidth A (U+FF21) → "A"
    assert ucd.to_nfkc([0xFF21]) == [0x41]
    # Precomposed é (U+00E9) stays é under NFKC.
    assert ucd.to_nfkc([0x00E9]) == [0x00E9]
    # Decomposed e + combining acute → é under NFKC.
    assert ucd.to_nfkc([0x0065, 0x0301]) == [0x00E9]
    # Hangul jamo L+V+T → precomposed syllable 한 (U+D55C).
    assert ucd.to_nfkc([0x1112, 0x1161, 0x11AB]) == [0xD55C]
    # Plain ASCII unchanged.
    assert ucd.to_nfkc([0x48, 0x69]) == [0x48, 0x69]


def test_to_nfkd_known_vectors() -> None:
    # Fullwidth A → "A" (compatibility decomposition, no recomposition).
    assert ucd.to_nfkd([0xFF21]) == [0x41]
    # ﬁ → "fi".
    assert ucd.to_nfkd([0xFB01]) == [0x66, 0x69]
    # Precomposed é → e + combining acute under NFKD.
    assert ucd.to_nfkd([0x00E9]) == [0x0065, 0x0301]


def test_compose_blocking_d115() -> None:
    """Canonical composition honors the UAX #15 D115 blocking rule,
    matching the Lean spec ``Unicode.Normalization.Compose.stepCompose``.

    A starter candidate is blocked from the active starter by any
    buffered non-starter between them; a non-starter is blocked only by
    a buffered combiner whose CCC is >= its own."""
    # Hangul L + combining grave (CCC 230) + Hangul V: the grave stands
    # between L and V, so V is blocked and L+V must NOT compose to U+AC00.
    assert ucd.to_nfc([0x1100, 0x0300, 0x1161]) == [0x1100, 0x0300, 0x1161]
    # Same jamo without the intervening mark composes normally.
    assert ucd.to_nfc([0x1100, 0x1161]) == [0xAC00]
    assert ucd.to_nfc([0x1100, 0x1161, 0x11A8]) == [0xAC01]
    # A + combining-below (CCC 220) + combining-grave (CCC 230): grave has
    # the higher CCC, so it is not blocked and composes with A to À, while
    # the lower-CCC below-mark remains buffered.
    assert ucd.to_nfc([0x0041, 0x0316, 0x0300]) == [0x00C0, 0x0316]
