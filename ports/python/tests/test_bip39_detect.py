"""bip39-canonical detect tests.

Ground truth: the detect spot-check theorems in
``Unicode.Security.Crypto.Bip39CanonicalVectorsDetect`` and the
canonicalisation spot-checks in ``Unicode.Security.Crypto.Bip39Canonical``."""

from unicode_python.security.crypto.bip39_canonical import (
    Language,
    bip39_canonical,
    detect,
)

ABANDON = [0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E]
ABOUT = [0x61, 0x62, 0x6F, 0x75, 0x74]


def _tag(cps: list[int]) -> str | None:
    return detect(cps).classify.tag


def test_canonicalisation_spot_checks() -> None:
    assert bip39_canonical([]) == []
    assert bip39_canonical([0x61, 0x20, 0x20, 0x62]) == [0x61, 0x20, 0x62]
    assert bip39_canonical([0x61, 0x20]) == [0x61]
    assert bip39_canonical([0x20, 0x61]) == [0x61]
    assert bip39_canonical([0x41]) == [0x61]
    assert bip39_canonical([0x61, 0x3000, 0x62]) == [0x61, 0x20, 0x62]


def test_detect_hazard_tags() -> None:
    assert _tag(ABANDON + [0x20]) == "TrailingWhitespace"
    assert _tag([0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E]) == "MixedCase"
    assert _tag(ABANDON + [0x20, 0x20] + ABOUT) == "WhitespaceAnomaly"
    assert _tag([0x20] + ABANDON) == "WhitespaceAnomaly"
    assert _tag([0xFB00]) == "NonNFKD"  # ﬀ ligature
    assert _tag([0x61, 0x00A0, 0x62]) == "NonNFKD"  # NBSP
    assert _tag([0x71, 0x7A, 0x71, 0x7A]) == "WordlistMismatch"  # "qzqz"


def test_detect_positions() -> None:
    assert detect(ABANDON + [0x20]).classify.positions == [7]
    assert detect([0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E]).classify.positions == [0]


def test_detect_clear_and_wordcount() -> None:
    empty = detect([])
    assert empty.classify.is_clear is True
    assert empty.classify.language is Language.ENGLISH

    # "abandon" x11 + "about" — a canonical 12-word English mnemonic.
    mnemonic: list[int] = []
    for _ in range(11):
        mnemonic += ABANDON + [0x20]
    mnemonic += ABOUT
    verdict = detect(mnemonic)
    assert verdict.classify.is_clear is True
    assert verdict.classify.language is Language.ENGLISH
    assert verdict.word_count == 12
