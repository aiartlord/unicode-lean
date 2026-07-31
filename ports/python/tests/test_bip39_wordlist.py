"""BIP-39 wordlist-layer tests.

Ground truth: the section 5-6 spot-check theorems in
``Unicode.Security.Crypto.Bip39Canonical`` (english_contains_abandon,
nonsense_in_no_wordlist, uniqueLanguage_abandon, uniqueLanguage_empty) and the
``every_wordlist_2048`` invariant from ``Unicode.Generated.BIP39``."""

from unicode_python.security.crypto.bip39_canonical import (
    ALL_LANGUAGES,
    Language,
    _wordlist_cps,
    is_in_wordlist,
    split_words,
    unique_language,
    wordlists_containing,
)

# "abandon" and "qzqzqz" as codepoint sequences.
ABANDON = [0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E]
NONSENSE = [0x71, 0x7A, 0x71, 0x7A, 0x71, 0x7A]


def test_every_wordlist_has_2048_entries() -> None:
    for lang in ALL_LANGUAGES:
        assert len(_wordlist_cps(lang)) == 2048, lang


def test_english_contains_abandon() -> None:
    assert is_in_wordlist(Language.ENGLISH, ABANDON) is True


def test_nonsense_in_no_wordlist() -> None:
    assert wordlists_containing(NONSENSE) == []


def test_unique_language_abandon() -> None:
    assert unique_language([ABANDON]) is Language.ENGLISH


def test_unique_language_empty() -> None:
    assert unique_language([]) is Language.ENGLISH


def test_split_words_boundaries() -> None:
    # "a b" -> [[a], [b]]; leading / trailing / double spaces contribute no
    # empty words (canonical form never has them, but the split is robust).
    assert split_words([0x61, 0x20, 0x62]) == [[0x61], [0x62]]
    assert split_words([0x20, 0x61, 0x20, 0x20, 0x62, 0x20]) == [[0x61], [0x62]]
    assert split_words([]) == []


def test_first_words_of_each_wordlist_are_members() -> None:
    # Sanity across all ten languages: the first line of each vendored wordlist
    # round-trips through membership (guards the codepoint decoding for CJK /
    # accented scripts, not just ASCII English).
    from pathlib import Path

    data = Path(__file__).resolve().parents[1] / "src" / "unicode_python" / "data" / "bip39"
    for lang in ALL_LANGUAGES:
        first = (data / f"{lang.value}.txt").read_text(encoding="utf-8").split("\n")[0]
        word = [ord(ch) for ch in first]
        assert is_in_wordlist(lang, word), (lang, first)
