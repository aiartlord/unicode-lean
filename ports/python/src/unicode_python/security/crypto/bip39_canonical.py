"""BIP-39 wordlist layer for Bip39Canonical.

Mirrors sections 5-6 of ``Unicode.Security.Crypto.Bip39Canonical``: splitting a
canonical-form codepoint sequence into words at ``U+0020`` boundaries, and
membership / language resolution against the ten BIP-39 wordlists (English,
Japanese, Korean, Spanish, Chinese Simplified, Chinese Traditional, French,
Italian, Czech, Portuguese). Words and wordlist entries are compared as
codepoint sequences, matching the kernel-visible ``wordlistCps`` tables in
``Unicode.Generated.BIP39``.

The canonicalisation pipeline (NFKD -> toLower -> collapse whitespace -> trim)
and the top-level ``detect`` compose on top of this layer; ``toLower`` depends
on the casing subsystem and lands with it.
"""

from enum import Enum
from pathlib import Path

_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "bip39"


class Language(Enum):
    """The ten BIP-39 wordlist languages. The ``value`` is the vendored
    wordlist filename stem."""

    ENGLISH = "english"
    JAPANESE = "japanese"
    KOREAN = "korean"
    SPANISH = "spanish"
    CHINESE_SIMPLIFIED = "chinese_simplified"
    CHINESE_TRADITIONAL = "chinese_traditional"
    FRENCH = "french"
    ITALIAN = "italian"
    CZECH = "czech"
    PORTUGUESE = "portuguese"


# Declaration order, matching ``Unicode.Generated.BIP39.allLanguages``. English
# is first, so ``unique_language`` resolves an input that several wordlists
# could cover to English exactly as the Lean ``findSome?`` over ``allLanguages``
# does.
ALL_LANGUAGES = [
    Language.ENGLISH,
    Language.JAPANESE,
    Language.KOREAN,
    Language.SPANISH,
    Language.CHINESE_SIMPLIFIED,
    Language.CHINESE_TRADITIONAL,
    Language.FRENCH,
    Language.ITALIAN,
    Language.CZECH,
    Language.PORTUGUESE,
]

_wordlist_cache: dict[Language, frozenset[tuple[int, ...]]] = {}


def _wordlist_cps(lang: Language) -> frozenset[tuple[int, ...]]:
    """The language's 2,048 words as codepoint tuples, parsed once from the
    vendored line-separated wordlist and memoised."""
    cached = _wordlist_cache.get(lang)
    if cached is not None:
        return cached
    text = (_DATA_DIR / f"{lang.value}.txt").read_text(encoding="utf-8")
    entries = frozenset(
        tuple(ord(ch) for ch in line) for line in text.split("\n") if line != ""
    )
    _wordlist_cache[lang] = entries
    return entries


def split_words(canonical: list[int]) -> list[list[int]]:
    """Split a canonical-form codepoint sequence into words at ``U+0020``
    boundaries; empty runs between separators contribute no word."""
    words: list[list[int]] = []
    current: list[int] = []
    for cp in canonical:
        if cp == 0x0020:
            if current:
                words.append(current)
                current = []
        else:
            current.append(cp)
    if current:
        words.append(current)
    return words


def is_in_wordlist(lang: Language, word: list[int]) -> bool:
    """True iff ``word`` (as codepoints) appears in ``lang``'s wordlist."""
    return tuple(word) in _wordlist_cps(lang)


def wordlists_containing(word: list[int]) -> list[Language]:
    """Every language whose wordlist contains ``word``; empty if none do."""
    return [lang for lang in ALL_LANGUAGES if is_in_wordlist(lang, word)]


def unique_language(words: list[list[int]]) -> Language | None:
    """The first language whose wordlist covers every word in ``words``, else
    ``None``. Empty ``words`` returns English (every predicate holds vacuously),
    matching the Lean ``findSome?`` over ``allLanguages``."""
    for lang in ALL_LANGUAGES:
        if all(is_in_wordlist(lang, word) for word in words):
            return lang
    return None
