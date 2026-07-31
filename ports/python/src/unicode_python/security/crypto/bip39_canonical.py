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

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from ..casing import Locale, to_lower
from ..identity.ucd import to_nfkd

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


# ─────────────────────────────────────────────────────────────────────
# Canonicalisation pipeline: NFKD -> toLower(default) -> collapse -> trim.
# ─────────────────────────────────────────────────────────────────────


def is_bip39_whitespace(cp: int) -> bool:
    """The two BIP-39 word separators: U+0020 SPACE and U+3000 IDEOGRAPHIC
    SPACE (Japanese mnemonics)."""
    return cp == 0x0020 or cp == 0x3000


def collapse_whitespace_to_single(cps: list[int]) -> list[int]:
    """Replace every maximal run of BIP-39 whitespace with a single U+0020."""
    out: list[int] = []
    in_ws = False
    for cp in cps:
        if is_bip39_whitespace(cp):
            if not in_ws:
                out.append(0x0020)
            in_ws = True
        else:
            out.append(cp)
            in_ws = False
    return out


def trim_leading_trailing(cps: list[int]) -> list[int]:
    """Strip leading and trailing U+0020 (after whitespace has been collapsed)."""
    start = 0
    end = len(cps)
    while start < end and cps[start] == 0x0020:
        start += 1
    while end > start and cps[end - 1] == 0x0020:
        end -= 1
    return cps[start:end]


def bip39_canonical(cps: list[int]) -> list[int]:
    """The BIP-39 canonical form: NFKD, then default-locale lowercase, then
    whitespace collapse, then leading/trailing trim (spec order)."""
    return trim_leading_trailing(
        collapse_whitespace_to_single(to_lower(Locale.DEFAULT, to_nfkd(cps)))
    )


# ─────────────────────────────────────────────────────────────────────
# Hazard probes (per-priority position finders).
# ─────────────────────────────────────────────────────────────────────


def count_trailing_whitespace(cps: list[int]) -> int:
    count = 0
    for cp in reversed(cps):
        if is_bip39_whitespace(cp):
            count += 1
        else:
            break
    return count


def first_uppercase_pos(cps: list[int]) -> int | None:
    for index, cp in enumerate(cps):
        if 0x41 <= cp <= 0x5A:
            return index
    return None


def first_whitespace_run_pos(cps: list[int]) -> int | None:
    """First position of a leading or consecutive BIP-39 whitespace run; single
    internal separators do not fire."""
    for index, cp in enumerate(cps):
        if is_bip39_whitespace(cp):
            if index == 0:
                return index
            if index + 1 < len(cps) and is_bip39_whitespace(cps[index + 1]):
                return index
    return None


def first_array_divergence(a: list[int], b: list[int]) -> int | None:
    """First position at which ``a`` and ``b`` differ (in element, or one ends);
    ``None`` when identical."""
    for index in range(min(len(a), len(b))):
        if a[index] != b[index]:
            return index
    if len(a) != len(b):
        return min(len(a), len(b))
    return None


# ─────────────────────────────────────────────────────────────────────
# Top-level detection.
# ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Classification:
    is_clear: bool
    language: Language | None
    sub: str | None
    positions: list[int] = field(default_factory=list)

    @property
    def tag(self) -> str | None:
        return self.sub


@dataclass(frozen=True, slots=True)
class Verdict:
    input: list[int]
    classify: Classification
    canonical_form: list[int]
    word_count: int


def _clear(lang: Language) -> Classification:
    return Classification(is_clear=True, language=lang, sub=None, positions=[])


def _hazard(sub: str, positions: list[int]) -> Classification:
    return Classification(is_clear=False, language=None, sub=sub, positions=positions)


def detect(cps: list[int]) -> Verdict:
    """Detect a non-canonical or wordlist-mismatched BIP-39 mnemonic. Six probes
    in priority order (first hit wins), mirroring
    ``Unicode.Security.Crypto.Bip39Canonical.detect``."""
    canonical = bip39_canonical(cps)
    words = split_words(canonical)

    trailing_count = count_trailing_whitespace(cps)
    uppercase_pos = first_uppercase_pos(cps)
    whitespace_pos = first_whitespace_run_pos(cps)

    nfkd = to_nfkd(cps)
    non_nfkd_pos = None if cps == nfkd else first_array_divergence(cps, nfkd)

    wordlists_per_word = [wordlists_containing(word) for word in words]
    first_unknown_idx = next(
        (idx for idx, langs in enumerate(wordlists_per_word) if not langs), None
    )

    if trailing_count > 0:
        classify = _hazard("TrailingWhitespace", [len(cps) - trailing_count])
    elif uppercase_pos is not None:
        classify = _hazard("MixedCase", [uppercase_pos])
    elif whitespace_pos is not None:
        classify = _hazard("WhitespaceAnomaly", [whitespace_pos])
    elif non_nfkd_pos is not None:
        classify = _hazard("NonNFKD", [non_nfkd_pos])
    elif first_unknown_idx is not None:
        classify = _hazard("WordlistMismatch", [first_unknown_idx])
    else:
        unique = unique_language(words)
        if unique is not None:
            classify = _clear(unique)
        else:
            union: list[Language] = []
            for langs in wordlists_per_word:
                for lang in langs:
                    if lang not in union:
                        union.append(lang)
            # LanguageAmbiguous carries the union of possible languages; no
            # single position is implicated.
            classify = Classification(
                is_clear=False, language=None, sub="LanguageAmbiguous", positions=[]
            )

    return Verdict(
        input=cps,
        classify=classify,
        canonical_form=canonical,
        word_count=len(words),
    )
