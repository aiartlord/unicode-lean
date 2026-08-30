#!/usr/bin/env python3
"""Emit the supply-chain text-attack corpus fixture.

The corpus is the acceptance corpus for the supply-chain scanner: source
code, package metadata, filenames, and commit messages that either carry a
Unicode-level attack or are legitimate international text that must pass
clean. Each case names the detector families expected to fire, drawn from
the family vocabulary in `fixtures/security/detectors/`, so the corpus
stays in the repository's own terms.

Cases are written here as Python string literals with explicit escapes and
lowered to codepoint arrays on emit, so the attack payload is readable in
the generator and exact in the fixture.

Every case also carries the profile of the field it is drawn from, so the
corpus can be read two ways: which detectors fire, which is profile-
independent, and what the product does about them, which is not. See the
deployment-context block below for how each profile was chosen.

Run: python3 scripts/internal/generate_supply_chain_corpus.py
Writes: fixtures/security/supply-chain-corpus.json
"""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parents[2] / "fixtures" / "security" / "supply-chain-corpus.json"


def case(
    name: str,
    text: str,
    disposition: str,
    families: list[str],
    provenance: str,
) -> dict[str, object]:
    """One corpus row. `disposition` is `hazard` or `clear`."""
    if disposition not in ("hazard", "clear"):
        raise ValueError(f"{name}: disposition must be hazard or clear")
    if disposition == "clear" and families:
        raise ValueError(f"{name}: a clear case must expect no families")
    if disposition == "hazard" and not families:
        raise ValueError(f"{name}: a hazard case must name expected families")
    return {
        "name": name,
        "disposition": disposition,
        "expected_families": families,
        "input": [ord(ch) for ch in text],
        "provenance": provenance,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Attacks — every case must produce a hazard from at least one named family
# ═══════════════════════════════════════════════════════════════════════════

ATTACKS = [
    case(
        "trojan-source-commenting-out",
        'if (accessLevel != "user‮ ⁦// Check if admin⁩ ⁦") {',
        "hazard",
        ["source-display-divergence"],
        "CVE-2021-42574, Boucher and Anderson 2021, commenting-out variant. The "
        "bidi stack balances, so the divergence between rendered and lexical "
        "order is the signal, not stack imbalance.",
    ),
    case(
        "trojan-source-stretched-string",
        'const access = "⁦ user ⁩ admin";',
        "hazard",
        ["source-display-divergence"],
        "CVE-2021-42574 stretched-string variant. An isolate pair widens the "
        "apparent extent of a string literal.",
    ),
    case(
        "trojan-source-early-return",
        "if (isAdmin) { ‭return‬; }",
        "hazard",
        ["source-display-divergence"],
        "CVE-2021-42574 early-return variant using LRO U+202D and PDF U+202C.",
    ),
    case(
        "trojan-source-early-return-unbalanced",
        'if (access_level != "user‮ admin");',
        "hazard",
        ["bidi-control-balance", "source-display-divergence"],
        "CVE-2021-42574 early-return C variant. A lone RLO leaves the embedding "
        "stack unbalanced, so the balance checker fires as well.",
    ),
    case(
        "homoglyph-identifier-cyrillic-o",
        "scоpe",
        "hazard",
        ["homoglyph-confusable", "mixed-script-admissibility"],
        "CVE-2021-42694. Cyrillic o U+043E against Latin o in the identifier "
        "`scope`.",
    ),
    case(
        "homoglyph-identifier-dotless-i",
        "admın",
        "hazard",
        ["homoglyph-confusable"],
        "Dotless i U+0131 against Latin i in the identifier `admin`.",
    ),
    case(
        "zero-width-in-identifier",
        "is_ad​min",
        "hazard",
        ["zero-width-payload"],
        "Zero-width space U+200B splitting the identifier `is_admin`.",
    ),
    case(
        "package-name-armenian-seh",
        "reqսests",
        "hazard",
        ["homoglyph-confusable", "mixed-script-admissibility"],
        "Armenian seh U+057D against Latin u in the package name `requests`.",
    ),
    case(
        "nfkc-fold-collision-fi-ligature",
        "ﬁle",
        "hazard",
        ["identifier-form-drift"],
        "The fi ligature U+FB01 folds to `fi` under NFKC, so `ﬁle` and "
        "`file` collide after normalization.",
    ),
    case(
        "normalization-expansion-arabic-ligature",
        "ﷺ",
        "hazard",
        ["normalization-bomb"],
        "U+FDFA expands to eighteen codepoints under NFKC, far past a bounded "
        "expansion factor.",
    ),
    case(
        "domain-confusable-cyrillic-a",
        "аpple.com",
        "hazard",
        ["homoglyph-confusable"],
        "Cyrillic a U+0430 against Latin a in a registrable domain.",
    ),
    case(
        "filename-direction-spoof",
        "invoice‮gnp.exe",
        "hazard",
        ["filename-disguise"],
        "RLO U+202E makes an executable render as `invoiceexe.png`.",
    ),
    case(
        "soft-hyphen-in-import-path",
        "import foo­bar",
        "hazard",
        ["zero-width-payload"],
        "Soft hyphen U+00AD is Default_Ignorable and invisible in an import "
        "path.",
    ),
    case(
        "commit-message-unterminated-rlo",
        "fix: ‮resu ot ssecca tnarg",
        "hazard",
        ["bidi-control-balance"],
        "An unterminated RLO reorders the remainder of a log line.",
    ),
    case(
        "tag-block-in-comment",
        "// note\U000E0001\U000E0041\U000E0042\U000E007F",
        "hazard",
        ["tag-block-payload"],
        "Tag characters U+E0001 and U+E0020..U+E007F carry an invisible payload "
        "inside a comment.",
    ),
]

# ═══════════════════════════════════════════════════════════════════════════
# Negative controls — legitimate text that must produce no finding at all.
# A false positive here is worse than a missed detection, because teams
# switch off a scanner that flags their own language.
# ═══════════════════════════════════════════════════════════════════════════

CONTROLS = [
    case(
        "arabic-string-literal-balanced",
        'const greeting = "‫مرحبا‬";',
        "clear",
        [],
        "Balanced RLE/PDF around an Arabic literal renders exactly as written. "
        "Bidi is not an attack.",
    ),
    case(
        "hebrew-comment",
        "// שלום עולם",
        "clear",
        [],
        "A Hebrew comment in a Hebrew-language codebase.",
    ),
    case(
        "cjk-identifier-single-script",
        "変数名 = 1",
        "clear",
        [],
        "Single-script Japanese identifier. Single-script non-Latin text is not "
        "confusable.",
    ),
    case(
        "korean-identifier-single-script",
        "변수명 = 1",
        "clear",
        [],
        "Single-script Korean identifier.",
    ),
    case(
        "legitimate-diacritics-and-casing",
        "straße İstanbul Nguyễn",
        "clear",
        [],
        "German eszett, Turkish dotted capital I, and Vietnamese stacked "
        "diacritics are ordinary text.",
    ),
    case(
        "emoji-zwj-family-sequence",
        "\U0001F468‍\U0001F469‍\U0001F467",
        "clear",
        [],
        "ZWJ is load-bearing in emoji. A registered family sequence must pass.",
    ),
    case(
        "devanagari-orthographic-zwnj",
        "क्‌ष",
        "clear",
        [],
        "ZWNJ U+200C after the Virama U+094D suppresses a Devanagari conjunct. "
        "RFC 5892 A.1 sanctions it by the Virama rule; it is required for "
        "correct rendering, not a covert channel.",
    ),
    case(
        "persian-orthographic-zwnj",
        "می‌روم",
        "clear",
        [],
        "ZWNJ between a dual-joining Farsi yeh U+06CC and a right-joining reh "
        "U+0631 writes a Persian word boundary inside a cursive run. RFC 5892 "
        "A.1 sanctions it by the joining-type rule.",
    ),
    case(
        "pure-ascii-source",
        "def total(items):\n    return sum(items)\n",
        "clear",
        [],
        "Pure ASCII source. Zero findings, and it should be fast.",
    ),
    case(
        "mathematical-notation",
        "δ = α − β",
        "clear",
        [],
        "U+2212 MINUS SIGN with Greek variables is legitimate technical text.",
    ),
]


# ═══════════════════════════════════════════════════════════════════════════
# Deployment context
# ═══════════════════════════════════════════════════════════════════════════
#
# A corpus case is a claim about a deployment, and the profile is how a caller
# declares which one. It matters because the same bytes are a different
# question in different fields: a Hebrew comment is ordinary in a source file
# and worth a second look in an HTTP header, and `Unicode/Security/Policy.lean`
# already grades the two apart. Scanning every case under one profile asks only
# whether a detector fires; naming the field each case actually lives in also
# asks what the product does about it.
#
# The profile does not change which detectors run -- that is fixed by
# `Unicode/Security/RunAll.lean`, and measurement confirms the finding list is
# identical across profiles. It selects the level in `policyOfProfile`, which
# decides which families are admission-relevant, and so decides the action.
#
# Each choice below is the field the sample is drawn from, not the field that
# produces a convenient answer.

PROFILES = {
    # Source files: the trojan-source variants, a zero-width identifier split,
    # an import path, and a tag block in a comment are all source text.
    "trojan-source-commenting-out": "source-code",
    "trojan-source-stretched-string": "source-code",
    "trojan-source-early-return": "source-code",
    "trojan-source-early-return-unbalanced": "source-code",
    "zero-width-in-identifier": "source-code",
    "soft-hyphen-in-import-path": "source-code",
    "tag-block-in-comment": "source-code",
    # Identifiers and package names are submitted names, which is what the
    # username profile grades.
    "homoglyph-identifier-cyrillic-o": "username",
    "homoglyph-identifier-dotless-i": "username",
    "package-name-armenian-seh": "username",
    "nfkc-fold-collision-fi-ligature": "username",
    "normalization-expansion-arabic-ligature": "username",
    # A registrable domain has its own profile.
    "domain-confusable-cyrillic-a": "domain-name",
    # A filename is rendered to a person, which is the display-name question.
    "filename-direction-spoof": "display-name",
    # A commit message is free-form human text.
    "commit-message-unterminated-rlo": "chat-message",
    # Controls. Source text a multilingual team writes every day.
    "arabic-string-literal-balanced": "source-code",
    "hebrew-comment": "source-code",
    "cjk-identifier-single-script": "source-code",
    "korean-identifier-single-script": "source-code",
    "pure-ascii-source": "source-code",
    "mathematical-notation": "source-code",
    # Rendered human text: a display string, and orthography that only means
    # anything once rendered.
    "legitimate-diacritics-and-casing": "display-name",
    "devanagari-orthographic-zwnj": "display-name",
    "persian-orthographic-zwnj": "display-name",
    "emoji-zwj-family-sequence": "chat-message",
}

# The profile vocabulary of `Unicode.Security.Policy.Profile`, in its order.
KNOWN_PROFILES = (
    "gateway-header",
    "domain-name",
    "dns-label",
    "url",
    "username",
    "display-name",
    "chat-message",
    "source-code",
    "opaque-secret",
    "binary-blob",
)


def attach_profiles(cases: list[dict[str, object]]) -> list[dict[str, object]]:
    """Attach each case's deployment profile, refusing anything unaccounted for.

    A case with no profile, and a profile naming no case, are both errors: the
    corpus states every case's field explicitly, and no case takes a default
    nobody chose for it.
    """
    named = {case["name"] for case in cases}
    missing = sorted(named - set(PROFILES))
    if missing:
        raise ValueError(f"cases with no profile: {', '.join(missing)}")
    unknown_case = sorted(set(PROFILES) - named)
    if unknown_case:
        raise ValueError(f"profiles naming no case: {', '.join(unknown_case)}")
    bad = sorted({p for p in PROFILES.values() if p not in KNOWN_PROFILES})
    if bad:
        raise ValueError(f"not profiles of Unicode.Security.Policy: {', '.join(bad)}")
    return [dict(case, profile=PROFILES[case["name"]]) for case in cases]


def main() -> None:
    payload = {
        "schema": 2,
        "corpus": "supply-chain-text-attacks",
        "cases": attach_profiles(ATTACKS + CONTROLS),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    hazards = sum(1 for c in payload["cases"] if c["disposition"] == "hazard")
    clears = sum(1 for c in payload["cases"] if c["disposition"] == "clear")
    print(f"wrote {OUT} — {hazards} attack cases, {clears} negative controls")


if __name__ == "__main__":
    main()
