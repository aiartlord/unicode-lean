#!/usr/bin/env python3
"""Generate Zig lookup tables from vendored Unicode runtime data."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "data" / "confusables.txt"
OUTPUT = ROOT / "src" / "confusables_data.zig"
UNICODE_DATA_SOURCE = ROOT / "src" / "data" / "UnicodeData.txt"
COMPOSITION_EXCLUSIONS_SOURCE = ROOT / "src" / "data" / "CompositionExclusions.txt"
NORMALIZATION_OUTPUT = ROOT / "src" / "normalization_data.zig"
CASE_FOLDING_SOURCE = ROOT / "src" / "data" / "CaseFolding.txt"
CASE_FOLDING_OUTPUT = ROOT / "src" / "case_folding_data.zig"
BIDI_SOURCE = ROOT / "src" / "data" / "DerivedBidiClass.txt"
BIDI_OUTPUT = ROOT / "src" / "bidi_class_data.zig"
SPECIAL_CASING_SOURCE = ROOT / "src" / "data" / "SpecialCasing.txt"
DERIVED_CORE_PROPERTIES_SOURCE = ROOT / "src" / "data" / "DerivedCoreProperties.txt"
CASING_OUTPUT = ROOT / "src" / "casing_data.zig"
BIP39_DIR = ROOT / "src" / "data" / "bip39"
BIP39_OUTPUT = ROOT / "src" / "bip39_data.zig"

# BIP-39 wordlist languages in Unicode.Generated.BIP39.allLanguages order;
# English first so a mnemonic several wordlists could cover resolves to English.
BIP39_LANGUAGES = [
    "english",
    "japanese",
    "korean",
    "spanish",
    "chinese_simplified",
    "chinese_traditional",
    "french",
    "italian",
    "czech",
    "portuguese",
]


def parse_codepoints(field: str) -> list[int]:
    return [int(token, 16) for token in field.split()]


def parse_confusables(text: str) -> dict[int, list[int]]:
    entries: dict[int, list[int]] = {}
    for raw_line in text.splitlines():
        body = raw_line.split("#", 1)[0].strip()
        if not body:
            continue
        fields = body.split(";")
        if len(fields) < 2:
            continue
        try:
            src = int(fields[0].strip(), 16)
            replacement = parse_codepoints(fields[1].strip())
        except ValueError:
            continue
        if replacement:
            entries[src] = replacement
    return entries


def zig_hex(value: int) -> str:
    return f"0x{value:04X}" if value <= 0xFFFF else f"0x{value:06X}"


def render(entries: dict[int, list[int]]) -> str:
    lines = [
        "// GENERATED FILE - DO NOT EDIT.",
        "// Source: src/data/confusables.txt",
        "",
        "pub const Entry = struct {",
        "    src: u32,",
        "    replacement: []const u32,",
        "};",
        "",
        "pub const entries = [_]Entry{",
    ]
    for src, replacement in sorted(entries.items()):
        if len(replacement) == 1:
            values = zig_hex(replacement[0])
            array_literal = f"&[_]u32{{{values}}}"
        else:
            values = ", ".join(zig_hex(cp) for cp in replacement)
            array_literal = f"&[_]u32{{ {values} }}"
        lines.append(
            f"    .{{ .src = {zig_hex(src)}, .replacement = {array_literal} }},"
        )
    lines.extend(["};", ""])
    return "\n".join(lines)


def parse_unicode_data(text: str) -> dict[int, tuple[int, list[int], list[int]]]:
    """Parse UnicodeData.txt into ``cp -> (ccc, canonical, compat)``.

    Field 5 carries the character decomposition mapping.  A leading
    ``<tag>`` marks a compatibility decomposition (NFKD/NFKC only); the tag
    is stripped and the codepoints kept in ``compat``.  Without a tag the
    mapping is canonical (NFD/NFC) and kept in ``canonical``.  A row is
    retained whenever it carries a non-zero combining class or either
    decomposition, so compatibility-only characters (fullwidth forms,
    ligatures, circled digits) are present for NFKD/NFKC."""
    entries: dict[int, tuple[int, list[int], list[int]]] = {}
    for raw_line in text.splitlines():
        fields = raw_line.split(";")
        if len(fields) < 6:
            continue
        try:
            cp = int(fields[0], 16)
            ccc = int(fields[3])
        except ValueError:
            continue
        decomp_field = fields[5].strip()
        canonical: list[int] = []
        compat: list[int] = []
        if decomp_field:
            if decomp_field.startswith("<"):
                after_tag = decomp_field.split(">", 1)[1] if ">" in decomp_field else decomp_field
                try:
                    compat = parse_codepoints(after_tag.strip())
                except ValueError:
                    compat = []
            else:
                try:
                    canonical = parse_codepoints(decomp_field)
                except ValueError:
                    canonical = []
        if ccc != 0 or canonical or compat:
            entries[cp] = (ccc, canonical, compat)
    return entries


def parse_composition_exclusions(text: str) -> set[int]:
    """Parse CompositionExclusions.txt into a set of excluded codepoints.

    Each data line names one codepoint that must never recompose during
    canonical composition (NFC/NFKC)."""
    out: set[int] = set()
    for raw_line in text.splitlines():
        body = raw_line.split("#", 1)[0].strip()
        if not body:
            continue
        try:
            out.add(int(body, 16))
        except ValueError:
            continue
    return out


def build_composition_table(
    entries: dict[int, tuple[int, list[int], list[int]]],
    exclusions: set[int],
) -> dict[tuple[int, int], int]:
    """Invert the canonical decompositions into a ``(a, b) -> c`` composition
    table.  A pair contributes only when the composite has a two-codepoint
    canonical decomposition, is absent from the exclusion set, and its first
    element is a starter (combining class zero) — the UAX #15 primary
    composite rule mirrored from the Rust port's ``build_composition_table``."""
    out: dict[tuple[int, int], int] = {}
    for cp, (_ccc, canonical, _compat) in entries.items():
        if len(canonical) == 2 and cp not in exclusions:
            first_ccc = entries.get(canonical[0], (0, [], []))[0]
            if first_ccc == 0:
                out[(canonical[0], canonical[1])] = cp
    return out


def _decomp_literal(decomp: list[int]) -> str:
    if not decomp:
        return "&[_]u32{}"
    if len(decomp) == 1:
        return f"&[_]u32{{{zig_hex(decomp[0])}}}"
    values = ", ".join(zig_hex(part) for part in decomp)
    return f"&[_]u32{{ {values} }}"


def render_normalization(
    entries: dict[int, tuple[int, list[int], list[int]]],
    compositions: dict[tuple[int, int], int],
) -> str:
    lines = [
        "// GENERATED FILE - DO NOT EDIT.",
        "// Source: src/data/UnicodeData.txt, src/data/CompositionExclusions.txt",
        "",
        "pub const Entry = struct {",
        "    cp: u32,",
        "    ccc: u8,",
        "    decomp: []const u32,",
        "    compat: []const u32,",
        "};",
        "",
        "pub const entries = [_]Entry{",
    ]
    for cp, (ccc, decomp, compat) in sorted(entries.items()):
        lines.append(
            f"    .{{ .cp = {zig_hex(cp)}, .ccc = {ccc}, "
            f".decomp = {_decomp_literal(decomp)}, "
            f".compat = {_decomp_literal(compat)} }},"
        )
    lines.append("};")
    lines.append("")
    lines.append("pub const Composition = struct {")
    lines.append("    a: u32,")
    lines.append("    b: u32,")
    lines.append("    c: u32,")
    lines.append("};")
    lines.append("")
    lines.append(
        "// Canonical composition pairs: the inverse of every two-codepoint"
    )
    lines.append(
        "// canonical decomposition minus CompositionExclusions.txt, sorted by"
    )
    lines.append("// (a, b) for binary search.")
    lines.append("pub const compositions = [_]Composition{")
    for (a, b), c in sorted(compositions.items()):
        lines.append(
            f"    .{{ .a = {zig_hex(a)}, .b = {zig_hex(b)}, .c = {zig_hex(c)} }},"
        )
    lines.extend(["};", ""])
    return "\n".join(lines)


def _bidi_range_bounds(field: str) -> tuple[int, int]:
    """Parse a DerivedBidiClass range field, either ``LO..HI`` or a single
    ``CP``, into inclusive (lo, hi) integer bounds."""
    field = field.strip()
    if ".." in field:
        lo_text, hi_text = field.split("..", 1)
        return int(lo_text, 16), int(hi_text, 16)
    cp = int(field, 16)
    return cp, cp


def _map_bidi_short(short: str) -> str:
    """Map a DerivedBidiClass abbreviation to the four-value Strong tag.
    Only R, AL, and L carry directional weight; everything else collapses
    to ``other`` so that binary search over the explicit ranges reproduces
    the spec's Bidi_Class lookup for non-strong codepoints."""
    return {"R": "r", "AL": "al", "L": "l"}.get(short, "other")


def _map_bidi_long(name: str) -> str:
    """Map a DerivedBidiClass ``@missing`` long name to the Strong tag."""
    return {
        "Right_To_Left": "r",
        "Arabic_Letter": "al",
        "Left_To_Right": "l",
    }.get(name, "other")


def parse_derived_bidi(
    text: str,
) -> tuple[list[tuple[int, int, str]], list[tuple[int, int, str]]]:
    """Parse DerivedBidiClass.txt into two range tables.

    ``explicit`` holds ``(lo, hi, tag)`` from DATA lines
    (``LO..HI ; SHORT # ...`` or ``CP ; SHORT # ...``), sorted by ``lo``.
    ``defaults`` holds ``(lo, hi, tag)`` from ``# @missing: LO..HI; Long_Name``
    comment lines, in file order. Both mirror
    ``Unicode.Generated.DerivedBidiClass``."""
    explicit: list[tuple[int, int, str]] = []
    defaults: list[tuple[int, int, str]] = []
    for raw_line in text.splitlines():
        if "@missing:" in raw_line:
            _prefix, rest = raw_line.split("@missing:", 1)
            parts = rest.split(";")
            if len(parts) < 2:
                continue
            try:
                lo, hi = _bidi_range_bounds(parts[0])
            except ValueError:
                continue
            defaults.append((lo, hi, _map_bidi_long(parts[1].strip())))
            continue
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split(";")
        if len(fields) < 2:
            continue
        short = fields[1].split("#", 1)[0].strip()
        try:
            lo, hi = _bidi_range_bounds(fields[0])
        except ValueError:
            continue
        explicit.append((lo, hi, _map_bidi_short(short)))
    explicit.sort(key=lambda row: row[0])
    return explicit, defaults


def render_bidi_class(
    explicit: list[tuple[int, int, str]],
    defaults: list[tuple[int, int, str]],
) -> str:
    lines = [
        "// GENERATED FILE - DO NOT EDIT.",
        "// Source: src/data/DerivedBidiClass.txt",
        "",
        "pub const Strong = enum { r, al, l, other };",
        "",
        "pub const Range = struct {",
        "    start: u32,",
        "    end: u32,",
        "    class: Strong,",
        "};",
        "",
        "// Explicit Bidi_Class ranges from DATA lines, sorted by start.",
        "// Binary search over this table takes priority in the lookup.",
        "pub const explicit = [_]Range{",
    ]
    for start, end, cls in explicit:
        lines.append(
            f"    .{{ .start = {zig_hex(start)}, .end = {zig_hex(end)}, "
            f".class = .{cls} }},"
        )
    lines.append("};")
    lines.append("")
    lines.append("// Default (@missing) ranges in file order; the last match wins.")
    lines.append("pub const defaults = [_]Range{")
    for start, end, cls in defaults:
        lines.append(
            f"    .{{ .start = {zig_hex(start)}, .end = {zig_hex(end)}, "
            f".class = .{cls} }},"
        )
    lines.extend(["};", ""])
    return "\n".join(lines)


def parse_case_folding(text: str) -> dict[int, list[int]]:
    entries: dict[int, list[int]] = {}
    for raw_line in text.splitlines():
        body = raw_line.split("#", 1)[0].strip()
        if not body:
            continue
        fields = body.split(";")
        if len(fields) < 3:
            continue
        status = fields[1].strip()
        if status not in {"C", "F"}:
            continue
        try:
            cp = int(fields[0].strip(), 16)
            mapping = parse_codepoints(fields[2].strip())
        except ValueError:
            continue
        if mapping:
            entries[cp] = mapping
    return entries


def render_case_folding(entries: dict[int, list[int]]) -> str:
    lines = [
        "// GENERATED FILE - DO NOT EDIT.",
        "// Source: src/data/CaseFolding.txt",
        "",
        "pub const Entry = struct {",
        "    cp: u32,",
        "    mapping: []const u32,",
        "};",
        "",
        "pub const entries = [_]Entry{",
    ]
    for cp, mapping in sorted(entries.items()):
        if len(mapping) == 1:
            array_literal = f"&[_]u32{{{zig_hex(mapping[0])}}}"
        else:
            values = ", ".join(zig_hex(part) for part in mapping)
            array_literal = f"&[_]u32{{ {values} }}"
        lines.append(
            f"    .{{ .cp = {zig_hex(cp)}, .mapping = {array_literal} }},"
        )
    lines.extend(["};", ""])
    return "\n".join(lines)


def parse_simple_lowercase(text: str) -> dict[int, int]:
    """Parse UnicodeData.txt field 13 (simple lowercase mapping) into
    ``cp -> lower``; codepoints without a mapping lowercase to themselves and
    are omitted."""
    out: dict[int, int] = {}
    for raw_line in text.splitlines():
        if not raw_line:
            continue
        fields = raw_line.split(";")
        if len(fields) < 14:
            continue
        lower_field = fields[13].strip()
        if not lower_field:
            continue
        try:
            out[int(fields[0], 16)] = int(lower_field, 16)
        except ValueError:
            continue
    return out


def parse_special_casing(text: str) -> list[tuple[int, list[int], list[str]]]:
    """Parse SpecialCasing.txt into ``(code, lower, conditions)`` rows in file
    order (per codepoint, the file lists conditional rows before the
    unconditional fallback, and toLower keeps that order). Only the lowercase
    mapping (field 1) and the condition list (field 4) are retained."""
    rows: list[tuple[int, list[int], list[str]]] = []
    for raw_line in text.splitlines():
        body = raw_line.split("#", 1)[0].strip()
        if not body:
            continue
        fields = [f.strip() for f in body.split(";")]
        if len(fields) < 4:
            continue
        try:
            code = int(fields[0], 16)
            lower = parse_codepoints(fields[1])
        except ValueError:
            continue
        conditions = fields[4].split() if len(fields) > 4 and fields[4] else []
        rows.append((code, lower, conditions))
    return rows


def parse_derived_property(text: str, name: str) -> list[tuple[int, int]]:
    """Parse DerivedCoreProperties.txt into inclusive ``(lo, hi)`` ranges for a
    single property (``Cased`` or ``Soft_Dotted``), sorted by ``lo``."""
    out: list[tuple[int, int]] = []
    for raw_line in text.splitlines():
        body = raw_line.split("#", 1)[0].strip()
        if not body:
            continue
        parts = body.split(";")
        if len(parts) < 2 or parts[1].strip() != name:
            continue
        field = parts[0].strip()
        if ".." in field:
            lo_text, hi_text = field.split("..", 1)
            try:
                out.append((int(lo_text, 16), int(hi_text, 16)))
            except ValueError:
                continue
        else:
            try:
                cp = int(field, 16)
            except ValueError:
                continue
            out.append((cp, cp))
    out.sort(key=lambda row: row[0])
    return out


def _u32_slice_literal(values: list[int]) -> str:
    if not values:
        return "&[_]u32{}"
    if len(values) == 1:
        return f"&[_]u32{{{zig_hex(values[0])}}}"
    joined = ", ".join(zig_hex(v) for v in values)
    return f"&[_]u32{{ {joined} }}"


def render_casing(
    simple_lower: dict[int, int],
    special: list[tuple[int, list[int], list[str]]],
    cased: list[tuple[int, int]],
    soft_dotted: list[tuple[int, int]],
) -> str:
    lines = [
        "// GENERATED FILE - DO NOT EDIT.",
        "// Source: src/data/UnicodeData.txt, src/data/SpecialCasing.txt,",
        "//         src/data/DerivedCoreProperties.txt",
        "",
        "pub const SimpleLower = struct {",
        "    cp: u32,",
        "    lower: u32,",
        "};",
        "",
        "// Simple lowercase mappings (UnicodeData.txt field 13), sorted by cp.",
        "pub const simple_lower = [_]SimpleLower{",
    ]
    for cp, lower in sorted(simple_lower.items()):
        lines.append(f"    .{{ .cp = {zig_hex(cp)}, .lower = {zig_hex(lower)} }},")
    lines.append("};")
    lines.append("")
    lines.append("pub const SpecialRow = struct {")
    lines.append("    code: u32,")
    lines.append("    lower: []const u32,")
    lines.append("    conditions: []const []const u8,")
    lines.append("};")
    lines.append("")
    lines.append(
        "// SpecialCasing.txt rows, sorted by code (stable, so the per-code file"
    )
    lines.append(
        "// order of conditional rows is preserved for first-match priority)."
    )
    lines.append("pub const special = [_]SpecialRow{")
    for code, lower, conditions in sorted(special, key=lambda row: row[0]):
        if conditions:
            conds = ", ".join(f'"{token}"' for token in conditions)
            cond_literal = f"&[_][]const u8{{ {conds} }}"
        else:
            cond_literal = "&[_][]const u8{}"
        lines.append(
            f"    .{{ .code = {zig_hex(code)}, "
            f".lower = {_u32_slice_literal(lower)}, "
            f".conditions = {cond_literal} }},"
        )
    lines.append("};")
    lines.append("")
    lines.append("pub const Range = struct {")
    lines.append("    start: u32,")
    lines.append("    end: u32,")
    lines.append("};")
    lines.append("")
    lines.append("// Cased ranges (DerivedCoreProperties.txt), sorted by start.")
    lines.append("pub const cased = [_]Range{")
    for start, end in cased:
        lines.append(f"    .{{ .start = {zig_hex(start)}, .end = {zig_hex(end)} }},")
    lines.append("};")
    lines.append("")
    lines.append("// Soft_Dotted ranges (DerivedCoreProperties.txt), sorted by start.")
    lines.append("pub const soft_dotted = [_]Range{")
    for start, end in soft_dotted:
        lines.append(f"    .{{ .start = {zig_hex(start)}, .end = {zig_hex(end)} }},")
    lines.extend(["};", ""])
    return "\n".join(lines)


def parse_bip39_wordlists() -> dict[str, list[list[int]]]:
    """Read each BIP-39 wordlist into a list of codepoint sequences, one per
    non-empty line, preserving file order (the wordlists are already sorted)."""
    out: dict[str, list[list[int]]] = {}
    for lang in BIP39_LANGUAGES:
        text = (BIP39_DIR / f"{lang}.txt").read_text(encoding="utf-8")
        words = [[ord(ch) for ch in line] for line in text.split("\n") if line != ""]
        out[lang] = words
    return out


def render_bip39(wordlists: dict[str, list[list[int]]]) -> str:
    lines = [
        "// GENERATED FILE - DO NOT EDIT.",
        "// Source: src/data/bip39/*.txt",
        "",
        "pub const Wordlist = struct {",
        "    name: []const u8,",
        "    words: []const []const u32,",
        "};",
        "",
    ]
    # Each wordlist is emitted sorted lexicographically by codepoint sequence so
    # membership can binary-search; the language table below keeps allLanguages
    # order for language resolution.
    for lang in BIP39_LANGUAGES:
        words = sorted(wordlists[lang])
        lines.append(f"const {lang}_words = [_][]const u32{{")
        for word in words:
            lines.append(f"    {_u32_slice_literal(word)},")
        lines.append("};")
        lines.append("")
    lines.append("// BIP-39 languages in Unicode.Generated.BIP39.allLanguages order.")
    lines.append("pub const languages = [_]Wordlist{")
    for lang in BIP39_LANGUAGES:
        lines.append(f'    .{{ .name = "{lang}", .words = &{lang}_words }},')
    lines.extend(["};", ""])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Zig Unicode lookup tables.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the checked-in output matches the generator",
    )
    args = parser.parse_args()

    entries = parse_confusables(SOURCE.read_text(encoding="utf-8"))
    output = render(entries)
    normalization_entries = parse_unicode_data(
        UNICODE_DATA_SOURCE.read_text(encoding="utf-8")
    )
    composition_exclusions = parse_composition_exclusions(
        COMPOSITION_EXCLUSIONS_SOURCE.read_text(encoding="utf-8")
    )
    composition_table = build_composition_table(
        normalization_entries, composition_exclusions
    )
    normalization_output = render_normalization(
        normalization_entries, composition_table
    )
    case_folding_entries = parse_case_folding(
        CASE_FOLDING_SOURCE.read_text(encoding="utf-8")
    )
    case_folding_output = render_case_folding(case_folding_entries)
    bidi_explicit, bidi_defaults = parse_derived_bidi(
        BIDI_SOURCE.read_text(encoding="utf-8")
    )
    bidi_output = render_bidi_class(bidi_explicit, bidi_defaults)
    simple_lower = parse_simple_lowercase(
        UNICODE_DATA_SOURCE.read_text(encoding="utf-8")
    )
    special_casing = parse_special_casing(
        SPECIAL_CASING_SOURCE.read_text(encoding="utf-8")
    )
    derived_core = DERIVED_CORE_PROPERTIES_SOURCE.read_text(encoding="utf-8")
    cased = parse_derived_property(derived_core, "Cased")
    soft_dotted = parse_derived_property(derived_core, "Soft_Dotted")
    casing_output = render_casing(simple_lower, special_casing, cased, soft_dotted)
    bip39_wordlists = parse_bip39_wordlists()
    bip39_output = render_bip39(bip39_wordlists)

    if args.check:
        actual = OUTPUT.read_text(encoding="utf-8")
        actual_normalization = NORMALIZATION_OUTPUT.read_text(encoding="utf-8")
        actual_case_folding = CASE_FOLDING_OUTPUT.read_text(encoding="utf-8")
        actual_bidi = BIDI_OUTPUT.read_text(encoding="utf-8")
        actual_casing = CASING_OUTPUT.read_text(encoding="utf-8")
        actual_bip39 = BIP39_OUTPUT.read_text(encoding="utf-8")
        if (
            actual != output
            or actual_normalization != normalization_output
            or actual_case_folding != case_folding_output
            or actual_bidi != bidi_output
            or actual_casing != casing_output
            or actual_bip39 != bip39_output
        ):
            print(
                "FATAL: Zig generated data is stale; "
                "run ports/zig/tools/generate_confusables_data.py",
                file=sys.stderr,
            )
            sys.exit(1)
        print(
            "clean: Zig generated Unicode tables match generator output "
            f"({len(entries)} confusables, "
            f"{len(normalization_entries)} normalization entries, "
            f"{len(composition_table)} composition pairs, "
            f"{len(case_folding_entries)} case-folding entries, "
            f"{len(bidi_explicit)} bidi explicit ranges, "
            f"{len(bidi_defaults)} bidi default ranges, "
            f"{len(simple_lower)} simple-lowercase mappings, "
            f"{len(special_casing)} special-casing rows, "
            f"{sum(len(w) for w in bip39_wordlists.values())} bip39 words)"
        )
        return

    OUTPUT.write_text(output, encoding="utf-8")
    NORMALIZATION_OUTPUT.write_text(normalization_output, encoding="utf-8")
    CASE_FOLDING_OUTPUT.write_text(case_folding_output, encoding="utf-8")
    BIDI_OUTPUT.write_text(bidi_output, encoding="utf-8")
    CASING_OUTPUT.write_text(casing_output, encoding="utf-8")
    BIP39_OUTPUT.write_text(bip39_output, encoding="utf-8")
    print(f"generated {OUTPUT.relative_to(ROOT)} from {len(entries)} entries")
    print(
        f"generated {NORMALIZATION_OUTPUT.relative_to(ROOT)} "
        f"from {len(normalization_entries)} entries "
        f"and {len(composition_table)} composition pairs"
    )
    print(
        f"generated {CASE_FOLDING_OUTPUT.relative_to(ROOT)} "
        f"from {len(case_folding_entries)} entries"
    )
    print(
        f"generated {BIDI_OUTPUT.relative_to(ROOT)} "
        f"from {len(bidi_explicit)} explicit ranges "
        f"and {len(bidi_defaults)} default ranges"
    )
    print(
        f"generated {CASING_OUTPUT.relative_to(ROOT)} "
        f"from {len(simple_lower)} simple-lowercase mappings, "
        f"{len(special_casing)} special-casing rows, "
        f"{len(cased)} Cased ranges, {len(soft_dotted)} Soft_Dotted ranges"
    )
    print(
        f"generated {BIP39_OUTPUT.relative_to(ROOT)} "
        f"from {sum(len(w) for w in bip39_wordlists.values())} words "
        f"across {len(bip39_wordlists)} languages"
    )


if __name__ == "__main__":
    main()
