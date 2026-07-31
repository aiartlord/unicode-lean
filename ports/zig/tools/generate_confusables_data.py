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
NORMALIZATION_OUTPUT = ROOT / "src" / "normalization_data.zig"
CASE_FOLDING_SOURCE = ROOT / "src" / "data" / "CaseFolding.txt"
CASE_FOLDING_OUTPUT = ROOT / "src" / "case_folding_data.zig"
BIDI_SOURCE = ROOT / "src" / "data" / "DerivedBidiClass.txt"
BIDI_OUTPUT = ROOT / "src" / "bidi_class_data.zig"


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


def parse_unicode_data(text: str) -> dict[int, tuple[int, list[int]]]:
    entries: dict[int, tuple[int, list[int]]] = {}
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
        decomp: list[int] = []
        if decomp_field and not decomp_field.startswith("<"):
            try:
                decomp = parse_codepoints(decomp_field)
            except ValueError:
                decomp = []
        if ccc != 0 or decomp:
            entries[cp] = (ccc, decomp)
    return entries


def render_normalization(entries: dict[int, tuple[int, list[int]]]) -> str:
    lines = [
        "// GENERATED FILE - DO NOT EDIT.",
        "// Source: src/data/UnicodeData.txt",
        "",
        "pub const Entry = struct {",
        "    cp: u32,",
        "    ccc: u8,",
        "    decomp: []const u32,",
        "};",
        "",
        "pub const entries = [_]Entry{",
    ]
    for cp, (ccc, decomp) in sorted(entries.items()):
        if not decomp:
            array_literal = "&[_]u32{}"
        elif len(decomp) == 1:
            array_literal = f"&[_]u32{{{zig_hex(decomp[0])}}}"
        else:
            values = ", ".join(zig_hex(part) for part in decomp)
            array_literal = f"&[_]u32{{ {values} }}"
        lines.append(
            f"    .{{ .cp = {zig_hex(cp)}, .ccc = {ccc}, .decomp = {array_literal} }},"
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
    normalization_output = render_normalization(normalization_entries)
    case_folding_entries = parse_case_folding(
        CASE_FOLDING_SOURCE.read_text(encoding="utf-8")
    )
    case_folding_output = render_case_folding(case_folding_entries)
    bidi_explicit, bidi_defaults = parse_derived_bidi(
        BIDI_SOURCE.read_text(encoding="utf-8")
    )
    bidi_output = render_bidi_class(bidi_explicit, bidi_defaults)

    if args.check:
        actual = OUTPUT.read_text(encoding="utf-8")
        actual_normalization = NORMALIZATION_OUTPUT.read_text(encoding="utf-8")
        actual_case_folding = CASE_FOLDING_OUTPUT.read_text(encoding="utf-8")
        actual_bidi = BIDI_OUTPUT.read_text(encoding="utf-8")
        if (
            actual != output
            or actual_normalization != normalization_output
            or actual_case_folding != case_folding_output
            or actual_bidi != bidi_output
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
            f"{len(case_folding_entries)} case-folding entries, "
            f"{len(bidi_explicit)} bidi explicit ranges, "
            f"{len(bidi_defaults)} bidi default ranges)"
        )
        return

    OUTPUT.write_text(output, encoding="utf-8")
    NORMALIZATION_OUTPUT.write_text(normalization_output, encoding="utf-8")
    CASE_FOLDING_OUTPUT.write_text(case_folding_output, encoding="utf-8")
    BIDI_OUTPUT.write_text(bidi_output, encoding="utf-8")
    print(f"generated {OUTPUT.relative_to(ROOT)} from {len(entries)} entries")
    print(
        f"generated {NORMALIZATION_OUTPUT.relative_to(ROOT)} "
        f"from {len(normalization_entries)} entries"
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


if __name__ == "__main__":
    main()
