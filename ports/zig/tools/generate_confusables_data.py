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

    if args.check:
        actual = OUTPUT.read_text(encoding="utf-8")
        actual_normalization = NORMALIZATION_OUTPUT.read_text(encoding="utf-8")
        actual_case_folding = CASE_FOLDING_OUTPUT.read_text(encoding="utf-8")
        if (
            actual != output
            or actual_normalization != normalization_output
            or actual_case_folding != case_folding_output
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
            f"{len(case_folding_entries)} case-folding entries)"
        )
        return

    OUTPUT.write_text(output, encoding="utf-8")
    NORMALIZATION_OUTPUT.write_text(normalization_output, encoding="utf-8")
    CASE_FOLDING_OUTPUT.write_text(case_folding_output, encoding="utf-8")
    print(f"generated {OUTPUT.relative_to(ROOT)} from {len(entries)} entries")
    print(
        f"generated {NORMALIZATION_OUTPUT.relative_to(ROOT)} "
        f"from {len(normalization_entries)} entries"
    )
    print(
        f"generated {CASE_FOLDING_OUTPUT.relative_to(ROOT)} "
        f"from {len(case_folding_entries)} entries"
    )


if __name__ == "__main__":
    main()
