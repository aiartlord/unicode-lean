#!/usr/bin/env python3
"""Generate the Zig confusables lookup table from vendored UTS #39 data."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "data" / "confusables.txt"
OUTPUT = ROOT / "src" / "confusables_data.zig"


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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate the Zig confusables lookup table."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the checked-in output matches the generator",
    )
    args = parser.parse_args()

    entries = parse_confusables(SOURCE.read_text(encoding="utf-8"))
    output = render(entries)

    if args.check:
        actual = OUTPUT.read_text(encoding="utf-8")
        if actual != output:
            print(
                "FATAL: src/confusables_data.zig is stale; "
                "run ports/zig/tools/generate_confusables_data.py",
                file=sys.stderr,
            )
            sys.exit(1)
        print(
            "clean: Zig confusables table matches generator output "
            f"({len(entries)} entries)"
        )
        return

    OUTPUT.write_text(output, encoding="utf-8")
    print(f"generated {OUTPUT.relative_to(ROOT)} from {len(entries)} entries")


if __name__ == "__main__":
    main()
