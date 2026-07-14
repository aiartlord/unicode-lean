#!/usr/bin/env python3
"""Generate chunked Lean confusables mappings from UTS #39 confusables.txt."""

from __future__ import annotations

import argparse
from pathlib import Path


def parse_codepoints(field: str) -> list[int]:
    return [int(token, 16) for token in field.split() if token.strip()]


def parse_rows(path: Path) -> list[tuple[int, list[int]]]:
    rows: list[tuple[int, list[int]]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        body = raw.split("#", 1)[0].strip()
        if not body:
            continue
        parts = [part.strip() for part in body.split(";")]
        if len(parts) < 2:
            continue
        source = int(parts[0], 16)
        target = parse_codepoints(parts[1])
        if target:
            rows.append((source, target))
    return rows


def nat_hex(value: int) -> str:
    return f"0x{value:X}"


def array_expr(values: list[int]) -> str:
    return "#[" + ", ".join(nat_hex(value) for value in values) + "]"


def chunks(items: list[tuple[int, list[int]]], size: int) -> list[list[tuple[int, list[int]]]]:
    return [items[index : index + size] for index in range(0, len(items), size)]


def render_lookup_tree(rows: list[tuple[int, list[int]]], indent: str) -> list[str]:
    if not rows:
        return [f"{indent}none"]

    pivot_index = len(rows) // 2
    source, target = rows[pivot_index]
    left = rows[:pivot_index]
    right = rows[pivot_index + 1 :]
    return (
        [f"{indent}if cp < {nat_hex(source)} then"]
        + render_lookup_tree(left, indent + "  ")
        + [f"{indent}else if {nat_hex(source)} < cp then"]
        + render_lookup_tree(right, indent + "  ")
        + [f"{indent}else", f"{indent}  some {array_expr(target)}"]
    )


def render(rows: list[tuple[int, list[int]]], chunk_size: int, source_name: str) -> str:
    sorted_rows = sorted(rows, key=lambda row: row[0])
    chunked = chunks(sorted_rows, chunk_size)
    out: list[str] = [
        "/-",
        "  Unicode.Generated.Confusables",
        "",
        f"  Generated from {source_name}.",
        "  Do not edit by hand; run scripts/internal/generate_confusables_lean.py.",
        "-/",
        "",
        "set_option maxHeartbeats 0",
        "",
        "namespace Unicode.Generated.Confusables",
        "",
        "/-! Confusable-skeleton mappings. Each entry `(source, skeleton)` has",
        "    `source : Nat` as a single codepoint and `skeleton : Array Nat` as",
        "    the sequence of one or more target codepoints. -/",
        "",
    ]
    for index, chunk in enumerate(chunked):
        out.append(f"def mappingsChunk{index} : List (Nat × Array Nat) := [")
        for row_index, (source, target) in enumerate(chunk):
            suffix = "," if row_index + 1 < len(chunk) else ""
            out.append(f"  ({nat_hex(source)}, {array_expr(target)}){suffix}")
        out.append("]")
        out.append("")

    if chunked:
        joined = "\n  ++ ".join(f"mappingsChunk{index}" for index in range(len(chunked)))
    else:
        joined = "[]"
    out.extend(
        [
            "def mappingsList : List (Nat × Array Nat) :=",
            f"  {joined}",
            "",
            "def mappings : Array (Nat × Array Nat) :=",
            "  mappingsList.toArray",
            "",
            "/-- Direct source-codepoint lookup over the generated UTS #39",
            "    confusables table.  The generator emits a balanced decision tree",
            "    so kernel reduction does not have to materialize and binary-search",
            "    the full mapping array for every lookup. -/",
            "def lookup? (cp : Nat) : Option (Array Nat) :=",
        ]
    )
    out.extend(render_lookup_tree(sorted_rows, "  "))
    out.extend(
        [
            "",
            f"def mappingsCount : Nat := {len(rows)}",
            "",
            "end Unicode.Generated.Confusables",
            "",
        ]
    )
    return "\n".join(out)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=Path("Unicode/Ucd/confusables.txt"))
    parser.add_argument("--output", type=Path, default=Path("Unicode/Generated/Confusables.lean"))
    parser.add_argument("--chunk-size", type=int, default=64)
    args = parser.parse_args()

    rows = parse_rows(args.input)
    args.output.write_text(
        render(rows, args.chunk_size, args.input.as_posix()),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
