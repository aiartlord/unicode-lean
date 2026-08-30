#!/usr/bin/env python3
"""Emit the materialized `rowsList` block for a Security vector harness.

`Unicode/Conformance/Security/VectorFile.lean` parses
`Unicode/Ucd/Security/*Test.txt` at compile time, but a `decide +kernel`
obligation cannot run over that parse: the kernel would have to reduce the
string operations. `Unicode/Conformance/GraphemeBreakTest.lean` resolves the
same tension by proving over a materialized row list and mirroring it against
the fresh parse with a build-time `#eval` gate, and this emits that list.

The grammar implemented here is the grammar `VectorFile.parseRow` implements,
deliberately: the `#eval` gate compares this output against what Lean parses
from the same bytes, so a disagreement between the two readings fails the build
rather than passing silently.

Run: python3 scripts/internal/generate_security_vector_rows.py <TestName>...
     python3 scripts/internal/generate_security_vector_rows.py --all
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "Unicode" / "Ucd" / "Security"


def parse_row(raw_line: str) -> tuple[list[int], str, list[int]] | None:
    """One vector row, or None for a comment, a blank, or a short line.

    Mirrors `VectorFile.parseRow`: fields split on `;`, field 1 the hex scalar
    values, field 2 the verdict, field 3 the decimal positions. Field 1 and
    field 3 both separate tokens by spaces or commas, and the position column
    writes both, sometimes in the same row (`0, 3`). Trailing attribution
    fields are the file's own commentary and are not read.
    """
    line = raw_line.strip()
    if line == "" or line.startswith("#"):
        return None
    fields = line.split(";")
    if len(fields) < 3:
        return None
    codepoints = [int(t, 16) for t in fields[0].replace(",", " ").split() if t]
    classification = fields[1].strip()
    positions = [int(t) for t in fields[2].replace(",", " ").split() if t]
    if not codepoints or classification == "":
        return None
    return codepoints, classification, positions


def parse_file(path: Path) -> list[tuple[list[int], str, list[int]]]:
    rows = []
    for raw_line in path.read_text(encoding="utf-8").split("\n"):
        row = parse_row(raw_line)
        if row is not None:
            rows.append(row)
    return rows


def render_rows(rows: list[tuple[list[int], str, list[int]]]) -> str:
    """The Lean literal for `rowsList`, one row per line."""
    out = ["def rowsList : List VectorRow := ["]
    for index, (codepoints, classification, positions) in enumerate(rows):
        cps = ", ".join(f"0x{cp:04X}" for cp in codepoints)
        poss = ", ".join(str(p) for p in positions)
        comma = "" if index == len(rows) - 1 else ","
        out.append(f'  ⟨[{cps}], "{classification}", [{poss}]⟩{comma}')
    out.append("]")
    return "\n".join(out)


def attr_fields(raw_line: str) -> list[str] | None:
    """The attribution fields of one row, mirroring `VectorFile.attrFields`."""
    if parse_row(raw_line) is None:
        return None
    line = raw_line.strip()
    before_comment = line.split("#")[0]
    fields = before_comment.split(";")[3:]
    return [f.strip() for f in fields if f.strip()]


def render_attrs(path: Path) -> str:
    """The Lean literal for `attrsList`, index-aligned with `rowsList`."""
    entries = []
    for raw_line in path.read_text(encoding="utf-8").split("\n"):
        fields = attr_fields(raw_line)
        if fields is not None:
            entries.append(fields)
    out = ["def attrsList : List (List String) := ["]
    for index, fields in enumerate(entries):
        rendered = ", ".join(f'"{f}"' for f in fields)
        comma = "" if index == len(entries) - 1 else ","
        out.append(f"  [{rendered}]{comma}")
    out.append("]")
    return "\n".join(out)


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 2
    flags = [a for a in args if a.startswith("--")]
    names = [a for a in args if not a.startswith("--")]
    if "--all" in flags:
        names = sorted(p.stem for p in VECTORS.glob("*Test.txt"))
    if not names:
        print(__doc__)
        return 2
    args = flags
    for name in names:
        path = VECTORS / f"{name}.txt"
        if not path.is_file():
            print(f"no such vector file: {path}", file=sys.stderr)
            return 1
        rows = parse_file(path)
        print(f"-- {name}: {len(rows)} rows")
        print(render_rows(rows))
        if "--attrs" in args:
            print()
            print(render_attrs(path))
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
