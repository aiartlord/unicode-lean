#!/usr/bin/env python3
"""Search the tracked source tree for a regular expression.

The repository ships no declaration index of its own, so this is the plain
intake instrument: it walks the git-tracked files under a path prefix, matches
each line against a Python regular expression, and prints every hit as
`path:line: text` followed by a per-file count summary. It reads only; it never
edits. A match localises where a name, tactic, or idiom is used — the compiler
remains the authority on whether a proof holds.

Usage:
  scripts/unicode-find.py PATTERN [--under PREFIX] [--ext .lean] [--count-only]

  PATTERN        a Python `re` pattern, matched per line (not anchored)
  --under PREFIX tree prefix to search (default: Unicode)
  --ext EXT      file extension to include (default: .lean; repeatable)
  --count-only   print only the per-file counts, not each matching line
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys


def tracked_files(prefix: str, exts: list[str]) -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", prefix],
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout.split()
    return [f for f in out if any(f.endswith(e) for e in exts)]


def main() -> int:
    parser = argparse.ArgumentParser(description="Search the tracked source tree.")
    parser.add_argument("pattern")
    parser.add_argument("--under", default="Unicode")
    parser.add_argument("--ext", action="append", default=None)
    parser.add_argument("--count-only", action="store_true")
    args = parser.parse_args()

    exts = args.ext if args.ext else [".lean"]
    try:
        rx = re.compile(args.pattern)
    except re.error as exc:
        print(f"bad pattern: {exc}", file=sys.stderr)
        return 2

    counts: dict[str, int] = {}
    for path in tracked_files(args.under, exts):
        try:
            lines = open(path, encoding="utf-8").read().splitlines()
        except OSError:
            continue
        n = 0
        for index, line in enumerate(lines, start=1):
            if rx.search(line):
                n += 1
                if not args.count_only:
                    print(f"{path}:{index}: {line.strip()[:100]}")
        if n:
            counts[path] = n

    total = sum(counts.values())
    print(f"--- {total} match(es) across {len(counts)} file(s) ---")
    for path in sorted(counts, key=lambda k: -counts[k]):
        print(f"  {counts[path]:4}  {path}")
    return 0 if total else 1


if __name__ == "__main__":
    raise SystemExit(main())
