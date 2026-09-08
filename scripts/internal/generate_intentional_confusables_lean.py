#!/usr/bin/env python3
"""Generate the Lean intentional-confusable pair table from UTS #39 intentional.txt.

intentional.txt lists pairs of code points whose confusability the Unicode
Consortium designates as intentional -- cross-script look-alikes such as
LATIN CAPITAL A and GREEK CAPITAL ALPHA.  Each row is `source ; target`; a
source may recur with several targets.  The emitted table is the data the
coverage theorem reduces against, certifying that the detector's UTS #39 skeleton
unifies every such pair.
"""

from __future__ import annotations

import argparse
from pathlib import Path


def parse_pairs(path: Path) -> list[tuple[int, int]]:
    pairs: list[tuple[int, int]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        body = raw.split("#", 1)[0].strip()
        if not body:
            continue
        parts = [part.strip() for part in body.split(";")]
        if len(parts) < 2:
            continue
        source = int(parts[0], 16)
        target = int(parts[1].split()[0], 16)
        pairs.append((source, target))
    return pairs


def nat_hex(value: int) -> str:
    return f"0x{value:X}"


def class_representatives(pairs: list[tuple[int, int]]) -> dict[int, int]:
    """Union-find over the pairs; the representative of a class is its least
    code point.  ASCII members are least in their class, so the map is the
    identity on ASCII."""
    parent: dict[int, int] = {}

    def find(x: int) -> int:
        parent.setdefault(x, x)
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:
            parent[x], x = root, parent[x]
        return root

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    for source, target in pairs:
        union(source, target)
    members: set[int] = set()
    for source, target in pairs:
        members.add(source)
        members.add(target)
    return {member: find(member) for member in members}


def render_canon_tree(entries: list[tuple[int, int]], indent: str) -> list[str]:
    if not entries:
        return [f"{indent}cp"]
    pivot = len(entries) // 2
    member, rep = entries[pivot]
    left = entries[:pivot]
    right = entries[pivot + 1 :]
    return (
        [f"{indent}if cp < {nat_hex(member)} then"]
        + render_canon_tree(left, indent + "  ")
        + [f"{indent}else if {nat_hex(member)} < cp then"]
        + render_canon_tree(right, indent + "  ")
        + [f"{indent}else {nat_hex(rep)}"]
    )


def render(pairs: list[tuple[int, int]], source_name: str) -> str:
    ordered = sorted(pairs)
    out: list[str] = [
        "/-",
        "  Unicode.Generated.IntentionalConfusables",
        "",
        f"  Generated from {source_name}.",
        "  Do not edit by hand; run",
        "  scripts/internal/generate_intentional_confusables_lean.py.",
        "-/",
        "",
        "namespace Unicode.Generated.IntentionalConfusables",
        "",
        "/-! UTS #39 intentional-confusable pairs.  Each entry `(source, target)`",
        "    names two code points whose confusability the Unicode Consortium",
        "    designates as intentional.  A source code point may appear in more",
        "    than one pair. -/",
        "",
        "def pairs : List (Nat × Nat) := [",
    ]
    for index, (source, target) in enumerate(ordered):
        suffix = "," if index + 1 < len(ordered) else ""
        out.append(f"  ({nat_hex(source)}, {nat_hex(target)}){suffix}")
    reps = class_representatives(ordered)
    canon_entries = sorted((m, r) for m, r in reps.items() if m != r)
    out.extend(
        [
            "]",
            "",
            f"def pairsCount : Nat := {len(ordered)}",
            "",
            "/-! Canonical representative of each intentional-confusable class: the",
            "    least code point in the class.  The map is the identity outside the",
            "    classes, and every class's least member is its ASCII or lowest-Latin",
            "    letter, so it is the identity on ASCII and never rewrites an ordinary",
            "    identifier.  Applying it before the skeleton folds a class member to",
            "    its representative, collapsing the capital cross-script look-alikes",
            "    that the case-folding skeleton keeps apart. -/",
            "def canonicalRep (cp : Nat) : Nat :=",
        ]
    )
    out.extend(render_canon_tree(canon_entries, "  "))
    out.extend(
        [
            "",
            "end Unicode.Generated.IntentionalConfusables",
            "",
        ]
    )
    return "\n".join(out)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=Path("Unicode/Ucd/intentional.txt"))
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("Unicode/Generated/IntentionalConfusables.lean"),
    )
    args = parser.parse_args()

    pairs = parse_pairs(args.input)
    args.output.write_text(render(pairs, args.input.as_posix()), encoding="utf-8")


if __name__ == "__main__":
    main()
