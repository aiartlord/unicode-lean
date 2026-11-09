"""The shared segmentation vector fixture, replayed the same way everywhere.

The published corpora in this package are the authority. These vectors are the
second half of the same contract: one case per UAX rule, the same bytes in
every port, so each port's segmentation tests ask the same questions instead of
a per-port selection of them. A case added to the root fixture is added to all
sixteen ports at once.

This port reads the root fixture rather than a vendored copy, as it does for
the shared security fixtures.

A case carries the rule it pins, its code points, the canonical UCD class of
each code point, and the expected boundary mask. The mask is what every port
must reproduce. The classes are checked here too, which this port can do
because it names classes in the canonical form -- the other ports spell them
differently inside themselves.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

# This module sits a level deeper than the suites that read the security
# fixtures, so the repository root is four parents up, not three:
# corpus -> tests -> python -> ports -> root.
FIXTURE_DIR = Path(__file__).resolve().parents[4] / "fixtures" / "segmentation"


def load(name: str, algorithm: str) -> dict:
    """One shared vector fixture, with its envelope checked."""
    document = json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))
    assert document["schema"] == 1, (
        f"{name} carries schema {document['schema']}, expected 1"
    )
    assert document["algorithm"] == algorithm, (
        f"{name} is for {document['algorithm']}, expected {algorithm}"
    )
    assert document["cases"], f"{name} carries no cases"
    return document


def replay(
    document: dict,
    breaks_of: Callable[[list[int]], list[bool]],
    class_of: Callable[[int], str],
) -> None:
    """Every case's boundary mask and class list, reproduced.

    A failure names the rule and what the case is for, so the red reads as a
    sentence rather than an index.
    """
    for case in document["cases"]:
        codepoints = case["input"]
        label = f"{case['rule']}: {case['name']}"
        points = " ".join(f"U+{cp:04X}" for cp in codepoints)

        produced_classes = [class_of(cp) for cp in codepoints]
        assert produced_classes == case["classes"], (
            f"{label}\n  code points : {points}\n"
            f"  fixture     : {case['classes']}\n"
            f"  produced    : {produced_classes}"
        )

        produced = breaks_of(codepoints)
        assert produced == case["breaks"], (
            f"{label}\n  code points : {points}\n"
            f"  fixture     : {_flags(case['breaks'])}\n"
            f"  produced    : {_flags(produced)}"
        )


def _flags(values: list[bool]) -> str:
    """The markers the published files write: a break opportunity, or none."""
    return " ".join("/" if is_break else "x" for is_break in values)
