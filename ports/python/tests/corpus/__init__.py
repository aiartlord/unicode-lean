"""The gate every published UAX break corpus gets, once.

Hand-written vectors cannot establish a segmentation algorithm. Its rules
read context on both sides of a boundary and the answer depends on state
carried from earlier in the sequence, so a wrong rule survives any vector a
person would pick. The Unicode Consortium publishes a corpus per algorithm
for exactly that reason.

The four break suites share one row format, so they share one judge here.
Each algorithm's test supplies its implementation and its corpus; the two
gates and the failure report live here.

Those two gates are the spec repo's own: agree with every published row,
and separately account for the whole file, so a row lost between the corpus
module and this fold is a failure rather than a smaller denominator.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Disagreement:
    """A published row whose expected flags differ from what the
    implementation produced."""

    index: int
    codepoints: list[int]
    published: list[bool]
    produced: list[bool]


def assert_corpus_shape(
    rows: list[tuple[list[int], list[bool]]],
    published: int,
) -> None:
    """What the corpus must be before it can judge anything: every published
    row reaches the fold, and each row carries one more flag than code
    points."""
    assert len(rows) == published, (
        f"the corpus table carries {len(rows)} rows but the pinned file "
        f"carries {published}"
    )
    ragged = [
        index
        for index, (codepoints, flags) in enumerate(rows)
        if len(flags) != len(codepoints) + 1
    ]
    assert not ragged, (
        "rows carry a flag count that is not one more than their code "
        f"points: {ragged}"
    )


def disagreements(
    rows: list[tuple[list[int], list[bool]]],
    breaks_of: Callable[[list[int]], list[bool]],
) -> list[Disagreement]:
    """Every row the implementation disagrees with, in corpus order."""
    out: list[Disagreement] = []
    for index, (codepoints, published) in enumerate(rows):
        produced = breaks_of(codepoints)
        if produced != published:
            out.append(
                Disagreement(
                    index=index,
                    codepoints=codepoints,
                    published=published,
                    produced=produced,
                )
            )
    return out


def report(published: int, failures: list[Disagreement]) -> str:
    """A failure names the count and the first failing row in full.

    A conformance red is only actionable if it says which row and which
    position disagreed, so the first differing boundary is reported
    alongside the two flag lists.
    """
    if not failures:
        return "no disagreements"
    first = failures[0]
    points = " ".join(f"U+{cp:04X}" for cp in first.codepoints)
    return "\n".join(
        [
            f"{len(failures)} of {published} published rows disagree; "
            f"first at row index {first.index}",
            f"  codepoints : {points}",
            f"  published  : {_flags(first.published)}",
            f"  produced   : {_flags(first.produced)}",
            f"  first differing boundary: "
            f"{_first_boundary(first.published, first.produced)}",
        ]
    )


def _flags(values: list[bool]) -> str:
    """The markers the published files write: a break opportunity, or none."""
    return " ".join("/" if is_break else "x" for is_break in values)


def _first_boundary(published: list[bool], produced: list[bool]) -> str:
    """The index of the first boundary the two flag lists disagree on, or a
    note that they differ only in length."""
    for index, (left, right) in enumerate(zip(published, produced)):
        if left != right:
            return str(index)
    return (
        f"none - the lists differ in length ({len(published)} published, "
        f"{len(produced)} produced)"
    )
