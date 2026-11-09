"""UAX #14 default line breaking, judged against the published corpus.

The corpus and the two gates it answers to live in ``corpus``, shared with the
other break suites. This file supplies the implementation under test and the
rows to judge it by.

Agreeing with all of ``LineBreakTest.txt`` is also the evidence the two
departures declared at ``segmentation.line_break``'s head needed -- slice reads
in place of positional ``lits[i]!``, and dropping the Lean's write-only
``spSinceNoSp`` snapshot field.
"""

from __future__ import annotations

from corpus import assert_corpus_shape, disagreements, report
from corpus import vectors
from corpus.line_break_rows import PUBLISHED_COUNT, PUBLISHED_ROWS

from unicode_python.segmentation import line_breaks, line_runs, resolved_class
from unicode_python.segmentation.line_break_tables import raw_class


def test_the_corpus_is_well_formed() -> None:
    assert_corpus_shape(PUBLISHED_ROWS, PUBLISHED_COUNT)


def test_the_implementation_agrees_with_every_published_row() -> None:
    failures = disagreements(PUBLISHED_ROWS, line_breaks)
    assert not failures, report(PUBLISHED_COUNT, failures)


def test_the_shared_vectors_replay() -> None:
    # One case per UAX #14 rule, the same bytes every port replays.
    document = vectors.load("line_break_vectors.json", "uax14-line-break")
    vectors.replay(document, line_breaks, resolved_class)


def test_the_corpus_and_the_vectors_agree_on_the_row_count() -> None:
    # Both gates count the same published file, so they cannot drift apart.
    document = vectors.load("line_break_vectors.json", "uax14-line-break")
    assert document["published_row_count"] == PUBLISHED_COUNT


def test_output_carries_one_flag_per_boundary() -> None:
    # The Lean ``lineBreaks_length`` theorem: ``len(cps) + 1`` flags.
    for length in range(8):
        cps = [0x61 + i for i in range(length)]
        assert len(line_breaks(cps)) == length + 1


def test_a_space_opens_the_next_run() -> None:
    # LB18 breaks after a space, so the space stays with the word before it.
    # The run split is a shape the boundary masks do not state.
    assert line_runs([0x61, 0x20, 0x62]) == [[0x61, 0x20], [0x62]]


def test_a_numeric_chain_is_one_run() -> None:
    # LB25: "1,000" is one run across its separator.
    assert len(line_runs([0x31, 0x2C, 0x30, 0x30, 0x30])) == 1


def test_lb1_resolves_the_tailorable_classes() -> None:
    # U+3041 HIRAGANA LETTER SMALL A is CJ, resolving to NS.
    assert raw_class(0x3041) == "CJ"
    assert resolved_class(0x3041) == "NS"
    # U+00A7 SECTION SIGN is AI, resolving to AL.
    assert raw_class(0x00A7) == "AI"
    assert resolved_class(0x00A7) == "AL"
    # A surrogate code point is SG, resolving to AL.
    assert raw_class(0xD800) == "SG"
    assert resolved_class(0xD800) == "AL"
    # U+05EB lies in the Hebrew block's unassigned gap, which no range
    # covers, so it takes the ``@missing`` XX default and LB1 reads it as AL.
    assert raw_class(0x05EB) == "XX"
    assert resolved_class(0x05EB) == "AL"


def test_lb1_resolves_sa_by_general_category() -> None:
    # U+0E31 THAI CHARACTER MAI HAN-AKAT is SA with General_Category Mn, so
    # LB1 reads it as CM; U+0E01 THAI CHARACTER KO KAI is SA with category
    # Lo, so LB1 reads it as AL.
    assert raw_class(0x0E31) == "SA"
    assert resolved_class(0x0E31) == "CM"
    assert raw_class(0x0E01) == "SA"
    assert resolved_class(0x0E01) == "AL"
