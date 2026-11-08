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
from corpus.line_break_rows import PUBLISHED_COUNT, PUBLISHED_ROWS

from unicode_python.segmentation import line_breaks, line_runs, resolved_class
from unicode_python.segmentation.line_break_tables import raw_class


def test_the_corpus_is_well_formed() -> None:
    assert_corpus_shape(PUBLISHED_ROWS, PUBLISHED_COUNT)


def test_the_implementation_agrees_with_every_published_row() -> None:
    failures = disagreements(PUBLISHED_ROWS, line_breaks)
    assert not failures, report(PUBLISHED_COUNT, failures)


def test_output_carries_one_flag_per_boundary() -> None:
    # The Lean ``lineBreaks_length`` theorem: ``len(cps) + 1`` flags.
    for length in range(8):
        cps = [0x61 + i for i in range(length)]
        assert len(line_breaks(cps)) == length + 1


def test_start_of_text_never_breaks_and_end_always_does() -> None:
    breaks = line_breaks([0x61, 0x62])
    assert breaks[0] is False  # LB2
    assert breaks[-1] is True  # LB3


def test_a_word_is_one_run_and_a_space_opens_the_next() -> None:
    # LB28 keeps letters together; LB18 breaks after a space.
    assert line_breaks([0x61, 0x62]) == [False, False, True]
    assert line_runs([0x61, 0x20, 0x62]) == [[0x61, 0x20], [0x62]]


def test_a_mandatory_break_character_breaks_after_itself() -> None:
    # LB4: BK divides. U+000C FORM FEED is class BK.
    assert line_breaks([0x61, 0x000C, 0x62]) == [False, False, True, True]


def test_carriage_return_line_feed_is_not_split() -> None:
    # LB5: CR times LF, then a mandatory break after the pair.
    assert line_breaks([0x0D, 0x0A, 0x61]) == [False, False, True, True]


def test_a_combining_mark_takes_the_class_of_its_base() -> None:
    # LB9: ``X CM`` behaves as ``X``, so no break falls inside the pair.
    assert line_breaks([0x61, 0x0301]) == [False, False, True]


def test_a_word_joiner_glues_both_sides() -> None:
    # LB11: before WJ and after WJ.
    assert line_breaks([0x61, 0x2060, 0x62]) == [False, False, False, True]


def test_a_space_before_a_number_opening_period_breaks() -> None:
    # LB15c: SP divides IS NU -- "a .35" breaks before the period.
    breaks = line_breaks([0x61, 0x20, 0x2E, 0x33, 0x35])
    assert breaks == [False, False, True, False, False, True]


def test_a_numeric_chain_holds_together() -> None:
    # LB25: "1,000" is one run across the SY separator.
    assert len(line_runs([0x31, 0x2C, 0x30, 0x30, 0x30])) == 1


def test_regional_indicators_pair_off() -> None:
    # LB30a: an even-length RI run takes no break inside a pair, and a second
    # pair may start a new line.
    breaks = line_breaks([0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8])
    assert breaks == [False, False, True, False, True]


def test_an_emoji_modifier_stays_on_its_base() -> None:
    # LB30b: EB times EM.
    assert line_breaks([0x1F466, 0x1F3FB]) == [False, False, True]


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
