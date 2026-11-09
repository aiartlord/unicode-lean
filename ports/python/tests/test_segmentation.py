"""UAX #29 extended grapheme clusters, judged against the published corpus.

The corpus and the two gates it answers to live in ``corpus``, shared with the
other break suites: agree with every published row, and separately account for
the whole file so a row lost between the corpus module and this fold is a
failure rather than a smaller denominator.
"""

from __future__ import annotations

from corpus import assert_corpus_shape, disagreements, report
from corpus import vectors
from corpus.grapheme_rows import PUBLISHED_COUNT, PUBLISHED_ROWS

from unicode_python.segmentation import grapheme_breaks, grapheme_clusters
from unicode_python.segmentation.grapheme import lookup_gcb


def test_the_corpus_is_well_formed() -> None:
    assert_corpus_shape(PUBLISHED_ROWS, PUBLISHED_COUNT)


def test_the_implementation_agrees_with_every_published_row() -> None:
    failures = disagreements(PUBLISHED_ROWS, grapheme_breaks)
    assert not failures, report(PUBLISHED_COUNT, failures)


def test_the_shared_vectors_replay() -> None:
    # One case per UAX #29 rule, the same bytes every port replays.
    document = vectors.load("grapheme_vectors.json", "uax29-grapheme-cluster")
    vectors.replay(document, grapheme_breaks, lookup_gcb)


def test_the_corpus_and_the_vectors_agree_on_the_row_count() -> None:
    # Both gates count the same published file, so they cannot drift apart.
    document = vectors.load("grapheme_vectors.json", "uax29-grapheme-cluster")
    assert document["published_row_count"] == PUBLISHED_COUNT


def test_output_carries_one_flag_per_boundary() -> None:
    # A sequence of n code points yields n + 1 flags.
    for length in range(8):
        cps = [0x61 + i for i in range(length)]
        assert len(grapheme_breaks(cps)) == length + 1


def test_grapheme_clusters_cover_ri_parity_and_zwj_sequence() -> None:
    # Cluster counts are a shape the boundary masks do not state.
    four_ri = [0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8]
    assert len(grapheme_clusters(four_ri)) == 2

    family = [0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467]
    assert len(grapheme_clusters(family)) == 1

    assert len(grapheme_clusters([0x61, 0x62, 0x63])) == 3
