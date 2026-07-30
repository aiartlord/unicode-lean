from unicode_python.segmentation import grapheme_breaks, grapheme_clusters


def test_grapheme_breaks_cover_core_uax29_cases() -> None:
    assert grapheme_breaks([0x61, 0x62, 0x63]) == [True, True, True, True]
    assert grapheme_breaks([0x65, 0x0301]) == [True, False, True]
    assert grapheme_breaks([0x0D, 0x0A]) == [True, False, True]
    assert grapheme_breaks([0x1F1EF, 0x1F1F5]) == [True, False, True]


def test_grapheme_clusters_cover_ri_parity_and_zwj_sequence() -> None:
    four_ri = [0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8]
    assert len(grapheme_clusters(four_ri)) == 2

    family = [0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467]
    assert len(grapheme_clusters(family)) == 1
