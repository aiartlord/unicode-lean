//! UAX #29 grapheme segmentation integration tests.

use unicode_rust::segmentation::{grapheme_breaks, grapheme_clusters};

#[test]
fn grapheme_breaks_cover_core_uax29_cases() {
    assert_eq!(
        grapheme_breaks(&[0x61, 0x62, 0x63]),
        vec![true, true, true, true]
    );
    assert_eq!(grapheme_breaks(&[0x65, 0x0301]), vec![true, false, true]);
    assert_eq!(grapheme_breaks(&[0x0d, 0x0a]), vec![true, false, true]);
    assert_eq!(
        grapheme_breaks(&[0x1f1ef, 0x1f1f5]),
        vec![true, false, true]
    );
}

#[test]
fn grapheme_clusters_cover_ri_parity_and_zwj_sequence() {
    let four_ri = [0x1f1ef, 0x1f1f5, 0x1f1fa, 0x1f1f8];
    assert_eq!(grapheme_clusters(&four_ri).len(), 2);

    let family = [0x1f468, 0x200d, 0x1f469, 0x200d, 0x1f467];
    assert_eq!(grapheme_clusters(&family).len(), 1);
}
