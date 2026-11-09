//! UAX #29 extended grapheme clusters, judged against the published corpus.
//!
//! The corpus and the two gates it answers to live in [`corpus`], shared with
//! the other break suites: agree with every published row, and separately
//! account for the whole file so a row lost between the corpus module and this
//! fold is a failure rather than a smaller denominator.

#[allow(dead_code)]
mod corpus;

use corpus::grapheme_rows::{PUBLISHED_COUNT, PUBLISHED_ROWS};
use corpus::vector_cases::{GRAPHEME_ALGORITHM, GRAPHEME_CASES, GRAPHEME_PUBLISHED_ROW_COUNT};
use corpus::{assert_corpus_shape, disagreements, replay_vectors, report};
use unicode_rust::segmentation::{grapheme_breaks, grapheme_clusters};

#[test]
fn the_corpus_is_well_formed() {
    assert_corpus_shape(PUBLISHED_ROWS, PUBLISHED_COUNT);
}

#[test]
fn the_implementation_agrees_with_every_published_row() {
    let failures = disagreements(PUBLISHED_ROWS, |cps| grapheme_breaks(cps));
    assert!(failures.is_empty(), "{}", report(PUBLISHED_COUNT, &failures));
}

#[test]
fn the_shared_vectors_replay() {
    let failures = replay_vectors(GRAPHEME_ALGORITHM, GRAPHEME_CASES, |cps| {
        grapheme_breaks(cps)
    });
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn the_corpus_and_the_vectors_agree_on_the_row_count() {
    // Both gates count the same published file, so they cannot drift apart.
    assert_eq!(GRAPHEME_PUBLISHED_ROW_COUNT, PUBLISHED_COUNT);
}

#[test]
fn output_carries_one_flag_per_boundary() {
    // A sequence of n code points yields n + 1 flags.
    for length in 0..8usize {
        let cps: Vec<u32> = (0..length).map(|i| 0x61 + i as u32).collect();
        assert_eq!(grapheme_breaks(&cps).len(), length + 1);
    }
}

#[test]
fn grapheme_clusters_cover_ri_parity_and_zwj_sequence() {
    // Cluster counts are a shape the boundary masks do not state.
    let four_ri = [0x1f1ef, 0x1f1f5, 0x1f1fa, 0x1f1f8];
    assert_eq!(grapheme_clusters(&four_ri).len(), 2);

    let family = [0x1f468, 0x200d, 0x1f469, 0x200d, 0x1f467];
    assert_eq!(grapheme_clusters(&family).len(), 1);

    assert_eq!(grapheme_clusters(&[0x61, 0x62, 0x63]).len(), 3);
}
