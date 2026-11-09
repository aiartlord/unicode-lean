//! UAX #14 default line breaking, judged against the published corpus.
//!
//! The corpus and the two gates it answers to live in [`corpus`], shared with
//! the other break suites. This file supplies the implementation under test and
//! the rows to judge it by.
//!
//! Agreeing with all of `LineBreakTest.txt` is also the evidence the two
//! departures declared at `segmentation::line_break`'s head needed — slice
//! reads in place of positional `lits[i]!`, and dropping the Lean's write-only
//! `spSinceNoSp` snapshot field.

#[allow(dead_code)]
mod corpus;

use corpus::line_break_rows::{PUBLISHED_COUNT, PUBLISHED_ROWS};
use corpus::vector_cases::{
    LINE_BREAK_ALGORITHM, LINE_BREAK_CASES, LINE_BREAK_PUBLISHED_ROW_COUNT,
};
use corpus::{assert_corpus_shape, disagreements, replay_vectors, report};
use unicode_rust::segmentation::line_breaks;

#[test]
fn the_corpus_is_well_formed() {
    assert_corpus_shape(PUBLISHED_ROWS, PUBLISHED_COUNT);
}

#[test]
fn the_implementation_agrees_with_every_published_row() {
    let failures = disagreements(PUBLISHED_ROWS, |cps| line_breaks(cps));
    assert!(failures.is_empty(), "{}", report(PUBLISHED_COUNT, &failures));
}

#[test]
fn the_shared_vectors_replay() {
    // One case per UAX #14 rule, the same bytes every port replays, so no port
    // can carry a weaker set of rule checks than another.
    let failures = replay_vectors(LINE_BREAK_ALGORITHM, LINE_BREAK_CASES, |cps| {
        line_breaks(cps)
    });
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn the_corpus_and_the_vectors_agree_on_the_row_count() {
    // Both gates count the same published file, so they cannot drift apart.
    assert_eq!(LINE_BREAK_PUBLISHED_ROW_COUNT, PUBLISHED_COUNT);
}
