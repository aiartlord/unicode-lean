//! The gate every published UAX break corpus gets, once.
//!
//! Hand-written vectors cannot establish a segmentation algorithm. Its rules
//! read context on both sides of a boundary and the answer depends on state
//! carried from earlier in the sequence, so a wrong rule survives any vector a
//! person would pick. The Unicode Consortium publishes a corpus per algorithm
//! for exactly that reason.
//!
//! The four break suites share one row format, so they share one judge here.
//! Each algorithm's test supplies its implementation and its corpus; the two
//! gates and the failure report live here.
//!
//! Those two gates are the spec repo's own: agree with every published row,
//! and separately account for the whole file, so a row lost between the corpus
//! module and this fold is a failure rather than a smaller denominator.

pub mod grapheme_rows;
pub mod line_break_rows;
pub mod vector_cases;

/// Every shared vector case whose boundary mask the implementation does not
/// reproduce, as a ready failure line each.
///
/// The published corpus is the authority; these cases name which rule each
/// boundary exercises, so a failure here says which rule broke rather than
/// which row index did. The algorithm name is checked too, so a test pointed at
/// the wrong case list fails rather than passing vacuously.
pub fn replay_vectors<F>(
    algorithm: &str,
    cases: &[vector_cases::VectorCase],
    breaks_of: F,
) -> Vec<String>
where
    F: Fn(&[u32]) -> Vec<bool>,
{
    assert!(!cases.is_empty(), "{} carries no vector cases", algorithm);
    cases
        .iter()
        .filter_map(|case| {
            let produced = breaks_of(case.input);
            if produced == case.breaks {
                return None;
            }
            Some(format!(
                "{}: {}\n  codepoints : {}\n  fixture    : {}\n  produced   : {}",
                case.rule,
                case.name,
                case.input
                    .iter()
                    .map(|cp| format!("U+{:04X}", cp))
                    .collect::<Vec<String>>()
                    .join(" "),
                flags(case.breaks),
                flags(&produced),
            ))
        })
        .collect()
}

/// A published row whose expected flags differ from what the implementation
/// produced: the row's index, its code points, the published flags, and the
/// produced ones.
pub struct Disagreement<'a> {
    pub index: usize,
    pub codepoints: &'a [u32],
    pub published: &'a [bool],
    pub produced: Vec<bool>,
}

/// What the corpus must be before it can judge anything: every published row
/// reaches the fold, and each row carries one more flag than code points.
///
/// Panics with the offending row indices when either does not hold.
pub fn assert_corpus_shape(rows: &[(&[u32], &[bool])], published: usize) {
    assert_eq!(
        rows.len(),
        published,
        "the corpus table carries {} rows but the pinned file carries {}",
        rows.len(),
        published
    );
    let ragged: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_index, (codepoints, flags))| flags.len() != codepoints.len() + 1)
        .map(|(index, _row)| index)
        .collect();
    assert!(
        ragged.is_empty(),
        "rows carry a flag count that is not one more than their code points: {:?}",
        ragged
    );
}

/// Every row the implementation disagrees with, in corpus order.
pub fn disagreements<'a, F>(rows: &'a [(&'a [u32], &'a [bool])], breaks_of: F) -> Vec<Disagreement<'a>>
where
    F: Fn(&[u32]) -> Vec<bool>,
{
    rows.iter()
        .enumerate()
        .filter_map(|(index, &(codepoints, published))| {
            let produced = breaks_of(codepoints);
            if produced == published {
                None
            } else {
                Some(Disagreement {
                    index,
                    codepoints,
                    published,
                    produced,
                })
            }
        })
        .collect()
}

/// A failure names the count and the first failing row in full. A conformance
/// red is only actionable if it says which row and which position disagreed,
/// so the first differing boundary is reported alongside the two flag lists.
pub fn report(published: usize, failures: &[Disagreement<'_>]) -> String {
    let first = match failures.first() {
        None => return String::from("no disagreements"),
        Some(first) => first,
    };
    format!(
        "{} of {} published rows disagree; first at row index {}\n  \
         codepoints : {}\n  published  : {}\n  produced   : {}\n  \
         first differing boundary: {}",
        failures.len(),
        published,
        first.index,
        first
            .codepoints
            .iter()
            .map(|cp| format!("U+{:04X}", cp))
            .collect::<Vec<String>>()
            .join(" "),
        flags(first.published),
        flags(&first.produced),
        first_boundary(first.published, &first.produced),
    )
}

/// The markers the published files write: a break opportunity, or none.
fn flags(values: &[bool]) -> String {
    values
        .iter()
        .map(|&is_break| if is_break { "/" } else { "x" })
        .collect::<Vec<&str>>()
        .join(" ")
}

/// The index of the first boundary the two flag lists disagree on, or a note
/// that they differ only in length.
fn first_boundary(published: &[bool], produced: &[bool]) -> String {
    match published
        .iter()
        .zip(produced.iter())
        .position(|(left, right)| left != right)
    {
        Some(boundary) => boundary.to_string(),
        None => format!(
            "none — the lists differ in length ({} published, {} produced)",
            published.len(),
            produced.len()
        ),
    }
}
