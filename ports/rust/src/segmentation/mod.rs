//! Text segmentation algorithms (UAX #29).
//!
//! Ports of the formally verified Lean segmentation algorithms. Grapheme
//! cluster breaking is available today; word / sentence / line follow the same
//! verified template.

pub mod grapheme;
mod grapheme_tables;

pub use grapheme::{grapheme_breaks, grapheme_clusters, is_ext_pict, lookup_gcb, lookup_incb};
pub use grapheme_tables::{Gcb, Incb};
