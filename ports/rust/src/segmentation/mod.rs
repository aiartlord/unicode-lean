//! Text segmentation algorithms (UAX #29 and UAX #14).
//!
//! Ports of the formally verified Lean segmentation algorithms. Grapheme
//! cluster breaking and line breaking are available today; word and sentence
//! breaking follow the same verified template.

pub mod grapheme;
mod grapheme_tables;
pub mod line_break;
mod line_break_tables;

pub use grapheme::{grapheme_breaks, grapheme_clusters, is_ext_pict, lookup_gcb, lookup_incb};
pub use grapheme_tables::{Gcb, Incb};
pub use line_break::{line_breaks, line_runs, raw_class, resolved_class, Snapshot};
pub use line_break_tables::Lb;
