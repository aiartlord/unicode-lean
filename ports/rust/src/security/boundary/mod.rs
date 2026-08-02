//! Boundary / compound detector family.
//!
//! Cross-layer detectors that compose the shared library primitives the
//! single-layer families build on — confusable-source membership, bidi
//! format-control class, the normalization pipelines, and the identifier
//! admissibility predicates — to catch attacks that only appear when two
//! signals coincide.

pub mod confusable_bidi_compound;
pub mod covert_display_compound;
pub mod identifier_form_drift;
