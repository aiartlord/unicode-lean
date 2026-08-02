//! Display-integrity detector family.
//!
//! Detectors for hazards that arise from the gap between a string's
//! logical codepoint order and how a bidi-aware renderer presents it —
//! right-to-left injection into a left-to-right-declared field being
//! the first member.

pub mod filename_disguise;
pub mod renderer_divergence;
pub mod rtl_injection;
pub mod source_display_divergence;
