//! Security Conformance Layer.
//!
//! Per-family modules under `unicode_rust::security::{covert,
//! identity, display, form, boundary, crypto}` import the shared
//! vocabulary from [`calculus`] and refine it into family-specific
//! verdict structures.

pub mod boundary;
pub mod calculus;
pub mod covert;
pub mod display;
pub mod identity;
pub mod policy;

pub use calculus::{
    default_severity, AdversaryTier, ClassificationKind, Family, HazardPosition,
    KeyValueAttribution, Severity,
};
pub use policy::{
    blocking_findings, family_blocks, family_layer_code, family_slug, finding_to_json, permits,
    policy_of_profile, reason_base, reason_code, rejection_set, scan, scan_default, scan_utf16be,
    scan_utf16le, scan_utf32be, scan_utf32le, scan_utf8, select_action, utf8_reject_tag,
    verdict_to_json, Action, CryptoContext, Finding, Mode, PolicyLevel, Profile, ProfilePolicy,
    Verdict,
};
