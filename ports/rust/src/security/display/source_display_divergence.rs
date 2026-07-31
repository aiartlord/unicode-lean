//! Source-display divergence — the aggregate "what a reviewer sees differs
//! from what the machine runs" detector.
//!
//! Threat model.  Tier D1.  A single covert or identity trick may be
//! individually benign-looking, but any hit means the rendered source
//! diverges from its logical content; two or more is a strong compound
//! signal.  This detector runs the five constituent detectors on the same
//! codepoint stream and aggregates: zero fire → clear, exactly one →
//! pass-through that family's tag, two or more → `Compound`.
//!
//! Direct port of `Unicode/Security/Display/SourceDisplayDivergence.lean`
//! (`detect` + `buildClassification`).  Every constituent fires
//! region-agnostically — payloads inside string literals or comments count.

use crate::security::calculus::ClassificationKind;
use crate::security::covert::{bidi_control_balance, tag_block_payload, zero_width_payload};
use crate::security::covert::variation_selector_payload;
use crate::security::identity::homoglyph_confusable;

/// One source-display-divergence scan result.  `sub` is `None` for a clear
/// input; a single constituent hit passes through its family tag; two or
/// more yield `"Compound"`.  Positions are empty at this layer by the Lean
/// spec (the per-family verdicts carry them), so this result carries only
/// the sub-threat; the scan wiring emits an empty position list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detection {
    pub sub: Option<&'static str>,
}

fn fired(kind: ClassificationKind) -> bool {
    kind != ClassificationKind::Clear
}

/// Aggregate the five constituent detectors into a single D1 verdict.
pub fn detect(input: &[u32]) -> Detection {
    // Constituent family tags in canonical aggregation order: C1 tag-block,
    // C2 variation-selector, C3 zero-width, C5 bidi-control, I1 homoglyph.
    let mut fires: Vec<&'static str> = Vec::new();
    if fired(tag_block_payload::detect(input).kind) {
        fires.push("TagBlock");
    }
    if fired(variation_selector_payload::detect(input).kind) {
        fires.push("VariationSelector");
    }
    if fired(zero_width_payload::detect(input).kind) {
        fires.push("ZeroWidth");
    }
    if fired(bidi_control_balance::detect(input).kind) {
        fires.push("BidiControl");
    }
    if fired(homoglyph_confusable::detect(input).kind) {
        fires.push("IdentifierHomoglyph");
    }

    let sub = match fires.len() {
        0 => None,
        1 => Some(fires[0]),
        _ => Some("Compound"),
    };
    Detection { sub }
}

#[cfg(test)]
mod tests {
    use super::detect;

    // Ground truth: the `detect_*` spot-check theorems in
    // `Unicode/Security/Display/SourceDisplayDivergence.lean`.

    fn sub(input: &[u32]) -> Option<&'static str> {
        detect(input).sub
    }

    #[test]
    fn clear_cases() {
        assert_eq!(sub(&[]), None);
        // "Hello world"
        assert_eq!(
            sub(&[0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64]),
            None
        );
        // "let x = 1;"
        assert_eq!(
            sub(&[0x6C, 0x65, 0x74, 0x20, 0x78, 0x20, 0x3D, 0x20, 0x31, 0x3B]),
            None
        );
    }

    #[test]
    fn single_fire_passthrough() {
        // tag-encoded "AB"
        assert_eq!(sub(&[0xE0041, 0xE0042]), Some("TagBlock"));
        // A + VS16
        assert_eq!(sub(&[0x0041, 0xFE0F]), Some("VariationSelector"));
        // H + ZWSP + i
        assert_eq!(sub(&[0x0048, 0x200B, 0x69]), Some("ZeroWidth"));
        // RLO + A
        assert_eq!(sub(&[0x202E, 0x41]), Some("BidiControl"));
        // "Neth<Cyrillic е>um"
        assert_eq!(
            sub(&[0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D]),
            Some("IdentifierHomoglyph")
        );
    }

    #[test]
    fn two_or_more_is_compound() {
        // A + VS16 + ZWSP
        assert_eq!(sub(&[0x0041, 0xFE0F, 0x200B]), Some("Compound"));
        // tag "AB" + ZWSP
        assert_eq!(sub(&[0xE0041, 0xE0042, 0x200B]), Some("Compound"));
    }
}
