//! Confusable-in-bidi-context compound detector (CVE-2021-42574 class).
//!
//! Threat model.  Tier compound.  A confusable (homoglyph) codepoint co-located
//! with a bidi format-control is materially more dangerous than either alone:
//! the homoglyph disguises an identifier while the bidi control reorders how a
//! reviewer reads it.  This detector fires only when both are present.
//!
//! Direct port of `Unicode/Security/Boundary/ConfusableBidiCompound.lean`.
//! The confusable-source predicate reads confusables.txt (via
//! [`homoglyph_confusable::is_confusable_source`]); the bidi predicates split
//! the format-controls into the override class (LRE/RLE/LRO/RLO/PDF) and the
//! isolate class (LRI/RLI/FSI/PDI), matching `Unicode.TrojanSource`.

use crate::security::covert::bidi_control_balance::{
    is_pdf, is_pdi, opens_embedding, opens_isolate,
};
use crate::security::identity::homoglyph_confusable::is_confusable_source;

/// One confusable-bidi-compound scan result.  `sub` is `None` for a clear
/// input; otherwise it is the sub-threat tag with the offending positions
/// `[confusable_pos, bidi_pos]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detection {
    pub sub: Option<&'static str>,
    pub positions: Vec<usize>,
}

/// True iff `cp` is an override-class bidi control (LRE, RLE, LRO, RLO, PDF).
fn is_override(cp: u32) -> bool {
    opens_embedding(cp) || is_pdf(cp)
}

/// True iff `cp` is an isolate-class bidi control (LRI, RLI, FSI, PDI).
fn is_isolate(cp: u32) -> bool {
    opens_isolate(cp) || is_pdi(cp)
}

fn first_pos(input: &[u32], pred: impl Fn(u32) -> bool) -> Option<usize> {
    input.iter().position(|&cp| pred(cp))
}

/// Detect a confusable codepoint sharing the input with a bidi control.
/// Priority mirrors the spec: with a confusable present, an override-class
/// control fires `ConfusableInOverride`; otherwise an isolate-class control
/// fires `ConfusableInIsolate`; otherwise clear.
pub fn detect(input: &[u32]) -> Detection {
    let confusable_pos = match first_pos(input, is_confusable_source) {
        Some(pos) => pos,
        None => {
            return Detection {
                sub: None,
                positions: Vec::new(),
            }
        }
    };
    if let Some(bidi_pos) = first_pos(input, is_override) {
        return Detection {
            sub: Some("ConfusableInOverride"),
            positions: vec![confusable_pos, bidi_pos],
        };
    }
    if let Some(bidi_pos) = first_pos(input, is_isolate) {
        return Detection {
            sub: Some("ConfusableInIsolate"),
            positions: vec![confusable_pos, bidi_pos],
        };
    }
    Detection {
        sub: None,
        positions: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::detect;

    // Ground truth: the `detect_*` spot-check theorems in
    // `Unicode/Security/Boundary/ConfusableBidiCompound.lean`.

    fn sub(input: &[u32]) -> Option<&'static str> {
        detect(input).sub
    }

    #[test]
    fn empty_and_ascii_clear() {
        assert_eq!(sub(&[]), None);
        assert_eq!(sub(&[0x48, 0x65, 0x6C, 0x6C, 0x6F]), None);
    }

    #[test]
    fn bidi_without_confusable_clear() {
        // RLO + plain ASCII A B C — no confusable source.
        assert_eq!(sub(&[0x202E, 0x0041, 0x0042, 0x0043]), None);
    }

    #[test]
    fn confusable_without_bidi_clear() {
        // Cyrillic а alone — confusable but no bidi control.
        assert_eq!(sub(&[0x0430]), None);
    }

    #[test]
    fn confusable_in_override() {
        // RLO (override) + Cyrillic а (confusable).
        assert_eq!(sub(&[0x202E, 0x0430]), Some("ConfusableInOverride"));
    }

    #[test]
    fn confusable_in_isolate() {
        // LRI (isolate) + Greek ο (confusable).
        assert_eq!(sub(&[0x2066, 0x03BF]), Some("ConfusableInIsolate"));
    }
}
