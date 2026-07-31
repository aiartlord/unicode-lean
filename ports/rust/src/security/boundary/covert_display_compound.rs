//! Covert-display compound detector (bidi control co-located with a hidden
//! covert channel).
//!
//! Threat model.  Tier compound.  A bidi format-control that reorders the
//! visible glyphs is materially more dangerous when the same input also
//! carries a covert channel — an unregistered variation selector or a
//! tag-block character — because the reorder hides where the covert payload
//! sits.  This detector fires only when a bidi control coincides with one of
//! those covert classes.
//!
//! Direct port of `Unicode/Security/Boundary/CovertDisplayCompound.lean`.
//! A "suspicious VS" is a variation selector that does not form a registered
//! (base, VS) pair (StandardizedVariants / emoji-variation-sequences), the
//! `.suspicious` case of the variation-selector classifier.

use crate::security::covert::bidi_control_balance::is_bidi_format_control;
use crate::security::covert::variation_selector_payload::{
    is_registered_variation_pair, is_variation_selector,
};

/// One covert-display-compound scan result.  `sub` is `None` for a clear
/// input; otherwise the sub-threat tag with the offending positions
/// `[bidi_pos, covert_pos]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detection {
    pub sub: Option<&'static str>,
    pub positions: Vec<usize>,
}

/// True iff `cp` is in the tag-block range U+E0000..U+E007F.
fn is_tag_block_char(cp: u32) -> bool {
    (0xE0000..=0xE007F).contains(&cp)
}

fn first_bidi_pos(input: &[u32]) -> Option<usize> {
    input.iter().position(|&cp| is_bidi_format_control(cp))
}

/// First position holding a suspicious variation selector — a VS that does
/// not form a registered (base, VS) pair with its predecessor.  Mirrors the
/// `.suspicious` case of the Lean `classifyPositions`.
fn first_suspicious_vs_pos(input: &[u32]) -> Option<usize> {
    input.iter().enumerate().find_map(|(i, &cp)| {
        if is_variation_selector(cp)
            && !(i > 0 && is_registered_variation_pair(input[i - 1], cp))
        {
            Some(i)
        } else {
            None
        }
    })
}

fn first_tag_block_pos(input: &[u32]) -> Option<usize> {
    input.iter().position(|&cp| is_tag_block_char(cp))
}

/// Detect a bidi control co-located with a covert channel.  Priority mirrors
/// the spec: a bidi control must be present; then a suspicious VS fires
/// `BidiPlusUnregisteredVs`; otherwise a tag-block character fires
/// `BidiPlusTagBlock`; otherwise clear.
pub fn detect(input: &[u32]) -> Detection {
    let bidi_pos = match first_bidi_pos(input) {
        Some(pos) => pos,
        None => {
            return Detection {
                sub: None,
                positions: Vec::new(),
            }
        }
    };
    if let Some(vs_pos) = first_suspicious_vs_pos(input) {
        return Detection {
            sub: Some("BidiPlusUnregisteredVs"),
            positions: vec![bidi_pos, vs_pos],
        };
    }
    if let Some(tag_pos) = first_tag_block_pos(input) {
        return Detection {
            sub: Some("BidiPlusTagBlock"),
            positions: vec![bidi_pos, tag_pos],
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
    // `Unicode/Security/Boundary/CovertDisplayCompound.lean`.

    fn sub(input: &[u32]) -> Option<&'static str> {
        detect(input).sub
    }

    #[test]
    fn clear_cases() {
        assert_eq!(sub(&[]), None);
        assert_eq!(sub(&[0x48, 0x65, 0x6C, 0x6C, 0x6F]), None); // "Hello"
        assert_eq!(sub(&[0x202E]), None); // RLO alone
        assert_eq!(sub(&[0x0041, 0xFE00]), None); // A + VS1 alone, no bidi
    }

    #[test]
    fn bidi_plus_unregistered_vs() {
        // RLO + A + VS1 — the VS is not a registered (A, VS1) pair.
        assert_eq!(sub(&[0x202E, 0x0041, 0xFE00]), Some("BidiPlusUnregisteredVs"));
    }

    #[test]
    fn bidi_plus_tag_block() {
        // RLO + A + tag char — no suspicious VS, so the tag-block class fires.
        assert_eq!(sub(&[0x202E, 0x0041, 0xE0001]), Some("BidiPlusTagBlock"));
    }
}
