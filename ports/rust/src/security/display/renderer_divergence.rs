//! RendererDivergence — detection of codepoint/sequence shapes known to render
//! differently across font + terminal + browser stacks (display-layer detector).
//!
//! Byte-faithful transliteration of
//! `Unicode/Security/Display/RendererDivergence.lean`.
//!
//! Threat model. An adversary crafts content that renders one way in the
//! auditor's renderer (a benign glyph or an empty span) and a different way in
//! the consumer's renderer (a misleading glyph, a wider glyph, or a different
//! sequence). This is the "fingerprint stability" family — clear inputs render
//! the same across the renderer cohort the Standard documents as stable.
//!
//! What the detector draws. A heuristic three-value split, surfaced through the
//! universal clear/hazard carrier: an input is clear when none of the documented
//! variance triggers fire, and otherwise is classified by the first trigger in
//! priority order — combining-mark stack overflow, variation-selector presence,
//! an unregistered ZWJ shape, fullwidth/halfwidth display, or mixed direction.
//! It reuses the port's own tables (variation-selector set, grapheme
//! Extend class, the RGI ZWJ registry, and strong-bidi classes), never a host
//! rendering or shaping library.
//!
//! Sub-threats (priority order):
//!   1. `CombiningStackOverflow`   Zalgo-like combining-mark stack >= 4 on a base.
//!   2. `VariationSelectorVariance` any variation selector present.
//!   3. `UnregisteredZwjVariance`  ZWJ-containing input not in the RGI ZWJ set.
//!   4. `FullwidthVariance`        a fullwidth/halfwidth codepoint present.
//!   5. `MixedDirectionVariance`   both strong-LTR and strong-RTL codepoints.

use crate::security::covert::variation_selector_payload;
use crate::security::identity::emoji_zwj_integrity;
use crate::security::identity::ucd;
use crate::segmentation::grapheme;

// ─────────────────────────────────────────────────────────────────────
// §1 Constants
// ─────────────────────────────────────────────────────────────────────

/// The combining-mark stack depth (on a single base) at or beyond which the
/// input is treated as a Zalgo-style rendering-variance hazard.
pub const MIN_COMBINING_STACK: usize = 4;

/// The ZERO WIDTH JOINER codepoint.
pub const ZWJ: u32 = 0x200D;

// ─────────────────────────────────────────────────────────────────────
// §2 Types
// ─────────────────────────────────────────────────────────────────────

/// Sub-threat enumeration for RendererDivergence, in priority order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubThreat {
    /// A combining-mark stack of `stack_len` marks on the base at `base_pos`.
    CombiningStackOverflow {
        /// Position of the base the stack sits on.
        base_pos: usize,
        /// The stack depth tested (>= MIN_COMBINING_STACK).
        stack_len: usize,
    },
    /// A variation selector at `first_vs_pos` (codepoint `first_vs_cp`).
    VariationSelectorVariance {
        /// Position of the first variation selector.
        first_vs_pos: usize,
        /// Codepoint of the first variation selector.
        first_vs_cp: u32,
    },
    /// A ZWJ-containing input not present in the registered RGI ZWJ set.
    UnregisteredZwjVariance {
        /// Position of the first ZWJ.
        first_zwj_pos: usize,
    },
    /// A fullwidth/halfwidth codepoint at `first_fw_pos` (codepoint `first_fw_cp`).
    FullwidthVariance {
        /// Position of the first fullwidth/halfwidth codepoint.
        first_fw_pos: usize,
        /// The fullwidth/halfwidth codepoint.
        first_fw_cp: u32,
    },
    /// Both strong-LTR and strong-RTL codepoints in one input.
    MixedDirectionVariance {
        /// Count of strong-LTR codepoints.
        ltr_count: usize,
        /// Count of strong-RTL codepoints.
        rtl_count: usize,
    },
}

impl SubThreat {
    /// Fixture-row tag string for this sub-threat (matches `SubThreat.tag`).
    pub fn tag(&self) -> &'static str {
        match self {
            SubThreat::CombiningStackOverflow {
                base_pos: _,
                stack_len: _,
            } => "CombiningStackOverflow",
            SubThreat::VariationSelectorVariance {
                first_vs_pos: _,
                first_vs_cp: _,
            } => "VariationSelectorVariance",
            SubThreat::UnregisteredZwjVariance { first_zwj_pos: _ } => "UnregisteredZwjVariance",
            SubThreat::FullwidthVariance {
                first_fw_pos: _,
                first_fw_cp: _,
            } => "FullwidthVariance",
            SubThreat::MixedDirectionVariance {
                ltr_count: _,
                rtl_count: _,
            } => "MixedDirectionVariance",
        }
    }
}

/// Top-level classification (stable = `Clear`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Classification {
    /// Rendering is consistent across the documented renderer cohort.
    Clear,
    /// A documented variance mode fired.
    Hazard {
        /// The sub-threat that fired.
        sub: SubThreat,
        /// The implicated positions.
        positions: Vec<usize>,
        /// The decoded-byte projection (always empty here; shape parity with Lean).
        decoded: Vec<u8>,
    },
}

impl Classification {
    /// True iff the classification is `Clear` (i.e. stable).
    pub fn is_clear(&self) -> bool {
        match self {
            Classification::Clear => true,
            Classification::Hazard {
                sub: _,
                positions: _,
                decoded: _,
            } => false,
        }
    }

    /// Human-facing tag for a hazard, or `None` when clear.
    pub fn tag(&self) -> Option<&'static str> {
        match self {
            Classification::Clear => None,
            Classification::Hazard {
                sub,
                positions: _,
                decoded: _,
            } => Some(sub.tag()),
        }
    }

    /// Implicated positions (empty when clear).
    pub fn positions(&self) -> &[usize] {
        match self {
            Classification::Clear => &[],
            Classification::Hazard {
                sub: _,
                positions,
                decoded: _,
            } => positions,
        }
    }
}

/// The structured output of `detect` (mirrors the Lean `Verdict`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// The scanned input codepoints.
    pub input: Vec<u32>,
    /// The classification verdict.
    pub classify: Classification,
    /// Count of variation selectors.
    pub vs_count: usize,
    /// Count of combining (Extend) marks.
    pub combining_count: usize,
    /// Count of fullwidth/halfwidth codepoints.
    pub fullwidth_count: usize,
    /// Whether the input contains any ZWJ.
    pub has_zwj: bool,
    /// Count of strong-LTR codepoints.
    pub strong_ltr_count: usize,
    /// Count of strong-RTL codepoints.
    pub strong_rtl_count: usize,
}

// ─────────────────────────────────────────────────────────────────────
// §3 Core predicates
// ─────────────────────────────────────────────────────────────────────

/// True iff `cp` is a variation selector (reuses the port's own predicate).
pub fn is_variation_selector(cp: u32) -> bool {
    variation_selector_payload::is_variation_selector(cp)
}

/// True iff `cp` is the ZWJ codepoint.
pub fn is_zwj(cp: u32) -> bool {
    cp == ZWJ
}

/// True iff `cp` is in the Halfwidth/Fullwidth Forms block.
pub fn is_fullwidth_halfwidth(cp: u32) -> bool {
    (0xFF01..=0xFFEF).contains(&cp)
}

/// True iff `cp` has `Grapheme_Cluster_Break = Extend` (reuses the port's table).
pub fn is_grapheme_extend(cp: u32) -> bool {
    grapheme::is_grapheme_extend(cp)
}

// ─────────────────────────────────────────────────────────────────────
// §4 Sub-detectors
// ─────────────────────────────────────────────────────────────────────

fn count_vs(input: &[u32]) -> usize {
    input.iter().filter(|&&cp| is_variation_selector(cp)).count()
}

fn count_combining(input: &[u32]) -> usize {
    input.iter().filter(|&&cp| is_grapheme_extend(cp)).count()
}

fn count_fullwidth(input: &[u32]) -> usize {
    input.iter().filter(|&&cp| is_fullwidth_halfwidth(cp)).count()
}

fn input_has_zwj(input: &[u32]) -> bool {
    input.iter().any(|&cp| is_zwj(cp))
}

fn count_strong_ltr(input: &[u32]) -> usize {
    input.iter().filter(|&&cp| ucd::is_strong_ltr(cp)).count()
}

fn count_strong_rtl(input: &[u32]) -> usize {
    input.iter().filter(|&&cp| ucd::is_strong_rtl(cp)).count()
}

/// Position and codepoint of the first variation selector.
fn first_vs_pos(input: &[u32]) -> Option<(usize, u32)> {
    input
        .iter()
        .enumerate()
        .find_map(|(idx, &cp)| if is_variation_selector(cp) { Some((idx, cp)) } else { None })
}

/// Position of the first ZWJ.
fn first_zwj_pos(input: &[u32]) -> Option<usize> {
    input
        .iter()
        .enumerate()
        .find_map(|(idx, &cp)| if is_zwj(cp) { Some(idx) } else { None })
}

/// Position and codepoint of the first fullwidth/halfwidth codepoint.
fn first_fullwidth_pos(input: &[u32]) -> Option<(usize, u32)> {
    input
        .iter()
        .enumerate()
        .find_map(|(idx, &cp)| if is_fullwidth_halfwidth(cp) { Some((idx, cp)) } else { None })
}

/// The first base position (a non-Extend codepoint) immediately followed by
/// exactly `min_stack` consecutive Extend codepoints. Returns
/// `(base_pos, min_stack)` on hit.
fn first_combining_stack(input: &[u32], min_stack: usize) -> Option<(usize, usize)> {
    for (idx, &cp) in input.iter().enumerate() {
        if !is_grapheme_extend(cp) {
            let following: Vec<u32> = input.iter().skip(idx + 1).take(min_stack).copied().collect();
            if following.len() == min_stack && following.iter().all(|&c| is_grapheme_extend(c)) {
                return Some((idx, min_stack));
            }
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────
// §5 Top-level detection
// ─────────────────────────────────────────────────────────────────────

/// The RendererDivergence detection function.
pub fn detect(input: &[u32]) -> Verdict {
    let vs_count = count_vs(input);
    let combining_count = count_combining(input);
    let fullwidth_count = count_fullwidth(input);
    let has_zwj = input_has_zwj(input);
    let ltr_count = count_strong_ltr(input);
    let rtl_count = count_strong_rtl(input);

    let classification: Classification =
        // Priority 1: combining-mark stack overflow (Zalgo).
        match first_combining_stack(input, MIN_COMBINING_STACK) {
            Some((base_pos, stack_len)) => Classification::Hazard {
                sub: SubThreat::CombiningStackOverflow { base_pos, stack_len },
                positions: vec![base_pos],
                decoded: Vec::new(),
            },
            None => {
                // Priority 2: any variation selector triggers presentation variance.
                match first_vs_pos(input) {
                    Some((pos, cp)) => Classification::Hazard {
                        sub: SubThreat::VariationSelectorVariance {
                            first_vs_pos: pos,
                            first_vs_cp: cp,
                        },
                        positions: vec![pos],
                        decoded: Vec::new(),
                    },
                    None => {
                        // Priority 3: ZWJ-containing input not in the registered RGI set.
                        if has_zwj && !emoji_zwj_integrity::is_registered_zwj_sequence(input) {
                            match first_zwj_pos(input) {
                                Some(pos) => Classification::Hazard {
                                    sub: SubThreat::UnregisteredZwjVariance { first_zwj_pos: pos },
                                    positions: vec![pos],
                                    decoded: Vec::new(),
                                },
                                None => Classification::Clear,
                            }
                        } else {
                            // Priority 4: fullwidth/halfwidth.
                            match first_fullwidth_pos(input) {
                                Some((pos, cp)) => Classification::Hazard {
                                    sub: SubThreat::FullwidthVariance {
                                        first_fw_pos: pos,
                                        first_fw_cp: cp,
                                    },
                                    positions: vec![pos],
                                    decoded: Vec::new(),
                                },
                                None => {
                                    // Priority 5: mixed direction.
                                    if ltr_count > 0 && rtl_count > 0 {
                                        Classification::Hazard {
                                            sub: SubThreat::MixedDirectionVariance {
                                                ltr_count,
                                                rtl_count,
                                            },
                                            positions: Vec::new(),
                                            decoded: Vec::new(),
                                        }
                                    } else {
                                        Classification::Clear
                                    }
                                }
                            }
                        }
                    }
                }
            }
        };

    Verdict {
        input: input.to_vec(),
        classify: classification,
        vs_count,
        combining_count,
        fullwidth_count,
        has_zwj,
        strong_ltr_count: ltr_count,
        strong_rtl_count: rtl_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ground truth: every `detect_*` theorem in
    // `Unicode/Security/Display/RendererDivergence.lean`. Each Lean theorem maps
    // to one `#[test]` below; the shared context-free fixture
    // (`fixtures/security/detectors/renderer_divergence.json`) carries the same
    // vectors.

    fn tag(input: &[u32]) -> Option<&'static str> {
        detect(input).classify.tag()
    }

    // `detect_empty_clear`
    #[test]
    fn detect_empty_clear() {
        assert!(detect(&[]).classify.is_clear());
    }

    // `detect_ascii_clear`
    #[test]
    fn detect_ascii_clear() {
        assert!(detect(&[0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.is_clear());
    }

    // `detect_han_clear`
    #[test]
    fn detect_han_clear() {
        assert!(detect(&[0x4E2D, 0x6587]).classify.is_clear());
    }

    // `detect_vs_variance` — a single VS (FE0F) after an emoji.
    #[test]
    fn detect_vs_variance() {
        assert_eq!(tag(&[0x1F600, 0xFE0F]), Some("VariationSelectorVariance"));
    }

    // `detect_rgi_family_clear` — a registered RGI family ZWJ sequence.
    #[test]
    fn detect_rgi_family_clear() {
        let v = detect(&[0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466]);
        assert!(v.classify.is_clear());
        assert!(v.has_zwj);
    }

    // `detect_unregistered_zwj_variance` — man + ZWJ + woman, not in RGI.
    #[test]
    fn detect_unregistered_zwj_variance() {
        assert_eq!(
            tag(&[0x1F468, 0x200D, 0x1F469]),
            Some("UnregisteredZwjVariance")
        );
    }

    // `detect_zalgo_variance` — a 4-deep combining stack.
    #[test]
    fn detect_zalgo_variance() {
        let v = detect(&[0x0061, 0x0301, 0x0302, 0x0303, 0x0304]);
        assert_eq!(v.classify.tag(), Some("CombiningStackOverflow"));
        assert_eq!(v.classify.positions(), &[0]);
        assert_eq!(v.combining_count, 4);
    }

    // `detect_fullwidth_variance` — fullwidth 'A'.
    #[test]
    fn detect_fullwidth_variance() {
        assert_eq!(tag(&[0xFF21]), Some("FullwidthVariance"));
    }

    // `detect_mixed_direction` — Latin + Hebrew in one input.
    #[test]
    fn detect_mixed_direction() {
        let v = detect(&[0x41, 0x42, 0x05D0, 0x05D1]);
        assert_eq!(v.classify.tag(), Some("MixedDirectionVariance"));
        assert!(v.strong_ltr_count > 0 && v.strong_rtl_count > 0);
    }

    // ── priority-ladder structural checks ────────────────────────────────

    // A combining stack outranks a variation selector present later.
    #[test]
    fn combining_stack_beats_vs() {
        let v = detect(&[0x0061, 0x0301, 0x0302, 0x0303, 0x0304, 0xFE0F]);
        assert_eq!(v.classify.tag(), Some("CombiningStackOverflow"));
    }

    // Exactly three combining marks is below the stack threshold — no overflow.
    #[test]
    fn three_marks_below_threshold() {
        let v = detect(&[0x0061, 0x0301, 0x0302, 0x0303]);
        assert!(v.classify.tag() != Some("CombiningStackOverflow"));
    }
}
