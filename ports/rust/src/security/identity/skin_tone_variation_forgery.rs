//! SkinToneVariationForgery — skin-tone modifier and variation-selector abuse on
//! emoji bases per UTS #51 (identity-layer detector).
//!
//! Byte-faithful transliteration of
//! `Unicode/Security/Identity/SkinToneVariationForgery.lean`.
//!
//! Threat model. Tier A₁. An adversary places a skin-tone modifier on a codepoint
//! that does NOT bear `Emoji_Modifier_Base`, stacks multiple skin-tones on one
//! base, or forces a text-style render on an emoji-default codepoint via `U+FE0E`
//! (VS15) — sometimes to hide a payload-bearing glyph in plain sight.
//!
//! Distinct from VariationSelectorPayload (pair-aligned VS runs that decode to
//! bytes): this catches the orthogonal case of *semantic* VS / skin-tone misuse on
//! a single base. Both can fire on the same input; SourceDisplayDivergence
//! aggregates.
//!
//! It reuses the port's own emoji property tables (the bundled `emoji-data.txt`),
//! never a host emoji library.
//!
//! Sub-threats (priority order):
//!   1. `StackedSkinTones`      a base immediately followed by >= 2 skin-tone modifiers.
//!   2. `InvalidSkinToneTarget` a skin-tone modifier on a non-`Emoji_Modifier_Base`.
//!   3. `ForcedTextStyle`       `U+FE0E` on an `Emoji_Presentation` codepoint.

use crate::security::identity::emoji_zwj_integrity;
use std::sync::OnceLock;

// ─────────────────────────────────────────────────────────────────────
// §1 Types
// ─────────────────────────────────────────────────────────────────────

/// Sub-threat enumeration for SkinToneVariationForgery, in priority order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubThreat {
    /// A base at `base_pos` followed by >= 2 skin-tone modifiers (`modifiers`).
    StackedSkinTones {
        /// Position of the base codepoint.
        base_pos: usize,
        /// The first two stacked skin-tone modifiers.
        modifiers: Vec<u32>,
    },
    /// A skin-tone `modifier_cp` at `base_pos + 1` on a non-modifier-base `base_cp`.
    InvalidSkinToneTarget {
        /// Position of the (invalid) base codepoint.
        base_pos: usize,
        /// The base codepoint that lacks `Emoji_Modifier_Base`.
        base_cp: u32,
        /// The skin-tone modifier codepoint.
        modifier_cp: u32,
    },
    /// A `U+FE0E` at `base_pos + 1` forcing text-style on an `Emoji_Presentation`
    /// `base_cp`.
    ForcedTextStyle {
        /// Position of the `Emoji_Presentation` codepoint.
        base_pos: usize,
        /// The `Emoji_Presentation` codepoint forced to text style.
        base_cp: u32,
    },
}

impl SubThreat {
    /// Fixture-row tag string for this sub-threat (matches `SubThreat.tag`).
    pub fn tag(&self) -> &'static str {
        match self {
            SubThreat::StackedSkinTones {
                base_pos: _,
                modifiers: _,
            } => "StackedSkinTones",
            SubThreat::InvalidSkinToneTarget {
                base_pos: _,
                base_cp: _,
                modifier_cp: _,
            } => "InvalidSkinToneTarget",
            SubThreat::ForcedTextStyle {
                base_pos: _,
                base_cp: _,
            } => "ForcedTextStyle",
        }
    }
}

/// Top-level classification for SkinToneVariationForgery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Classification {
    /// No skin-tone / variation-selector abuse present.
    Clear,
    /// An abuse pattern fired.
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
    /// True iff the classification is `Clear`.
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
    /// Count of skin-tone modifier codepoints.
    pub skin_tone_count: usize,
    /// Count of `U+FE0E` (VS15) codepoints.
    pub variation_selector15_count: usize,
    /// Count of `U+FE0F` (VS16) codepoints.
    pub variation_selector16_count: usize,
}

// ─────────────────────────────────────────────────────────────────────
// §2 Core predicates (reuse the port's own emoji tables)
// ─────────────────────────────────────────────────────────────────────

const EMOJI_DATA_RAW: &str = include_str!("../../../data/emoji-data.txt");

/// Parse the closed intervals for a single emoji property from emoji-data.txt.
/// Each non-comment row is `<range> ; <property> # <comment>`; we keep only rows
/// whose property field matches `property` exactly.
fn parse_emoji_property(property: &str) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    for raw_line in EMOJI_DATA_RAW.lines() {
        let body = match raw_line.find('#') {
            Some(idx) => &raw_line[..idx],
            None => raw_line,
        };
        let stripped = body.trim();
        if stripped.is_empty() {
            continue;
        }
        let mut fields = stripped.split(';');
        let (Some(range_field), Some(prop_field)) = (fields.next(), fields.next()) else {
            continue;
        };
        if prop_field.trim() != property {
            continue;
        }
        let range = range_field.trim();
        let (lo, hi) = match range.split_once("..") {
            Some((a, b)) => {
                let (Some(a), Some(b)) =
                    (u32::from_str_radix(a.trim(), 16).ok(), u32::from_str_radix(b.trim(), 16).ok())
                else {
                    continue;
                };
                (a, b)
            }
            None => match u32::from_str_radix(range, 16) {
                Ok(single) => (single, single),
                Err(_parse_error) => continue,
            },
        };
        out.push((lo, hi));
    }
    out
}

fn emoji_modifier_base_ranges() -> &'static Vec<(u32, u32)> {
    static T: OnceLock<Vec<(u32, u32)>> = OnceLock::new();
    T.get_or_init(|| parse_emoji_property("Emoji_Modifier_Base"))
}

fn emoji_presentation_ranges() -> &'static Vec<(u32, u32)> {
    static T: OnceLock<Vec<(u32, u32)>> = OnceLock::new();
    T.get_or_init(|| parse_emoji_property("Emoji_Presentation"))
}

/// True iff `cp` is an emoji skin-tone modifier (reuses the port's predicate).
pub fn is_skin_tone(cp: u32) -> bool {
    emoji_zwj_integrity::is_emoji_modifier(cp)
}

/// True iff `cp` has `Emoji_Modifier_Base` per emoji-data.txt.
pub fn is_skin_tone_base(cp: u32) -> bool {
    emoji_modifier_base_ranges().iter().any(|&(lo, hi)| lo <= cp && cp <= hi)
}

/// True iff `cp` has `Emoji_Presentation` per emoji-data.txt.
pub fn is_emoji_presentation(cp: u32) -> bool {
    emoji_presentation_ranges().iter().any(|&(lo, hi)| lo <= cp && cp <= hi)
}

/// True iff `cp` is `U+FE0E` (VS15, text-style variation selector).
pub fn is_vs15(cp: u32) -> bool {
    cp == 0xFE0E
}

/// True iff `cp` is `U+FE0F` (VS16, emoji-style variation selector).
pub fn is_vs16(cp: u32) -> bool {
    cp == 0xFE0F
}

// ─────────────────────────────────────────────────────────────────────
// §3 Sub-detectors
// ─────────────────────────────────────────────────────────────────────

/// First position `p` whose next two codepoints are both skin-tone modifiers,
/// as `(base_pos, [mod1, mod2])`.
fn first_stacked_skin_tones(input: &[u32]) -> Option<(usize, Vec<u32>)> {
    (0..input.len()).find_map(|i| match (input.get(i + 1), input.get(i + 2)) {
        (Some(&m1), Some(&m2)) if is_skin_tone(m1) && is_skin_tone(m2) => Some((i, vec![m1, m2])),
        (_next1, _next2) => None,
    })
}

/// First skin-tone modifier whose preceding codepoint is NOT `Emoji_Modifier_Base`,
/// as `(base_pos, base_cp, modifier_cp)`.
fn first_invalid_skin_tone_target(input: &[u32]) -> Option<(usize, u32, u32)> {
    (0..input.len()).find_map(|i| match input.get(i + 1) {
        Some(&cp) if is_skin_tone(cp) && !is_skin_tone_base(input[i]) => Some((i, input[i], cp)),
        _other => None,
    })
}

/// First `U+FE0E` whose preceding codepoint has `Emoji_Presentation`, as
/// `(base_pos, base_cp)`.
fn first_forced_text_style(input: &[u32]) -> Option<(usize, u32)> {
    (0..input.len()).find_map(|i| match input.get(i + 1) {
        Some(&cp) if is_vs15(cp) && is_emoji_presentation(input[i]) => Some((i, input[i])),
        _other => None,
    })
}

fn skin_tone_count(input: &[u32]) -> usize {
    input.iter().filter(|&&cp| is_skin_tone(cp)).count()
}

fn vs15_count(input: &[u32]) -> usize {
    input.iter().filter(|&&cp| is_vs15(cp)).count()
}

fn vs16_count(input: &[u32]) -> usize {
    input.iter().filter(|&&cp| is_vs16(cp)).count()
}

// ─────────────────────────────────────────────────────────────────────
// §4 Top-level detection
// ─────────────────────────────────────────────────────────────────────

/// The SkinToneVariationForgery detection function.
pub fn detect(input: &[u32]) -> Verdict {
    let stc = skin_tone_count(input);
    let v15 = vs15_count(input);
    let v16 = vs16_count(input);

    let classification = match first_stacked_skin_tones(input) {
        // Priority 1: a base followed by two stacked skin tones.
        Some((base_pos, modifiers)) => {
            let positions = (0..modifiers.len()).map(|i| base_pos + 1 + i).collect();
            Classification::Hazard {
                sub: SubThreat::StackedSkinTones { base_pos, modifiers },
                positions,
                decoded: Vec::new(),
            }
        }
        None => match first_invalid_skin_tone_target(input) {
            // Priority 2: a skin tone on a non-modifier-base.
            Some((base_pos, base_cp, modifier_cp)) => Classification::Hazard {
                sub: SubThreat::InvalidSkinToneTarget {
                    base_pos,
                    base_cp,
                    modifier_cp,
                },
                positions: vec![base_pos + 1],
                decoded: Vec::new(),
            },
            None => match first_forced_text_style(input) {
                // Priority 3: VS15 forcing text style on an emoji-presentation cp.
                Some((base_pos, base_cp)) => Classification::Hazard {
                    sub: SubThreat::ForcedTextStyle { base_pos, base_cp },
                    positions: vec![base_pos + 1],
                    decoded: Vec::new(),
                },
                None => Classification::Clear,
            },
        },
    };

    Verdict {
        input: input.to_vec(),
        classify: classification,
        skin_tone_count: stc,
        variation_selector15_count: v15,
        variation_selector16_count: v16,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::calculus::Family;
    use crate::security::policy::reason_code;

    // Ground truth: every `detect_*` theorem in
    // `Unicode/Security/Identity/SkinToneVariationForgery.lean`. Each maps to one
    // `#[test]`; the shared context-free fixture
    // (`fixtures/security/detectors/skin_tone_variation_forgery.json`) carries the
    // same vectors.

    fn tag(input: &[u32]) -> Option<&'static str> {
        detect(input).classify.tag()
    }

    // `detect_empty_clear`
    #[test]
    fn detect_empty_clear() {
        assert!(detect(&[]).classify.is_clear());
    }

    // `detect_ascii_clear` — "He"
    #[test]
    fn detect_ascii_clear() {
        assert!(detect(&[0x48, 0x65]).classify.is_clear());
    }

    // `detect_plain_emoji_clear` — grinning face
    #[test]
    fn detect_plain_emoji_clear() {
        assert!(detect(&[0x1F600]).classify.is_clear());
    }

    // `detect_wave_skin_tone_clear` — waving hand (a modifier base) + one skin tone.
    #[test]
    fn detect_wave_skin_tone_clear() {
        let v = detect(&[0x1F44B, 0x1F3FB]);
        assert!(v.classify.is_clear());
        assert_eq!(v.skin_tone_count, 1);
    }

    // `detect_stacked_skin_tones` — waving hand + two skin tones.
    #[test]
    fn detect_stacked_skin_tones() {
        let v = detect(&[0x1F44B, 0x1F3FB, 0x1F3FC]);
        assert_eq!(v.classify.tag(), Some("StackedSkinTones"));
        assert_eq!(v.classify.positions(), &[1, 2]);
    }

    // `detect_invalid_target_ascii` — skin tone on ASCII 'A'.
    #[test]
    fn detect_invalid_target_ascii() {
        let v = detect(&[0x0041, 0x1F3FB]);
        assert_eq!(v.classify.tag(), Some("InvalidSkinToneTarget"));
        assert_eq!(v.classify.positions(), &[1]);
    }

    // `detect_invalid_target_smiley` — skin tone on grinning face (not a modifier base).
    #[test]
    fn detect_invalid_target_smiley() {
        assert_eq!(tag(&[0x1F600, 0x1F3FB]), Some("InvalidSkinToneTarget"));
    }

    // `detect_forced_text_style` — VS15 on grinning face (Emoji_Presentation).
    #[test]
    fn detect_forced_text_style() {
        let v = detect(&[0x1F600, 0xFE0E]);
        assert_eq!(v.classify.tag(), Some("ForcedTextStyle"));
        assert_eq!(v.variation_selector15_count, 1);
    }

    // The composed reason codes for each sub-threat.
    #[test]
    fn reason_code_is_stable() {
        assert_eq!(
            reason_code(Family::SkinToneVariationForgery, Some("StackedSkinTones")),
            "unicode.security.I.skin-tone-variation-forgery.StackedSkinTones"
        );
        assert_eq!(
            reason_code(Family::SkinToneVariationForgery, Some("ForcedTextStyle")),
            "unicode.security.I.skin-tone-variation-forgery.ForcedTextStyle"
        );
    }
}
