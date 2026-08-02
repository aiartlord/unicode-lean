//! CaseExpansionMismatch — codepoints whose UAX #21 default-locale case mapping
//! changes the codepoint count (form-layer detector).
//!
//! Byte-faithful transliteration of
//! `Unicode/Security/Form/CaseExpansionMismatch.lean`.
//!
//! Threat model. Tier A₁..A₂. An attacker submits text whose case-mapped form has
//! a different codepoint count than the input. A receiver that fixes a 16-byte
//! username column and stores `toUpper(username)` overflows when the user picks
//! "ßßßßßßßß" (8 in → 16 stored); a receiver that checks `len(stored) == len(input)`
//! rejects valid case-insensitive logins whose names expand under folding.
//! Examples: U+00DF ß → "SS", U+FB01 ﬁ → "FI", U+0130 İ → toLower "i̇" (i + U+0307).
//!
//! Distinct from LocaleCaseInversion (case mapping that changes ACROSS locales):
//! this fires on shapes whose mapping is locale-stable but length-changing under
//! the default locale itself.
//!
//! It reuses the port's own UAX #21 case mapping (`ucd::upper_codepoint` /
//! `ucd::lower_codepoint`, which evaluate the SpecialCasing context predicates),
//! never a host casing library.
//!
//! Sub-threats (priority order):
//!   1. `UpperExpansion` — first position whose default `upper_codepoint` yields > 1 cp.
//!   2. `LowerExpansion` — first position whose default `lower_codepoint` yields > 1 cp
//!      (reached only when no upper expansion fires first).

use crate::security::identity::ucd::{self, Locale};

// ─────────────────────────────────────────────────────────────────────
// §1 Types
// ─────────────────────────────────────────────────────────────────────

/// Sub-threat enumeration for CaseExpansionMismatch, in priority order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubThreat {
    /// A codepoint whose default uppercase mapping expands, at `base_pos`.
    UpperExpansion {
        /// Position of the expanding codepoint.
        base_pos: usize,
        /// The expanding codepoint.
        cp: u32,
        /// Length of the uppercase expansion (> 1).
        expansion_len: usize,
    },
    /// A codepoint whose default lowercase mapping expands, at `base_pos`.
    LowerExpansion {
        /// Position of the expanding codepoint.
        base_pos: usize,
        /// The expanding codepoint.
        cp: u32,
        /// Length of the lowercase expansion (> 1).
        expansion_len: usize,
    },
}

impl SubThreat {
    /// Fixture-row tag string for this sub-threat (matches `SubThreat.tag`).
    pub fn tag(&self) -> &'static str {
        match self {
            SubThreat::UpperExpansion {
                base_pos: _,
                cp: _,
                expansion_len: _,
            } => "UpperExpansion",
            SubThreat::LowerExpansion {
                base_pos: _,
                cp: _,
                expansion_len: _,
            } => "LowerExpansion",
        }
    }
}

/// Top-level classification for CaseExpansionMismatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Classification {
    /// No case-mapped expansion present.
    Clear,
    /// An expansion fired.
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
    /// Count of positions whose default uppercase mapping expands.
    pub upper_expansion_count: usize,
    /// Count of positions whose default lowercase mapping expands.
    pub lower_expansion_count: usize,
    /// Maximum case-mapped expansion length across all positions (upper or lower).
    pub max_expansion_len: usize,
}

// ─────────────────────────────────────────────────────────────────────
// §2 Per-position expansion scan
// ─────────────────────────────────────────────────────────────────────

/// The default-locale uppercase expansion length at position `i`, evaluating the
/// SpecialCasing context (preceding codepoints nearest-first, following ones).
fn upper_len_at(input: &[u32], i: usize) -> usize {
    let rev_prefix: Vec<u32> = input[..i].iter().rev().copied().collect();
    let suffix = &input[i + 1..];
    ucd::upper_codepoint(Locale::Default, &rev_prefix, suffix, input[i]).len()
}

/// The default-locale lowercase expansion length at position `i`.
fn lower_len_at(input: &[u32], i: usize) -> usize {
    let rev_prefix: Vec<u32> = input[..i].iter().rev().copied().collect();
    let suffix = &input[i + 1..];
    ucd::lower_codepoint(Locale::Default, &rev_prefix, suffix, input[i]).len()
}

/// First position whose default uppercase mapping expands to > 1 codepoint.
fn first_upper_expansion(input: &[u32]) -> Option<(usize, u32, usize)> {
    (0..input.len()).find_map(|i| {
        let len = upper_len_at(input, i);
        if len > 1 {
            Some((i, input[i], len))
        } else {
            None
        }
    })
}

/// First position whose default lowercase mapping expands to > 1 codepoint.
fn first_lower_expansion(input: &[u32]) -> Option<(usize, u32, usize)> {
    (0..input.len()).find_map(|i| {
        let len = lower_len_at(input, i);
        if len > 1 {
            Some((i, input[i], len))
        } else {
            None
        }
    })
}

fn upper_expansion_count(input: &[u32]) -> usize {
    (0..input.len()).filter(|&i| upper_len_at(input, i) > 1).count()
}

fn lower_expansion_count(input: &[u32]) -> usize {
    (0..input.len()).filter(|&i| lower_len_at(input, i) > 1).count()
}

fn max_expansion_len(input: &[u32]) -> usize {
    (0..input.len())
        .map(|i| upper_len_at(input, i).max(lower_len_at(input, i)))
        .max()
        .unwrap_or(0)
}

// ─────────────────────────────────────────────────────────────────────
// §3 Top-level detection
// ─────────────────────────────────────────────────────────────────────

/// The CaseExpansionMismatch detection function.
pub fn detect(input: &[u32]) -> Verdict {
    let classification = match first_upper_expansion(input) {
        // Priority 1: an uppercase expansion.
        Some((pos, cp, len)) => Classification::Hazard {
            sub: SubThreat::UpperExpansion {
                base_pos: pos,
                cp,
                expansion_len: len,
            },
            positions: vec![pos],
            decoded: Vec::new(),
        },
        None => match first_lower_expansion(input) {
            // Priority 2: a lowercase expansion.
            Some((pos, cp, len)) => Classification::Hazard {
                sub: SubThreat::LowerExpansion {
                    base_pos: pos,
                    cp,
                    expansion_len: len,
                },
                positions: vec![pos],
                decoded: Vec::new(),
            },
            None => Classification::Clear,
        },
    };

    Verdict {
        input: input.to_vec(),
        classify: classification,
        upper_expansion_count: upper_expansion_count(input),
        lower_expansion_count: lower_expansion_count(input),
        max_expansion_len: max_expansion_len(input),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::calculus::Family;
    use crate::security::policy::reason_code;

    // Ground truth: every `detect_*` theorem in
    // `Unicode/Security/Form/CaseExpansionMismatch.lean`. Each maps to one
    // `#[test]`; the shared context-free fixture
    // (`fixtures/security/detectors/case_expansion_mismatch.json`) carries the
    // same vectors.

    fn tag(input: &[u32]) -> Option<&'static str> {
        detect(input).classify.tag()
    }

    // `detect_empty_clear`
    #[test]
    fn detect_empty_clear() {
        assert!(detect(&[]).classify.is_clear());
    }

    // `detect_ascii_clear` — "Hello"; every ASCII cp case-maps to a single cp.
    #[test]
    fn detect_ascii_clear() {
        let v = detect(&[0x48, 0x65, 0x6C, 0x6C, 0x6F]);
        assert!(v.classify.is_clear());
        assert_eq!(v.max_expansion_len, 1);
    }

    // `detect_sharp_s_upper` — ß (U+00DF) toUpper → "SS".
    #[test]
    fn detect_sharp_s_upper() {
        let v = detect(&[0x00DF]);
        assert_eq!(v.classify.tag(), Some("UpperExpansion"));
        assert_eq!(v.classify.positions(), &[0]);
        assert_eq!(v.upper_expansion_count, 1);
        assert_eq!(v.max_expansion_len, 2);
    }

    // `detect_fi_ligature_upper` — ﬁ (U+FB01) toUpper → "FI".
    #[test]
    fn detect_fi_ligature_upper() {
        assert_eq!(tag(&[0xFB01]), Some("UpperExpansion"));
    }

    // `detect_dotted_I_lower` — İ (U+0130) toLower under default → "i + 0307";
    // no upper expansion, so the detector falls through to the lower scan.
    #[test]
    fn detect_dotted_I_lower() {
        let v = detect(&[0x0130]);
        assert_eq!(v.classify.tag(), Some("LowerExpansion"));
        assert_eq!(v.lower_expansion_count, 1);
    }

    // ﬃ (U+FB03) toUpper → "FFI" (length 3) — the expansion length is reported.
    #[test]
    fn detect_ffi_ligature_len3() {
        let v = detect(&[0xFB03]);
        assert_eq!(v.classify.tag(), Some("UpperExpansion"));
        assert_eq!(v.max_expansion_len, 3);
    }

    // A leading ASCII then ß: the upper expansion is reported at position 1.
    #[test]
    fn detect_reports_first_expansion_position() {
        let v = detect(&[0x61, 0x00DF]);
        assert_eq!(v.classify.positions(), &[1]);
    }

    // The composed reason codes for each sub-threat.
    #[test]
    fn reason_code_is_stable() {
        assert_eq!(
            reason_code(Family::CaseExpansionMismatch, Some("UpperExpansion")),
            "unicode.security.F.case-expansion-mismatch.UpperExpansion"
        );
        assert_eq!(
            reason_code(Family::CaseExpansionMismatch, Some("LowerExpansion")),
            "unicode.security.F.case-expansion-mismatch.LowerExpansion"
        );
    }
}
