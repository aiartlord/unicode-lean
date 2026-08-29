//! Detection of UAX #11 East Asian Width class confusion.
//!
//! Inputs that contain Fullwidth (EAW = F) or Halfwidth (EAW = H) codepoints
//! whose NFKD form has a different EAW class are flagged. These are the
//! canonical compatibility-fold homograph shapes:
//!
//!   * U+FF21 'Ａ' (F)  →  U+0041 'A' (Na)
//!   * U+FF11 '１' (F)  →  U+0031 '1' (Na)
//!   * U+FF71 'ｱ' (H)  →  U+30A2 'ア' (W)
//!
//! Threat model.  Tier A2.  Two-system bypass shape: a validator that
//! whitelists ASCII rejects `Ａ`, while a downstream NFKC step at storage or
//! comparison time folds it to plain `A`. The attacker uses `ＡＤＭＩＮ` to
//! claim the username `ADMIN` against a system that did not normalise before
//! whitelisting.
//!
//! Distinct from RendererDivergence's FullwidthVariance, which fires on
//! F-class codepoints for renderer-cohort reasons. This detector is the
//! NFKC-fold-driven verdict, and the two can fire on one input independently.
//!
//! Detection is per input position and uses NFKD, because every compatibility
//! decomposition path goes through it: the EAW class of the input codepoint is
//! compared against the EAW class of the first NFKD output codepoint. Hangul
//! syllables decompose to jamos that are still W class, so pure Hangul stays
//! clear.
//!
//! Direct port of `Unicode/Security/Form/WidthClassConfusion.lean`.

use crate::security::identity::ucd::{self, EastAsianWidthClass};

/// Sub-threat, in the priority order `detect` applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubThreat {
    /// A Fullwidth codepoint whose NFKD head has a different width class.
    FullwidthFold,
    /// A Halfwidth codepoint whose NFKD head has a different width class.
    HalfwidthFold,
}

impl SubThreat {
    /// Stable wire tag.
    pub fn tag(self) -> &'static str {
        match self {
            SubThreat::FullwidthFold => "FullwidthFold",
            SubThreat::HalfwidthFold => "HalfwidthFold",
        }
    }
}

/// Verdict over a codepoint sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// The sub-threat, when one fires.
    pub sub: Option<&'static str>,
    /// The single input position the fold was found at.
    pub positions: Vec<usize>,
    /// Count of Fullwidth positions that fold to another class.
    pub fullwidth_fold_count: usize,
    /// Count of Halfwidth positions that fold to another class.
    pub halfwidth_fold_count: usize,
}

/// The NFKD head of `cp` when it has a different width class, else `None`.
fn has_width_fold(cp: u32) -> Option<u32> {
    let folded = ucd::to_nfkd(&[cp]);
    let head = *folded.first()?;
    if ucd::east_asian_width(head) == ucd::east_asian_width(cp) {
        None
    } else {
        Some(head)
    }
}

/// The first input position whose codepoint has width class `want` and folds
/// to a different class.
fn first_fold(input: &[u32], want: EastAsianWidthClass) -> Option<usize> {
    input.iter().enumerate().find_map(|(index, &cp)| {
        if ucd::east_asian_width(cp) == want && has_width_fold(cp).is_some() {
            Some(index)
        } else {
            None
        }
    })
}

fn fold_count(input: &[u32], want: EastAsianWidthClass) -> usize {
    input
        .iter()
        .filter(|&&cp| ucd::east_asian_width(cp) == want && has_width_fold(cp).is_some())
        .count()
}

/// Classify a codepoint sequence. A Fullwidth fold takes priority over a
/// Halfwidth one, matching the reference's sub-threat order.
pub fn detect(input: &[u32]) -> Detection {
    let fullwidth_fold_count = fold_count(input, EastAsianWidthClass::F);
    let halfwidth_fold_count = fold_count(input, EastAsianWidthClass::H);

    if let Some(position) = first_fold(input, EastAsianWidthClass::F) {
        return Detection {
            sub: Some(SubThreat::FullwidthFold.tag()),
            positions: vec![position],
            fullwidth_fold_count,
            halfwidth_fold_count,
        };
    }
    if let Some(position) = first_fold(input, EastAsianWidthClass::H) {
        return Detection {
            sub: Some(SubThreat::HalfwidthFold.tag()),
            positions: vec![position],
            fullwidth_fold_count,
            halfwidth_fold_count,
        };
    }
    Detection {
        sub: None,
        positions: Vec::new(),
        fullwidth_fold_count,
        halfwidth_fold_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_is_clear() {
        assert_eq!(detect(&[0x41, 0x42, 0x43]).sub, None);
    }

    #[test]
    fn empty_is_clear() {
        assert_eq!(detect(&[]).sub, None);
    }

    #[test]
    fn fullwidth_capital_a_folds() {
        // U+FF21 (F) folds to U+0041 (Na).
        let v = detect(&[0xFF21]);
        assert_eq!(v.sub, Some("FullwidthFold"));
        assert_eq!(v.positions, vec![0]);
        assert_eq!(v.fullwidth_fold_count, 1);
    }

    #[test]
    fn fullwidth_admin_reports_first_position() {
        let v = detect(&[0xFF21, 0xFF24, 0xFF2D, 0xFF29, 0xFF2E]);
        assert_eq!(v.sub, Some("FullwidthFold"));
        assert_eq!(v.positions, vec![0]);
        assert_eq!(v.fullwidth_fold_count, 5);
    }

    #[test]
    fn halfwidth_katakana_folds() {
        // U+FF71 (H) folds to U+30A2 (W).
        let v = detect(&[0xFF71]);
        assert_eq!(v.sub, Some("HalfwidthFold"));
        assert_eq!(v.halfwidth_fold_count, 1);
    }

    #[test]
    fn fullwidth_takes_priority_over_halfwidth() {
        let v = detect(&[0xFF71, 0xFF21]);
        assert_eq!(v.sub, Some("FullwidthFold"));
        assert_eq!(v.positions, vec![1]);
    }

    #[test]
    fn precomposed_hangul_stays_clear() {
        // Hangul syllables decompose to jamos that are still W class.
        assert_eq!(detect(&[0xD55C, 0xAE00]).sub, None);
    }
}
