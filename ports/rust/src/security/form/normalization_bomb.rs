//! Normalization-bomb detection (F1) — inputs whose NFD or NFKD expansion
//! exceeds documented bounds, the classic normalization-expansion DoS. A small
//! input that expands to a very large normalized form exhausts memory/CPU at the
//! receiving layer (Arabic ligature U+FDFA → 18 codepoints under NFKD, etc.).
//!
//! Direct port of `Unicode/Security/Form/NormalizationBomb.lean`. Pure
//! functional: compute NFD and NFKD lengths, then three priority-ordered checks
//! — a per-codepoint blow-up scan, an overall NFKD ratio, an overall NFD ratio.
//! Ratios are expressed in hundredths to avoid floats.

use crate::security::identity::ucd;

/// Maximum allowed NFKD expansion per single codepoint. Hangul ≤ 3, Greek
/// extended forms 4, the largest non-FDFA Arabic ligature (FDFB) 8; anything
/// greater than 8 is flagged.
const MAX_NFKD_PER_CP: usize = 8;

/// Overall-sequence NFD expansion ratio threshold, in hundredths (300 = 3×).
/// Pure Hangul sits at exactly 300 and stays clear under strict `>`.
const NFD_RATIO_PCT: usize = 300;

/// Overall-sequence NFKD expansion ratio threshold, in hundredths (400 = 4×).
const NFKD_RATIO_PCT: usize = 400;

/// One normalization-bomb scan result. `sub` is `None` for a clear input; a
/// per-codepoint blow-up carries the offending position, the ratio hazards
/// carry no position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detection {
    /// The sub-threat tag, or `None` for a clear input.
    pub sub: Option<&'static str>,
    /// Implicated positions (the blow-up codepoint's index; empty for ratio hazards).
    pub positions: Vec<usize>,
}

/// First position whose single-codepoint NFKD expansion exceeds
/// `MAX_NFKD_PER_CP`, with the codepoint and its expansion length.
fn first_blowup_cp(input: &[u32]) -> Option<(usize, u32, usize)> {
    input.iter().enumerate().find_map(|(index, &cp)| {
        let expand = ucd::to_nfkd(&[cp]).len();
        if expand > MAX_NFKD_PER_CP {
            Some((index, cp, expand))
        } else {
            None
        }
    })
}

/// NFD ratio percentage (`100 * nfdLen / inputLen`); 0 on empty input.
fn nfd_ratio_pct(input: &[u32]) -> usize {
    if input.is_empty() {
        0
    } else {
        ucd::to_nfd(input).len() * 100 / input.len()
    }
}

/// NFKD ratio percentage (`100 * nfkdLen / inputLen`); 0 on empty input.
fn nfkd_ratio_pct(input: &[u32]) -> usize {
    if input.is_empty() {
        0
    } else {
        ucd::to_nfkd(input).len() * 100 / input.len()
    }
}

/// Detect a normalization-expansion bomb. Priority: per-codepoint blow-up,
/// then overall NFKD ratio, then overall NFD ratio.
pub fn detect(input: &[u32]) -> Detection {
    if let Some((pos, _cp, _expand)) = first_blowup_cp(input) {
        return Detection {
            sub: Some("SingleCpBlowup"),
            positions: vec![pos],
        };
    }
    if nfkd_ratio_pct(input) > NFKD_RATIO_PCT {
        return Detection {
            sub: Some("NfkdHighExpansion"),
            positions: Vec::new(),
        };
    }
    if nfd_ratio_pct(input) > NFD_RATIO_PCT {
        return Detection {
            sub: Some("NfdHighExpansion"),
            positions: Vec::new(),
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

    // Ground truth: the `detect_*` theorems in
    // `Unicode/Security/Form/NormalizationBomb.lean`, plus the two ratio-branch
    // shapes the module docstring guarantees (FDFB → NFKD 8× ratio; a Greek
    // extended form → NFD 4× ratio).

    fn sub(input: &[u32]) -> Option<&'static str> {
        detect(input).sub
    }

    #[test]
    fn empty_and_ascii_are_clear() {
        assert_eq!(sub(&[]), None);
        assert_eq!(sub(&[0x48, 0x65, 0x6C, 0x6C, 0x6F]), None);
    }

    #[test]
    fn korean_and_circled_one_stay_clear() {
        assert_eq!(sub(&[0xD55C]), None); // NFD ratio exactly 300, not > 300
        assert_eq!(sub(&[0x2460]), None); // circled one, NFKD 1×
    }

    #[test]
    fn arabic_ligature_fires_single_cp_blowup() {
        assert_eq!(sub(&[0xFDFA]), Some("SingleCpBlowup"));
        assert_eq!(detect(&[0xFDFA]).positions, vec![0]);
    }

    #[test]
    fn fdfb_fires_nfkd_high_expansion() {
        // U+FDFB: NFKD length 8 passes the per-cp gate (not > 8) but the overall
        // ratio is 800% > 400%.
        assert_eq!(sub(&[0xFDFB]), Some("NfkdHighExpansion"));
    }

    #[test]
    fn greek_extended_fires_nfd_high_expansion() {
        // U+1F82: NFD length 4 (== NFKD), so NFKD ratio 400% is not > 400% but
        // NFD ratio 400% > 300%.
        assert_eq!(sub(&[0x1F82]), Some("NfdHighExpansion"));
    }
}
