//! IdentifierFormDrift — cross-layer identifier × form drift (boundary-layer detector).
//!
//! Byte-faithful transliteration of
//! `Unicode/Security/Boundary/IdentifierFormDrift.lean`.
//!
//! Threat model. Tier A₂ two-system bypass. An identity validator and a form
//! normalizer disagree about a codepoint: stage A runs the UTS #39
//! `Identifier_Status` check before normalisation and rejects, say, U+1D44E
//! MATHEMATICAL ITALIC SMALL A (Restricted); stage B normalises first and then
//! runs the same check, seeing U+0061 'a' (Allowed) and accepting. The attacker
//! controls which stage processes the input and exploits the disagreement. The
//! same shape covers fullwidth (U+FF21), circled (U+24B6), ligature (U+FB01),
//! and Roman-numeral (U+2163) compatibility forms.
//!
//! The detector fires on the *form transition* itself — it reports every input
//! position whose `Identifier_Status` differs from the `Identifier_Status` of
//! that codepoint's NFKD head. This is orthogonal to the single-form
//! identity-spoofing detectors (which examine the input under one form) and
//! stronger than a form-of-input fold (it asks whether the identifier verdict
//! changes, not whether any output bit changes).
//!
//! Note on Hangul: precomposed syllables are Allowed while their NFKD-head
//! jamos are Restricted, so pure Korean text fires; callers intending to accept
//! Korean identifiers should apply NFC before evaluating admissibility.
//!
//! It reuses the port's own UTS #39 `Identifier_Status` predicate and NFKD
//! pipeline, never a host normalization or identifier library.
//!
//! Sub-threat (direction-agnostic):
//!   `IdentifierStatusShift` — the first input position whose `Identifier_Status`
//!   differs from its NFKD-head's. The verdict carries the total shift count.

use crate::security::identity::ucd;

// ─────────────────────────────────────────────────────────────────────
// §1 Types
// ─────────────────────────────────────────────────────────────────────

/// Sub-threat enumeration for IdentifierFormDrift.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubThreat {
    /// A codepoint at `base_pos` whose `Identifier_Status` differs from its
    /// NFKD-head's (codepoint `cp`).
    IdentifierStatusShift {
        /// Position of the first status-shifting codepoint.
        base_pos: usize,
        /// The status-shifting codepoint.
        cp: u32,
    },
}

impl SubThreat {
    /// Fixture-row tag string for this sub-threat (matches `SubThreat.tag`).
    pub fn tag(&self) -> &'static str {
        match self {
            SubThreat::IdentifierStatusShift {
                base_pos: _,
                cp: _,
            } => "IdentifierStatusShift",
        }
    }
}

/// Top-level classification for IdentifierFormDrift.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Classification {
    /// No status shift present.
    Clear,
    /// A status shift fired.
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
    /// Total count of positions whose status shifts under NFKD.
    pub shift_count: usize,
}

// ─────────────────────────────────────────────────────────────────────
// §2 Core predicates
// ─────────────────────────────────────────────────────────────────────

/// `Identifier_Status = Allowed` of the first codepoint of `cp`'s NFKD form, or
/// `cp`'s own status when NFKD is empty (defensive — `to_nfkd` is total and
/// returns at least `[cp]`). Reuses the port's own UTS #39 predicate and NFKD.
pub fn nfkd_head_allowed(cp: u32) -> bool {
    match ucd::to_nfkd(&[cp]).first() {
        Some(&head) => ucd::is_id_allowed(head),
        None => ucd::is_id_allowed(cp),
    }
}

// ─────────────────────────────────────────────────────────────────────
// §3 Sub-detectors
// ─────────────────────────────────────────────────────────────────────

/// First input position whose `is_id_allowed` differs from its NFKD-head's.
fn first_status_shift(input: &[u32]) -> Option<(usize, u32)> {
    input.iter().enumerate().find_map(|(idx, &cp)| {
        if status_shift(cp) {
            Some((idx, cp))
        } else {
            None
        }
    })
}

/// A codepoint drifts when normalizing it turns an identifier character a
/// validator rejects into one it accepts: Restricted before NFKD, Allowed
/// after. That is the direction an attacker gains from, and it is the direction
/// every case this detector exists for takes -- U+FB01 the fi ligature, U+2163
/// the Roman numeral, U+24B6 the circled capital, each Restricted with an
/// Allowed head.
///
/// The opposite direction is not a drift. A precomposed Hangul syllable is
/// Allowed while its head jamo is Restricted, so an equality test reports every
/// one of the 11,172 syllables and therefore all Korean text. Normalizing there
/// makes the character less acceptable, not more, which gains an attacker
/// nothing.
fn status_shift(cp: u32) -> bool {
    !ucd::is_id_allowed(cp) && nfkd_head_allowed(cp)
}

/// Total count of input positions where the per-cp status shifts under NFKD.
fn status_shift_count(input: &[u32]) -> usize {
    input.iter().filter(|&&cp| status_shift(cp)).count()
}

// ─────────────────────────────────────────────────────────────────────
// §4 Top-level detection
// ─────────────────────────────────────────────────────────────────────

/// The IdentifierFormDrift detection function.
pub fn detect(input: &[u32]) -> Verdict {
    let classification = match first_status_shift(input) {
        Some((pos, cp)) => Classification::Hazard {
            sub: SubThreat::IdentifierStatusShift { base_pos: pos, cp },
            positions: vec![pos],
            decoded: Vec::new(),
        },
        None => Classification::Clear,
    };

    Verdict {
        input: input.to_vec(),
        classify: classification,
        shift_count: status_shift_count(input),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::calculus::Family;
    use crate::security::policy::reason_code;

    // Ground truth: every `detect_*` theorem in
    // `Unicode/Security/Boundary/IdentifierFormDrift.lean`. Each maps to one
    // `#[test]`; the shared context-free fixture
    // (`fixtures/security/detectors/identifier_form_drift.json`) carries the
    // context-free vectors.

    fn tag(input: &[u32]) -> Option<&'static str> {
        detect(input).classify.tag()
    }

    // `detect_empty_clear`
    #[test]
    fn detect_empty_clear() {
        assert!(detect(&[]).classify.is_clear());
    }

    // `detect_ascii_clear` — "Hello"; every ASCII letter is Allowed, identity NFKD.
    #[test]
    fn detect_ascii_clear() {
        let v = detect(&[0x48, 0x65, 0x6C, 0x6C, 0x6F]);
        assert!(v.classify.is_clear());
        assert_eq!(v.shift_count, 0);
    }

    // `detect_greek_alpha_clear` — α is Allowed with identity NFKD.
    #[test]
    fn detect_greek_alpha_clear() {
        assert!(detect(&[0x03B1]).classify.is_clear());
    }

    // `detect_math_italic_a_shift` — U+1D44E Restricted, NFKD head U+0061 Allowed.
    #[test]
    fn detect_math_italic_a_shift() {
        let v = detect(&[0x1D44E]);
        assert_eq!(v.classify.tag(), Some("IdentifierStatusShift"));
        assert_eq!(v.classify.positions(), &[0]);
        assert_eq!(v.shift_count, 1);
    }

    // `detect_fullwidth_A_shift` — U+FF21 Restricted, NFKD head U+0041 Allowed.
    #[test]
    fn detect_fullwidth_A_shift() {
        assert_eq!(tag(&[0xFF21]), Some("IdentifierStatusShift"));
    }

    // Docstring case — U+24B6 CIRCLED LATIN CAPITAL LETTER A → Restricted → Allowed (A).
    #[test]
    fn detect_circled_A_shift() {
        assert_eq!(tag(&[0x24B6]), Some("IdentifierStatusShift"));
    }

    // Docstring case — U+FB01 'ﬁ' ligature → Restricted → Allowed (f).
    #[test]
    fn detect_fi_ligature_shift() {
        assert_eq!(tag(&[0xFB01]), Some("IdentifierStatusShift"));
    }

    // Docstring case — U+2163 ROMAN NUMERAL FOUR → Restricted → Allowed (I).
    #[test]
    fn detect_roman_iv_shift() {
        assert_eq!(tag(&[0x2163]), Some("IdentifierStatusShift"));
    }

    // A shift embedded mid-string reports the first shifting position, not 0.
    #[test]
    fn detect_reports_first_shift_position() {
        // "ab" + U+1D44E: positions 0,1 are Allowed/identity, position 2 shifts.
        let v = detect(&[0x61, 0x62, 0x1D44E]);
        assert_eq!(v.classify.positions(), &[2]);
        assert_eq!(v.shift_count, 1);
    }

    // The composed reason code for the sole sub-threat.
    #[test]
    fn reason_code_is_stable() {
        assert_eq!(
            reason_code(Family::IdentifierFormDrift, Some("IdentifierStatusShift")),
            "unicode.security.X.identifier-form-drift.IdentifierStatusShift"
        );
    }
}
