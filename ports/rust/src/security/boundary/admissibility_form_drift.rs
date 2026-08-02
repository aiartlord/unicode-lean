//! AdmissibilityFormDrift — cross-layer identifier-admissibility × form drift
//! (boundary-layer detector).
//!
//! Byte-faithful transliteration of
//! `Unicode/Security/Boundary/AdmissibilityFormDrift.lean`.
//!
//! Fires on inputs whose UTS #39 whole-string `isAllowedIdentifier` verdict
//! differs between the input and its NFKC form. This is the string-level
//! complement of IdentifierFormDrift (which scans `Identifier_Status` against the
//! per-codepoint NFKD head): here the whole-string admissibility predicate is
//! evaluated twice — once on the input, once on `to_nfkc(input)`. The two are not
//! redundant. In particular, a sequence of decomposed Hangul jamos passes the
//! per-codepoint scan cleanly (each jamo has identity NFKD and Restricted status
//! on both sides) but fires here: the jamo sequence is rejected by
//! `isAllowedIdentifier`, while its NFKC composition into a precomposed Hangul
//! syllable is accepted.
//!
//! It reuses the port's own UTS #39 admissibility predicate
//! (`ucd::is_allowed_identifier` = UAX #31 default identifier ∧ every codepoint
//! Allowed) and NFKC pipeline (`ucd::to_nfkc`), never a host normalization or
//! identifier library.
//!
//! Sub-threat (direction-agnostic):
//!   `AdmissibilityFormDrift` — `is_allowed_identifier(input) !=
//!   is_allowed_identifier(to_nfkc(input))`. The pair of booleans is carried so
//!   the verdict records which direction the drift goes; no position is reported
//!   because the predicate is whole-string.

use crate::security::identity::ucd;

// ─────────────────────────────────────────────────────────────────────
// §1 Types
// ─────────────────────────────────────────────────────────────────────

/// Sub-threat enumeration for AdmissibilityFormDrift.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubThreat {
    /// The whole-string admissibility verdict differs between the input and its
    /// NFKC form.
    AdmissibilityFormDrift {
        /// `is_allowed_identifier(input)`.
        input_admissible: bool,
        /// `is_allowed_identifier(to_nfkc(input))`.
        nfkc_admissible: bool,
    },
}

impl SubThreat {
    /// Fixture-row tag string for this sub-threat (matches `SubThreat.tag`).
    pub fn tag(&self) -> &'static str {
        match self {
            SubThreat::AdmissibilityFormDrift {
                input_admissible: _,
                nfkc_admissible: _,
            } => "AdmissibilityFormDrift",
        }
    }
}

/// Top-level classification for AdmissibilityFormDrift.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Classification {
    /// The admissibility verdict agrees across forms.
    Clear,
    /// The admissibility verdict drifts across forms.
    Hazard {
        /// The sub-threat that fired.
        sub: SubThreat,
        /// The implicated positions (always empty; the predicate is whole-string).
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

    /// Implicated positions (always empty — the predicate is whole-string).
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
    /// `is_allowed_identifier(input)`.
    pub input_admissible: bool,
    /// `is_allowed_identifier(to_nfkc(input))`.
    pub nfkc_admissible: bool,
}

// ─────────────────────────────────────────────────────────────────────
// §2 Top-level detection
// ─────────────────────────────────────────────────────────────────────

/// The AdmissibilityFormDrift detection function.
pub fn detect(input: &[u32]) -> Verdict {
    let nfkc = ucd::to_nfkc(input);
    let in_ok = ucd::is_allowed_identifier(input);
    let nfkc_ok = ucd::is_allowed_identifier(&nfkc);

    let classification = if in_ok == nfkc_ok {
        Classification::Clear
    } else {
        Classification::Hazard {
            sub: SubThreat::AdmissibilityFormDrift {
                input_admissible: in_ok,
                nfkc_admissible: nfkc_ok,
            },
            positions: Vec::new(),
            decoded: Vec::new(),
        }
    };

    Verdict {
        input: input.to_vec(),
        classify: classification,
        input_admissible: in_ok,
        nfkc_admissible: nfkc_ok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::calculus::Family;
    use crate::security::policy::reason_code;

    // Ground truth: every `detect_*` theorem in
    // `Unicode/Security/Boundary/AdmissibilityFormDrift.lean`. Each maps to one
    // `#[test]`; the shared context-free fixture
    // (`fixtures/security/detectors/admissibility_form_drift.json`) carries the
    // same vectors.

    fn tag(input: &[u32]) -> Option<&'static str> {
        detect(input).classify.tag()
    }

    // `detect_empty_clear` — both admissibility calls return false, so they agree.
    #[test]
    fn detect_empty_clear() {
        assert!(detect(&[]).classify.is_clear());
    }

    // `detect_ascii_clear` — "admin"; admissible on both sides (NFKC is identity).
    #[test]
    fn detect_ascii_clear() {
        let v = detect(&[0x61, 0x64, 0x6D, 0x69, 0x6E]);
        assert!(v.classify.is_clear());
        assert!(v.input_admissible);
        assert!(v.nfkc_admissible);
    }

    // `detect_fi_ligature_drift` — ﬁ (U+FB01) is Restricted (inadmissible), but
    // NFKC decomposes it to "fi" (admissible). Drift fires.
    #[test]
    fn detect_fi_ligature_drift() {
        let v = detect(&[0xFB01]);
        assert_eq!(v.classify.tag(), Some("AdmissibilityFormDrift"));
        assert!(!v.input_admissible);
        assert!(v.nfkc_admissible);
    }

    // `detect_jamo_sequence_drift` — decomposed Hangul jamos [U+1112, U+1161,
    // U+11AB] are inadmissible, but NFKC composes them to U+D55C 한 (admissible).
    #[test]
    fn detect_jamo_sequence_drift() {
        assert_eq!(tag(&[0x1112, 0x1161, 0x11AB]), Some("AdmissibilityFormDrift"));
    }

    // The composed reason code for the sole sub-threat.
    #[test]
    fn reason_code_is_stable() {
        assert_eq!(
            reason_code(Family::AdmissibilityFormDrift, Some("AdmissibilityFormDrift")),
            "unicode.security.X.admissibility-form-drift.AdmissibilityFormDrift"
        );
    }
}
