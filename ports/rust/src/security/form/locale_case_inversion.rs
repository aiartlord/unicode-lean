//! Locale-case-inversion — inputs whose lowercase result inverts across
//! locales, the homograph-via-locale attack (CVE-2007-6692, CVE-2021-30245,
//! the Spotify "İSTANBUL" / "iSTANBUL" incident class).
//!
//! Threat model. Tier A2. An attacker submits text containing Turkish / Azeri /
//! Lithuanian-conditional codepoints. One stage folds the input under the
//! default locale to compare against a stored credential, while another folds
//! the same input under a Turkish or Lithuanian locale; the two folds diverge
//! and the attacker controls which fold is used where.
//!
//! Detection compares per-position `lower_codepoint` under each locale against
//! the default, rather than diffing whole-string `to_lower`, because
//! `lower_codepoint` evaluates the SpecialCasing context predicates (After_I,
//! More_Above, Not_Before_Dot, After_Soft_Dotted, Final_Sigma) with the full
//! surrounding context — so a per-position diff is sound under the
//! context-sensitive conditional rules.
//!
//! Direct port of `Unicode/Security/Form/LocaleCaseInversion.lean` (`detect` +
//! `firstLocaleDivergence`). Priority order: Turkish divergence (covers Azeri —
//! SpecialCasing v17 has no `az`-only codepoint) before Lithuanian.

use crate::security::identity::ucd::{lower_codepoint, Locale};

/// One locale-case-inversion scan result. `sub` is `None` for a clear input,
/// else the divergent locale's tag; `positions` carries the first divergent
/// input position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detection {
    /// The divergent-locale sub-threat tag, or `None` for a clear input.
    pub sub: Option<&'static str>,
    /// The first divergent input position (empty when clear).
    pub positions: Vec<usize>,
}

/// First input position whose `lower_codepoint` under `locale` differs from the
/// default-locale result, with the codepoint at that position.
fn first_locale_divergence(locale: Locale, input: &[u32]) -> Option<(usize, u32)> {
    let mut rev_prefix: Vec<u32> = Vec::new();
    for (index, &cp) in input.iter().enumerate() {
        let suffix = &input[index + 1..];
        let default_lower = lower_codepoint(Locale::Default, &rev_prefix, suffix, cp);
        let locale_lower = lower_codepoint(locale, &rev_prefix, suffix, cp);
        if default_lower != locale_lower {
            return Some((index, cp));
        }
        rev_prefix.insert(0, cp);
    }
    None
}

/// Detect an input whose lowercase fold inverts across locales. Turkish
/// divergence takes priority; Lithuanian is reached only when no Turkish
/// divergence is found.
pub fn detect(input: &[u32]) -> Detection {
    if let Some((pos, _cp)) = first_locale_divergence(Locale::Turkish, input) {
        return Detection {
            sub: Some("TurkishCaseDivergence"),
            positions: vec![pos],
        };
    }
    if let Some((pos, _cp)) = first_locale_divergence(Locale::Lithuanian, input) {
        return Detection {
            sub: Some("LithuanianCaseDivergence"),
            positions: vec![pos],
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
    // `Unicode/Security/Form/LocaleCaseInversion.lean`.

    fn sub(input: &[u32]) -> Option<&'static str> {
        detect(input).sub
    }

    #[test]
    fn empty_is_clear() {
        assert_eq!(sub(&[]), None);
    }

    #[test]
    fn ascii_without_i_is_clear() {
        assert_eq!(sub(&[0x48, 0x65, 0x6C, 0x6C, 0x6F]), None);
    }

    #[test]
    fn capital_i_fires_turkish() {
        assert_eq!(sub(&[0x0049]), Some("TurkishCaseDivergence"));
        assert_eq!(detect(&[0x0049]).positions, vec![0]);
    }

    #[test]
    fn dotted_i_fires_turkish() {
        assert_eq!(sub(&[0x0130]), Some("TurkishCaseDivergence"));
    }

    #[test]
    fn i_with_grave_picks_turkish_first() {
        assert_eq!(sub(&[0x0049, 0x0300]), Some("TurkishCaseDivergence"));
    }

    #[test]
    fn j_with_grave_fires_lithuanian() {
        assert_eq!(sub(&[0x004A, 0x0300]), Some("LithuanianCaseDivergence"));
    }
}
