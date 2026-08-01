//! bip39-canonical: BIP-39 mnemonic canonicalisation + wordlist checks.
//!
//! Mirrors `Unicode.Security.Crypto.Bip39Canonical`. Canonical form is
//! NFKD -> to_lower(default) -> collapse BIP-39 whitespace -> trim; `detect`
//! runs six probes in priority order over the input and its canonical words.

use std::collections::HashSet;
use std::sync::OnceLock;

use crate::security::identity::ucd::{self, Locale};

const ENGLISH: &str = include_str!("../../../data/bip39/english.txt");
const JAPANESE: &str = include_str!("../../../data/bip39/japanese.txt");
const KOREAN: &str = include_str!("../../../data/bip39/korean.txt");
const SPANISH: &str = include_str!("../../../data/bip39/spanish.txt");
const CHINESE_SIMPLIFIED: &str = include_str!("../../../data/bip39/chinese_simplified.txt");
const CHINESE_TRADITIONAL: &str = include_str!("../../../data/bip39/chinese_traditional.txt");
const FRENCH: &str = include_str!("../../../data/bip39/french.txt");
const ITALIAN: &str = include_str!("../../../data/bip39/italian.txt");
const CZECH: &str = include_str!("../../../data/bip39/czech.txt");
const PORTUGUESE: &str = include_str!("../../../data/bip39/portuguese.txt");

/// One bip39-canonical scan result.  `sub` is `None` for a clear input (with
/// `language` set to the covering wordlist); otherwise it carries the
/// sub-threat tag and its position(s).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detection {
    /// Sub-threat tag, or `None` when the mnemonic is canonical and covered.
    pub sub: Option<&'static str>,
    /// Position(s) implicated by the sub-threat.
    pub positions: Vec<usize>,
    /// Covering wordlist language when clear, else `None`.
    pub language: Option<&'static str>,
    /// The BIP-39 canonical form of the input.
    pub canonical: Vec<u32>,
    /// Number of whitespace-separated canonical words.
    pub word_count: usize,
}

fn wordlist_set(raw: &str) -> HashSet<Vec<u32>> {
    raw.lines()
        .filter(|line| !line.is_empty())
        .map(|line| line.chars().map(|c| c as u32).collect())
        .collect()
}

/// The ten wordlists as codepoint-sequence sets, in
/// `Unicode.Generated.BIP39.allLanguages` order (English first).
fn wordlists() -> &'static Vec<(&'static str, HashSet<Vec<u32>>)> {
    static T: OnceLock<Vec<(&'static str, HashSet<Vec<u32>>)>> = OnceLock::new();
    T.get_or_init(|| {
        vec![
            ("english", wordlist_set(ENGLISH)),
            ("japanese", wordlist_set(JAPANESE)),
            ("korean", wordlist_set(KOREAN)),
            ("spanish", wordlist_set(SPANISH)),
            ("chinese_simplified", wordlist_set(CHINESE_SIMPLIFIED)),
            ("chinese_traditional", wordlist_set(CHINESE_TRADITIONAL)),
            ("french", wordlist_set(FRENCH)),
            ("italian", wordlist_set(ITALIAN)),
            ("czech", wordlist_set(CZECH)),
            ("portuguese", wordlist_set(PORTUGUESE)),
        ]
    })
}

fn split_words(canonical: &[u32]) -> Vec<Vec<u32>> {
    let mut words = Vec::new();
    let mut current = Vec::new();
    for &cp in canonical {
        if cp == 0x0020 {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
        } else {
            current.push(cp);
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn wordlists_containing(word: &[u32]) -> Vec<&'static str> {
    wordlists()
        .iter()
        .filter(|(_, set)| set.contains(word))
        .map(|(name, _)| *name)
        .collect()
}

fn unique_language(words: &[Vec<u32>]) -> Option<&'static str> {
    wordlists()
        .iter()
        .find(|(_, set)| words.iter().all(|w| set.contains(w)))
        .map(|(name, _)| *name)
}

fn is_bip39_whitespace(cp: u32) -> bool {
    cp == 0x0020 || cp == 0x3000
}

fn collapse_whitespace_to_single(cps: &[u32]) -> Vec<u32> {
    let mut out = Vec::new();
    let mut in_ws = false;
    for &cp in cps {
        if is_bip39_whitespace(cp) {
            if !in_ws {
                out.push(0x0020);
            }
            in_ws = true;
        } else {
            out.push(cp);
            in_ws = false;
        }
    }
    out
}

fn trim_leading_trailing(cps: &[u32]) -> Vec<u32> {
    let start = match cps.iter().position(|&cp| cp != 0x0020) {
        Some(s) => s,
        None => return Vec::new(),
    };
    let end = cps
        .iter()
        .rposition(|&cp| cp != 0x0020)
        .map_or(start, |i| i + 1);
    cps[start..end].to_vec()
}

fn bip39_canonical(cps: &[u32]) -> Vec<u32> {
    let nfkd = ucd::to_nfkd(cps);
    let lowered = ucd::to_lower(Locale::Default, &nfkd);
    let collapsed = collapse_whitespace_to_single(&lowered);
    trim_leading_trailing(&collapsed)
}

fn count_trailing_whitespace(cps: &[u32]) -> usize {
    cps.iter()
        .rev()
        .take_while(|&&cp| is_bip39_whitespace(cp))
        .count()
}

fn first_uppercase_pos(cps: &[u32]) -> Option<usize> {
    cps.iter().position(|&cp| (0x41..=0x5A).contains(&cp))
}

fn first_whitespace_run_pos(cps: &[u32]) -> Option<usize> {
    for (i, &cp) in cps.iter().enumerate() {
        if is_bip39_whitespace(cp) {
            if i == 0 {
                return Some(i);
            }
            if let Some(&next) = cps.get(i + 1) {
                if is_bip39_whitespace(next) {
                    return Some(i);
                }
            }
        }
    }
    None
}

fn first_array_divergence(a: &[u32], b: &[u32]) -> Option<usize> {
    let n = a.len().min(b.len());
    for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
        if x != y {
            return Some(i);
        }
    }
    if a.len() != b.len() {
        Some(n)
    } else {
        None
    }
}

/// Detect a non-canonical or wordlist-mismatched BIP-39 mnemonic.  Six probes
/// in priority order (first hit wins), mirroring `Bip39Canonical.detect`.
pub fn detect(input: &[u32]) -> Detection {
    let canonical = bip39_canonical(input);
    let words = split_words(&canonical);
    let word_count = words.len();

    let trailing_count = count_trailing_whitespace(input);
    let uppercase_pos = first_uppercase_pos(input);
    let whitespace_pos = first_whitespace_run_pos(input);
    let nfkd = ucd::to_nfkd(input);
    let non_nfkd_pos = if input == nfkd.as_slice() {
        None
    } else {
        first_array_divergence(input, &nfkd)
    };
    let first_unknown_idx = words
        .iter()
        .position(|w| wordlists_containing(w).is_empty());

    let (sub, positions, language): (Option<&'static str>, Vec<usize>, Option<&'static str>) =
        if trailing_count > 0 {
            (
                Some("TrailingWhitespace"),
                vec![input.len() - trailing_count],
                None,
            )
        } else if let Some(p) = uppercase_pos {
            (Some("MixedCase"), vec![p], None)
        } else if let Some(p) = whitespace_pos {
            (Some("WhitespaceAnomaly"), vec![p], None)
        } else if let Some(p) = non_nfkd_pos {
            (Some("NonNFKD"), vec![p], None)
        } else if let Some(idx) = first_unknown_idx {
            (Some("WordlistMismatch"), vec![idx], None)
        } else {
            match unique_language(&words) {
                Some(lang) => (None, Vec::new(), Some(lang)),
                None => (Some("LanguageAmbiguous"), Vec::new(), None),
            }
        };

    Detection {
        sub,
        positions,
        language,
        canonical,
        word_count,
    }
}

#[cfg(test)]
mod tests {
    use super::detect;

    const ABANDON: &[u32] = &[0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E];
    const ABOUT: &[u32] = &[0x61, 0x62, 0x6F, 0x75, 0x74];

    fn tag(input: &[u32]) -> Option<&'static str> {
        detect(input).sub
    }

    #[test]
    fn detect_hazard_tags() {
        let mut trailing = ABANDON.to_vec();
        trailing.push(0x20);
        assert_eq!(tag(&trailing), Some("TrailingWhitespace"));
        assert_eq!(
            tag(&[0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E]),
            Some("MixedCase")
        );
        let mut dbl = ABANDON.to_vec();
        dbl.extend_from_slice(&[0x20, 0x20]);
        dbl.extend_from_slice(ABOUT);
        assert_eq!(tag(&dbl), Some("WhitespaceAnomaly"));
        let mut lead = vec![0x20];
        lead.extend_from_slice(ABANDON);
        assert_eq!(tag(&lead), Some("WhitespaceAnomaly"));
        assert_eq!(tag(&[0xFB00]), Some("NonNFKD")); // ﬀ ligature
        assert_eq!(tag(&[0x61, 0x00A0, 0x62]), Some("NonNFKD")); // NBSP
        assert_eq!(tag(&[0x71, 0x7A, 0x71, 0x7A]), Some("WordlistMismatch"));
    }

    #[test]
    fn detect_positions_and_empty_clear() {
        let mut trailing = ABANDON.to_vec();
        trailing.push(0x20);
        assert_eq!(detect(&trailing).positions, vec![7]);
        assert_eq!(
            detect(&[0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E]).positions,
            vec![0]
        );
        let empty = detect(&[]);
        assert_eq!(empty.sub, None);
        assert_eq!(empty.language, Some("english"));
    }

    #[test]
    fn detect_clear_12word_english() {
        let mut mnemonic = Vec::new();
        for _ in 0..11 {
            mnemonic.extend_from_slice(ABANDON);
            mnemonic.push(0x20);
        }
        mnemonic.extend_from_slice(ABOUT);
        let verdict = detect(&mnemonic);
        assert_eq!(verdict.sub, None);
        assert_eq!(verdict.language, Some("english"));
        assert_eq!(verdict.word_count, 12);
    }
}
