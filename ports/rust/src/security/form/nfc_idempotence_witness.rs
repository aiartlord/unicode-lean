//! NFC-idempotence-witness detection (F6) — inputs that are not already in NFC
//! (or, failing that, not in NFKC), the silent normalization-drift class where a
//! signer and verifier pick different canonical forms and their hashes diverge.
//!
//! Direct port of `Unicode/Security/Form/NfcIdempotenceWitness.lean`. Compares
//! `input` element-wise against `to_nfc(input)` and `to_nfkc(input)`, reporting
//! the first divergent position: a mismatch against NFC is `NonNfcForm`; a
//! sequence already in NFC but not NFKC is `NonNfkcCompatForm`.

use crate::security::identity::ucd;

/// One NFC-idempotence-witness scan result. `sub` is `None` for a clear input
/// (already in NFC and NFKC), else the divergence tag with its first position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detection {
    /// The sub-threat tag, or `None` when the input is already NFC- and NFKC-stable.
    pub sub: Option<&'static str>,
    /// The first divergent position (empty when clear).
    pub positions: Vec<usize>,
}

/// First index at which two sequences diverge (in element, or one ends);
/// `None` when identical.
fn first_divergence(a: &[u32], b: &[u32]) -> Option<usize> {
    let common = a.len().min(b.len());
    for i in 0..common {
        if a[i] != b[i] {
            return Some(i);
        }
    }
    if a.len() != b.len() {
        return Some(common);
    }
    None
}

/// Detect an input that is not in canonical (NFC), or not in compatibility
/// (NFKC), form. NFC divergence takes priority over NFKC.
pub fn detect(input: &[u32]) -> Detection {
    let nfc = ucd::to_nfc(input);
    if let Some(pos) = first_divergence(input, &nfc) {
        return Detection {
            sub: Some("NonNfcForm"),
            positions: vec![pos],
        };
    }
    let nfkc = ucd::to_nfkc(input);
    if let Some(pos) = first_divergence(input, &nfkc) {
        return Detection {
            sub: Some("NonNfkcCompatForm"),
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

    // Ground truth: the `detect_*` theorems in
    // `Unicode/Security/Form/NfcIdempotenceWitness.lean`.

    fn sub(input: &[u32]) -> Option<&'static str> {
        detect(input).sub
    }

    #[test]
    fn empty_and_ascii_are_clear() {
        assert_eq!(sub(&[]), None);
        assert_eq!(sub(&[0x48, 0x65, 0x6C, 0x6C, 0x6F]), None);
    }

    #[test]
    fn precomposed_e_acute_is_clear() {
        assert_eq!(sub(&[0x00E9]), None);
    }

    #[test]
    fn decomposed_e_acute_fires_non_nfc() {
        assert_eq!(sub(&[0x0065, 0x0301]), Some("NonNfcForm"));
        assert_eq!(detect(&[0x0065, 0x0301]).positions, vec![0]);
    }

    #[test]
    fn fi_ligature_fires_non_nfkc() {
        assert_eq!(sub(&[0xFB01]), Some("NonNfkcCompatForm"));
    }
}
