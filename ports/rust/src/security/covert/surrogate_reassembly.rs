//! Surrogate-reassembly / malformed-byte-stream detection.
//!
//! Threat model.  Tier C.  An adversary hides intent in a byte stream that
//! is not well-formed UTF-8 — an overlong encoding, a CESU-8 / surrogate
//! codepoint, a truncated sequence, an invalid start or continuation byte,
//! or a value beyond U+10FFFF — betting a lenient decoder will "reassemble"
//! it into something the security scanner never saw in codepoint form.
//!
//! Direct port of `Unicode/Security/Covert/SurrogateReassembly.lean`.  The
//! input codepoint list is treated as a byte stream (one octet per entry);
//! the family only applies when every entry is a byte (`< 0x100`), matching
//! the `looksLikeByteStream` gate in `Unicode/Security/RunAll.lean`.  The
//! verdict projects the first UTF-8 violation found by the shared strict
//! decoder onto a covert-layer sub-threat.

use crate::strict::Utf8RejectKind;
use crate::utf8::first_invalid_utf8_offset;

/// One surrogate-reassembly scan result.  `sub` is `None` for a clear
/// input (well-formed, or not a byte stream); otherwise it carries the
/// sub-threat tag of the first UTF-8 violation and its byte offset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detection {
    pub sub: Option<&'static str>,
    pub positions: Vec<usize>,
}

/// True iff every entry fits in one octet — the `looksLikeByteStream`
/// gate.  A codepoint-array input containing any value `>= 0x100` is not a
/// byte stream, and running the UTF-8 decoder on it would be meaningless.
fn looks_like_byte_stream(input: &[u32]) -> bool {
    input.iter().all(|&cp| cp < 0x100)
}

/// Project a `Utf8RejectKind` to its surrogate-reassembly sub-threat tag,
/// mirroring `subThreatOfRejectKind` in the Lean spec.
fn sub_threat_of_reject_kind(kind: Utf8RejectKind) -> &'static str {
    match kind {
        Utf8RejectKind::OverlongEncoding => "Overlong",
        Utf8RejectKind::SurrogateCodepoint => "Cesu8",
        Utf8RejectKind::TruncatedSequence => "Truncated",
        Utf8RejectKind::InvalidStartByte => "InvalidStartByte",
        Utf8RejectKind::InvalidContinuationByte => "InvalidContinuation",
        Utf8RejectKind::CodepointBeyondMax => "CodepointBeyondMax",
    }
}

/// Detect a malformed UTF-8 byte stream hidden in a codepoint list.  Only
/// applies to byte-stream-shaped input (every entry `< 0x100`); otherwise
/// clear.  Reports the sub-threat of the first violation at its byte
/// offset.
pub fn detect(input: &[u32]) -> Detection {
    if !looks_like_byte_stream(input) {
        return Detection {
            sub: None,
            positions: Vec::new(),
        };
    }
    let bytes: Vec<u8> = input.iter().map(|&cp| cp as u8).collect();
    match first_invalid_utf8_offset(&bytes) {
        None => Detection {
            sub: None,
            positions: Vec::new(),
        },
        Some((offset, kind)) => Detection {
            sub: Some(sub_threat_of_reject_kind(kind)),
            positions: vec![offset],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::detect;

    // Ground truth: the `detect_*` spot-check theorems in
    // `Unicode/Security/Covert/SurrogateReassembly.lean`, each proven by `decide`.

    fn sub(input: &[u32]) -> Option<&'static str> {
        detect(input).sub
    }

    #[test]
    fn clear_cases() {
        assert_eq!(sub(&[]), None);
        assert_eq!(sub(&[0x48, 0x65, 0x6C, 0x6C, 0x6F]), None);
        assert_eq!(sub(&[0xC3, 0xA9]), None); // é
        assert_eq!(sub(&[0xE4, 0xB8, 0xAD]), None); // 中
        assert_eq!(sub(&[0xF0, 0x9F, 0x98, 0x80]), None); // 😀
    }

    #[test]
    fn invalid_start_byte() {
        assert_eq!(sub(&[0xC0, 0x80]), Some("InvalidStartByte"));
        assert_eq!(sub(&[0xC0, 0xAF]), Some("InvalidStartByte"));
        assert_eq!(sub(&[0xFE]), Some("InvalidStartByte"));
        assert_eq!(sub(&[0x80]), Some("InvalidStartByte"));
        assert_eq!(sub(&[0xFF]), Some("InvalidStartByte"));
    }

    #[test]
    fn overlong() {
        assert_eq!(sub(&[0xE0, 0x80, 0xAF]), Some("Overlong"));
        assert_eq!(sub(&[0xF0, 0x80, 0x80, 0xAF]), Some("Overlong"));
    }

    #[test]
    fn cesu8_surrogate() {
        assert_eq!(sub(&[0xED, 0xA0, 0x80]), Some("Cesu8"));
        assert_eq!(sub(&[0xED, 0xAF, 0xBF]), Some("Cesu8"));
    }

    #[test]
    fn truncated() {
        assert_eq!(sub(&[0xC3]), Some("Truncated"));
        assert_eq!(sub(&[0xF0, 0x9F, 0x98]), Some("Truncated"));
    }

    #[test]
    fn non_byte_stream_is_clear() {
        // Any entry >= 0x100 means this is a codepoint array, not a byte
        // stream, so the family does not apply.
        assert_eq!(sub(&[0x1F600]), None);
        assert_eq!(sub(&[0x41, 0x100]), None);
    }
}
