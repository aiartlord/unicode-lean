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
/// gate from `Unicode/Security/RunAll.lean`.  A codepoint-array input
/// containing any value `>= 0x100` is not a byte stream; the scan
/// orchestrator uses this to skip the family on such inputs, exactly as
/// `runAll` does.
pub fn looks_like_byte_stream(input: &[u32]) -> bool {
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

/// Detect a malformed UTF-8 byte stream in a codepoint list, mirroring the
/// Lean module `Unicode.Security.Covert.SurrogateReassembly.detect`.  The
/// input is treated as a byte stream: any value `> 0xFF` is clamped to
/// `0xFF` (never a valid UTF-8 start byte), exactly as the Lean `toBytes`
/// helper does, so out-of-range values surface as a malformed stream rather
/// than being dropped.  Reports the sub-threat of the first violation at its
/// byte offset.  The byte-stream gate lives in the scan orchestrator
/// (`looks_like_byte_stream`), mirroring `runAll` in the Lean spec.
pub fn detect(input: &[u32]) -> Detection {
    let bytes: Vec<u8> = input
        .iter()
        .map(|&cp| if cp > 0xFF { 0xFF } else { cp as u8 })
        .collect();
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
    fn non_byte_stream_clamps_to_ff() {
        // The module clamps any value > 0xFF to 0xFF (mirroring the Lean
        // `toBytes` helper), which the strict decoder rejects as an invalid
        // start byte.  The scan orchestrator gates these inputs out via
        // `looks_like_byte_stream` before calling `detect`.
        assert_eq!(sub(&[0x1F600]), Some("InvalidStartByte"));
        assert_eq!(sub(&[0x41, 0x100]), Some("InvalidStartByte"));
    }

    #[test]
    fn byte_stream_gate() {
        use super::looks_like_byte_stream;
        assert!(looks_like_byte_stream(&[0x41, 0xFF]));
        assert!(!looks_like_byte_stream(&[0x1F600]));
        assert!(!looks_like_byte_stream(&[0x41, 0x100]));
    }
}
