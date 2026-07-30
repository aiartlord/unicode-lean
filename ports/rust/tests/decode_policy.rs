//! Shared raw UTF-8 security policy tests.

use unicode_rust::security::{
    scan_utf16be, scan_utf16le, scan_utf32be, scan_utf32le, scan_utf8, Action, Mode, Profile,
    Verdict,
};

fn has_code(verdict: &Verdict, code: &str) -> bool {
    verdict.findings.iter().any(|finding| finding.code == code)
}

fn positions_for<'a>(verdict: &'a Verdict, code: &str) -> Option<&'a [usize]> {
    verdict
        .findings
        .iter()
        .find(|finding| finding.code == code)
        .map(|finding| finding.positions.as_slice())
}

#[test]
fn scan_utf8_ascii_gateway_enforce_allows() {
    let verdict = scan_utf8(Profile::GatewayHeader, Mode::Enforce, b"Hello");
    assert_eq!(verdict.action, Action::Allow);
    assert_eq!(verdict.input, vec![72, 101, 108, 108, 111]);
    assert!(verdict.findings.is_empty());
}

#[test]
fn scan_utf8_malformed_reject_kinds_are_reason_codes() {
    let cases: &[(&[u8], &str, &[usize])] = &[
        (
            &[0x80],
            "unicode.security.C.malformed-utf8.InvalidStartByte",
            &[0],
        ),
        (
            &[0xC2, 0x00],
            "unicode.security.C.malformed-utf8.InvalidContinuationByte",
            &[1],
        ),
        (
            &[0xE0, 0x80, 0xAF],
            "unicode.security.C.malformed-utf8.OverlongEncoding",
            &[0],
        ),
        (
            &[0xED, 0xA0, 0x80],
            "unicode.security.C.malformed-utf8.SurrogateCodepoint",
            &[2],
        ),
        (
            &[0xF4, 0x90, 0x80, 0x80],
            "unicode.security.C.malformed-utf8.CodepointBeyondMax",
            &[3],
        ),
        (
            &[0xC2],
            "unicode.security.C.malformed-utf8.TruncatedSequence",
            &[1],
        ),
    ];

    for (input, code, positions) in cases {
        let verdict = scan_utf8(Profile::GatewayHeader, Mode::Enforce, input);
        assert_eq!(verdict.action, Action::Reject, "{code}");
        assert!(verdict.input.is_empty(), "{code}");
        assert!(has_code(&verdict, code), "{code}");
        assert_eq!(positions_for(&verdict, code), Some(*positions), "{code}");
    }
}

#[test]
fn scan_utf8_observe_keeps_malformed_report_only() {
    let verdict = scan_utf8(Profile::GatewayHeader, Mode::Observe, &[0x80]);
    assert_eq!(verdict.action, Action::Observe);
    assert!(has_code(
        &verdict,
        "unicode.security.C.malformed-utf8.InvalidStartByte",
    ));
}

#[test]
fn scan_utf8_valid_bytes_continue_to_codepoint_policy() {
    let verdict = scan_utf8(
        Profile::SourceCode,
        Mode::Strict,
        &[b'a', 0xE2, 0x80, 0x8B, b'b'],
    );
    assert_eq!(verdict.action, Action::Reject);
    assert_eq!(verdict.input, vec![97, 8203, 98]);
    assert!(has_code(
        &verdict,
        "unicode.security.C.zero-width-payload.BareZeroWidth",
    ));
    assert_eq!(
        positions_for(
            &verdict,
            "unicode.security.C.zero-width-payload.BareZeroWidth",
        ),
        Some(&[1][..]),
    );
}

#[test]
fn scan_utf16_malformed_reject_kinds_are_reason_codes() {
    let cases: &[(&[u8], bool, &str, &[usize])] = &[
        (
            &[0x61],
            false,
            "unicode.security.C.malformed-utf16.TruncatedCodeUnit",
            &[1],
        ),
        (
            &[0xDC, 0x00],
            true,
            "unicode.security.C.malformed-utf16.LoneSurrogate",
            &[0],
        ),
        (
            &[0x00, 0xD8, 0x41, 0x00],
            false,
            "unicode.security.C.malformed-utf16.InvalidSurrogatePair",
            &[2],
        ),
        (
            &[0x00, 0xD8],
            false,
            "unicode.security.C.malformed-utf16.TruncatedSurrogatePair",
            &[2],
        ),
    ];

    for (input, big_endian, code, positions) in cases {
        let verdict = if *big_endian {
            scan_utf16be(Profile::GatewayHeader, Mode::Enforce, input)
        } else {
            scan_utf16le(Profile::GatewayHeader, Mode::Enforce, input)
        };
        assert_eq!(verdict.action, Action::Reject, "{code}");
        assert!(verdict.input.is_empty(), "{code}");
        assert!(has_code(&verdict, code), "{code}");
        assert_eq!(positions_for(&verdict, code), Some(*positions), "{code}");
    }
}

#[test]
fn scan_utf16_valid_bytes_continue_to_codepoint_policy() {
    let verdict = scan_utf16le(
        Profile::SourceCode,
        Mode::Strict,
        &[b'a', 0x00, 0x0B, 0x20, b'b', 0x00],
    );
    assert_eq!(verdict.action, Action::Reject);
    assert_eq!(verdict.input, vec![97, 8203, 98]);
    assert!(has_code(
        &verdict,
        "unicode.security.C.zero-width-payload.BareZeroWidth",
    ));
}

#[test]
fn scan_utf32_malformed_reject_kinds_are_reason_codes() {
    let cases: &[(&[u8], bool, &str, &[usize])] = &[
        (
            &[0x00, 0x00, 0x00],
            true,
            "unicode.security.C.malformed-utf32.TruncatedCodeUnit",
            &[3],
        ),
        (
            &[0x00, 0xD8, 0x00, 0x00],
            false,
            "unicode.security.C.malformed-utf32.SurrogateCodepoint",
            &[0],
        ),
        (
            &[0x00, 0x11, 0x00, 0x00],
            true,
            "unicode.security.C.malformed-utf32.CodepointBeyondMax",
            &[0],
        ),
    ];

    for (input, big_endian, code, positions) in cases {
        let verdict = if *big_endian {
            scan_utf32be(Profile::GatewayHeader, Mode::Enforce, input)
        } else {
            scan_utf32le(Profile::GatewayHeader, Mode::Enforce, input)
        };
        assert_eq!(verdict.action, Action::Reject, "{code}");
        assert!(verdict.input.is_empty(), "{code}");
        assert!(has_code(&verdict, code), "{code}");
        assert_eq!(positions_for(&verdict, code), Some(*positions), "{code}");
    }
}

#[test]
fn scan_utf32_ascii_gateway_enforce_allows() {
    let verdict = scan_utf32le(
        Profile::GatewayHeader,
        Mode::Enforce,
        &[
            b'H', 0, 0, 0, b'e', 0, 0, 0, b'l', 0, 0, 0, b'l', 0, 0, 0, b'o', 0, 0, 0,
        ],
    );
    assert_eq!(verdict.action, Action::Allow);
    assert_eq!(verdict.input, vec![72, 101, 108, 108, 111]);
    assert!(verdict.findings.is_empty());
}
