use unicode_rust::security::{
    permits, reason_code, scan, verdict_to_json, Action, Family, Mode, Profile,
};

fn has_code(verdict: &unicode_rust::security::Verdict, code: &str) -> bool {
    verdict.findings.iter().any(|finding| finding.code == code)
}

#[test]
fn policy_reason_codes_are_stable() {
    assert_eq!(
        reason_code(Family::TagBlockPayload, Some("DirectAscii")),
        "unicode.security.C.tag-block-payload.DirectAscii",
    );
    assert_eq!(
        reason_code(Family::BidiControlBalance, None),
        "unicode.security.C.bidi-control-balance.hazard",
    );
    assert_eq!(
        reason_code(Family::HomoglyphConfusable, Some("TargetMatch")),
        "unicode.security.I.homoglyph-confusable.TargetMatch",
    );
    assert_eq!(
        reason_code(Family::MixedScriptAdmissibility, Some("CrossScriptMix")),
        "unicode.security.I.mixed-script-admissibility.CrossScriptMix",
    );
    assert_eq!(
        reason_code(Family::NoncharacterControl, Some("Noncharacter")),
        "unicode.security.C.noncharacter-control.Noncharacter",
    );
    assert_eq!(
        reason_code(Family::MalformedUtf8, Some("InvalidStartByte")),
        "unicode.security.C.malformed-utf8.InvalidStartByte",
    );
}

#[test]
fn ascii_gateway_enforce_allows() {
    let verdict = scan(
        Profile::GatewayHeader,
        Mode::Enforce,
        &[72, 101, 108, 108, 111],
    );
    assert_eq!(verdict.action, Action::Allow);
    assert!(verdict.findings.is_empty());
    assert_eq!(
        verdict_to_json(&verdict),
        "{\"action\":\"allow\",\"profile\":\"gateway-header\",\"mode\":\"enforce\",\"input\":[72,101,108,108,111],\"findings\":[],\"normalized\":null}"
    );
}

#[test]
fn tag_block_gateway_enforce_rejects() {
    let verdict = scan(Profile::GatewayHeader, Mode::Enforce, &[0xE0041, 0xE0042]);
    assert_eq!(verdict.action, Action::Reject);
    assert!(has_code(
        &verdict,
        "unicode.security.C.tag-block-payload.DirectAscii"
    ));
}

#[test]
fn noncharacter_gateway_enforce_rejects() {
    let verdict = scan(Profile::GatewayHeader, Mode::Enforce, &[0xFDD0]);
    assert_eq!(verdict.action, Action::Reject);
    assert!(has_code(
        &verdict,
        "unicode.security.C.noncharacter-control.Noncharacter"
    ));
    // A noncharacter resolves to no script, so it is Unrestricted and the
    // homoglyph ladder reports RestrictionLow, which in turn makes the
    // source-display aggregator see a second constituent fire. The three
    // findings are the reading pinned by the `noncharacter-gateway-reject`
    // case of `fixtures/security/verdict_contract.json`.
    assert!(has_code(
        &verdict,
        "unicode.security.I.homoglyph-confusable.RestrictionLow"
    ));
    assert_eq!(
        verdict_to_json(&verdict),
        "{\"action\":\"reject\",\"profile\":\"gateway-header\",\"mode\":\"enforce\",\"input\":[64976],\"findings\":[{\"code\":\"unicode.security.C.noncharacter-control.Noncharacter\",\"family\":\"noncharacter-control\",\"severity\":2,\"positions\":[0],\"sub_threat\":\"Noncharacter\",\"detail\":\"noncharacter-control\"},{\"code\":\"unicode.security.I.homoglyph-confusable.RestrictionLow\",\"family\":\"homoglyph-confusable\",\"severity\":2,\"positions\":[0],\"sub_threat\":\"RestrictionLow\",\"detail\":\"homoglyph-confusable\"},{\"code\":\"unicode.security.D.source-display-divergence.IdentifierHomoglyph\",\"family\":\"source-display-divergence\",\"severity\":2,\"positions\":[],\"sub_threat\":\"IdentifierHomoglyph\",\"detail\":\"source-display-divergence\"}],\"normalized\":null}"
    );
}

#[test]
fn structured_whitespace_is_not_c0_control() {
    let verdict = scan(
        Profile::GatewayHeader,
        Mode::Enforce,
        &[b'a' as u32, 0x09, 0x0A, 0x0D, b'b' as u32],
    );
    assert_eq!(verdict.action, Action::Allow);
    assert!(verdict.findings.is_empty());
}

#[test]
fn tag_block_username_enforce_quarantines() {
    let verdict = scan(Profile::Username, Mode::Enforce, &[0xE0041, 0xE0042]);
    assert_eq!(verdict.action, Action::Quarantine);
    assert!(has_code(
        &verdict,
        "unicode.security.C.tag-block-payload.DirectAscii"
    ));
}

#[test]
fn zero_width_display_name_enforce_reports_but_allows() {
    let verdict = scan(
        Profile::DisplayName,
        Mode::Enforce,
        &[b'a' as u32, 0x200B, b'b' as u32],
    );
    assert_eq!(verdict.action, Action::Allow);
    assert!(has_code(
        &verdict,
        "unicode.security.C.zero-width-payload.BareZeroWidth"
    ));
}

#[test]
fn zero_width_source_strict_rejects() {
    let verdict = scan(
        Profile::SourceCode,
        Mode::Strict,
        &[b'a' as u32, 0x200B, b'b' as u32],
    );
    assert_eq!(verdict.action, Action::Reject);
    assert!(has_code(
        &verdict,
        "unicode.security.C.zero-width-payload.BareZeroWidth"
    ));
}

#[test]
fn bidi_source_enforce_rejects() {
    let verdict = scan(
        Profile::SourceCode,
        Mode::Enforce,
        &[
            b'i' as u32,
            b'f' as u32,
            b' ' as u32,
            0x202E,
            b')' as u32,
            b'{' as u32,
        ],
    );
    assert_eq!(verdict.action, Action::Reject);
    assert!(has_code(
        &verdict,
        "unicode.security.C.bidi-control-balance.UnbalancedEmbedding"
    ));
    assert!(!permits(
        Profile::SourceCode,
        Mode::Enforce,
        &[
            b'i' as u32,
            b'f' as u32,
            b' ' as u32,
            0x202E,
            b')' as u32,
            b'{' as u32,
        ]
    ));
}
