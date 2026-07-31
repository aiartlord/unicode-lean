//! Product-facing security policy contract.
//!
//! This module mirrors `Unicode.Security.Policy`: named profiles, runtime
//! modes, stable reason codes, and a `scan` verdict over decoded codepoints.

use crate::noncharacters;
use crate::security::calculus::{ClassificationKind, Family, Severity};
use crate::security::covert::{
    bidi_control_balance, surrogate_reassembly, tag_block_payload, variation_selector_payload,
    zero_width_payload,
};
use crate::security::boundary::confusable_bidi_compound;
use crate::security::display::rtl_injection;
use crate::security::identity::homoglyph_confusable;
use crate::strict::Utf8RejectKind;
use crate::utf8::{decode_to_codepoints, first_invalid_utf8_offset};
use std::fmt::Write as _;

/// Runtime action recommended for the current payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// Pass the input.
    Allow,
    /// Block the input.
    Reject,
    /// Hold the input for review or delayed handling.
    Quarantine,
    /// Pass a rewritten form.
    Rewrite,
    /// Pass while reporting findings.
    Observe,
}

impl Action {
    /// Stable wire tag.
    pub fn tag(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Reject => "reject",
            Action::Quarantine => "quarantine",
            Action::Rewrite => "rewrite",
            Action::Observe => "observe",
        }
    }
}

/// Operator-selected runtime mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Classify and report, never block.
    Observe,
    /// Report findings while passing traffic.
    Warn,
    /// Apply profile blocking policy.
    Enforce,
    /// Block on any finding.
    Strict,
}

impl Mode {
    /// Stable wire tag.
    pub fn tag(self) -> &'static str {
        match self {
            Mode::Observe => "observe",
            Mode::Warn => "warn",
            Mode::Enforce => "enforce",
            Mode::Strict => "strict",
        }
    }
}

/// Product context profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    /// Gateway or protocol header.
    GatewayHeader,
    /// Fully qualified domain name.
    DomainName,
    /// Single DNS label.
    DnsLabel,
    /// URL or URI-shaped field.
    Url,
    /// Login or account identifier.
    Username,
    /// Human-visible account label.
    DisplayName,
    /// Message body.
    ChatMessage,
    /// Source-code or config text.
    SourceCode,
    /// Secret material before hashing or KDF use.
    OpaqueSecret,
    /// Binary payload boundary.
    BinaryBlob,
}

impl Profile {
    /// Stable wire tag.
    pub fn tag(self) -> &'static str {
        match self {
            Profile::GatewayHeader => "gateway-header",
            Profile::DomainName => "domain-name",
            Profile::DnsLabel => "dns-label",
            Profile::Url => "url",
            Profile::Username => "username",
            Profile::DisplayName => "display-name",
            Profile::ChatMessage => "chat-message",
            Profile::SourceCode => "source-code",
            Profile::OpaqueSecret => "opaque-secret",
            Profile::BinaryBlob => "binary-blob",
        }
    }
}

/// Policy strictness level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyLevel {
    /// Smallest pass set.
    Restrictive,
    /// Default multilingual text gate.
    Moderate,
    /// Structural checks only.
    Minimal,
}

/// Optional crypto-shaped policy context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptoContext {
    /// General Unicode input.
    NonCrypto,
    /// BIP-39 mnemonic input.
    Bip39Mnemonic,
    /// Hash input.
    HashInput,
    /// AI provenance input.
    AiAttribution,
}

impl CryptoContext {
    fn families(self) -> &'static [Family] {
        match self {
            CryptoContext::NonCrypto => &[],
            CryptoContext::Bip39Mnemonic => &[Family::Bip39Canonical],
            CryptoContext::HashInput => &[Family::HashInputStability],
            CryptoContext::AiAttribution => &[Family::AiWatermarkDetectability],
        }
    }
}

/// Runtime policy derived from a named profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProfilePolicy {
    /// Detector rejection level.
    pub level: PolicyLevel,
    /// Crypto context.
    pub crypto_context: CryptoContext,
    /// Whether blocking findings should quarantine instead of reject.
    pub quarantine: bool,
}

/// Product-facing finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Stable reason code.
    pub code: String,
    /// Detector family.
    pub family: Family,
    /// Severity.
    pub severity: Severity,
    /// Codepoint offsets.
    pub positions: Vec<usize>,
    /// Family-specific sub-threat tag.
    pub sub_threat: Option<String>,
    /// Human-readable family detail.
    pub detail: String,
}

/// Runtime verdict returned by `scan`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// Input codepoints.
    pub input: Vec<u32>,
    /// Profile used to scan.
    pub profile: Profile,
    /// Mode used to scan.
    pub mode: Mode,
    /// Policy action.
    pub action: Action,
    /// Findings in detector order.
    pub findings: Vec<Finding>,
    /// Rewritten or normalized output when a later policy allows it.
    pub normalized: Option<Vec<u32>>,
}

const RESTRICTIVE_REJECTION_SET: &[Family] = &[
    Family::MalformedUtf8,
    Family::MalformedUtf16,
    Family::MalformedUtf32,
    Family::TagBlockPayload,
    Family::VariationSelectorPayload,
    Family::ZeroWidthPayload,
    Family::SurrogateReassembly,
    Family::BidiControlBalance,
    Family::NoncharacterControl,
    Family::HomoglyphConfusable,
    Family::MixedScriptAdmissibility,
    Family::EmojiZwjIntegrity,
    Family::SkinToneVariationForgery,
    Family::SourceDisplayDivergence,
    Family::FilenameDisguise,
    Family::RtlInjection,
    Family::RendererDivergence,
    Family::NormalizationBomb,
    Family::StreamSafeViolation,
    Family::LocaleCaseInversion,
    Family::CaseExpansionMismatch,
    Family::WidthClassConfusion,
    Family::NfcIdempotenceWitness,
    Family::IdentifierFormDrift,
    Family::CovertDisplayCompound,
    Family::ConfusableBidiCompound,
    Family::AdmissibilityFormDrift,
];

const MODERATE_REJECTION_SET: &[Family] = &[
    Family::MalformedUtf8,
    Family::MalformedUtf16,
    Family::MalformedUtf32,
    Family::TagBlockPayload,
    Family::VariationSelectorPayload,
    Family::ZeroWidthPayload,
    Family::SurrogateReassembly,
    Family::BidiControlBalance,
    Family::NoncharacterControl,
    Family::HomoglyphConfusable,
    Family::MixedScriptAdmissibility,
    Family::SkinToneVariationForgery,
    Family::SourceDisplayDivergence,
    Family::FilenameDisguise,
    Family::StreamSafeViolation,
    Family::LocaleCaseInversion,
    Family::CaseExpansionMismatch,
    Family::WidthClassConfusion,
    Family::NfcIdempotenceWitness,
    Family::IdentifierFormDrift,
    Family::CovertDisplayCompound,
    Family::ConfusableBidiCompound,
    Family::AdmissibilityFormDrift,
];

const MINIMAL_REJECTION_SET: &[Family] = &[
    Family::MalformedUtf8,
    Family::MalformedUtf16,
    Family::MalformedUtf32,
    Family::SurrogateReassembly,
    Family::BidiControlBalance,
    Family::NoncharacterControl,
    Family::StreamSafeViolation,
];

/// Families whose findings block at `level`.
pub fn rejection_set(level: PolicyLevel) -> &'static [Family] {
    match level {
        PolicyLevel::Restrictive => RESTRICTIVE_REJECTION_SET,
        PolicyLevel::Moderate => MODERATE_REJECTION_SET,
        PolicyLevel::Minimal => MINIMAL_REJECTION_SET,
    }
}

/// Default policy for a named profile.
pub fn policy_of_profile(profile: Profile) -> ProfilePolicy {
    match profile {
        Profile::GatewayHeader => ProfilePolicy {
            level: PolicyLevel::Restrictive,
            crypto_context: CryptoContext::NonCrypto,
            quarantine: false,
        },
        Profile::DomainName => ProfilePolicy {
            level: PolicyLevel::Restrictive,
            crypto_context: CryptoContext::NonCrypto,
            quarantine: false,
        },
        Profile::DnsLabel => ProfilePolicy {
            level: PolicyLevel::Restrictive,
            crypto_context: CryptoContext::NonCrypto,
            quarantine: false,
        },
        Profile::Url => ProfilePolicy {
            level: PolicyLevel::Moderate,
            crypto_context: CryptoContext::NonCrypto,
            quarantine: false,
        },
        Profile::Username => ProfilePolicy {
            level: PolicyLevel::Moderate,
            crypto_context: CryptoContext::NonCrypto,
            quarantine: true,
        },
        Profile::DisplayName => ProfilePolicy {
            level: PolicyLevel::Minimal,
            crypto_context: CryptoContext::NonCrypto,
            quarantine: true,
        },
        Profile::ChatMessage => ProfilePolicy {
            level: PolicyLevel::Minimal,
            crypto_context: CryptoContext::NonCrypto,
            quarantine: true,
        },
        Profile::SourceCode => ProfilePolicy {
            level: PolicyLevel::Restrictive,
            crypto_context: CryptoContext::NonCrypto,
            quarantine: false,
        },
        Profile::OpaqueSecret => ProfilePolicy {
            level: PolicyLevel::Minimal,
            crypto_context: CryptoContext::HashInput,
            quarantine: false,
        },
        Profile::BinaryBlob => ProfilePolicy {
            level: PolicyLevel::Minimal,
            crypto_context: CryptoContext::NonCrypto,
            quarantine: false,
        },
    }
}

/// Stable reason-code layer letter.
pub fn family_layer_code(family: Family) -> &'static str {
    match family {
        Family::MalformedUtf8
        | Family::MalformedUtf16
        | Family::MalformedUtf32
        | Family::TagBlockPayload
        | Family::VariationSelectorPayload
        | Family::ZeroWidthPayload
        | Family::SurrogateReassembly
        | Family::BidiControlBalance
        | Family::NoncharacterControl => "C",
        Family::HomoglyphConfusable
        | Family::MixedScriptAdmissibility
        | Family::EmojiZwjIntegrity
        | Family::SkinToneVariationForgery => "I",
        Family::SourceDisplayDivergence
        | Family::FilenameDisguise
        | Family::RtlInjection
        | Family::RendererDivergence => "D",
        Family::NormalizationBomb
        | Family::StreamSafeViolation
        | Family::LocaleCaseInversion
        | Family::CaseExpansionMismatch
        | Family::WidthClassConfusion
        | Family::NfcIdempotenceWitness => "F",
        Family::IdentifierFormDrift
        | Family::CovertDisplayCompound
        | Family::ConfusableBidiCompound
        | Family::AdmissibilityFormDrift => "X",
        Family::Bip39Canonical | Family::HashInputStability | Family::AiWatermarkDetectability => {
            "K"
        }
    }
}

/// Stable reason-code family slug.
pub fn family_slug(family: Family) -> &'static str {
    match family {
        Family::MalformedUtf8 => "malformed-utf8",
        Family::MalformedUtf16 => "malformed-utf16",
        Family::MalformedUtf32 => "malformed-utf32",
        Family::TagBlockPayload => "tag-block-payload",
        Family::VariationSelectorPayload => "variation-selector-payload",
        Family::ZeroWidthPayload => "zero-width-payload",
        Family::SurrogateReassembly => "surrogate-reassembly",
        Family::BidiControlBalance => "bidi-control-balance",
        Family::NoncharacterControl => "noncharacter-control",
        Family::HomoglyphConfusable => "homoglyph-confusable",
        Family::MixedScriptAdmissibility => "mixed-script-admissibility",
        Family::EmojiZwjIntegrity => "emoji-zwj-integrity",
        Family::SkinToneVariationForgery => "skin-tone-variation-forgery",
        Family::SourceDisplayDivergence => "source-display-divergence",
        Family::FilenameDisguise => "filename-disguise",
        Family::RtlInjection => "rtl-injection",
        Family::RendererDivergence => "renderer-divergence",
        Family::NormalizationBomb => "normalization-bomb",
        Family::StreamSafeViolation => "stream-safe-violation",
        Family::LocaleCaseInversion => "locale-case-inversion",
        Family::CaseExpansionMismatch => "case-expansion-mismatch",
        Family::WidthClassConfusion => "width-class-confusion",
        Family::NfcIdempotenceWitness => "nfc-idempotence-witness",
        Family::IdentifierFormDrift => "identifier-form-drift",
        Family::CovertDisplayCompound => "covert-display-compound",
        Family::ConfusableBidiCompound => "confusable-bidi-compound",
        Family::AdmissibilityFormDrift => "admissibility-form-drift",
        Family::Bip39Canonical => "bip39-canonical",
        Family::HashInputStability => "hash-input-stability",
        Family::AiWatermarkDetectability => "ai-watermark-detectability",
    }
}

/// Stable reason-code base for a detector family.
pub fn reason_base(family: Family) -> String {
    format!(
        "unicode.security.{}.{}",
        family_layer_code(family),
        family_slug(family)
    )
}

/// Stable reason code for a detector result.
pub fn reason_code(family: Family, sub_threat: Option<&str>) -> String {
    match sub_threat {
        Some(tag) => format!("{}.{}", reason_base(family), tag),
        None => format!("{}.hazard", reason_base(family)),
    }
}

/// Serialize a finding to the stable compact JSON verdict shape.
pub fn finding_to_json(finding: &Finding) -> String {
    let mut out = String::new();
    push_finding_json(&mut out, finding);
    out
}

/// Serialize a verdict to the stable compact JSON verdict shape.
pub fn verdict_to_json(verdict: &Verdict) -> String {
    let mut out = String::new();
    out.push('{');
    out.push_str("\"action\":");
    push_json_string(&mut out, verdict.action.tag());
    out.push_str(",\"profile\":");
    push_json_string(&mut out, verdict.profile.tag());
    out.push_str(",\"mode\":");
    push_json_string(&mut out, verdict.mode.tag());
    out.push_str(",\"input\":");
    push_u32_array(&mut out, &verdict.input);
    out.push_str(",\"findings\":[");
    for (index, finding) in verdict.findings.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_finding_json(&mut out, finding);
    }
    out.push_str("],\"normalized\":");
    match &verdict.normalized {
        Some(normalized) => push_u32_array(&mut out, normalized),
        None => out.push_str("null"),
    }
    out.push('}');
    out
}

fn push_finding_json(out: &mut String, finding: &Finding) {
    out.push('{');
    out.push_str("\"code\":");
    push_json_string(out, &finding.code);
    out.push_str(",\"family\":");
    push_json_string(out, family_slug(finding.family));
    out.push_str(",\"severity\":");
    let _ = write!(out, "{}", finding.severity as u8);
    out.push_str(",\"positions\":");
    push_usize_array(out, &finding.positions);
    out.push_str(",\"sub_threat\":");
    match &finding.sub_threat {
        Some(sub_threat) => push_json_string(out, sub_threat),
        None => out.push_str("null"),
    }
    out.push_str(",\"detail\":");
    push_json_string(out, &finding.detail);
    out.push('}');
}

fn push_u32_array(out: &mut String, values: &[u32]) {
    out.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let _ = write!(out, "{value}");
    }
    out.push(']');
}

fn push_usize_array(out: &mut String, values: &[usize]) {
    out.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let _ = write!(out, "{value}");
    }
    out.push(']');
}

fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch <= '\u{1F}' => {
                let _ = write!(out, "\\u{:04x}", ch as u32);
            }
            _ => out.push(ch),
        }
    }
    out.push('"');
}

/// Stable sub-threat tag for a strict UTF-8 reject kind.
pub fn utf8_reject_tag(kind: Utf8RejectKind) -> &'static str {
    match kind {
        Utf8RejectKind::OverlongEncoding => "OverlongEncoding",
        Utf8RejectKind::SurrogateCodepoint => "SurrogateCodepoint",
        Utf8RejectKind::CodepointBeyondMax => "CodepointBeyondMax",
        Utf8RejectKind::TruncatedSequence => "TruncatedSequence",
        Utf8RejectKind::InvalidStartByte => "InvalidStartByte",
        Utf8RejectKind::InvalidContinuationByte => "InvalidContinuationByte",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endian {
    Big,
    Little,
}

fn malformed_decode_verdict(
    profile: Profile,
    mode: Mode,
    family: Family,
    sub_threat: &'static str,
    offset: usize,
) -> Verdict {
    let findings = vec![Finding {
        code: reason_code(family, Some(sub_threat)),
        family,
        severity: Severity::Moderate,
        positions: vec![offset],
        sub_threat: Some(sub_threat.to_string()),
        detail: family_slug(family).to_string(),
    }];
    Verdict {
        input: Vec::new(),
        profile,
        mode,
        action: select_action(profile, mode, &findings),
        findings,
        normalized: None,
    }
}

/// True when a detector family blocks under the profile.
pub fn family_blocks(profile: Profile, family: Family) -> bool {
    let policy = policy_of_profile(profile);
    rejection_set(policy.level).contains(&family)
        || policy.crypto_context.families().contains(&family)
}

/// Findings that block under the profile.
pub fn blocking_findings(profile: Profile, findings: &[Finding]) -> Vec<Finding> {
    findings
        .iter()
        .filter(|finding| family_blocks(profile, finding.family))
        .cloned()
        .collect()
}

/// Select the action for a profile/mode/findings tuple.
pub fn select_action(profile: Profile, mode: Mode, findings: &[Finding]) -> Action {
    let has_findings = !findings.is_empty();
    let has_blocking = findings
        .iter()
        .any(|finding| family_blocks(profile, finding.family));
    match mode {
        Mode::Observe | Mode::Warn => {
            if has_findings {
                Action::Observe
            } else {
                Action::Allow
            }
        }
        Mode::Enforce => {
            if !has_blocking {
                Action::Allow
            } else if policy_of_profile(profile).quarantine {
                Action::Quarantine
            } else {
                Action::Reject
            }
        }
        Mode::Strict => {
            if has_findings {
                Action::Reject
            } else {
                Action::Allow
            }
        }
    }
}

fn push_finding(
    findings: &mut Vec<Finding>,
    family: Family,
    kind: ClassificationKind,
    sub_threat: Option<&str>,
    positions: Vec<usize>,
) {
    if kind == ClassificationKind::Clear {
        return;
    }
    findings.push(Finding {
        code: reason_code(family, sub_threat),
        family,
        severity: default_policy_severity(kind),
        positions,
        sub_threat: sub_threat.map(str::to_string),
        detail: family_slug(family).to_string(),
    });
}

fn push_positional_hazard(
    findings: &mut Vec<Finding>,
    family: Family,
    sub_threat: &str,
    positions: Vec<usize>,
) {
    if positions.is_empty() {
        return;
    }
    push_finding(
        findings,
        family,
        ClassificationKind::Hazard,
        Some(sub_threat),
        positions,
    );
}

fn default_policy_severity(kind: ClassificationKind) -> Severity {
    match kind {
        ClassificationKind::Clear => Severity::Informational,
        ClassificationKind::Hazard => Severity::Moderate,
        ClassificationKind::Compound => Severity::High,
        ClassificationKind::Informational => Severity::Informational,
    }
}

fn positions_where(input: &[u32], predicate: impl Fn(u32) -> bool) -> Vec<usize> {
    input
        .iter()
        .enumerate()
        .filter_map(|(index, &cp)| predicate(cp).then_some(index))
        .collect()
}

fn is_c0_control(cp: u32) -> bool {
    (cp <= 0x1F && cp != 0x09 && cp != 0x0A && cp != 0x0D) || cp == 0x7F
}

fn is_c1_control(cp: u32) -> bool {
    (0x80..=0x9F).contains(&cp)
}

/// Scan a decoded codepoint sequence with the currently implemented native
/// detector families.
pub fn scan(profile: Profile, mode: Mode, input: &[u32]) -> Verdict {
    let mut findings = Vec::new();

    let tag = tag_block_payload::detect(input);
    push_finding(
        &mut findings,
        Family::TagBlockPayload,
        tag.kind,
        tag.sub.as_ref().map(|sub| sub.tag()),
        tag.tag_positions,
    );

    let vs = variation_selector_payload::detect(input);
    push_finding(
        &mut findings,
        Family::VariationSelectorPayload,
        vs.kind,
        vs.sub.as_ref().map(|sub| sub.tag()),
        vs.vs_positions,
    );

    let zw = zero_width_payload::detect(input);
    push_finding(
        &mut findings,
        Family::ZeroWidthPayload,
        zw.kind,
        zw.sub.as_ref().map(|sub| sub.tag()),
        zw.zero_width_positions,
    );

    let surrogate = surrogate_reassembly::detect(input);
    if let Some(sub) = surrogate.sub {
        push_finding(
            &mut findings,
            Family::SurrogateReassembly,
            ClassificationKind::Hazard,
            Some(sub),
            surrogate.positions,
        );
    }

    let bidi = bidi_control_balance::detect(input);
    push_finding(
        &mut findings,
        Family::BidiControlBalance,
        bidi.kind,
        bidi.sub.as_ref().map(|sub| sub.tag()),
        bidi.bidi_positions,
    );

    push_positional_hazard(
        &mut findings,
        Family::NoncharacterControl,
        "Noncharacter",
        positions_where(input, noncharacters::is_noncharacter),
    );
    push_positional_hazard(
        &mut findings,
        Family::NoncharacterControl,
        "C0Control",
        positions_where(input, is_c0_control),
    );
    push_positional_hazard(
        &mut findings,
        Family::NoncharacterControl,
        "C1Control",
        positions_where(input, is_c1_control),
    );

    let homoglyph = homoglyph_confusable::detect(input);
    let homoglyph_sub = homoglyph.sub.as_ref().map(|sub| sub.tag());
    if homoglyph_sub != Some("CrossScriptMix") {
        push_finding(
            &mut findings,
            Family::HomoglyphConfusable,
            homoglyph.kind,
            homoglyph_sub,
            if homoglyph.kind == ClassificationKind::Clear {
                Vec::new()
            } else {
                (0..input.len()).collect()
            },
        );
    }
    if homoglyph_confusable::has_mixed_script_admissibility(input) {
        push_finding(
            &mut findings,
            Family::MixedScriptAdmissibility,
            ClassificationKind::Hazard,
            Some(homoglyph_confusable::mixed_script_subthreat(input)),
            (0..input.len()).collect(),
        );
    }

    let rtl = rtl_injection::detect(input);
    if let Some(sub) = rtl.sub {
        push_finding(
            &mut findings,
            Family::RtlInjection,
            ClassificationKind::Hazard,
            Some(sub),
            rtl.positions,
        );
    }

    let confusable_bidi = confusable_bidi_compound::detect(input);
    if let Some(sub) = confusable_bidi.sub {
        push_finding(
            &mut findings,
            Family::ConfusableBidiCompound,
            ClassificationKind::Hazard,
            Some(sub),
            confusable_bidi.positions,
        );
    }

    Verdict {
        input: input.to_vec(),
        profile,
        mode,
        action: select_action(profile, mode, &findings),
        findings,
        normalized: None,
    }
}

/// Scan raw UTF-8 bytes with strict decoding before the codepoint policy.
pub fn scan_utf8(profile: Profile, mode: Mode, bytes: &[u8]) -> Verdict {
    if let Some((offset, kind)) = first_invalid_utf8_offset(bytes) {
        let sub_threat = utf8_reject_tag(kind);
        return malformed_decode_verdict(profile, mode, Family::MalformedUtf8, sub_threat, offset);
    }

    let input = decode_to_codepoints(bytes);
    scan(profile, mode, &input)
}

fn read_u16(bytes: &[u8], offset: usize, endian: Endian) -> u16 {
    match endian {
        Endian::Big => u16::from_be_bytes([bytes[offset], bytes[offset + 1]]),
        Endian::Little => u16::from_le_bytes([bytes[offset], bytes[offset + 1]]),
    }
}

fn read_u32(bytes: &[u8], offset: usize, endian: Endian) -> u32 {
    match endian {
        Endian::Big => u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]),
        Endian::Little => u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]),
    }
}

fn decode_utf16_stream(bytes: &[u8], endian: Endian) -> Result<Vec<u32>, (&'static str, usize)> {
    let mut input = Vec::with_capacity(bytes.len() / 2);
    let mut offset = 0;

    while offset < bytes.len() {
        if offset + 2 > bytes.len() {
            return Err(("TruncatedCodeUnit", bytes.len()));
        }

        let unit = read_u16(bytes, offset, endian) as u32;
        let unit_offset = offset;
        offset += 2;

        if (0xD800..=0xDBFF).contains(&unit) {
            if offset + 2 > bytes.len() {
                return Err(("TruncatedSurrogatePair", bytes.len()));
            }
            let low = read_u16(bytes, offset, endian) as u32;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(("InvalidSurrogatePair", offset));
            }
            input.push(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00));
            offset += 2;
        } else if (0xDC00..=0xDFFF).contains(&unit) {
            return Err(("LoneSurrogate", unit_offset));
        } else {
            input.push(unit);
        }
    }

    Ok(input)
}

fn decode_utf32_stream(bytes: &[u8], endian: Endian) -> Result<Vec<u32>, (&'static str, usize)> {
    if bytes.len() % 4 != 0 {
        return Err(("TruncatedCodeUnit", bytes.len()));
    }

    let mut input = Vec::with_capacity(bytes.len() / 4);
    let mut offset = 0;
    while offset < bytes.len() {
        let cp = read_u32(bytes, offset, endian);
        if (0xD800..=0xDFFF).contains(&cp) {
            return Err(("SurrogateCodepoint", offset));
        }
        if cp > 0x10FFFF {
            return Err(("CodepointBeyondMax", offset));
        }
        input.push(cp);
        offset += 4;
    }
    Ok(input)
}

fn scan_utf16(profile: Profile, mode: Mode, bytes: &[u8], endian: Endian) -> Verdict {
    match decode_utf16_stream(bytes, endian) {
        Ok(input) => scan(profile, mode, &input),
        Err((sub_threat, offset)) => {
            malformed_decode_verdict(profile, mode, Family::MalformedUtf16, sub_threat, offset)
        }
    }
}

fn scan_utf32(profile: Profile, mode: Mode, bytes: &[u8], endian: Endian) -> Verdict {
    match decode_utf32_stream(bytes, endian) {
        Ok(input) => scan(profile, mode, &input),
        Err((sub_threat, offset)) => {
            malformed_decode_verdict(profile, mode, Family::MalformedUtf32, sub_threat, offset)
        }
    }
}

/// Scan raw UTF-16 big-endian bytes before the codepoint policy.
pub fn scan_utf16be(profile: Profile, mode: Mode, bytes: &[u8]) -> Verdict {
    scan_utf16(profile, mode, bytes, Endian::Big)
}

/// Scan raw UTF-16 little-endian bytes before the codepoint policy.
pub fn scan_utf16le(profile: Profile, mode: Mode, bytes: &[u8]) -> Verdict {
    scan_utf16(profile, mode, bytes, Endian::Little)
}

/// Scan raw UTF-32 big-endian bytes before the codepoint policy.
pub fn scan_utf32be(profile: Profile, mode: Mode, bytes: &[u8]) -> Verdict {
    scan_utf32(profile, mode, bytes, Endian::Big)
}

/// Scan raw UTF-32 little-endian bytes before the codepoint policy.
pub fn scan_utf32le(profile: Profile, mode: Mode, bytes: &[u8]) -> Verdict {
    scan_utf32(profile, mode, bytes, Endian::Little)
}

/// Scan in default enforce mode.
pub fn scan_default(profile: Profile, input: &[u32]) -> Verdict {
    scan(profile, Mode::Enforce, input)
}

/// True when policy passes or only observes the input.
pub fn permits(profile: Profile, mode: Mode, input: &[u32]) -> bool {
    matches!(
        scan(profile, mode, input).action,
        Action::Allow | Action::Observe | Action::Rewrite
    )
}
