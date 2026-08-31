const std = @import("std");
const confusables_data = @import("confusables_data.zig");
const case_folding_data = @import("case_folding_data.zig");
const normalization_data = @import("normalization_data.zig");
const bidi_class_data = @import("bidi_class_data.zig");
const east_asian_width_data = @import("east_asian_width_data.zig");
const casing_data = @import("casing_data.zig");
const bip39_data = @import("bip39_data.zig");

const known_attack_targets_raw = @embedFile("data/KnownAttackTargets.txt");
const standardized_variants_raw = @embedFile("data/StandardizedVariants.txt");
const emoji_variation_sequences_raw = @embedFile("data/emoji-variation-sequences.txt");
const emoji_data_raw = @embedFile("data/emoji-data.txt");
const emoji_zwj_sequences_raw = @embedFile("data/emoji-zwj-sequences.txt");
const derived_core_properties_raw = @embedFile("data/DerivedCoreProperties.txt");
const identifier_status_raw = @embedFile("data/IdentifierStatus.txt");
const scripts_raw = @embedFile("data/Scripts.txt");
const script_extensions_raw = @embedFile("data/ScriptExtensions.txt");
const property_value_aliases_raw = @embedFile("data/PropertyValueAliases.txt");
const derived_joining_type_raw = @embedFile("data/DerivedJoiningType.txt");
const MaxSkeletonLen = 128;

pub const Action = enum {
    allow,
    reject,
    quarantine,
    rewrite,
    observe,

    pub fn fromTag(wire_tag: []const u8) ?Action {
        if (std.mem.eql(u8, wire_tag, "allow")) return .allow;
        if (std.mem.eql(u8, wire_tag, "reject")) return .reject;
        if (std.mem.eql(u8, wire_tag, "quarantine")) return .quarantine;
        if (std.mem.eql(u8, wire_tag, "rewrite")) return .rewrite;
        if (std.mem.eql(u8, wire_tag, "observe")) return .observe;
        return null;
    }

    pub fn tag(self: Action) []const u8 {
        return switch (self) {
            .allow => "allow",
            .reject => "reject",
            .quarantine => "quarantine",
            .rewrite => "rewrite",
            .observe => "observe",
        };
    }
};

pub const Mode = enum {
    observe,
    warn,
    enforce,
    strict,

    pub fn fromTag(wire_tag: []const u8) ?Mode {
        if (std.mem.eql(u8, wire_tag, "observe")) return .observe;
        if (std.mem.eql(u8, wire_tag, "warn")) return .warn;
        if (std.mem.eql(u8, wire_tag, "enforce")) return .enforce;
        if (std.mem.eql(u8, wire_tag, "strict")) return .strict;
        return null;
    }

    pub fn tag(self: Mode) []const u8 {
        return switch (self) {
            .observe => "observe",
            .warn => "warn",
            .enforce => "enforce",
            .strict => "strict",
        };
    }
};

pub const Profile = enum {
    gateway_header,
    domain_name,
    dns_label,
    url,
    username,
    display_name,
    chat_message,
    source_code,
    opaque_secret,
    binary_blob,

    pub fn fromTag(wire_tag: []const u8) ?Profile {
        if (std.mem.eql(u8, wire_tag, "gateway-header")) return .gateway_header;
        if (std.mem.eql(u8, wire_tag, "domain-name")) return .domain_name;
        if (std.mem.eql(u8, wire_tag, "dns-label")) return .dns_label;
        if (std.mem.eql(u8, wire_tag, "url")) return .url;
        if (std.mem.eql(u8, wire_tag, "username")) return .username;
        if (std.mem.eql(u8, wire_tag, "display-name")) return .display_name;
        if (std.mem.eql(u8, wire_tag, "chat-message")) return .chat_message;
        if (std.mem.eql(u8, wire_tag, "source-code")) return .source_code;
        if (std.mem.eql(u8, wire_tag, "opaque-secret")) return .opaque_secret;
        if (std.mem.eql(u8, wire_tag, "binary-blob")) return .binary_blob;
        return null;
    }

    pub fn tag(self: Profile) []const u8 {
        return switch (self) {
            .gateway_header => "gateway-header",
            .domain_name => "domain-name",
            .dns_label => "dns-label",
            .url => "url",
            .username => "username",
            .display_name => "display-name",
            .chat_message => "chat-message",
            .source_code => "source-code",
            .opaque_secret => "opaque-secret",
            .binary_blob => "binary-blob",
        };
    }
};

pub const PolicyLevel = enum {
    restrictive,
    moderate,
    minimal,
};

pub const Family = enum {
    malformed_utf8,
    malformed_utf16,
    malformed_utf32,
    tag_block_payload,
    variation_selector_payload,
    zero_width_payload,
    surrogate_reassembly,
    bidi_control_balance,
    noncharacter_control,
    homoglyph_confusable,
    mixed_script_admissibility,
    rtl_injection,
    confusable_bidi_compound,
    covert_display_compound,
    emoji_zwj_integrity,
    skin_tone_variation_forgery,
    filename_disguise,
    renderer_divergence,
    stream_safe_violation,
    case_expansion_mismatch,
    identifier_form_drift,
    admissibility_form_drift,
    normalization_bomb,
    locale_case_inversion,
    nfc_idempotence_witness,
    width_class_confusion,
    source_display_divergence,

    pub fn tag(self: Family) []const u8 {
        return switch (self) {
            .malformed_utf8 => "malformed-utf8",
            .malformed_utf16 => "malformed-utf16",
            .malformed_utf32 => "malformed-utf32",
            .tag_block_payload => "tag-block-payload",
            .variation_selector_payload => "variation-selector-payload",
            .zero_width_payload => "zero-width-payload",
            .surrogate_reassembly => "surrogate-reassembly",
            .bidi_control_balance => "bidi-control-balance",
            .noncharacter_control => "noncharacter-control",
            .homoglyph_confusable => "homoglyph-confusable",
            .mixed_script_admissibility => "mixed-script-admissibility",
            .rtl_injection => "rtl-injection",
            .confusable_bidi_compound => "confusable-bidi-compound",
            .covert_display_compound => "covert-display-compound",
            .emoji_zwj_integrity => "emoji-zwj-integrity",
            .skin_tone_variation_forgery => "skin-tone-variation-forgery",
            .filename_disguise => "filename-disguise",
            .renderer_divergence => "renderer-divergence",
            .stream_safe_violation => "stream-safe-violation",
            .case_expansion_mismatch => "case-expansion-mismatch",
            .identifier_form_drift => "identifier-form-drift",
            .admissibility_form_drift => "admissibility-form-drift",
            .normalization_bomb => "normalization-bomb",
            .locale_case_inversion => "locale-case-inversion",
            .nfc_idempotence_witness => "nfc-idempotence-witness",
            .width_class_confusion => "width-class-confusion",
            .source_display_divergence => "source-display-divergence",
        };
    }
};

pub const ProfilePolicy = struct {
    level: PolicyLevel,
    quarantine: bool,
};

pub const Finding = struct {
    code: []const u8,
    family: Family,
    severity: u8,
    positions: [MaxFindingPositions]usize,
    position_count: usize,
    sub_threat: []const u8,
    detail: []const u8,
};

pub const MaxFindings = 24;

/// Positions one finding can localise. The port scans without an allocator, so
/// every buffer is bounded; this bound is `MaxSkeletonLen`, the same working
/// width the normalization and skeleton buffers use. A hazard occupying more
/// positions than this reports the first `MaxFindingPositions` of them, which
/// is the one place the port's verdict is narrower than the reference's
/// unbounded list.
pub const MaxFindingPositions = MaxSkeletonLen;

pub const FindingList = struct {
    items: [MaxFindings]Finding = undefined,
    len: usize = 0,

    pub fn append(self: *FindingList, finding: Finding) void {
        if (self.len >= MaxFindings) return;
        self.items[self.len] = finding;
        self.len += 1;
    }

    pub fn containsCode(self: FindingList, code: []const u8) bool {
        for (self.items[0..self.len]) |finding| {
            if (std.mem.eql(u8, finding.code, code)) return true;
        }
        return false;
    }
};

pub const Verdict = struct {
    input: []const u32,
    profile: Profile,
    mode: Mode,
    action: Action,
    findings: FindingList,
    normalized: ?[]const u32 = null,
};

pub fn writeFindingJson(writer: anytype, finding: Finding) !void {
    try writer.writeAll("{\"code\":");
    try writeJsonString(writer, finding.code);
    try writer.writeAll(",\"family\":");
    try writeJsonString(writer, finding.family.tag());
    try writer.writeAll(",\"severity\":");
    try writer.print("{d}", .{finding.severity});
    try writer.writeAll(",\"positions\":");
    try writeUsizeArray(writer, finding.positions[0..finding.position_count]);
    try writer.writeAll(",\"sub_threat\":");
    try writeJsonString(writer, finding.sub_threat);
    try writer.writeAll(",\"detail\":");
    try writeJsonString(writer, finding.detail);
    try writer.writeByte('}');
}

pub fn writeVerdictJson(writer: anytype, verdict: Verdict) !void {
    try writer.writeAll("{\"action\":");
    try writeJsonString(writer, verdict.action.tag());
    try writer.writeAll(",\"profile\":");
    try writeJsonString(writer, verdict.profile.tag());
    try writer.writeAll(",\"mode\":");
    try writeJsonString(writer, verdict.mode.tag());
    try writer.writeAll(",\"input\":");
    try writeU32Array(writer, verdict.input);
    try writer.writeAll(",\"findings\":[");
    for (verdict.findings.items[0..verdict.findings.len], 0..) |finding, index| {
        if (index > 0) try writer.writeByte(',');
        try writeFindingJson(writer, finding);
    }
    try writer.writeAll("],\"normalized\":");
    if (verdict.normalized) |normalized| {
        try writeU32Array(writer, normalized);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeByte('}');
}

fn writeJsonString(writer: anytype, value: []const u8) !void {
    const hex = "0123456789abcdef";
    try writer.writeByte('"');
    for (value) |byte| {
        switch (byte) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (byte < 0x20) {
                    try writer.writeAll("\\u00");
                    try writer.writeByte(hex[@as(usize, (byte >> 4) & 0x0f)]);
                    try writer.writeByte(hex[@as(usize, byte & 0x0f)]);
                } else {
                    try writer.writeByte(byte);
                }
            },
        }
    }
    try writer.writeByte('"');
}

fn writeU32Array(writer: anytype, values: []const u32) !void {
    try writer.writeByte('[');
    for (values, 0..) |value, index| {
        if (index > 0) try writer.writeByte(',');
        try writer.print("{d}", .{value});
    }
    try writer.writeByte(']');
}

fn writeUsizeArray(writer: anytype, values: []const usize) !void {
    try writer.writeByte('[');
    for (values, 0..) |value, index| {
        if (index > 0) try writer.writeByte(',');
        try writer.print("{d}", .{value});
    }
    try writer.writeByte(']');
}

pub fn policyOfProfile(profile: Profile) ProfilePolicy {
    return switch (profile) {
        .gateway_header, .domain_name, .dns_label => .{
            .level = .restrictive,
            .quarantine = false,
        },
        // Source files legitimately carry right-to-left string literals, comments
        // written in Hebrew or Arabic, and emoji. Restrictive admits RtlInjection,
        // whose contract treats its input as a declared-LTR field, so under it an
        // ordinary Hebrew comment is rejected. Moderate retains every detector that
        // catches the Trojan Source class while dropping the field-direction
        // assumption a source file does not satisfy.
        .url, .source_code => .{ .level = .moderate, .quarantine = false },
        .username => .{ .level = .moderate, .quarantine = true },
        .display_name, .chat_message => .{ .level = .minimal, .quarantine = true },
        .opaque_secret, .binary_blob => .{ .level = .minimal, .quarantine = false },
    };
}

// True iff the profile names a field that holds one identifier rather than
// running text.
//
// A username, a registrable domain and a DNS label are single identifiers, so a
// codepoint outside the General Security Profile is a hazard in them. The
// remaining profiles carry prose, source, URLs or opaque bytes, where a space
// and a punctuation mark are ordinary content. Mirrors profileIsIdentifierField
// in Unicode/Security/Policy.lean.
pub fn profileIsIdentifierField(profile: Profile) bool {
    return switch (profile) {
        .domain_name, .dns_label, .username => true,
        .gateway_header, .url, .display_name, .chat_message, .source_code, .opaque_secret, .binary_blob => false,
    };
}

pub fn scan(profile: Profile, mode: Mode, input: []const u32) Verdict {
    const findings = detect(input, profileIsIdentifierField(profile));
    const action = decide(profile, mode, findings);
    return .{
        .input = input,
        .profile = profile,
        .mode = mode,
        .action = action,
        .findings = findings,
    };
}

pub fn scanUtf8(profile: Profile, mode: Mode, bytes: []const u8, decoded_buffer: []u32) Verdict {
    if (firstInvalidUtf8Offset(bytes)) |invalid| {
        var findings = FindingList{};
        var positions: [MaxFindingPositions]usize = undefined;
        positions[0] = invalid.offset;
        findings.append(.{
            .code = malformedUtf8ReasonCode(invalid.kind),
            .family = .malformed_utf8,
            .severity = 2,
            .positions = positions,
            .position_count = 1,
            .sub_threat = utf8RejectTag(invalid.kind),
            .detail = "malformed-utf8",
        });
        return .{
            .input = decoded_buffer[0..0],
            .profile = profile,
            .mode = mode,
            .action = decide(profile, mode, findings),
            .findings = findings,
        };
    }

    const decoded_len = decodeUtf8ToCodepoints(bytes, decoded_buffer);
    return scan(profile, mode, decoded_buffer[0..decoded_len]);
}

pub fn scanUtf16Be(profile: Profile, mode: Mode, bytes: []const u8, decoded_buffer: []u32) Verdict {
    return scanUtf16(profile, mode, bytes, decoded_buffer, .big);
}

pub fn scanUtf16Le(profile: Profile, mode: Mode, bytes: []const u8, decoded_buffer: []u32) Verdict {
    return scanUtf16(profile, mode, bytes, decoded_buffer, .little);
}

pub fn scanUtf32Be(profile: Profile, mode: Mode, bytes: []const u8, decoded_buffer: []u32) Verdict {
    return scanUtf32(profile, mode, bytes, decoded_buffer, .big);
}

pub fn scanUtf32Le(profile: Profile, mode: Mode, bytes: []const u8, decoded_buffer: []u32) Verdict {
    return scanUtf32(profile, mode, bytes, decoded_buffer, .little);
}

fn scanUtf16(profile: Profile, mode: Mode, bytes: []const u8, decoded_buffer: []u32, endian: Endian) Verdict {
    const result = decodeUtf16ToCodepoints(bytes, decoded_buffer, endian);
    if (result.failure) |failure| {
        return malformedDecodeVerdict(
            profile,
            mode,
            .malformed_utf16,
            malformedUtf16ReasonCode(failure.sub_threat),
            failure.sub_threat,
            "malformed-utf16",
            failure.offset,
            decoded_buffer,
        );
    }
    return scan(profile, mode, decoded_buffer[0..result.len]);
}

fn scanUtf32(profile: Profile, mode: Mode, bytes: []const u8, decoded_buffer: []u32, endian: Endian) Verdict {
    const result = decodeUtf32ToCodepoints(bytes, decoded_buffer, endian);
    if (result.failure) |failure| {
        return malformedDecodeVerdict(
            profile,
            mode,
            .malformed_utf32,
            malformedUtf32ReasonCode(failure.sub_threat),
            failure.sub_threat,
            "malformed-utf32",
            failure.offset,
            decoded_buffer,
        );
    }
    return scan(profile, mode, decoded_buffer[0..result.len]);
}

// Build a finding from any detector classification. Every one of them is a
// tagged union exposing isClear, tag and reasonCode, and carries the implicated
// positions on its hazard arm, so the copy into the finding's fixed array is
// written once here.
fn classifiedFinding(family: Family, classification: anytype) ?Finding {
    if (classification.isClear()) return null;
    var positions: [MaxFindingPositions]usize = undefined;
    var count: usize = 0;
    switch (classification) {
        .clear => {},
        .hazard => |hazard| {
            // Hazard payloads differ across these modules: most carry the
            // implicated positions as a plain array or as a bounded PosBuffer,
            // while source-display-divergence carries only the sub-threat,
            // because it judges the input as a unit and localises nothing.
            const Hazard = @TypeOf(hazard);
            if (@typeInfo(Hazard) == .@"struct" and @hasField(Hazard, "positions")) {
                const carried = hazard.positions;
                const slice = if (@typeInfo(@TypeOf(carried)) == .@"struct")
                    carried.items[0..carried.len]
                else
                    carried[0..];
                for (slice) |position| {
                    if (count < positions.len) {
                        positions[count] = position;
                        count += 1;
                    }
                }
            }
        },
    }
    return Finding{
        .code = classification.reasonCode().?,
        .family = family,
        .severity = 2,
        .positions = positions,
        .position_count = count,
        .sub_threat = classification.tag().?,
        .detail = family.tag(),
    };
}

// Reason code for the four form detectors that report a sub-threat string
// rather than a classification carrying its own code. Every sub-threat each of
// them can produce is enumerated: the codes are static strings, and this port
// has no allocator to build one at run time.
fn resultReasonCode(family: Family, sub_threat: []const u8) []const u8 {
    switch (family) {
        .normalization_bomb => {
            if (std.mem.eql(u8, sub_threat, "NfdHighExpansion")) return "unicode.security.F.normalization-bomb.NfdHighExpansion";
            if (std.mem.eql(u8, sub_threat, "NfkdHighExpansion")) return "unicode.security.F.normalization-bomb.NfkdHighExpansion";
            if (std.mem.eql(u8, sub_threat, "SingleCpBlowup")) return "unicode.security.F.normalization-bomb.SingleCpBlowup";
            unreachable;
        },
        .locale_case_inversion => {
            if (std.mem.eql(u8, sub_threat, "LithuanianCaseDivergence")) return "unicode.security.F.locale-case-inversion.LithuanianCaseDivergence";
            if (std.mem.eql(u8, sub_threat, "TurkishCaseDivergence")) return "unicode.security.F.locale-case-inversion.TurkishCaseDivergence";
            unreachable;
        },
        .nfc_idempotence_witness => {
            if (std.mem.eql(u8, sub_threat, "NonNfcForm")) return "unicode.security.F.nfc-idempotence-witness.NonNfcForm";
            if (std.mem.eql(u8, sub_threat, "NonNfkcCompatForm")) return "unicode.security.F.nfc-idempotence-witness.NonNfkcCompatForm";
            unreachable;
        },
        .width_class_confusion => {
            if (std.mem.eql(u8, sub_threat, "FullwidthFold")) return "unicode.security.F.width-class-confusion.FullwidthFold";
            if (std.mem.eql(u8, sub_threat, "HalfwidthFold")) return "unicode.security.F.width-class-confusion.HalfwidthFold";
            unreachable;
        },
        else => unreachable,
    }
}

// Build a finding from the four form detectors that return a result record
// rather than a classification union.
fn resultFinding(family: Family, result: anytype) ?Finding {
    const sub = result.sub_threat orelse return null;
    var positions: [MaxFindingPositions]usize = undefined;
    var count: usize = 0;
    while (count < result.position_count and count < positions.len) : (count += 1) {
        positions[count] = result.positions[count];
    }
    return Finding{
        .code = resultReasonCode(family, sub),
        .family = family,
        .severity = 2,
        .positions = positions,
        .position_count = count,
        .sub_threat = sub,
        .detail = family.tag(),
    };
}

// detect runs every family over input. identifier_field carries what the caller
// knows about the field, mirroring Unicode.Security.RunAll's Context: a family
// scoped to identifiers needs to know whether it is holding one.
fn detect(input: []const u32, identifier_field: bool) FindingList {
    var findings = FindingList{};

    if (positionsWhere(input, isTagBlockAsciiPayload)) |positions| {
        findings.append(.{
            .code = "unicode.security.C.tag-block-payload.DirectAscii",
            .family = .tag_block_payload,
            .severity = 2,
            .positions = positions.items,
            .position_count = positions.len,
            .sub_threat = "DirectAscii",
            .detail = "tag-block-payload",
        });
    }

    if (variationSelectorFinding(input)) |finding| {
        findings.append(finding);
    }

    // The sanctioning model: a ZWJ inside a registered emoji sequence and a
    // ZWNJ in an RFC 5892 CONTEXTJ-valid position both carry meaning a reader
    // depends on, so they are recorded as present but not treated as
    // suspicious. An input whose zero-width characters are all sanctioned
    // raises nothing.
    if (if (hasSuspiciousZeroWidth(input)) positionsWhere(input, isZeroWidthPayload) else null) |positions| {
        const zw_sub = zeroWidthSubThreat(input);
        findings.append(.{
            .code = zeroWidthReasonCode(zw_sub),
            .family = .zero_width_payload,
            .severity = 2,
            .positions = positions.items,
            .position_count = positions.len,
            .sub_threat = zw_sub,
            .detail = "zero-width-payload",
        });
    }

    if (surrogateReassemblyFinding(input)) |finding| {
        findings.append(finding);
    }

    if (positionsWhere(input, isBidiEmbeddingControl)) |positions| {
        findings.append(.{
            .code = "unicode.security.C.bidi-control-balance.UnbalancedEmbedding",
            .family = .bidi_control_balance,
            .severity = 2,
            .positions = positions.items,
            .position_count = positions.len,
            .sub_threat = "UnbalancedEmbedding",
            .detail = "bidi-control-balance",
        });
    }

    appendNoncharacterControlFindings(&findings, input);
    if (homoglyphConfusableFinding(input)) |finding| {
        findings.append(finding);
    }
    if (mixedScriptAdmissibilityFinding(input, identifier_field)) |finding| {
        findings.append(finding);
    }
    if (rtlInjectionFinding(input)) |finding| {
        findings.append(finding);
    }
    if (confusableBidiCompoundFinding(input)) |finding| {
        findings.append(finding);
    }
    if (covertDisplayCompoundFinding(input)) |finding| {
        findings.append(finding);
    }

    if (classifiedFinding(.emoji_zwj_integrity, emoji_zwj_integrity.detect(input).classify)) |finding| {
        findings.append(finding);
    }
    if (classifiedFinding(.skin_tone_variation_forgery, skin_tone_variation_forgery.detect(input).classify)) |finding| {
        findings.append(finding);
    }
    if (classifiedFinding(.filename_disguise, filename_disguise.detect(input).classify)) |finding| {
        findings.append(finding);
    }
    if (classifiedFinding(.renderer_divergence, renderer_divergence.detect(input).classify)) |finding| {
        findings.append(finding);
    }
    if (classifiedFinding(.stream_safe_violation, stream_safe_violation.detect(input).classify)) |finding| {
        findings.append(finding);
    }
    if (classifiedFinding(.case_expansion_mismatch, case_expansion_mismatch.detect(input).classify)) |finding| {
        findings.append(finding);
    }
    if (classifiedFinding(.identifier_form_drift, identifier_form_drift.detect(input).classify)) |finding| {
        findings.append(finding);
    }
    if (classifiedFinding(.admissibility_form_drift, admissibility_form_drift.detect(input).classify)) |finding| {
        findings.append(finding);
    }
    if (resultFinding(.normalization_bomb, normalizationBombDetect(input))) |finding| {
        findings.append(finding);
    }
    if (resultFinding(.locale_case_inversion, localeCaseInversionDetect(input))) |finding| {
        findings.append(finding);
    }
    if (resultFinding(.nfc_idempotence_witness, nfcIdempotenceWitnessDetect(input))) |finding| {
        findings.append(finding);
    }
    if (resultFinding(.width_class_confusion, widthClassConfusionDetect(input))) |finding| {
        findings.append(finding);
    }
    // SourceDisplayDivergence judges the input as a unit, so it localises
    // nothing and carries an empty position list.
    if (classifiedFinding(.source_display_divergence, source_display_divergence.detect(input).classify)) |finding| {
        findings.append(finding);
    }

    return findings;
}

fn decide(profile: Profile, mode: Mode, findings: FindingList) Action {
    if (findings.len == 0) return .allow;
    if (mode == .observe or mode == .warn) return .observe;
    if (mode == .strict) return .reject;

    const policy = policyOfProfile(profile);
    for (findings.items[0..findings.len]) |finding| {
        if (blocks(policy.level, finding.family)) {
            if (policy.quarantine) return .quarantine;
            return .reject;
        }
    }
    return .allow;
}

fn blocks(level: PolicyLevel, family: Family) bool {
    return switch (level) {
        .restrictive => switch (family) {
            .malformed_utf8, .malformed_utf16, .malformed_utf32, .tag_block_payload, .variation_selector_payload, .zero_width_payload, .surrogate_reassembly, .bidi_control_balance, .noncharacter_control, .homoglyph_confusable, .mixed_script_admissibility, .emoji_zwj_integrity, .skin_tone_variation_forgery, .source_display_divergence, .filename_disguise, .rtl_injection, .renderer_divergence, .normalization_bomb, .stream_safe_violation, .locale_case_inversion, .case_expansion_mismatch, .width_class_confusion, .nfc_idempotence_witness, .identifier_form_drift, .covert_display_compound, .confusable_bidi_compound, .admissibility_form_drift => true,
        },
        .moderate => switch (family) {
            .malformed_utf8, .malformed_utf16, .malformed_utf32, .tag_block_payload, .variation_selector_payload, .zero_width_payload, .surrogate_reassembly, .bidi_control_balance, .noncharacter_control, .homoglyph_confusable, .mixed_script_admissibility, .skin_tone_variation_forgery, .source_display_divergence, .filename_disguise, .stream_safe_violation, .locale_case_inversion, .case_expansion_mismatch, .width_class_confusion, .nfc_idempotence_witness, .identifier_form_drift, .covert_display_compound, .confusable_bidi_compound, .admissibility_form_drift => true,
            .emoji_zwj_integrity, .rtl_injection, .renderer_divergence, .normalization_bomb => false,
        },
        .minimal => switch (family) {
            .malformed_utf8, .malformed_utf16, .malformed_utf32, .surrogate_reassembly, .bidi_control_balance, .noncharacter_control, .stream_safe_violation => true,
            .tag_block_payload, .variation_selector_payload, .zero_width_payload, .homoglyph_confusable, .mixed_script_admissibility, .emoji_zwj_integrity, .skin_tone_variation_forgery, .source_display_divergence, .filename_disguise, .rtl_injection, .renderer_divergence, .normalization_bomb, .locale_case_inversion, .case_expansion_mismatch, .width_class_confusion, .nfc_idempotence_witness, .identifier_form_drift, .covert_display_compound, .confusable_bidi_compound, .admissibility_form_drift => false,
        },
    };
}

const Positions = struct {
    items: [MaxFindingPositions]usize,
    len: usize,
};

fn positionsWhere(input: []const u32, comptime pred: fn (u32) bool) ?Positions {
    var positions = Positions{ .items = undefined, .len = 0 };
    for (input, 0..) |cp, index| {
        if (pred(cp) and positions.len < positions.items.len) {
            positions.items[positions.len] = index;
            positions.len += 1;
        }
    }
    if (positions.len == 0) return null;
    return positions;
}

fn isTagBlockAsciiPayload(cp: u32) bool {
    return cp >= 0xE0020 and cp <= 0xE007E;
}

fn variationSelectorFinding(input: []const u32) ?Finding {
    const positions = positionsWhere(input, isVariationSelector) orelse return null;
    if (positions.len == 1 and isRegisteredVariationPosition(input, positions.items[0])) return null;
    const sub_threat = variationSelectorSubThreat(input, positions);
    return .{
        .code = variationSelectorReasonCode(sub_threat),
        .family = .variation_selector_payload,
        .severity = 2,
        .positions = positions.items,
        .position_count = positions.len,
        .sub_threat = sub_threat,
        .detail = "variation-selector-payload",
    };
}

fn variationSelectorSubThreat(input: []const u32, positions: Positions) []const u8 {
    if (positions.len >= 4 and allSameAt(input, positions)) return "RepeatedBase";
    if (decodeVariationSelectorRun(input, positions) > 0) return "DirectPayload";
    return "IllegalTarget";
}

fn isVariationSelector(cp: u32) bool {
    return (cp >= 0xFE00 and cp <= 0xFE0F) or
        (cp >= 0xE0100 and cp <= 0xE01EF) or
        (cp >= 0x180B and cp <= 0x180D);
}

fn isRegisteredVariationPosition(input: []const u32, position: usize) bool {
    return position > 0 and isRegisteredVariationPair(input[position - 1], input[position]);
}

fn isRegisteredVariationPair(base: u32, vs: u32) bool {
    return legalVariationSourceContains(standardized_variants_raw, base, vs) or
        legalVariationSourceContains(emoji_variation_sequences_raw, base, vs);
}

fn legalVariationSourceContains(raw: []const u8, base: u32, vs: u32) bool {
    var offset: usize = 0;
    while (nextLine(raw, &offset)) |raw_line| {
        const comment_end = std.mem.indexOfScalar(u8, raw_line, '#') orelse raw_line.len;
        const body = raw_line[0..comment_end];
        const pair_end = std.mem.indexOfScalar(u8, body, ';') orelse body.len;
        const pair_part = trimAscii(body[0..pair_end]);
        if (pair_part.len == 0) continue;

        var fields = std.mem.tokenizeAny(u8, pair_part, " \t\r\n");
        const base_token = fields.next() orelse continue;
        const vs_token = fields.next() orelse continue;
        if (fields.next() != null) continue;

        const parsed_base = parseHexU32(base_token) orelse continue;
        const parsed_vs = parseHexU32(vs_token) orelse continue;
        if (parsed_base == base and parsed_vs == vs) return true;
    }
    return false;
}

fn parseHexU32(field: []const u8) ?u32 {
    return std.fmt.parseInt(u32, field, 16) catch null;
}

fn variationSelectorNibble(cp: u32) ?u32 {
    if (cp >= 0xFE00 and cp <= 0xFE0F) return cp - 0xFE00;
    if (cp >= 0xE0100 and cp <= 0xE01EF) return cp - 0xE0100 + 16;
    return null;
}

fn decodeVariationSelectorRun(input: []const u32, positions: Positions) usize {
    var decoded_count: usize = 0;
    var have_high = false;
    for (positions.items[0..positions.len]) |position| {
        if (variationSelectorNibble(input[position]) == null) continue;
        if (!have_high) {
            have_high = true;
            continue;
        }
        decoded_count += 1;
        have_high = false;
    }
    return decoded_count;
}

fn allSameAt(input: []const u32, positions: Positions) bool {
    if (positions.len == 0) return true;
    const first = input[positions.items[0]];
    for (positions.items[0..positions.len]) |position| {
        if (input[position] != first) return false;
    }
    return true;
}

fn variationSelectorReasonCode(sub_threat: []const u8) []const u8 {
    if (std.mem.eql(u8, sub_threat, "DirectPayload")) {
        return "unicode.security.C.variation-selector-payload.DirectPayload";
    }
    if (std.mem.eql(u8, sub_threat, "RepeatedBase")) {
        return "unicode.security.C.variation-selector-payload.RepeatedBase";
    }
    return "unicode.security.C.variation-selector-payload.IllegalTarget";
}

// True iff cp renders as nothing, mirroring `isZeroWidth` in
// Unicode.Security.Covert.ZeroWidthPayload: the explicit historical set, which
// preserves sub-threat dispatch, extended by the UAX #44
// Default_Ignorable_Code_Point property, which catches every other invisible
// codepoint.
//
// The sibling ranges are excluded because their own family detector dispatches
// them with richer payload decoding or bidi-stack tracking, and counting them
// here as well would report one hazard twice. LRM and RLM are not excluded:
// they are direction markers rather than push-pop controls, and
// bidi-control-balance does not track them.
fn isZeroWidthPayload(cp: u32) bool {
    if (cp >= 0x200B and cp <= 0x200F) return true;
    if (cp >= 0x2060 and cp <= 0x2064) return true;
    if (cp == 0x202F or cp == 0xFEFF) return true;
    if (cp >= 0xFFF9 and cp <= 0xFFFB) return true;
    return isDefaultIgnorableCodepoint(cp) and !isZeroWidthSiblingHandled(cp);
}

// True iff cp is Default_Ignorable but belongs to a sibling detector's family
// rather than to zero-width-payload.
fn isZeroWidthSiblingHandled(cp: u32) bool {
    if (cp >= 0xFE00 and cp <= 0xFE0F) return true;
    if (cp >= 0xE0100 and cp <= 0xE01EF) return true;
    if (cp >= 0xE0000 and cp <= 0xE007F) return true;
    if (cp >= 0x202A and cp <= 0x202E) return true;
    if (cp >= 0x2066 and cp <= 0x2069) return true;
    return false;
}

// Which zero-width hazard the input carries, in the dispatch order of
// Unicode.Security.Covert.ZeroWidthPayload: an annotation outranks a word
// joiner, which outranks a narrow no-break space run, which outranks a binary
// payload, and a bare occurrence is the fallback once no richer class fits.
fn zeroWidthSubThreat(input: []const u32) []const u8 {
    var annotation: usize = 0;
    var word_joiner: usize = 0;
    var nnbsp: usize = 0;
    var zwj_zwsp: usize = 0;
    for (input) |cp| {
        if (!isZeroWidthPayload(cp)) continue;
        if (cp >= 0xFFF9 and cp <= 0xFFFB) {
            annotation += 1;
        } else if (cp == 0x2060) {
            word_joiner += 1;
        } else if (cp == 0x202F) {
            nnbsp += 1;
        } else if (cp == 0x200B or cp == 0x200D) {
            zwj_zwsp += 1;
        }
    }
    if (annotation > 0) return "AnnotationMisuse";
    if (word_joiner > 0) return "WordJoinerInjection";
    if (nnbsp >= 2) return "AiWatermarkNNBSP";
    if (zwj_zwsp >= 2) return "BinaryPayload";
    return "BareZeroWidth";
}

// The reason code naming one zero-width sub-threat. The codes are spelled out
// rather than concatenated so each one is a comptime string, matching how every
// other family in this port names its codes.
fn zeroWidthReasonCode(sub_threat: []const u8) []const u8 {
    if (std.mem.eql(u8, sub_threat, "AnnotationMisuse"))
        return "unicode.security.C.zero-width-payload.AnnotationMisuse";
    if (std.mem.eql(u8, sub_threat, "WordJoinerInjection"))
        return "unicode.security.C.zero-width-payload.WordJoinerInjection";
    if (std.mem.eql(u8, sub_threat, "AiWatermarkNNBSP"))
        return "unicode.security.C.zero-width-payload.AiWatermarkNNBSP";
    if (std.mem.eql(u8, sub_threat, "BinaryPayload"))
        return "unicode.security.C.zero-width-payload.BinaryPayload";
    return "unicode.security.C.zero-width-payload.BareZeroWidth";
}

fn isBidiEmbeddingControl(cp: u32) bool {
    return cp >= 0x202A and cp <= 0x202E;
}

fn appendNoncharacterControlFindings(findings: *FindingList, input: []const u32) void {
    if (positionsWhere(input, isNoncharacter)) |positions| {
        findings.append(.{
            .code = "unicode.security.C.noncharacter-control.Noncharacter",
            .family = .noncharacter_control,
            .severity = 2,
            .positions = positions.items,
            .position_count = positions.len,
            .sub_threat = "Noncharacter",
            .detail = "noncharacter-control",
        });
    }

    if (positionsWhere(input, isC0Control)) |positions| {
        findings.append(.{
            .code = "unicode.security.C.noncharacter-control.C0Control",
            .family = .noncharacter_control,
            .severity = 2,
            .positions = positions.items,
            .position_count = positions.len,
            .sub_threat = "C0Control",
            .detail = "noncharacter-control",
        });
    }

    if (positionsWhere(input, isC1Control)) |positions| {
        findings.append(.{
            .code = "unicode.security.C.noncharacter-control.C1Control",
            .family = .noncharacter_control,
            .severity = 2,
            .positions = positions.items,
            .position_count = positions.len,
            .sub_threat = "C1Control",
            .detail = "noncharacter-control",
        });
    }
}

fn homoglyphConfusableFinding(input: []const u32) ?Finding {
    var sub_threat: ?[]const u8 = null;
    if (homoglyphTargetMatch(input) != null) {
        sub_threat = "TargetMatch";
    } else {
        for (input) |cp| {
            if (isMathAlphanumeric(cp)) {
                sub_threat = "MathAlpha";
                break;
            }
        }
        if (sub_threat == null) {
            for (input) |cp| {
                if (isFullwidthHalfwidth(cp)) {
                    sub_threat = "WidthClass";
                    break;
                }
            }
        }
    }
    if (sub_threat == null and hasDecompositionSwap(input)) {
        sub_threat = "DecompositionSwap";
    }
    // The last two rungs of the Lean ladder, in its order: a cross-script mix
    // that is not Highly Restrictive, then a string failing every restriction
    // level. Both need real script resolution.
    if (sub_threat == null and hasCrossScriptMix(input)) {
        sub_threat = "CrossScriptMix";
    }
    if (sub_threat == null) {
        const level = restrictionLevel(input);
        if (level == .minimally_restrictive or level == .unrestricted) {
            sub_threat = "RestrictionLow";
        }
    }
    const threat = sub_threat orelse return null;
    const positions = fullSpanPositions(input);
    return .{
        .code = homoglyphConfusableReasonCode(threat),
        .family = .homoglyph_confusable,
        .severity = 2,
        .positions = positions.items,
        .position_count = positions.len,
        .sub_threat = threat,
        .detail = "homoglyph-confusable",
    };
}

// The mixed-script sub-threat for input, or null when it is admissible.
//
// The rung order is Unicode/Security/Identity/MixedScriptAdmissibility.lean's:
// a Restricted-status codepoint outranks every script question, then the two
// named Latin pairs, then a multi-script mix split by whether it stays inside a
// CJK covered set, and finally an Unrestricted level with no script mix.
//
// identifier_field carries what the caller knows about the field, mirroring
// that module's Context. Phase 1 is sound for an identifier, which cannot
// contain a space, and unsound for a document, where every space and every
// punctuation mark is Restricted.
fn mixedScriptVerdict(input: []const u32, identifier_field: bool) ?[]const u8 {
    if (identifier_field) {
        for (input) |cp| {
            if (!isIdAllowed(cp)) return "RestrictedStatusCp";
        }
    }
    const union_set = stringScriptUnion(input);
    const has_latin = union_set.contains("Latn");
    if (has_latin and union_set.contains("Cyrl")) return "LatinCyrillic";
    if (has_latin and union_set.contains("Grek")) return "LatinGreek";
    if (union_set.len >= 2 and !isHighlyRestrictive(input)) {
        return if (isCoveredCjk(input)) "CjkMix" else "ScriptMixOther";
    }
    if (identifier_field and restrictionLevel(input) == .unrestricted) return "UnrestrictedLevel";
    return null;
}

fn mixedScriptSubthreat(input: []const u32) []const u8 {
    return mixedScriptVerdict(input, true) orelse "ScriptMixOther";
}

fn mixedScriptAdmissibilityFinding(input: []const u32, identifier_field: bool) ?Finding {
    const sub = mixedScriptVerdict(input, identifier_field) orelse return null;
    const positions = fullSpanPositions(input);
    const code = if (std.mem.eql(u8, sub, "LatinCyrillic"))
        "unicode.security.I.mixed-script-admissibility.LatinCyrillic"
    else if (std.mem.eql(u8, sub, "LatinGreek"))
        "unicode.security.I.mixed-script-admissibility.LatinGreek"
    else if (std.mem.eql(u8, sub, "RestrictedStatusCp"))
        "unicode.security.I.mixed-script-admissibility.RestrictedStatusCp"
    else if (std.mem.eql(u8, sub, "CjkMix"))
        "unicode.security.I.mixed-script-admissibility.CjkMix"
    else if (std.mem.eql(u8, sub, "UnrestrictedLevel"))
        "unicode.security.I.mixed-script-admissibility.UnrestrictedLevel"
    else
        "unicode.security.I.mixed-script-admissibility.ScriptMixOther";
    return .{
        .code = code,
        .family = .mixed_script_admissibility,
        .severity = 2,
        .positions = positions.items,
        .position_count = positions.len,
        .sub_threat = sub,
        .detail = "mixed-script-admissibility",
    };
}

// -- rtl-injection ---------------------------------------------------------
//
// Direct port of ports/rust/src/security/display/rtl_injection.rs, itself a
// port of Unicode/Security/Display/RtlInjection.lean. Strong directionality
// reads Bidi_Class from bidi_class_data.zig, mirroring the spec's lookup:
// the explicit ranges (binary search) take priority, then the @missing
// defaults where the last covering range wins, then Left_To_Right.

fn bidiStrong(cp: u32) bidi_class_data.Strong {
    const explicit = bidi_class_data.explicit;
    var low: usize = 0;
    var high: usize = explicit.len;
    while (low < high) {
        const mid = low + (high - low) / 2;
        const range = explicit[mid];
        if (cp < range.start) {
            high = mid;
        } else if (cp > range.end) {
            low = mid + 1;
        } else {
            return range.class;
        }
    }
    var result: ?bidi_class_data.Strong = null;
    for (bidi_class_data.defaults) |range| {
        if (cp >= range.start and cp <= range.end) result = range.class;
    }
    return result orelse .l;
}

// ── East_Asian_Width: UAX #11 width class ────────────────────────────────────
// Mirrors Unicode.Generated.EastAsianWidth.lookup. Unlike bidiStrong there is
// no default table to scan: the source file's @missing line declares N over the
// whole codepoint space, so a binary-search miss is .n by declaration.

fn eastAsianWidth(cp: u32) east_asian_width_data.Width {
    const explicit = east_asian_width_data.explicit;
    var low: usize = 0;
    var high: usize = explicit.len;
    while (low < high) {
        const mid = low + (high - low) / 2;
        const range = explicit[mid];
        if (cp < range.start) {
            high = mid;
        } else if (cp > range.end) {
            low = mid + 1;
        } else {
            return range.class;
        }
    }
    return .n;
}

fn isStrongRtl(cp: u32) bool {
    const class = bidiStrong(cp);
    return class == .r or class == .al;
}

fn isStrongLtr(cp: u32) bool {
    return bidiStrong(cp) == .l;
}

fn isBidiFormatControl(cp: u32) bool {
    return (cp >= 0x202A and cp <= 0x202E) or (cp >= 0x2066 and cp <= 0x2069);
}

const RtlRun = struct {
    len: usize,
    start: usize,
};

// Length and starting position of the longest consecutive run of strong-RTL
// codepoints; {0, 0} when there are none.
fn longestRtlRun(input: []const u32) RtlRun {
    var longest: usize = 0;
    var longest_start: usize = 0;
    var current: usize = 0;
    var current_start: usize = 0;
    for (input, 0..) |cp, index| {
        if (isStrongRtl(cp)) {
            const new_start = if (current == 0) index else current_start;
            current += 1;
            current_start = new_start;
            if (current > longest) {
                longest = current;
                longest_start = new_start;
            }
        } else {
            current = 0;
        }
    }
    return .{ .len = longest, .start = longest_start };
}

fn rtlInjectionReasonCode(sub_threat: []const u8) []const u8 {
    if (std.mem.eql(u8, sub_threat, "BidiControlInLTRField")) {
        return "unicode.security.D.rtl-injection.BidiControlInLTRField";
    }
    if (std.mem.eql(u8, sub_threat, "FieldTakeover")) {
        return "unicode.security.D.rtl-injection.FieldTakeover";
    }
    if (std.mem.eql(u8, sub_threat, "MixedOverflow")) {
        return "unicode.security.D.rtl-injection.MixedOverflow";
    }
    return "unicode.security.D.rtl-injection.StrongRTLInLTR";
}

fn rtlInjectionAt(sub_threat: []const u8, position: usize) Finding {
    var positions: [MaxFindingPositions]usize = undefined;
    positions[0] = position;
    return .{
        .code = rtlInjectionReasonCode(sub_threat),
        .family = .rtl_injection,
        .severity = 2,
        .positions = positions,
        .position_count = 1,
        .sub_threat = sub_threat,
        .detail = "rtl-injection",
    };
}

const FirstStrong = struct {
    index: usize,
    rtl: bool,
};

// The declared display direction of the field holding an input. A caller
// handling Hebrew, Arabic or Persian UI text declares its field right-to-left;
// every other reading treats the input as a declared-LTR string, under which
// right-to-left content is itself the hazard.
//
// Mirrors FieldDirection in Unicode/Security/Display/RtlInjection.lean, that
// spec's alias for the UAX #9 paragraph-direction vocabulary.
pub const FieldDirection = enum { ltr, rtl };

// Detect right-to-left injection in a field whose declared display direction is
// `direction`.
//
// A bidi format control reorders what a reviewer sees whichever way the field
// runs, so Phase 1 holds unconditionally and trumps all.
//
// Phases 2 and 3 ask whether right-to-left text has taken over or been spliced
// into a left-to-right field. That question has no premise in a right-to-left
// field, where right-to-left text is the content. The mirror-image hazard,
// strong-LTR injection into a right-to-left field, belongs to the separate
// detector the scope note assigns it to.
//
// Within a left-to-right field: (1) any bidi format-control anywhere fires
// BidiControlInLTRField; otherwise (2) a leading strong-RTL codepoint fires
// FieldTakeover; otherwise (3) mid-stream strong-RTL is classified by run
// length (>= 4 is MixedOverflow, shorter is StrongRTLInLTR).
fn rtlInjectionFindingWithContext(direction: FieldDirection, input: []const u32) ?Finding {
    // Phase 1: bidi format-control trumps all, in either direction.
    for (input, 0..) |cp, index| {
        if (isBidiFormatControl(cp)) return rtlInjectionAt("BidiControlInLTRField", index);
    }

    // A right-to-left field carrying right-to-left text carries its content.
    if (direction == .rtl) return null;

    var first_strong: ?FirstStrong = null;
    for (input, 0..) |cp, index| {
        if (isStrongRtl(cp)) {
            first_strong = .{ .index = index, .rtl = true };
            break;
        } else if (isStrongLtr(cp)) {
            first_strong = .{ .index = index, .rtl = false };
            break;
        }
    }
    if (first_strong) |strong| {
        if (strong.rtl) return rtlInjectionAt("FieldTakeover", strong.index);
    }

    var first_rtl: ?usize = null;
    for (input, 0..) |cp, index| {
        if (isStrongRtl(cp)) {
            first_rtl = index;
            break;
        }
    }
    const rtl_index = first_rtl orelse return null;
    const run = longestRtlRun(input);
    if (run.len >= 4) return rtlInjectionAt("MixedOverflow", run.start);
    return rtlInjectionAt("StrongRTLInLTR", rtl_index);
}

// Detect right-to-left injection in a field declared left-to-right, the reading
// the module scope note fixes for an undeclared field.
fn rtlInjectionFinding(input: []const u32) ?Finding {
    return rtlInjectionFindingWithContext(.ltr, input);
}

// -- confusable-bidi-compound ----------------------------------------------
//
// Direct port of ports/rust/src/security/boundary/confusable_bidi_compound.rs,
// itself a port of Unicode/Security/Boundary/ConfusableBidiCompound.lean. A
// confusable (homoglyph) codepoint co-located with a bidi format control is
// materially more dangerous than either alone: the homoglyph disguises an
// identifier while the bidi control reorders how a reviewer reads it. The
// finding fires only when both are present. The confusable-source predicate
// reads the same confusables table the homoglyph detector uses; the bidi
// predicates split the format-controls into the override class
// (LRE/RLE/LRO/RLO/PDF, 0x202A..0x202E) and the isolate class
// (LRI/RLI/FSI/PDI, 0x2066..0x2069).

// True iff cp is a confusable source per UTS #39 §4 — i.e. it has a row in
// confusables.txt mapping it to a different skeleton sequence. Reuses the
// generated, source-sorted confusables table via binary search.
fn isConfusableSource(cp: u32) bool {
    var lo: usize = 0;
    var hi: usize = confusables_data.entries.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const entry = confusables_data.entries[mid];
        if (cp < entry.src) {
            hi = mid;
        } else if (cp > entry.src) {
            lo = mid + 1;
        } else {
            return true;
        }
    }
    return false;
}

// True iff cp is an isolate-class bidi control (LRI, RLI, FSI, PDI).
fn isBidiIsolateControl(cp: u32) bool {
    return cp >= 0x2066 and cp <= 0x2069;
}

fn firstPositionWhere(input: []const u32, comptime pred: fn (u32) bool) ?usize {
    for (input, 0..) |cp, index| {
        if (pred(cp)) return index;
    }
    return null;
}

fn confusableBidiCompoundReasonCode(sub_threat: []const u8) []const u8 {
    if (std.mem.eql(u8, sub_threat, "ConfusableInOverride")) {
        return "unicode.security.X.confusable-bidi-compound.ConfusableInOverride";
    }
    return "unicode.security.X.confusable-bidi-compound.ConfusableInIsolate";
}

fn confusableBidiCompoundAt(sub_threat: []const u8, confusable_pos: usize, bidi_pos: usize) Finding {
    var positions: [MaxFindingPositions]usize = undefined;
    positions[0] = confusable_pos;
    positions[1] = bidi_pos;
    return .{
        .code = confusableBidiCompoundReasonCode(sub_threat),
        .family = .confusable_bidi_compound,
        .severity = 2,
        .positions = positions,
        .position_count = 2,
        .sub_threat = sub_threat,
        .detail = "confusable-bidi-compound",
    };
}

// Detect a confusable codepoint sharing the input with a bidi control. Priority
// mirrors the spec: with a confusable present, an override-class control fires
// ConfusableInOverride; otherwise an isolate-class control fires
// ConfusableInIsolate; otherwise clear.
fn confusableBidiCompoundFinding(input: []const u32) ?Finding {
    const confusable_pos = firstPositionWhere(input, isConfusableSource) orelse return null;
    if (firstPositionWhere(input, isBidiEmbeddingControl)) |bidi_pos| {
        return confusableBidiCompoundAt("ConfusableInOverride", confusable_pos, bidi_pos);
    }
    if (firstPositionWhere(input, isBidiIsolateControl)) |bidi_pos| {
        return confusableBidiCompoundAt("ConfusableInIsolate", confusable_pos, bidi_pos);
    }
    return null;
}

// -- covert-display-compound -----------------------------------------------
//
// Direct port of ports/rust/src/security/boundary/covert_display_compound.rs,
// itself a port of Unicode/Security/Boundary/CovertDisplayCompound.lean. A bidi
// format-control that reorders the visible glyphs is materially more dangerous
// when the same input also carries a covert channel — an unregistered variation
// selector or a tag-block character — because the reorder hides where the
// covert payload sits. The finding fires only when a bidi control coincides
// with one of those covert classes. The bidi predicate covers both the
// override/embedding class (0x202A..0x202E) and the isolate class
// (0x2066..0x2069) via the shared isBidiFormatControl; the suspicious-VS class
// reuses isVariationSelector / isRegisteredVariationPair.

// True iff cp is a tag-block character in the range U+E0000..U+E007F.
fn isTagBlockChar(cp: u32) bool {
    return cp >= 0xE0000 and cp <= 0xE007F;
}

// First position holding a suspicious variation selector — a VS that does not
// form a registered (base, VS) pair with its predecessor. Mirrors the
// `.suspicious` case of the Lean classifyPositions.
fn firstSuspiciousVsPos(input: []const u32) ?usize {
    for (input, 0..) |cp, index| {
        if (isVariationSelector(cp) and
            !(index > 0 and isRegisteredVariationPair(input[index - 1], cp)))
        {
            return index;
        }
    }
    return null;
}

fn covertDisplayCompoundReasonCode(sub_threat: []const u8) []const u8 {
    if (std.mem.eql(u8, sub_threat, "BidiPlusUnregisteredVs")) {
        return "unicode.security.X.covert-display-compound.BidiPlusUnregisteredVs";
    }
    return "unicode.security.X.covert-display-compound.BidiPlusTagBlock";
}

fn covertDisplayCompoundAt(sub_threat: []const u8, bidi_pos: usize, covert_pos: usize) Finding {
    var positions: [MaxFindingPositions]usize = undefined;
    positions[0] = bidi_pos;
    positions[1] = covert_pos;
    return .{
        .code = covertDisplayCompoundReasonCode(sub_threat),
        .family = .covert_display_compound,
        .severity = 2,
        .positions = positions,
        .position_count = 2,
        .sub_threat = sub_threat,
        .detail = "covert-display-compound",
    };
}

// Detect a bidi control co-located with a covert channel. Priority mirrors the
// spec: a bidi control must be present; then a suspicious VS fires
// BidiPlusUnregisteredVs; otherwise a tag-block character fires
// BidiPlusTagBlock; otherwise clear.
fn covertDisplayCompoundFinding(input: []const u32) ?Finding {
    const bidi_pos = firstPositionWhere(input, isBidiFormatControl) orelse return null;
    if (firstSuspiciousVsPos(input)) |vs_pos| {
        return covertDisplayCompoundAt("BidiPlusUnregisteredVs", bidi_pos, vs_pos);
    }
    if (firstPositionWhere(input, isTagBlockChar)) |tag_pos| {
        return covertDisplayCompoundAt("BidiPlusTagBlock", bidi_pos, tag_pos);
    }
    return null;
}

fn fullSpanPositions(input: []const u32) Positions {
    var positions = Positions{ .items = undefined, .len = 0 };
    const capped_len = @min(input.len, positions.items.len);
    for (0..capped_len) |index| {
        positions.items[index] = index;
    }
    positions.len = capped_len;
    return positions;
}

fn isMathAlphanumeric(cp: u32) bool {
    return cp >= 0x1D400 and cp <= 0x1D7FF;
}

fn isFullwidthHalfwidth(cp: u32) bool {
    return cp >= 0xFF01 and cp <= 0xFFEF;
}

fn homoglyphConfusableReasonCode(sub_threat: []const u8) []const u8 {
    if (std.mem.eql(u8, sub_threat, "TargetMatch")) {
        return "unicode.security.I.homoglyph-confusable.TargetMatch";
    }
    if (std.mem.eql(u8, sub_threat, "MathAlpha")) {
        return "unicode.security.I.homoglyph-confusable.MathAlpha";
    }
    if (std.mem.eql(u8, sub_threat, "WidthClass")) {
        return "unicode.security.I.homoglyph-confusable.WidthClass";
    }
    if (std.mem.eql(u8, sub_threat, "DecompositionSwap")) {
        return "unicode.security.I.homoglyph-confusable.DecompositionSwap";
    }
    if (std.mem.eql(u8, sub_threat, "CrossScriptMix")) {
        return "unicode.security.I.homoglyph-confusable.CrossScriptMix";
    }
    if (std.mem.eql(u8, sub_threat, "RestrictionLow")) {
        return "unicode.security.I.homoglyph-confusable.RestrictionLow";
    }
    return "unicode.security.I.homoglyph-confusable.WidthClass";
}

const CpBuffer = struct {
    items: [MaxSkeletonLen]u32 = undefined,
    len: usize = 0,

    fn append(self: *CpBuffer, cp: u32) bool {
        if (self.len >= self.items.len) return false;
        self.items[self.len] = cp;
        self.len += 1;
        return true;
    }

    fn appendSlice(self: *CpBuffer, values: []const u32) bool {
        for (values) |cp| {
            if (!self.append(cp)) return false;
        }
        return true;
    }

    fn slice(self: *const CpBuffer) []const u32 {
        return self.items[0..self.len];
    }
};

fn homoglyphTargetMatch(input: []const u32) ?[]const u8 {
    if (input.len > MaxSkeletonLen) return null;
    const input_letters = letterSkeleton(input) orelse return null;
    var first_match: ?[]const u8 = null;
    var offset: usize = 0;
    while (nextLine(known_attack_targets_raw, &offset)) |raw_line| {
        const target = trimAscii(raw_line);
        if (target.len == 0 or target[0] == '#') continue;
        const target_cps = asciiCodepoints(target) orelse continue;
        const target_letters = letterSkeleton(target_cps.slice()) orelse continue;
        const matches = !cpSlicesEqual(target_cps.slice(), input) and
            ctCpSlicesEqual(target_letters.slice(), input_letters.slice());
        if (matches and first_match == null) {
            first_match = target;
        }
    }
    return first_match;
}

fn letterSkeleton(input: []const u32) ?CpBuffer {
    const iterated = iteratedSkeleton(input) orelse return null;
    var out = CpBuffer{};
    for (iterated.slice()) |cp| {
        if (!isCombiningMark(cp) and !isDefaultIgnorableCodepoint(cp) and !isWhiteSpaceCodepoint(cp)) {
            if (!out.append(cp)) return null;
        }
    }
    return out;
}

fn iteratedSkeleton(input: []const u32) ?CpBuffer {
    if (input.len > MaxSkeletonLen) return null;
    var current = CpBuffer{};
    if (!current.appendSlice(input)) return null;
    for (0..8) |_| {
        const next = skeletonStep(current.slice()) orelse return null;
        if (cpSlicesEqual(next.slice(), current.slice())) return current;
        current = next;
    }
    return current;
}

fn skeletonStep(input: []const u32) ?CpBuffer {
    const nfd1 = toNFD(input) orelse return null;
    const folded = caseFoldCodepoints(nfd1.slice()) orelse return null;

    var substituted = CpBuffer{};
    for (folded.slice()) |cp| {
        var replacement = CpBuffer{};
        if (confusableReplacement(cp, &replacement)) {
            if (!substituted.appendSlice(replacement.slice())) return null;
        } else {
            if (!substituted.append(cp)) return null;
        }
    }

    const out = caseFoldCodepoints(substituted.slice()) orelse return null;
    return toNFD(out.slice());
}

fn toNFD(input: []const u32) ?CpBuffer {
    var out = CpBuffer{};
    for (input) |cp| {
        if (!appendCanonicalDecomposition(&out, cp)) return null;
    }
    canonicalOrder(&out);
    return out;
}

fn appendCanonicalDecomposition(out: *CpBuffer, cp: u32) bool {
    if (hangulDecomposition(cp)) |jamo| return out.appendSlice(jamo.slice());
    if (normalizationEntry(cp)) |entry| {
        if (entry.decomp.len > 0) {
            for (entry.decomp) |part| {
                if (!appendCanonicalDecomposition(out, part)) return false;
            }
            return true;
        }
    }
    return out.append(cp);
}

fn canonicalOrder(buffer: *CpBuffer) void {
    if (buffer.len < 2) return;
    var index: usize = 1;
    while (index < buffer.len) : (index += 1) {
        const current_ccc = canonicalCombiningClass(buffer.items[index]);
        if (current_ccc == 0) continue;
        var j = index;
        while (j > 0) : (j -= 1) {
            const previous_ccc = canonicalCombiningClass(buffer.items[j - 1]);
            if (previous_ccc == 0 or previous_ccc <= current_ccc) break;
            const tmp = buffer.items[j - 1];
            buffer.items[j - 1] = buffer.items[j];
            buffer.items[j] = tmp;
        }
    }
}

fn canonicalCombiningClass(cp: u32) u8 {
    if (normalizationEntry(cp)) |entry| return entry.ccc;
    return 0;
}

fn normalizationEntry(cp: u32) ?normalization_data.Entry {
    var lo: usize = 0;
    var hi: usize = normalization_data.entries.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const entry = normalization_data.entries[mid];
        if (cp < entry.cp) {
            hi = mid;
        } else if (cp > entry.cp) {
            lo = mid + 1;
        } else {
            return entry;
        }
    }
    return null;
}

const HangulDecomposition = struct {
    items: [3]u32,
    len: usize,

    fn slice(self: *const HangulDecomposition) []const u32 {
        return self.items[0..self.len];
    }
};

fn hangulDecomposition(cp: u32) ?HangulDecomposition {
    const s_base = 0xAC00;
    const l_base = 0x1100;
    const v_base = 0x1161;
    const t_base = 0x11A7;
    const l_count = 19;
    const v_count = 21;
    const t_count = 28;
    const n_count = v_count * t_count;
    const s_count = l_count * n_count;

    if (cp < s_base or cp >= s_base + s_count) return null;
    const s_index = cp - s_base;
    const l = l_base + s_index / n_count;
    const v = v_base + (s_index % n_count) / t_count;
    const t_index = s_index % t_count;
    if (t_index == 0) {
        return .{ .items = .{ l, v, 0 }, .len = 2 };
    }
    return .{ .items = .{ l, v, t_base + t_index }, .len = 3 };
}

// ─────────────────────────────────────────────────────────────────────
// Full compatibility decomposition and canonical composition (NFKD/NFKC).
//
// Mirrors the Rust identity port (`security/identity/ucd.rs`) and the Lean
// `Unicode.Normalization.NFKD`/`NFKC` specifications.  NFKD applies the
// recursive compatibility decomposition followed by canonical reordering;
// NFKC recomposes that result with the canonical composition pass.
// ─────────────────────────────────────────────────────────────────────

/// Recursively decompose `cp` using its compatibility mapping when present,
/// otherwise its canonical mapping, otherwise Hangul algorithmic
/// decomposition — the full decomposition of UAX #15 for NFKD.
fn appendCompatDecomposition(out: *CpBuffer, cp: u32) bool {
    if (hangulDecomposition(cp)) |jamo| return out.appendSlice(jamo.slice());
    if (normalizationEntry(cp)) |entry| {
        if (entry.compat.len > 0) {
            for (entry.compat) |part| {
                if (!appendCompatDecomposition(out, part)) return false;
            }
            return true;
        }
        if (entry.decomp.len > 0) {
            for (entry.decomp) |part| {
                if (!appendCompatDecomposition(out, part)) return false;
            }
            return true;
        }
    }
    return out.append(cp);
}

/// UAX #15 NFKD — full compatibility decompose + canonical reorder.
fn toNFKD(input: []const u32) ?CpBuffer {
    var out = CpBuffer{};
    for (input) |cp| {
        if (!appendCompatDecomposition(&out, cp)) return null;
    }
    canonicalOrder(&out);
    return out;
}

/// Algorithmic Hangul composition (UAX #15): L + V → LV, and LV + T → LVT.
fn hangulComposition(a: u32, b: u32) ?u32 {
    const s_base = 0xAC00;
    const l_base = 0x1100;
    const v_base = 0x1161;
    const t_base = 0x11A7;
    const l_count = 19;
    const v_count = 21;
    const t_count = 28;
    const n_count = v_count * t_count;
    const s_count = l_count * n_count;

    if (a >= l_base and a < l_base + l_count and b >= v_base and b < v_base + v_count) {
        const l_index = a - l_base;
        const v_index = b - v_base;
        return s_base + (l_index * v_count + v_index) * t_count;
    }
    if (a >= s_base and a < s_base + s_count and (a - s_base) % t_count == 0 and
        b > t_base and b < t_base + t_count)
    {
        return a + (b - t_base);
    }
    return null;
}

/// Look up the primary composite of the starter/combiner pair `(a, b)` in
/// the generated composition table, which is sorted lexicographically by
/// `(a, b)`.
fn compositionEntry(a: u32, b: u32) ?u32 {
    var lo: usize = 0;
    var hi: usize = normalization_data.compositions.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const entry = normalization_data.compositions[mid];
        if (a < entry.a or (a == entry.a and b < entry.b)) {
            hi = mid;
        } else if (a > entry.a or (a == entry.a and b > entry.b)) {
            lo = mid + 1;
        } else {
            return entry.c;
        }
    }
    return null;
}

/// UAX #15 canonical composition pass: fold each combiner into the most
/// recent starter it is not blocked from, preferring Hangul composition
/// then the composition table.  Operates on an already reordered sequence.
fn canonicalCompose(seq: []const u32) ?CpBuffer {
    var out = CpBuffer{};
    var starter_idx: ?usize = null;
    var last_ccc: i32 = -1;

    for (seq) |cp| {
        const cp_ccc: i32 = canonicalCombiningClass(cp);

        if (starter_idx) |si| {
            const starter = out.items[si];
            const composed = hangulComposition(starter, cp) orelse compositionEntry(starter, cp);
            // Blocked check (UAX #15 D115): last_ccc != 0 means a combiner is
            // buffered between the active starter and this candidate. A
            // starter candidate (cp_ccc == 0) is blocked outright by any
            // buffered combiner; a non-starter is blocked when the buffered
            // combiner has CCC >= its own.
            const blocked = last_ccc != 0 and (cp_ccc == 0 or last_ccc >= cp_ccc);
            if (!blocked) {
                if (composed) |c| {
                    out.items[si] = c;
                    continue;
                }
            }
        }

        if (!out.append(cp)) return null;
        if (cp_ccc == 0) {
            starter_idx = out.len - 1;
            last_ccc = 0;
        } else {
            last_ccc = cp_ccc;
        }
    }

    return out;
}

/// UAX #15 NFC — canonical decompose + reorder + canonical recompose.
fn toNFC(input: []const u32) ?CpBuffer {
    const nfd = toNFD(input) orelse return null;
    return canonicalCompose(nfd.slice());
}

/// UAX #15 NFKC — NFKD followed by canonical recomposition.
fn toNFKC(input: []const u32) ?CpBuffer {
    const nfkd = toNFKD(input) orelse return null;
    return canonicalCompose(nfkd.slice());
}

fn confusableReplacement(cp: u32, out: *CpBuffer) bool {
    var lo: usize = 0;
    var hi: usize = confusables_data.entries.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const entry = confusables_data.entries[mid];
        if (cp < entry.src) {
            hi = mid;
        } else if (cp > entry.src) {
            lo = mid + 1;
        } else {
            return out.appendSlice(entry.replacement);
        }
    }
    return false;
}

fn caseFoldCodepoints(input: []const u32) ?CpBuffer {
    var out = CpBuffer{};
    for (input) |cp| {
        if (caseFoldingEntry(cp)) |entry| {
            if (!out.appendSlice(entry.mapping)) return null;
        } else {
            if (!out.append(cp)) return null;
        }
    }
    return out;
}

fn caseFoldingEntry(cp: u32) ?case_folding_data.Entry {
    var lo: usize = 0;
    var hi: usize = case_folding_data.entries.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const entry = case_folding_data.entries[mid];
        if (cp < entry.cp) {
            hi = mid;
        } else if (cp > entry.cp) {
            lo = mid + 1;
        } else {
            return entry;
        }
    }
    return null;
}

fn asciiCodepoints(target: []const u8) ?CpBuffer {
    if (target.len > MaxSkeletonLen) return null;
    var out = CpBuffer{};
    for (target) |byte| {
        if (!out.append(@as(u32, byte))) return null;
    }
    return out;
}

fn cpSlicesEqual(a: []const u32, b: []const u32) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (left != right) return false;
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────
// UAX #21 case mapping (toLower), mirroring Unicode.Casing.
//
// Full lowercase mappings come from SpecialCasing.txt (one-to-many and
// context/locale-dependent rows); the simple lowercase fallback is
// UnicodeData.txt field 13. Context predicates (Final_Sigma,
// After_Soft_Dotted, More_Above, Not_Before_Dot, After_I) read canonical
// combining class plus the Cased and Soft_Dotted ranges from
// DerivedCoreProperties.txt — mirroring the Lean-generated tables, whose
// soft_dotted set is empty, so After_Soft_Dotted is always false. This is
// the shared primitive the bip39-canonical detector lowercases through. Like
// the rest of this bounded port, the result is materialised in a CpBuffer
// (capacity MaxSkeletonLen); an input that overflows lowercases to null.
// ─────────────────────────────────────────────────────────────────────

pub const CasingLocale = enum { default, turkish, azeri, lithuanian };

fn simpleLowercase(cp: u32) u32 {
    var lo: usize = 0;
    var hi: usize = casing_data.simple_lower.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const entry = casing_data.simple_lower[mid];
        if (cp < entry.cp) {
            hi = mid;
        } else if (cp > entry.cp) {
            lo = mid + 1;
        } else {
            return entry.lower;
        }
    }
    return cp;
}

// Membership in a sorted, disjoint range table (Cased / Soft_Dotted).
fn inCasingRange(ranges: []const casing_data.Range, cp: u32) bool {
    var lo: usize = 0;
    var hi: usize = ranges.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const range = ranges[mid];
        if (cp < range.start) {
            hi = mid;
        } else if (cp > range.end) {
            lo = mid + 1;
        } else {
            return true;
        }
    }
    return false;
}

fn isCased(cp: u32) bool {
    return inCasingRange(casing_data.cased[0..], cp);
}

fn isSoftDotted(cp: u32) bool {
    return inCasingRange(casing_data.soft_dotted[0..], cp);
}

// Context predicates (UAX #21). `prefix` is the forward-ordered preceding
// codepoints (walked nearest-first, i.e. from the end); `suffix` the
// strictly-following ones (walked in order).
fn moreAboveAfter(suffix: []const u32) bool {
    for (suffix) |cp| {
        const c = canonicalCombiningClass(cp);
        if (c == 230) return true;
        if (c == 0) return false;
    }
    return false;
}

fn afterSoftDotted(prefix: []const u32) bool {
    var k = prefix.len;
    while (k > 0) {
        k -= 1;
        const cp = prefix[k];
        if (isSoftDotted(cp)) return true;
        const c = canonicalCombiningClass(cp);
        if (c == 0 or c == 230) return false;
    }
    return false;
}

fn afterI(prefix: []const u32) bool {
    var k = prefix.len;
    while (k > 0) {
        k -= 1;
        const cp = prefix[k];
        if (cp == 0x0049) return true;
        const c = canonicalCombiningClass(cp);
        if (c == 0 or c == 230) return false;
    }
    return false;
}

fn beforeDot(suffix: []const u32) bool {
    for (suffix) |cp| {
        if (cp == 0x0307) return true;
        if (canonicalCombiningClass(cp) == 0) return false;
    }
    return false;
}

fn hasCasedBefore(prefix: []const u32) bool {
    var k = prefix.len;
    while (k > 0) {
        k -= 1;
        const cp = prefix[k];
        if (isCased(cp)) return true;
        if (canonicalCombiningClass(cp) == 0) return false;
    }
    return false;
}

fn hasCasedAfter(suffix: []const u32) bool {
    for (suffix) |cp| {
        if (isCased(cp)) return true;
        if (canonicalCombiningClass(cp) == 0) return false;
    }
    return false;
}

fn finalSigma(prefix: []const u32, suffix: []const u32) bool {
    return hasCasedBefore(prefix) and !hasCasedAfter(suffix);
}

fn isLocaleCondition(cond: []const u8) bool {
    return std.mem.eql(u8, cond, "tr") or
        std.mem.eql(u8, cond, "az") or
        std.mem.eql(u8, cond, "lt");
}

fn casingLocaleMatches(locale: CasingLocale, conditions: []const []const u8) bool {
    var has_locale = false;
    for (conditions) |cond| {
        if (isLocaleCondition(cond)) {
            has_locale = true;
            break;
        }
    }
    if (!has_locale) return true;
    for (conditions) |cond| {
        if (std.mem.eql(u8, cond, "tr") and locale == .turkish) return true;
        if (std.mem.eql(u8, cond, "az") and locale == .azeri) return true;
        if (std.mem.eql(u8, cond, "lt") and locale == .lithuanian) return true;
    }
    return false;
}

fn casingConditionsHold(
    locale: CasingLocale,
    prefix: []const u32,
    suffix: []const u32,
    conditions: []const []const u8,
) bool {
    if (!casingLocaleMatches(locale, conditions)) return false;
    for (conditions) |cond| {
        if (isLocaleCondition(cond)) continue;
        const ok = if (std.mem.eql(u8, cond, "Final_Sigma"))
            finalSigma(prefix, suffix)
        else if (std.mem.eql(u8, cond, "Not_Final_Sigma"))
            !finalSigma(prefix, suffix)
        else if (std.mem.eql(u8, cond, "After_Soft_Dotted"))
            afterSoftDotted(prefix)
        else if (std.mem.eql(u8, cond, "More_Above"))
            moreAboveAfter(suffix)
        else if (std.mem.eql(u8, cond, "Not_Before_Dot"))
            !beforeDot(suffix)
        else if (std.mem.eql(u8, cond, "After_I"))
            afterI(prefix)
        else
            false;
        if (!ok) return false;
    }
    return true;
}

// UAX #21: a conditional SpecialCasing row whose conditions hold outranks the
// unconditional row for the same codepoint (first matching conditional in file
// order wins); with no special row the simple lowercase mapping applies.
fn findSpecialLower(
    locale: CasingLocale,
    prefix: []const u32,
    suffix: []const u32,
    cp: u32,
) ?[]const u32 {
    for (casing_data.special) |row| {
        if (row.code != cp) continue;
        if (row.conditions.len != 0 and
            casingConditionsHold(locale, prefix, suffix, row.conditions))
        {
            return row.lower;
        }
    }
    for (casing_data.special) |row| {
        if (row.code == cp and row.conditions.len == 0) return row.lower;
    }
    return null;
}

/// Lowercase a codepoint sequence under `locale` (UAX #21 full mapping),
/// mirroring `Unicode.Casing.toLower`. Returns null if the result overflows
/// the bounded CpBuffer.
pub fn toLower(locale: CasingLocale, cps: []const u32) ?CpBuffer {
    var out = CpBuffer{};
    for (cps, 0..) |cp, i| {
        const prefix = cps[0..i];
        const suffix = cps[i + 1 ..];
        if (findSpecialLower(locale, prefix, suffix, cp)) |lower| {
            if (!out.appendSlice(lower)) return null;
        } else {
            if (!out.append(simpleLowercase(cp))) return null;
        }
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────────
// UAX #21 uppercase mapping (upperCodepoint), the additive mirror of the
// lowercase path above. Full uppercase mappings come from SpecialCasing.txt
// (one-to-many and context/locale-dependent rows — the uppercase column, i.e.
// field 3, `code; lower; title; upper; conditions`); the simple uppercase
// fallback is UnicodeData.txt field 12. Both companion tables (special_upper /
// simple_upper) sit alongside their lowercase counterparts in the generated
// casing data, parsed the same way. The SpecialCasing context predicates
// (Final_Sigma, After_Soft_Dotted, More_Above, Not_Before_Dot, After_I) and
// the locale gate are shared verbatim with the lowercase path
// (casingConditionsHold), so this is purely additive: the lowercase mapping is
// untouched. This is the primitive the case-expansion-mismatch detector maps
// each position through to see whether the codepoint count changes.
// ─────────────────────────────────────────────────────────────────────

fn simpleUppercase(cp: u32) u32 {
    var lo: usize = 0;
    var hi: usize = casing_data.simple_upper.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const entry = casing_data.simple_upper[mid];
        if (cp < entry.cp) {
            hi = mid;
        } else if (cp > entry.cp) {
            lo = mid + 1;
        } else {
            return entry.upper;
        }
    }
    return cp;
}

// UAX #21: a conditional SpecialCasing row whose conditions hold outranks the
// unconditional row for the same codepoint (first matching conditional in file
// order wins); with no special row the simple uppercase mapping applies. Mirrors
// findSpecialLower over the uppercase column, reusing casingConditionsHold.
fn findSpecialUpper(
    locale: CasingLocale,
    prefix: []const u32,
    suffix: []const u32,
    cp: u32,
) ?[]const u32 {
    for (casing_data.special_upper) |row| {
        if (row.code != cp) continue;
        if (row.conditions.len != 0 and
            casingConditionsHold(locale, prefix, suffix, row.conditions))
        {
            return row.upper;
        }
    }
    for (casing_data.special_upper) |row| {
        if (row.code == cp and row.conditions.len == 0) return row.upper;
    }
    return null;
}

/// The UAX #21 full uppercase mapping of the codepoint at one position in
/// context, mirroring the port's lowercase composition (findSpecialLower orelse
/// simpleLowercase). `prefix` is the forward-ordered preceding codepoints and
/// `suffix` the strictly-following ones — the same context convention the
/// lowercase predicates consume. Returns the static SpecialCasing uppercase
/// slice when a row applies, else the single simple uppercase codepoint written
/// into `scratch`. The mapped length (not the value) is what the
/// case-expansion-mismatch detector inspects.
fn upperCodepoint(
    locale: CasingLocale,
    prefix: []const u32,
    suffix: []const u32,
    cp: u32,
    scratch: *[1]u32,
) []const u32 {
    if (findSpecialUpper(locale, prefix, suffix, cp)) |upper| return upper;
    scratch[0] = simpleUppercase(cp);
    return scratch[0..1];
}

/// The UAX #21 full lowercase mapping of the codepoint at one position in
/// context, the sibling of upperCodepoint (findSpecialLower orelse
/// simpleLowercase). Exposed so the case-expansion-mismatch detector maps upper
/// and lower through the same shape.
fn lowerCodepoint(
    locale: CasingLocale,
    prefix: []const u32,
    suffix: []const u32,
    cp: u32,
    scratch: *[1]u32,
) []const u32 {
    if (findSpecialLower(locale, prefix, suffix, cp)) |lower| return lower;
    scratch[0] = simpleLowercase(cp);
    return scratch[0..1];
}

// ─────────────────────────────────────────────────────────────────────
// BIP-39 canonical-form detector (crypto layer), mirroring
// Unicode.Security.Crypto.Bip39Canonical.
//
// Canonical form = NFKD -> toLower(default) -> collapse BIP-39 whitespace runs
// to a single U+0020 -> trim leading/trailing U+0020. The detector runs six
// probes in priority order (first hit wins): trailing whitespace, mixed case,
// whitespace anomaly, non-NFKD input, wordlist mismatch, then language
// resolution over the ten 2,048-word BIP-39 wordlists. Normalisation is bounded
// by the CpBuffer capacity, matching every other normalization consumer here.
// ─────────────────────────────────────────────────────────────────────

pub const Bip39CanonicalResult = struct {
    sub_threat: ?[]const u8 = null,
    positions: [1]usize = undefined,
    position_count: usize = 0,
    language: []const u8 = "english",
    canonical: CpBuffer = .{},
    word_count: usize = 0,
};

fn isBip39Whitespace(cp: u32) bool {
    return cp == 0x0020 or cp == 0x3000;
}

fn collapseBip39Whitespace(cps: []const u32) ?CpBuffer {
    var out = CpBuffer{};
    var in_ws = false;
    for (cps) |cp| {
        if (isBip39Whitespace(cp)) {
            if (!in_ws) {
                if (!out.append(0x0020)) return null;
            }
            in_ws = true;
        } else {
            if (!out.append(cp)) return null;
            in_ws = false;
        }
    }
    return out;
}

fn trimBip39(buffer: *const CpBuffer) CpBuffer {
    const s = buffer.slice();
    var start: usize = 0;
    var end: usize = s.len;
    while (start < end and s[start] == 0x0020) start += 1;
    while (end > start and s[end - 1] == 0x0020) end -= 1;
    var out = CpBuffer{};
    var i = start;
    while (i < end) : (i += 1) {
        _ = out.append(s[i]);
    }
    return out;
}

fn bip39CanonicalForm(input: []const u32) ?CpBuffer {
    const nfkd = toNFKD(input) orelse return null;
    const lowered = toLower(.default, nfkd.slice()) orelse return null;
    const collapsed = collapseBip39Whitespace(lowered.slice()) orelse return null;
    return trimBip39(&collapsed);
}

fn cpSeqLess(a: []const u32, b: []const u32) bool {
    const n = @min(a.len, b.len);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (a[i] < b[i]) return true;
        if (a[i] > b[i]) return false;
    }
    return a.len < b.len;
}

fn wordInList(words: []const []const u32, word: []const u32) bool {
    var lo: usize = 0;
    var hi: usize = words.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const entry = words[mid];
        if (cpSeqLess(word, entry)) {
            hi = mid;
        } else if (cpSeqLess(entry, word)) {
            lo = mid + 1;
        } else {
            return true;
        }
    }
    return false;
}

fn anyLanguageContains(word: []const u32) bool {
    for (bip39_data.languages) |lang| {
        if (wordInList(lang.words, word)) return true;
    }
    return false;
}

fn countBip39Words(canonical: []const u32) usize {
    var count: usize = 0;
    var in_word = false;
    for (canonical) |cp| {
        if (cp == 0x0020) {
            in_word = false;
        } else {
            if (!in_word) count += 1;
            in_word = true;
        }
    }
    return count;
}

// Index of the first canonical word absent from every wordlist, or null.
fn firstUnknownWordIndex(canonical: []const u32) ?usize {
    var word_index: usize = 0;
    var i: usize = 0;
    while (i < canonical.len) {
        if (canonical[i] == 0x0020) {
            i += 1;
            continue;
        }
        const start = i;
        while (i < canonical.len and canonical[i] != 0x0020) i += 1;
        if (!anyLanguageContains(canonical[start..i])) return word_index;
        word_index += 1;
    }
    return null;
}

fn allWordsInList(canonical: []const u32, words: []const []const u32) bool {
    var i: usize = 0;
    while (i < canonical.len) {
        if (canonical[i] == 0x0020) {
            i += 1;
            continue;
        }
        const start = i;
        while (i < canonical.len and canonical[i] != 0x0020) i += 1;
        if (!wordInList(words, canonical[start..i])) return false;
    }
    return true;
}

// The first language whose wordlist covers every word, else null. Empty input
// resolves to English (every predicate holds vacuously), matching the Lean
// findSome? over allLanguages.
fn bip39UniqueLanguage(canonical: []const u32) ?[]const u8 {
    for (bip39_data.languages) |lang| {
        if (allWordsInList(canonical, lang.words)) return lang.name;
    }
    return null;
}

fn countTrailingBip39Whitespace(input: []const u32) usize {
    var count: usize = 0;
    var k = input.len;
    while (k > 0) {
        k -= 1;
        if (isBip39Whitespace(input[k])) count += 1 else break;
    }
    return count;
}

fn firstUppercasePos(input: []const u32) ?usize {
    for (input, 0..) |cp, i| {
        if (cp >= 0x41 and cp <= 0x5A) return i;
    }
    return null;
}

// First position of a leading or consecutive BIP-39 whitespace run; a single
// internal separator does not fire.
fn firstWhitespaceRunPos(input: []const u32) ?usize {
    for (input, 0..) |cp, i| {
        if (isBip39Whitespace(cp)) {
            if (i == 0) return i;
            if (i + 1 < input.len and isBip39Whitespace(input[i + 1])) return i;
        }
    }
    return null;
}

// First position at which `a` and `b` differ (in element, or one ends);
// callers invoke it only when the two sequences are known to differ.
fn firstDivergence(a: []const u32, b: []const u32) usize {
    const n = @min(a.len, b.len);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (a[i] != b[i]) return i;
    }
    return n;
}

/// Detect a non-canonical or wordlist-mismatched BIP-39 mnemonic, mirroring
/// `Unicode.Security.Crypto.Bip39Canonical.detect`.
pub fn bip39CanonicalDetect(input: []const u32) Bip39CanonicalResult {
    const canonical_buf = bip39CanonicalForm(input) orelse CpBuffer{};
    var result = Bip39CanonicalResult{
        .canonical = canonical_buf,
        .word_count = countBip39Words(canonical_buf.slice()),
    };

    const trailing = countTrailingBip39Whitespace(input);
    if (trailing > 0) {
        result.sub_threat = "TrailingWhitespace";
        result.positions[0] = input.len - trailing;
        result.position_count = 1;
        return result;
    }
    if (firstUppercasePos(input)) |pos| {
        result.sub_threat = "MixedCase";
        result.positions[0] = pos;
        result.position_count = 1;
        return result;
    }
    if (firstWhitespaceRunPos(input)) |pos| {
        result.sub_threat = "WhitespaceAnomaly";
        result.positions[0] = pos;
        result.position_count = 1;
        return result;
    }
    if (toNFKD(input)) |nfkd| {
        if (!cpSlicesEqual(input, nfkd.slice())) {
            result.sub_threat = "NonNFKD";
            result.positions[0] = firstDivergence(input, nfkd.slice());
            result.position_count = 1;
            return result;
        }
    }
    if (firstUnknownWordIndex(canonical_buf.slice())) |idx| {
        result.sub_threat = "WordlistMismatch";
        result.positions[0] = idx;
        result.position_count = 1;
        return result;
    }
    if (bip39UniqueLanguage(canonical_buf.slice())) |lang| {
        result.language = lang;
        return result;
    }
    result.sub_threat = "LanguageAmbiguous";
    return result;
}

// ─────────────────────────────────────────────────────────────────────
// Hash-input-stability detector (crypto layer), mirroring
// Unicode.Security.Crypto.HashInputStability and its Rust port.
//
// A signer and a verifier that pick different canonical forms (NFC vs NFD,
// trim policy, line-ending convention) produce diverging hashes over the same
// apparent content. The hash-stable form is trimTrailing(toNFC(input)), where
// trimTrailing strips only ASCII whitespace {U+0020, U+0009, U+000A, U+000D};
// Unicode whitespace is content and is kept. NFC is the port's toNFC, never a
// host normalizer.
//
// Six probes run in strict priority order (first hit wins): encodingMismatch,
// webhookSignatureDrift, auditLogReinterpretation, signedMessageRule,
// trailingWhitespace, normalizationDrift, then clear. The four context-bearing
// probes carry more precise threat information and so precede the two generic
// ones; detect is detectWithContext with the empty context, which leaves the
// context-bearing probes silent.
// ─────────────────────────────────────────────────────────────────────

pub const hash_input_stability = struct {
    /// RFC canonicalisation profiles that the signedMessageRule probe checks
    /// against. Each variant names a specific canonicalisation rule from a
    /// published RFC; callers pass one as Context.rfc_rule to opt the probe in.
    pub const RfcRule = enum {
        /// RFC 4880 §5.2.4 — detached signatures normalise trailing whitespace.
        pgp4880_trailing_whitespace,
        /// RFC 9580 — line-endings normalise to CRLF before signing.
        pgp9580_line_ending,
        /// RFC 8785 §3.2.5 — JCS requires strings in NFC before serialisation.
        rfc8785_nfc_requirement,
        /// RFC 8259 §7 — JSON strings must escape control characters.
        rfc8259_control_char,
        /// RFC 7515 §2 — JWS Base64URL; any char outside [A-Za-z0-9_-] violates.
        rfc7515_jws_base64_url,
        /// RFC 6376 §3.4.4 — DKIM relaxed body collapses internal whitespace runs.
        rfc6376_dkim_relaxed,
        /// RFC 5751 §3.1.1 — S/MIME canonical text; a bare LF or bare CR violates.
        rfc5751_smime_line_ending,

        /// Fixture-string identifier for an RfcRule.
        pub fn tag(self: RfcRule) []const u8 {
            return switch (self) {
                .pgp4880_trailing_whitespace => "pgp4880TrailingWhitespace",
                .pgp9580_line_ending => "pgp9580LineEnding",
                .rfc8785_nfc_requirement => "rfc8785NfcRequirement",
                .rfc8259_control_char => "rfc8259ControlChar",
                .rfc7515_jws_base64_url => "rfc7515JwsBase64Url",
                .rfc6376_dkim_relaxed => "rfc6376DkimRelaxed",
                .rfc5751_smime_line_ending => "rfc5751SmimeLineEnding",
            };
        }

        /// Inverse of tag. Returns null for unrecognised strings.
        pub fn fromTag(wire_tag: []const u8) ?RfcRule {
            if (std.mem.eql(u8, wire_tag, "pgp4880TrailingWhitespace")) return .pgp4880_trailing_whitespace;
            if (std.mem.eql(u8, wire_tag, "pgp9580LineEnding")) return .pgp9580_line_ending;
            if (std.mem.eql(u8, wire_tag, "rfc8785NfcRequirement")) return .rfc8785_nfc_requirement;
            if (std.mem.eql(u8, wire_tag, "rfc8259ControlChar")) return .rfc8259_control_char;
            if (std.mem.eql(u8, wire_tag, "rfc7515JwsBase64Url")) return .rfc7515_jws_base64_url;
            if (std.mem.eql(u8, wire_tag, "rfc6376DkimRelaxed")) return .rfc6376_dkim_relaxed;
            if (std.mem.eql(u8, wire_tag, "rfc5751SmimeLineEnding")) return .rfc5751_smime_line_ending;
            return null;
        }
    };

    /// Sub-threats this detector can fire. Two probes fire from the raw input
    /// alone (normalization_drift, trailing_whitespace); the other four require
    /// the corresponding Context field to be set.
    pub const SubThreat = union(enum) {
        /// Input diverges from its NFC form at first_divergent_pos.
        normalization_drift: struct { first_divergent_pos: usize },
        /// Input has count trailing ASCII-whitespace codepoints.
        trailing_whitespace: struct { count: usize },
        /// Declared encoding disagrees with the codepoint array (or an invalid scalar).
        encoding_mismatch: struct { declared_enc: []const u8, detected_enc: []const u8 },
        /// Input violates the named RFC's canonicalisation rule at first_pos.
        signed_message_rule: struct { rfc_rule: []const u8, first_pos: usize },
        /// The re-read input differs from Context.as_written at first_divergent_pos.
        audit_log_reinterpretation: struct { first_divergent_pos: usize },
        /// The client input differs from Context.server_bytes at first_pos.
        webhook_signature_drift: struct { first_pos: usize },

        /// Human-facing classification tag for this sub-threat.
        pub fn tag(self: SubThreat) []const u8 {
            return switch (self) {
                .normalization_drift => "NormalizationDrift",
                .trailing_whitespace => "TrailingWhitespace",
                .encoding_mismatch => "EncodingMismatch",
                .signed_message_rule => "SignedMessageRule",
                .audit_log_reinterpretation => "AuditLogReinterpretation",
                .webhook_signature_drift => "WebhookSignatureDrift",
            };
        }
    };

    /// Context passed to detectWithContext to enable the four context-bearing
    /// probes. Each field is null by default — the empty context is the
    /// identity case: detectWithContext(Context{}, input) equals detect(input).
    pub const Context = struct {
        /// The encoding label the caller claims their input is in.
        declared_encoding: ?[]const u8 = null,
        /// The RFC canonicalisation rule the caller is operating under.
        rfc_rule: ?RfcRule = null,
        /// The original "as-written" form of an audit-log entry whose re-read is input.
        as_written: ?[]const u32 = null,
        /// The server-side recomputed bytes for a webhook signature.
        server_bytes: ?[]const u32 = null,
    };

    /// Top-level classification.
    pub const Classification = union(enum) {
        /// The input is already hash-stable under every enabled probe.
        clear,
        /// A hazard was found: the sub-threat and its implicated positions. Every
        /// probe implicates exactly one position, so the buffer is single-slot.
        hazard: struct { sub: SubThreat, positions: [1]usize },

        /// True iff the input is clear.
        pub fn isClear(self: Classification) bool {
            return switch (self) {
                .clear => true,
                .hazard => false,
            };
        }

        /// Human-facing tag for a hazard, or null when clear.
        pub fn tag(self: Classification) ?[]const u8 {
            return switch (self) {
                .clear => null,
                .hazard => |h| h.sub.tag(),
            };
        }

        /// Implicated positions (empty when clear).
        pub fn positions(self: *const Classification) []const usize {
            switch (self.*) {
                .clear => return &[_]usize{},
                .hazard => return self.hazard.positions[0..],
            }
        }
    };

    /// Verdict — the structured output of detect. stable_size is the codepoint
    /// count of the hash-stable canonical form; downstream callers compare it
    /// against input.len to size the byte-drift their hash sees.
    pub const Verdict = struct {
        /// The scanned input codepoints.
        input: []const u32,
        /// The classification verdict.
        classify: Classification,
        /// The hash-stable canonical form of the input.
        stable_form: CpBuffer,
        /// Codepoint count of stable_form.
        stable_size: usize,
    };

    const EncodingHit = struct { declared: []const u8, detected: []const u8, pos: usize };
    const RfcHit = struct { rule: RfcRule, pos: usize };

    // ── Canonicalisation pipeline ───────────────────────────────────────

    /// True iff cp is an ASCII whitespace codepoint that line-oriented
    /// hash-input protocols treat as framing rather than content: U+0020 SPACE,
    /// U+0009 TAB, U+000A LF, U+000D CR.
    fn isAsciiWhitespace(cp: u32) bool {
        return cp == 0x0020 or cp == 0x0009 or cp == 0x000A or cp == 0x000D;
    }

    /// Count of trailing ASCII whitespace codepoints in input.
    fn countTrailingWhitespace(input: []const u32) usize {
        var count: usize = 0;
        var k = input.len;
        while (k > 0) {
            k -= 1;
            if (isAsciiWhitespace(input[k])) count += 1 else break;
        }
        return count;
    }

    /// Strip trailing ASCII whitespace into a bounded buffer.
    fn trimTrailing(input: []const u32) CpBuffer {
        const keep = input.len - countTrailingWhitespace(input);
        var out = CpBuffer{};
        var i: usize = 0;
        while (i < keep) : (i += 1) {
            _ = out.append(input[i]);
        }
        return out;
    }

    /// The hash-stable form of an input: NFC then trim, in spec order. NFC that
    /// overflows the 128-codepoint buffer (impossible for inputs within the
    /// bound) falls back to the raw input, itself bounded by the buffer.
    pub fn hashStable(input: []const u32) CpBuffer {
        var nfc = CpBuffer{};
        if (toNFC(input)) |composed| {
            nfc = composed;
        } else {
            _ = nfc.appendSlice(input);
        }
        return trimTrailing(nfc.slice());
    }

    // ── Priority position-finder ────────────────────────────────────────

    /// First position at which a and b diverge, or the length of the shared
    /// prefix when one strictly extends the other. null when identical.
    fn firstArrayDivergence(a: []const u32, b: []const u32) ?usize {
        const common = @min(a.len, b.len);
        var i: usize = 0;
        while (i < common) : (i += 1) {
            if (a[i] != b[i]) return i;
        }
        if (a.len != b.len) return common;
        return null;
    }

    // ── Context-bearing probes ──────────────────────────────────────────

    /// Lower-case an ASCII letter (U+0041..U+005A → U+0061..U+007A).
    fn asciiLower(cp: u32) u32 {
        if (cp >= 0x41 and cp <= 0x5A) return cp + 0x20;
        return cp;
    }

    /// True iff the label, folded to ASCII lower-case per Unicode scalar,
    /// equals target (an ASCII spelling). Non-ASCII scalars pass through and
    /// cannot match. Invalid UTF-8 never matches an ASCII target.
    fn labelFoldsTo(label: []const u8, target: []const u8) bool {
        const view = std.unicode.Utf8View.init(label) catch return false;
        var it = view.iterator();
        var ti: usize = 0;
        while (it.nextCodepoint()) |cp| {
            if (ti >= target.len) return false;
            if (asciiLower(cp) != target[ti]) return false;
            ti += 1;
        }
        return ti == target.len;
    }

    /// True iff label (after ASCII case-fold) names UTF-8: accepts "utf-8",
    /// "UTF-8", "UTF8", "utf8".
    fn isUtf8Label(label: []const u8) bool {
        return labelFoldsTo(label, "utf-8") or labelFoldsTo(label, "utf8");
    }

    /// True iff cp is a valid Unicode scalar value: in [0, 0x10FFFF] and not a
    /// surrogate [0xD800, 0xDFFF].
    fn isValidScalar(cp: u32) bool {
        return cp <= 0x10FFFF and !(cp >= 0xD800 and cp <= 0xDFFF);
    }

    /// First position holding a codepoint that is not a valid Unicode scalar,
    /// or null if every codepoint is valid.
    fn firstInvalidScalar(input: []const u32) ?usize {
        for (input, 0..) |cp, i| {
            if (!isValidScalar(cp)) return i;
        }
        return null;
    }

    /// Probe: encodingMismatch. An invalid scalar fires with detected = "invalid"
    /// regardless of the declared label; otherwise a non-UTF-8 label fires with
    /// detected = "utf-8" at position 0.
    fn encodingMismatchProbe(declared: []const u8, input: []const u32) ?EncodingHit {
        if (firstInvalidScalar(input)) |pos| {
            return EncodingHit{ .declared = declared, .detected = "invalid", .pos = pos };
        }
        if (isUtf8Label(declared)) return null;
        return EncodingHit{ .declared = declared, .detected = "utf-8", .pos = 0 };
    }

    /// Probe: pgp4880TrailingWhitespace. Same condition as trailingWhitespace;
    /// returns the first position of the trailing run.
    fn pgp4880Violation(input: []const u32) ?usize {
        const trailing = countTrailingWhitespace(input);
        if (trailing > 0) return input.len - trailing;
        return null;
    }

    /// Probe: pgp9580LineEnding. First bare LF (U+000A not preceded by CR) or
    /// bare CR (U+000D not followed by LF).
    fn pgp9580Violation(input: []const u32) ?usize {
        for (input, 0..) |cp, i| {
            if (cp == 0x000A) {
                const preceded_by_cr = i > 0 and input[i - 1] == 0x000D;
                if (!preceded_by_cr) return i;
            } else if (cp == 0x000D) {
                const followed_by_lf = i + 1 < input.len and input[i + 1] == 0x000A;
                if (!followed_by_lf) return i;
            }
        }
        return null;
    }

    /// Probe: rfc8785NfcRequirement. Same condition as normalizationDrift;
    /// returns the first NFC divergence position.
    fn rfc8785Violation(input: []const u32) ?usize {
        const nfc = toNFC(input) orelse return null;
        if (cpSlicesEqual(input, nfc.slice())) return null;
        return firstArrayDivergence(input, nfc.slice());
    }

    /// Probe: rfc8259ControlChar. First C0 control (U+0000..U+001F).
    fn rfc8259Violation(input: []const u32) ?usize {
        for (input, 0..) |cp, i| {
            if (cp <= 0x1F) return i;
        }
        return null;
    }

    /// True iff cp is in the JWS Base64URL alphabet [A-Za-z0-9_-].
    fn isBase64Url(cp: u32) bool {
        return (cp >= 0x41 and cp <= 0x5A) or
            (cp >= 0x61 and cp <= 0x7A) or
            (cp >= 0x30 and cp <= 0x39) or
            cp == 0x2D or
            cp == 0x5F;
    }

    /// Probe: rfc7515JwsBase64Url. First codepoint outside [A-Za-z0-9_-].
    fn rfc7515Violation(input: []const u32) ?usize {
        for (input, 0..) |cp, i| {
            if (!isBase64Url(cp)) return i;
        }
        return null;
    }

    /// True iff cp is DKIM whitespace: U+0020 SPACE or U+0009 HTAB.
    fn isDkimWhitespace(cp: u32) bool {
        return cp == 0x20 or cp == 0x09;
    }

    /// Probe: rfc6376DkimRelaxed. Position of the second whitespace codepoint in
    /// the first internal whitespace run longer than one.
    fn rfc6376Violation(input: []const u32) ?usize {
        for (input, 0..) |cp, i| {
            if (isDkimWhitespace(cp) and i > 0 and isDkimWhitespace(input[i - 1])) return i;
        }
        return null;
    }

    /// Probe: rfc5751SmimeLineEnding. Reuses the PGP 9580 bare-line-ending rule.
    fn rfc5751Violation(input: []const u32) ?usize {
        return pgp9580Violation(input);
    }

    /// Dispatch the RFC-rule probe. First violation position, or null if clean.
    fn rfcRuleViolation(rule: RfcRule, input: []const u32) ?usize {
        return switch (rule) {
            .pgp4880_trailing_whitespace => pgp4880Violation(input),
            .pgp9580_line_ending => pgp9580Violation(input),
            .rfc8785_nfc_requirement => rfc8785Violation(input),
            .rfc8259_control_char => rfc8259Violation(input),
            .rfc7515_jws_base64_url => rfc7515Violation(input),
            .rfc6376_dkim_relaxed => rfc6376Violation(input),
            .rfc5751_smime_line_ending => rfc5751Violation(input),
        };
    }

    // ── Top-level detection ─────────────────────────────────────────────

    /// The priority resolver: first hit wins, in the spec's fixed order.
    fn classify(
        encoding_hit: ?EncodingHit,
        webhook_hit: ?usize,
        audit_hit: ?usize,
        rfc_hit: ?RfcHit,
        trailing_count: usize,
        input_len: usize,
        non_nfc_pos: ?usize,
    ) Classification {
        if (encoding_hit) |h| {
            return .{ .hazard = .{
                .sub = .{ .encoding_mismatch = .{ .declared_enc = h.declared, .detected_enc = h.detected } },
                .positions = .{h.pos},
            } };
        }
        if (webhook_hit) |pos| {
            return .{ .hazard = .{
                .sub = .{ .webhook_signature_drift = .{ .first_pos = pos } },
                .positions = .{pos},
            } };
        }
        if (audit_hit) |pos| {
            return .{ .hazard = .{
                .sub = .{ .audit_log_reinterpretation = .{ .first_divergent_pos = pos } },
                .positions = .{pos},
            } };
        }
        if (rfc_hit) |h| {
            return .{ .hazard = .{
                .sub = .{ .signed_message_rule = .{ .rfc_rule = h.rule.tag(), .first_pos = h.pos } },
                .positions = .{h.pos},
            } };
        }
        if (trailing_count > 0) {
            const p = input_len - trailing_count;
            return .{ .hazard = .{
                .sub = .{ .trailing_whitespace = .{ .count = trailing_count } },
                .positions = .{p},
            } };
        }
        if (non_nfc_pos) |p| {
            return .{ .hazard = .{
                .sub = .{ .normalization_drift = .{ .first_divergent_pos = p } },
                .positions = .{p},
            } };
        }
        return .{ .clear = {} };
    }

    /// The full detection function. Runs all six probes in priority order, with
    /// the context-bearing probes ahead of the generic ones.
    pub fn detectWithContext(ctx: Context, input: []const u32) @This().Verdict {
        const stable = hashStable(input);

        // Probe 1: encodingMismatch.
        const encoding_hit: ?EncodingHit = if (ctx.declared_encoding) |label|
            encodingMismatchProbe(label, input)
        else
            null;

        // Probe 2: webhookSignatureDrift.
        const webhook_hit: ?usize = if (ctx.server_bytes) |server|
            firstArrayDivergence(input, server)
        else
            null;

        // Probe 3: auditLogReinterpretation.
        const audit_hit: ?usize = if (ctx.as_written) |written|
            firstArrayDivergence(written, input)
        else
            null;

        // Probe 4: signedMessageRule.
        const rfc_hit: ?RfcHit = if (ctx.rfc_rule) |rule| blk: {
            if (rfcRuleViolation(rule, input)) |pos| {
                break :blk RfcHit{ .rule = rule, .pos = pos };
            }
            break :blk null;
        } else null;

        // Probe 5: trailingWhitespace.
        const trailing_count = countTrailingWhitespace(input);

        // Probe 6: normalizationDrift.
        const non_nfc_pos: ?usize = blk: {
            const nfc = toNFC(input) orelse break :blk null;
            if (cpSlicesEqual(input, nfc.slice())) break :blk null;
            break :blk firstArrayDivergence(input, nfc.slice());
        };

        const classification = classify(
            encoding_hit,
            webhook_hit,
            audit_hit,
            rfc_hit,
            trailing_count,
            input.len,
            non_nfc_pos,
        );

        return @This().Verdict{
            .input = input,
            .classify = classification,
            .stable_form = stable,
            .stable_size = stable.len,
        };
    }

    /// Convenience wrapper over detectWithContext with the empty context —
    /// equivalent to running only the two bare-input probes (trailingWhitespace,
    /// normalizationDrift).
    pub fn detect(input: []const u32) @This().Verdict {
        return detectWithContext(Context{}, input);
    }
};

// ─────────────────────────────────────────────────────────────────────
// ai-watermark-detectability (crypto layer), mirroring
// Unicode.Security.Crypto.AiWatermarkDetectability and the verified Rust
// port ports/rust/src/security/crypto/ai_watermark_detectability.rs.
//
// Character-level detector for inputs carrying codepoint patterns consistent
// with a known AI watermark scheme. Ten probes run in a fixed priority order
// (first hit wins): adversarial (NNBSP arithmetic progression), gpt5ZwspModulo
// (ZWSP arithmetic progression), unknown (invisible markers from >= 2
// categories), nnbspBoundary, variationSelectorCarrier (VS not emoji-adjacent),
// zwjNonEmoji (ZWJ not emoji-adjacent), smartQuoteAlternation, emDashPattern,
// statisticalTokenChoice (AI-favored vocabulary), defaultIgnorableCarrier,
// then clear.
//
// The Emoji property table is bundled in the port's own data/emoji-data.txt
// (UTS #51 17.0, byte-identical to the UCD source); the VS/ZWJ adjacency probes
// parse its Emoji rows, never a host emoji library. Default_Ignorable reuses the
// port's own predicate.
// ─────────────────────────────────────────────────────────────────────

pub const ai_watermark_detectability = struct {
    /// Number of marker positions a hazard can carry before the bounded buffer
    /// saturates. Positions are a subset of input indices; the cap mirrors the
    /// port's other bounded buffers.
    const MaxPositions = 512;

    /// Bounded position buffer — a hazard's implicated codepoint indices.
    const PosBuffer = struct {
        items: [MaxPositions]usize = undefined,
        len: usize = 0,

        fn append(self: *PosBuffer, p: usize) void {
            if (self.len >= self.items.len) return;
            self.items[self.len] = p;
            self.len += 1;
        }

        fn slice(self: *const PosBuffer) []const usize {
            return self.items[0..self.len];
        }
    };

    /// The conceptual watermark cue class a sub-threat probes for, drawn from
    /// the fixed vocabulary in Unicode.Generated.WatermarkSchemes.CueClass.
    pub const CueClass = enum {
        /// A codepoint-frequency bias toward a pinned "green list" of tokens.
        green_list_bias,
        /// A fixed-period or carrier-byte channel surfacing a pseudorandom function.
        pseudorandom_seq,
        /// A stylistic-distribution drift away from natural human writing.
        semantic_drift,
    };

    /// Sub-threats this detector can fire. Each variant has a corresponding
    /// probe in detect; the payload carries the position information the
    /// conformance harness's attribution column reads back.
    pub const SubThreat = union(enum) {
        /// Single-category NNBSP (U+202F) markers; marker_count is how many.
        nnbsp_boundary: struct { marker_count: usize },
        /// Variation selector(s) not adjacent to an emoji; marker_count is how many.
        variation_selector_carrier: struct { marker_count: usize },
        /// ZWJ(s) not adjacent to an emoji; marker_count is how many.
        zwj_non_emoji: struct { marker_count: usize },
        /// Residual Default_Ignorable markers; marker_count is how many.
        default_ignorable_carrier: struct { marker_count: usize },
        /// ZWSP (U+200B) markers at arithmetic-progression positions; first_pos
        /// is the first ZWSP position.
        gpt5_zwsp_modulo: struct { first_pos: usize },
        /// Em-dash (U+2014) stylistic signature; first_pos is the first em-dash.
        em_dash_pattern: struct { first_pos: usize },
        /// Paired curly-quote stylistic signature; first_pos is the first quote.
        smart_quote_alternation: struct { first_pos: usize },
        /// AI-favored lexical pattern hit; first_pos is the match start.
        statistical_token_choice: struct { first_pos: usize },
        /// Over-regular marker placement impersonating a scheme; impersonated_scheme
        /// names the surfaced scheme, first_pos the first marker position.
        adversarial: struct { impersonated_scheme: []const u8, first_pos: usize },
        /// Multi-category invisible-marker mixing; anomaly_marker is the total
        /// invisible-marker count (attribution to a single scheme fails).
        unknown: struct { anomaly_marker: usize },

        /// Human-facing classification tag for this sub-threat.
        pub fn tag(self: SubThreat) []const u8 {
            return switch (self) {
                .nnbsp_boundary => "NnbspBoundary",
                .variation_selector_carrier => "VariationSelectorCarrier",
                .zwj_non_emoji => "ZwjNonEmoji",
                .default_ignorable_carrier => "DefaultIgnorableCarrier",
                .gpt5_zwsp_modulo => "Gpt5ZwspModulo",
                .em_dash_pattern => "EmDashPattern",
                .smart_quote_alternation => "SmartQuoteAlternation",
                .statistical_token_choice => "StatisticalTokenChoice",
                .adversarial => "Adversarial",
                .unknown => "Unknown",
            };
        }

        /// Map this sub-threat to the conceptual watermark cue class it probes
        /// for. Marker-encoded sub-threats route to pseudorandom_seq;
        /// vocabulary-bias to green_list_bias; stylistic-distribution to
        /// semantic_drift; unknown (multi-category mixing) implicates no single
        /// scheme.
        pub fn cueClass(self: SubThreat) ?CueClass {
            return switch (self) {
                .nnbsp_boundary,
                .variation_selector_carrier,
                .zwj_non_emoji,
                .default_ignorable_carrier,
                .gpt5_zwsp_modulo,
                .adversarial,
                => .pseudorandom_seq,
                .em_dash_pattern, .smart_quote_alternation => .semantic_drift,
                .statistical_token_choice => .green_list_bias,
                .unknown => null,
            };
        }
    };

    /// Top-level classification.
    pub const Classification = union(enum) {
        /// No watermark marker detected (semantically noWatermark).
        clear,
        /// A hazard: the fired sub-threat plus the implicated marker positions.
        hazard: struct { sub: SubThreat, positions: PosBuffer },

        /// True iff no watermark marker was detected.
        pub fn isClear(self: Classification) bool {
            return switch (self) {
                .clear => true,
                .hazard => false,
            };
        }

        /// Human-facing tag for a hazard, or null when clear.
        pub fn tag(self: Classification) ?[]const u8 {
            return switch (self) {
                .clear => null,
                .hazard => |h| h.sub.tag(),
            };
        }

        /// Implicated positions (empty when clear).
        pub fn positions(self: *const Classification) []const usize {
            switch (self.*) {
                .clear => return &[_]usize{},
                .hazard => return self.hazard.positions.slice(),
            }
        }
    };

    /// Verdict — the structured output of detect. marker_count is the count of
    /// codepoints matching the fired scheme's probe (0 when clear).
    pub const Verdict = struct {
        /// The scanned input codepoints.
        input: []const u32,
        /// The classification verdict.
        classify: Classification,
        /// Count of codepoints matching the fired scheme (0 when clear).
        marker_count: usize,
    };

    /// Optional context for the modulo-probe tolerances. Each field controls how
    /// strictly the corresponding probe checks its arithmetic-progression
    /// condition; the defaults of 0 require exact equality of consecutive gaps.
    pub const Context = struct {
        /// ZWSP-modulo tolerance. 0 requires the ZWSP-position arithmetic
        /// progression to be exact. k > 0 accepts position gaps within +/- k of
        /// the first gap, catching modulo schedules with light jitter.
        zwsp_modulo_tolerance: usize = 0,
        /// NNBSP-arithmetic tolerance (the adversarial probe). Same semantic as
        /// zwsp_modulo_tolerance but for the NNBSP positions.
        adversarial_tolerance: usize = 0,
    };

    // ── Emoji property table (bundled data/emoji-data.txt, Emoji rows) ───

    /// True iff cp has the Emoji = Yes property per the bundled
    /// data/emoji-data.txt. Scans the embedded table's Emoji rows on each call,
    /// mirroring the port's runtime data-parse idiom (see homoglyphTargetMatch);
    /// never consults a host emoji library. Each non-comment row is
    /// `<range> ; <property> # <comment>`; only rows whose property is exactly
    /// Emoji are kept.
    fn isEmoji(cp: u32) bool {
        var offset: usize = 0;
        while (nextLine(emoji_data_raw, &offset)) |raw_line| {
            const body = if (std.mem.indexOfScalar(u8, raw_line, '#')) |idx| raw_line[0..idx] else raw_line;
            const stripped = trimAscii(body);
            if (stripped.len == 0) continue;
            var fields = std.mem.splitScalar(u8, stripped, ';');
            const range_field = fields.next() orelse continue;
            const prop_field = fields.next() orelse continue;
            if (!std.mem.eql(u8, trimAscii(prop_field), "Emoji")) continue;
            const range = trimAscii(range_field);
            if (std.mem.indexOf(u8, range, "..")) |dot_idx| {
                const lo = parseHexU32(trimAscii(range[0..dot_idx])) orelse continue;
                const hi = parseHexU32(trimAscii(range[dot_idx + 2 ..])) orelse continue;
                if (lo <= cp and cp <= hi) return true;
            } else {
                const single = parseHexU32(range) orelse continue;
                if (single == cp) return true;
            }
        }
        return false;
    }

    // ── Codepoint probes ────────────────────────────────────────────────

    /// True iff cp is U+202F NARROW NO-BREAK SPACE.
    fn isNnbsp(cp: u32) bool {
        return cp == 0x202F;
    }

    /// True iff cp is U+200D ZERO WIDTH JOINER.
    fn isZwj(cp: u32) bool {
        return cp == 0x200D;
    }

    /// True iff cp is a Variation Selector — the basic block U+FE00..U+FE0F
    /// (VS1..VS16) or the Plane-14 IVS block U+E0100..U+E01EF (VS17..VS256).
    fn isVariationSelector(cp: u32) bool {
        return (cp >= 0xFE00 and cp <= 0xFE0F) or (cp >= 0xE0100 and cp <= 0xE01EF);
    }

    /// True iff cp is Default_Ignorable_Code_Point. Reuses the port's own UCD
    /// predicate, never a host normalizer.
    fn isDefaultIgnorable(cp: u32) bool {
        return isDefaultIgnorableCodepoint(cp);
    }

    /// True iff cp is U+200B ZERO WIDTH SPACE.
    fn isZwsp(cp: u32) bool {
        return cp == 0x200B;
    }

    /// True iff cp is U+2014 EM DASH.
    fn isEmDash(cp: u32) bool {
        return cp == 0x2014;
    }

    /// True iff cp is U+002D HYPHEN-MINUS (ASCII).
    fn isHyphenMinus(cp: u32) bool {
        return cp == 0x002D;
    }

    /// True iff cp is one of the four "curly" quotation marks: U+2018 / U+2019
    /// (single open/close) and U+201C / U+201D (double open/close).
    fn isCurlyQuote(cp: u32) bool {
        return cp == 0x2018 or cp == 0x2019 or cp == 0x201C or cp == 0x201D;
    }

    /// True iff cp is an ASCII straight quote — U+0022 (double) or U+0027
    /// (single / apostrophe).
    fn isStraightQuote(cp: u32) bool {
        return cp == 0x0022 or cp == 0x0027;
    }

    /// True iff cp is a residual Default_Ignorable — default-ignorable but neither
    /// a variation selector nor ZWJ (both handled by earlier probes).
    fn isResidualDi(cp: u32) bool {
        return isDefaultIgnorable(cp) and !@This().isVariationSelector(cp) and !isZwj(cp);
    }

    /// True iff input[i] is adjacent (immediate predecessor OR immediate
    /// successor) to an emoji codepoint. Two-sided check. Used by the VS and ZWJ
    /// probes to exclude legitimate emoji-context occurrences.
    fn isAdjacentToEmoji(input: []const u32, i: usize) bool {
        const prev_is_emoji = if (i == 0) false else isEmoji(input[i - 1]);
        const next_is_emoji = if (i + 1 < input.len) isEmoji(input[i + 1]) else false;
        return prev_is_emoji or next_is_emoji;
    }

    /// All positions in input matching predicate p.
    fn allPositions(comptime p: fn (u32) bool, input: []const u32) PosBuffer {
        var out = PosBuffer{};
        for (input, 0..) |cp, idx| {
            if (p(cp)) out.append(idx);
        }
        return out;
    }

    /// True iff positions forms an arithmetic progression with all consecutive
    /// gaps within tolerance of the first gap. Empty + singleton lists are
    /// vacuously arithmetic. positions is assumed ascending, so gaps are
    /// non-negative.
    fn positionsAreArithmeticWithin(positions: []const usize, tolerance: usize) bool {
        if (positions.len < 2) return true;
        const first_gap = positions[1] - positions[0];
        var i: usize = 0;
        while (i < positions.len - 1) : (i += 1) {
            const gap = positions[i + 1] - positions[i];
            if (!(gap <= first_gap + tolerance and first_gap <= gap + tolerance)) return false;
        }
        return true;
    }

    /// First start-position at which pattern appears as a contiguous sub-slice of
    /// input, or null if absent.
    fn containsSublist(pattern: []const u32, input: []const u32) ?usize {
        if (pattern.len == 0 or pattern.len > input.len) return null;
        const max_start = input.len - pattern.len;
        var start: usize = 0;
        while (start <= max_start) : (start += 1) {
            if (cpSlicesEqual(input[start .. start + pattern.len], pattern)) return start;
        }
        return null;
    }

    /// True iff any codepoint in input satisfies p.
    fn anyMatches(comptime p: fn (u32) bool, input: []const u32) bool {
        for (input) |cp| {
            if (p(cp)) return true;
        }
        return false;
    }

    /// The "AI-favored" lexical-pattern catalog (each word as its codepoint
    /// sequence), transcribed verbatim from the pinned aiFavoredVocabulary literal
    /// in the Lean spec (parsed from Ucd/Security/AiFavoredVocabulary.txt and
    /// drift-gated there against a fresh parse).
    const ai_favored_vocabulary = [_][]const u32{
        &[_]u32{ 100, 101, 108, 118, 101 },
        &[_]u32{ 100, 101, 108, 118, 105, 110, 103 },
        &[_]u32{ 116, 97, 112, 101, 115, 116, 114, 121 },
        &[_]u32{ 105, 110, 116, 114, 105, 99, 97, 116, 101 },
        &[_]u32{ 110, 117, 97, 110, 99, 101, 100 },
        &[_]u32{ 109, 111, 114, 101, 111, 118, 101, 114 },
        &[_]u32{ 102, 117, 114, 116, 104, 101, 114, 109, 111, 114, 101 },
        &[_]u32{ 114, 101, 97, 108, 109 },
        &[_]u32{ 101, 108, 117, 99, 105, 100, 97, 116, 101 },
        &[_]u32{ 115, 104, 111, 119, 99, 97, 115, 105, 110, 103 },
        &[_]u32{ 117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 115 },
        &[_]u32{ 117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 100 },
        &[_]u32{ 112, 105, 118, 111, 116, 97, 108 },
        &[_]u32{ 98, 111, 108, 115, 116, 101, 114 },
        &[_]u32{ 109, 117, 108, 116, 105, 102, 97, 99, 101, 116, 101, 100 },
        &[_]u32{ 116, 101, 115, 116, 97, 109, 101, 110, 116 },
        &[_]u32{ 102, 111, 115, 116, 101, 114 },
        &[_]u32{ 104, 111, 108, 105, 115, 116, 105, 99 },
        &[_]u32{ 112, 97, 114, 97, 100, 105, 103, 109 },
        &[_]u32{ 116, 114, 97, 110, 115, 102, 111, 114, 109, 97, 116, 105, 118, 101 },
        &[_]u32{ 115, 112, 101, 97, 114, 104, 101, 97, 100 },
        &[_]u32{ 109, 101, 116, 105, 99, 117, 108, 111, 117, 115 },
        &[_]u32{ 109, 101, 116, 105, 99, 117, 108, 111, 117, 115, 108, 121 },
        &[_]u32{ 101, 109, 112, 111, 119, 101, 114 },
        &[_]u32{ 101, 109, 112, 111, 119, 101, 114, 105, 110, 103 },
        &[_]u32{ 112, 114, 111, 102, 111, 117, 110, 100 },
        &[_]u32{ 112, 114, 111, 102, 111, 117, 110, 100, 108, 121 },
        &[_]u32{ 99, 111, 109, 112, 101, 108, 108, 105, 110, 103 },
        &[_]u32{ 99, 111, 109, 112, 114, 101, 104, 101, 110, 115, 105, 118, 101 },
        &[_]u32{ 99, 114, 117, 99, 105, 97, 108 },
        &[_]u32{ 100, 97, 117, 110, 116, 105, 110, 103 },
        &[_]u32{ 114, 111, 98, 117, 115, 116 },
        &[_]u32{ 115, 116, 114, 101, 97, 109, 108, 105, 110, 101 },
        &[_]u32{ 101, 110, 114, 105, 99, 104 },
        &[_]u32{ 101, 120, 101, 109, 112, 108, 105, 102, 121 },
        &[_]u32{ 99, 97, 112, 116, 105, 118, 97, 116, 105, 110, 103 },
        &[_]u32{ 100, 105, 115, 99, 101, 114, 110, 105, 110, 103 },
        &[_]u32{ 109, 101, 115, 109, 101, 114, 105, 122, 101 },
        &[_]u32{ 105, 110, 116, 114, 105, 99, 97, 116, 101, 108, 121 },
        &[_]u32{ 105, 109, 98, 117, 101 },
        &[_]u32{ 112, 108, 97, 121, 115, 32, 97, 32, 99, 114, 117, 99, 105, 97, 108, 32, 114, 111, 108, 101 },
        &[_]u32{ 112, 108, 97, 121, 115, 32, 97, 32, 112, 105, 118, 111, 116, 97, 108, 32, 114, 111, 108, 101 },
        &[_]u32{ 105, 116, 32, 105, 115, 32, 105, 109, 112, 111, 114, 116, 97, 110, 116, 32, 116, 111, 32, 110, 111, 116, 101 },
        &[_]u32{ 105, 116, 32, 105, 115, 32, 119, 111, 114, 116, 104, 32, 110, 111, 116, 105, 110, 103 },
        &[_]u32{ 105, 110, 32, 99, 111, 110, 99, 108, 117, 115, 105, 111, 110 },
        &[_]u32{ 105, 110, 32, 101, 115, 115, 101, 110, 99, 101 },
        &[_]u32{ 100, 101, 108, 118, 101, 32, 105, 110, 116, 111 },
        &[_]u32{ 100, 101, 108, 118, 105, 110, 103, 32, 105, 110, 116, 111 },
        &[_]u32{ 116, 97, 112, 101, 115, 116, 114, 121, 32, 111, 102 },
        &[_]u32{ 114, 101, 97, 108, 109, 32, 111, 102 },
    };

    // ── Top-level detection ─────────────────────────────────────────────

    /// The detection function. Runs every probe in the fixed priority order
    /// (most-specific first); the first hit wins. See the section header for the
    /// probe inventory and the ordering rationale.
    pub fn detectWithContext(ctx: Context, input: []const u32) @This().Verdict {
        const nnbsp_positions = allPositions(isNnbsp, input);
        const nnbsp_count = nnbsp_positions.len;

        // Probe 1: adversarial — NNBSP too-regular.
        const adversarial_fires = nnbsp_count >= 3 and
            positionsAreArithmeticWithin(nnbsp_positions.slice(), ctx.adversarial_tolerance);

        // Probe 2: gpt5ZwspModulo — ZWSP arithmetic progression.
        const zwsp_positions = allPositions(isZwsp, input);
        const zwsp_count = zwsp_positions.len;
        const zwsp_modulo_fires = zwsp_count >= 3 and
            positionsAreArithmeticWithin(zwsp_positions.slice(), ctx.zwsp_modulo_tolerance);

        // Variation selectors not adjacent to an emoji.
        var vs_non_emoji = PosBuffer{};
        const vs_all_pos = allPositions(@This().isVariationSelector, input);
        for (vs_all_pos.slice()) |i| {
            if (!isAdjacentToEmoji(input, i)) vs_non_emoji.append(i);
        }
        const vs_non_emoji_count = vs_non_emoji.len;

        // ZWJ not adjacent to an emoji.
        var zwj_non_emoji = PosBuffer{};
        const zwj_all_pos = allPositions(isZwj, input);
        for (zwj_all_pos.slice()) |i| {
            if (!isAdjacentToEmoji(input, i)) zwj_non_emoji.append(i);
        }
        const zwj_non_emoji_count = zwj_non_emoji.len;

        // Probe 7: smartQuoteAlternation — curly quotes only.
        const curly_positions = allPositions(isCurlyQuote, input);
        const curly_count = curly_positions.len;
        const has_straight_quote = anyMatches(isStraightQuote, input);
        const smart_quote_fires = curly_count >= 2 and !has_straight_quote;

        // Probe 8: emDashPattern — em-dashes without hyphen-minus.
        const em_dash_positions = allPositions(isEmDash, input);
        const em_dash_count = em_dash_positions.len;
        const has_hyphen_minus = anyMatches(isHyphenMinus, input);
        const em_dash_fires = em_dash_count >= 2 and !has_hyphen_minus;

        // Probe 9: statisticalTokenChoice — scan the pinned vocabulary. Each word
        // is compared as a contiguous sub-slice of the input.
        const vocab_hit: ?usize = blk: {
            for (ai_favored_vocabulary) |pattern| {
                if (containsSublist(pattern, input)) |pos| break :blk pos;
            }
            break :blk null;
        };

        // Residual default-ignorables (excluding VS and ZWJ, handled above).
        const di_positions = allPositions(isResidualDi, input);
        const di_count = di_positions.len;

        // Probe 3: unknown — invisible markers from >= 2 distinct categories.
        const category_count = @as(usize, @intFromBool(nnbsp_count > 0)) +
            @as(usize, @intFromBool(vs_non_emoji_count > 0)) +
            @as(usize, @intFromBool(zwj_non_emoji_count > 0)) +
            @as(usize, @intFromBool(di_count > 0));
        const unknown_fires = category_count >= 2;
        const total_invisible_count = nnbsp_count + vs_non_emoji_count + zwj_non_emoji_count + di_count;

        if (adversarial_fires) {
            const first_pos = if (nnbsp_count > 0) nnbsp_positions.items[0] else 0;
            return @This().Verdict{
                .input = input,
                .classify = .{ .hazard = .{
                    .sub = .{ .adversarial = .{ .impersonated_scheme = "nnbspBoundary", .first_pos = first_pos } },
                    .positions = nnbsp_positions,
                } },
                .marker_count = nnbsp_count,
            };
        } else if (zwsp_modulo_fires) {
            const first_pos = if (zwsp_count > 0) zwsp_positions.items[0] else 0;
            return @This().Verdict{
                .input = input,
                .classify = .{ .hazard = .{
                    .sub = .{ .gpt5_zwsp_modulo = .{ .first_pos = first_pos } },
                    .positions = zwsp_positions,
                } },
                .marker_count = zwsp_count,
            };
        } else if (unknown_fires) {
            var all_invisible = PosBuffer{};
            for (input, 0..) |cp, idx| {
                if (isNnbsp(cp) or @This().isVariationSelector(cp) or isZwj(cp) or isDefaultIgnorable(cp)) {
                    all_invisible.append(idx);
                }
            }
            return @This().Verdict{
                .input = input,
                .classify = .{ .hazard = .{
                    .sub = .{ .unknown = .{ .anomaly_marker = total_invisible_count } },
                    .positions = all_invisible,
                } },
                .marker_count = total_invisible_count,
            };
        } else if (nnbsp_count > 0) {
            return @This().Verdict{
                .input = input,
                .classify = .{ .hazard = .{
                    .sub = .{ .nnbsp_boundary = .{ .marker_count = nnbsp_count } },
                    .positions = nnbsp_positions,
                } },
                .marker_count = nnbsp_count,
            };
        } else if (vs_non_emoji_count > 0) {
            return @This().Verdict{
                .input = input,
                .classify = .{ .hazard = .{
                    .sub = .{ .variation_selector_carrier = .{ .marker_count = vs_non_emoji_count } },
                    .positions = vs_non_emoji,
                } },
                .marker_count = vs_non_emoji_count,
            };
        } else if (zwj_non_emoji_count > 0) {
            return @This().Verdict{
                .input = input,
                .classify = .{ .hazard = .{
                    .sub = .{ .zwj_non_emoji = .{ .marker_count = zwj_non_emoji_count } },
                    .positions = zwj_non_emoji,
                } },
                .marker_count = zwj_non_emoji_count,
            };
        } else if (smart_quote_fires) {
            const first_pos = if (curly_count > 0) curly_positions.items[0] else 0;
            return @This().Verdict{
                .input = input,
                .classify = .{ .hazard = .{
                    .sub = .{ .smart_quote_alternation = .{ .first_pos = first_pos } },
                    .positions = curly_positions,
                } },
                .marker_count = curly_count,
            };
        } else if (em_dash_fires) {
            const first_pos = if (em_dash_count > 0) em_dash_positions.items[0] else 0;
            return @This().Verdict{
                .input = input,
                .classify = .{ .hazard = .{
                    .sub = .{ .em_dash_pattern = .{ .first_pos = first_pos } },
                    .positions = em_dash_positions,
                } },
                .marker_count = em_dash_count,
            };
        } else if (vocab_hit) |pos| {
            var single = PosBuffer{};
            single.append(pos);
            return @This().Verdict{
                .input = input,
                .classify = .{ .hazard = .{
                    .sub = .{ .statistical_token_choice = .{ .first_pos = pos } },
                    .positions = single,
                } },
                .marker_count = 1,
            };
        } else if (di_count > 0) {
            return @This().Verdict{
                .input = input,
                .classify = .{ .hazard = .{
                    .sub = .{ .default_ignorable_carrier = .{ .marker_count = di_count } },
                    .positions = di_positions,
                } },
                .marker_count = di_count,
            };
        } else {
            return @This().Verdict{
                .input = input,
                .classify = .{ .clear = {} },
                .marker_count = 0,
            };
        }
    }

    /// Convenience wrapper over detectWithContext with the empty context —
    /// exact-arithmetic settings (zwsp_modulo_tolerance = 0,
    /// adversarial_tolerance = 0).
    pub fn detect(input: []const u32) @This().Verdict {
        return detectWithContext(Context{}, input);
    }
};

// ─────────────────────────────────────────────────────────────────────
// stream-safe-violation (form layer), mirroring
// Unicode.Security.Form.StreamSafeViolation and the verified Rust port
// ports/rust/src/security/form/stream_safe_violation.rs.
//
// Detects inputs whose consecutive non-starter run exceeds the UAX #15 §13
// streamSafeLimit of 30 — the canonical "Zalgo" shape (a single base
// codepoint followed by a long combining-mark run) that forces unbounded
// combining-mark buffers in receiver-side streaming normalization and is a
// known DoS vector. A codepoint is a non-starter iff its
// Canonical_Combining_Class is non-zero (UAX #15 D49); CCC is read from the
// port's own bundled UCD table via canonicalCombiningClass, never a host
// normalizer. Context-free: the single sub-threat streamSafeOverrun fires on
// the first non-starter run whose length exceeds the limit.
// ─────────────────────────────────────────────────────────────────────

pub const stream_safe_violation = struct {
    /// UAX #15 §13 Stream-Safe limit: the maximum number of consecutive
    /// non-starters permitted before a COMBINING GRAPHEME JOINER must be
    /// inserted.
    pub const STREAM_SAFE_LIMIT: usize = 30;

    /// True iff cp is a non-starter — a codepoint with non-zero
    /// Canonical_Combining_Class (UAX #15 D49). Starters have CCC = 0. Reads
    /// the port's own bundled UCD table, never a host normalizer.
    fn isNonStarter(cp: u32) bool {
        return canonicalCombiningClass(cp) != 0;
    }

    // ── §1 Run inventory ─────────────────────────────────────────────────

    /// First non-starter run whose length exceeds STREAM_SAFE_LIMIT, as
    /// (base_pos, run_len). Mirrors non_starter_runs then find: a run opens on
    /// the first non-starter, its start is fixed to that codepoint's absolute
    /// index, and it closes on the next starter or at end of input. Runs close
    /// in order, so the first run to close overrunning is the first overrun.
    fn firstOverrun(input: []const u32) ?struct { base_pos: usize, run_len: usize } {
        var cur_start: ?usize = null;
        var cur_len: usize = 0;
        for (input, 0..) |cp, i| {
            if (isNonStarter(cp)) {
                if (cur_start == null) cur_start = i;
                cur_len += 1;
            } else {
                if (cur_start) |s| {
                    if (cur_len > STREAM_SAFE_LIMIT) return .{ .base_pos = s, .run_len = cur_len };
                }
                cur_start = null;
                cur_len = 0;
            }
        }
        if (cur_start) |s| {
            if (cur_len > STREAM_SAFE_LIMIT) return .{ .base_pos = s, .run_len = cur_len };
        }
        return null;
    }

    /// Longest non-starter run length in input.
    fn maxRunLen(input: []const u32) usize {
        var acc: usize = 0;
        var cur_len: usize = 0;
        for (input) |cp| {
            if (isNonStarter(cp)) {
                cur_len += 1;
                if (cur_len > acc) acc = cur_len;
            } else {
                cur_len = 0;
            }
        }
        return acc;
    }

    /// Number of distinct non-starter runs that exceed STREAM_SAFE_LIMIT.
    fn overrunCount(input: []const u32) usize {
        var acc: usize = 0;
        var in_run = false;
        var cur_len: usize = 0;
        for (input) |cp| {
            if (isNonStarter(cp)) {
                in_run = true;
                cur_len += 1;
            } else {
                if (in_run and cur_len > STREAM_SAFE_LIMIT) acc += 1;
                in_run = false;
                cur_len = 0;
            }
        }
        if (in_run and cur_len > STREAM_SAFE_LIMIT) acc += 1;
        return acc;
    }

    /// Total non-starter codepoints in input (sum of all run lengths).
    fn totalNonStarters(input: []const u32) usize {
        var acc: usize = 0;
        for (input) |cp| {
            if (isNonStarter(cp)) acc += 1;
        }
        return acc;
    }

    // ── §2 Types ─────────────────────────────────────────────────────────

    /// Sub-threats this detector can fire.
    pub const SubThreat = union(enum) {
        /// The first non-starter run whose length exceeds STREAM_SAFE_LIMIT.
        /// base_pos is the index of the run's first non-starter codepoint;
        /// run_len is the run's length.
        stream_safe_overrun: struct { base_pos: usize, run_len: usize },

        /// Human-facing classification tag for this sub-threat.
        pub fn tag(self: SubThreat) []const u8 {
            return switch (self) {
                .stream_safe_overrun => "StreamSafeOverrun",
            };
        }

        /// Fully-qualified reason code for this sub-threat, matching the shared
        /// fixture's required_findings entry.
        pub fn reasonCode(self: SubThreat) []const u8 {
            return switch (self) {
                .stream_safe_overrun => "unicode.security.F.stream-safe-violation.StreamSafeOverrun",
            };
        }
    };

    /// Top-level classification.
    pub const Classification = union(enum) {
        /// No non-starter run exceeds the Stream-Safe limit.
        clear,
        /// A hazard was found: the sub-threat, its implicated positions, and any
        /// decoded bytes (always empty for this detector — the field mirrors the
        /// spec's Classification.hazard shape). The single sub-threat implicates
        /// exactly one position, so the buffer is single-slot.
        hazard: struct { sub: SubThreat, positions: [1]usize, decoded: []const u8 = &[_]u8{} },

        /// True iff the input is clear.
        pub fn isClear(self: Classification) bool {
            return switch (self) {
                .clear => true,
                .hazard => false,
            };
        }

        /// Human-facing tag for a hazard, or null when clear.
        pub fn tag(self: Classification) ?[]const u8 {
            return switch (self) {
                .clear => null,
                .hazard => |h| h.sub.tag(),
            };
        }

        /// Fully-qualified reason code for a hazard, or null when clear.
        pub fn reasonCode(self: Classification) ?[]const u8 {
            return switch (self) {
                .clear => null,
                .hazard => |h| h.sub.reasonCode(),
            };
        }

        /// Implicated positions (empty when clear).
        pub fn positions(self: *const Classification) []const usize {
            switch (self.*) {
                .clear => return &[_]usize{},
                .hazard => return self.hazard.positions[0..],
            }
        }
    };

    /// Verdict — the structured output of detect. The run-inventory summaries
    /// (max_run_len, overrun_count, total_non_starters) are exposed so
    /// downstream callers can size the buffer pressure a streaming normalizer
    /// would see.
    pub const Verdict = struct {
        /// The scanned input codepoints.
        input: []const u32,
        /// The classification verdict.
        classify: Classification,
        /// Longest non-starter run length in input.
        max_run_len: usize,
        /// Number of distinct non-starter runs exceeding the Stream-Safe limit.
        overrun_count: usize,
        /// Total non-starter codepoints in input.
        total_non_starters: usize,
    };

    // ── §3 Top-level detection ───────────────────────────────────────────

    /// The detection function. Fires streamSafeOverrun on the first
    /// non-starter run whose length exceeds STREAM_SAFE_LIMIT.
    pub fn detect(input: []const u32) @This().Verdict {
        const classification: Classification = if (firstOverrun(input)) |hit|
            .{ .hazard = .{
                .sub = .{ .stream_safe_overrun = .{ .base_pos = hit.base_pos, .run_len = hit.run_len } },
                .positions = .{hit.base_pos},
            } }
        else
            .{ .clear = {} };
        return @This().Verdict{
            .input = input,
            .classify = classification,
            .max_run_len = maxRunLen(input),
            .overrun_count = overrunCount(input),
            .total_non_starters = totalNonStarters(input),
        };
    }
};

// ─────────────────────────────────────────────────────────────────────
// EmojiZwjIntegrity (identity layer I3), mirroring
// Unicode.Security.Identity.EmojiZwjIntegrity and the verified Rust port
// ports/rust/src/security/identity/emoji_zwj_integrity.rs.
//
// An adversary crafts an emoji-shaped codepoint sequence containing one or
// more U+200D ZERO WIDTH JOINERs but violating the sanctioned RGI ZWJ-sequence
// shape (UTS #51) — by exceeding the RGI length cap, joining a non-emoji
// codepoint, emitting adjacent ZWJ pairs, or overflowing the skin-tone count.
// Any non-RGI ZWJ-containing sequence is renderer-dependent, and that renderer
// divergence is the attack surface.
//
// The registered RGI set and the ZWJ alphabet are parsed from the port's own
// bundled data/emoji-zwj-sequences.txt (never a host emoji library), scanned on
// each call in the port's runtime data-parse idiom (see isEmoji above). The
// skin-tone predicate is the inline U+1F3FB..U+1F3FF modifier range.
//
// Algorithm (one pass over input): collect ZWJ positions and the skin-tone
// count; short-circuit Clear when there are no ZWJs and the skin-tone count is
// at most 1; a registered RGI sequence is always Clear; otherwise the priority
// ladder DoubleZWJ → NonEmojiInjection → OverLength → SkinToneOverflow →
// UnregisteredSequence.
// ─────────────────────────────────────────────────────────────────────

pub const emoji_zwj_integrity = struct {
    /// Conservative cap on the length of a sanctioned RGI ZWJ sequence
    /// (maxRgiLength in the Lean spec). The longest current entry (a four-person
    /// family with skin tones) reaches ~13-14 codepoints; 16 is a safe upper
    /// bound.
    pub const MAX_RGI_LENGTH: usize = 16;

    /// The ZERO WIDTH JOINER codepoint.
    pub const ZWJ: u32 = 0x200D;

    /// Upper bound on the codepoint count of a single parsed RGI row's sequence
    /// field. The longest current entry is ~13-14 codepoints; 64 is a safe cap
    /// for the row scratch buffer. A row whose sequence exceeds this is treated
    /// as unparseable (it cannot be a registered target for any bounded input).
    const MAX_ROW_LEN: usize = 64;

    /// Upper bound on the number of implicated positions a hazard can carry
    /// before the bounded buffer saturates. Positions are a subset of input
    /// indices; the cap mirrors the port's other bounded position buffers
    /// (ai_watermark_detectability). Inputs longer than this saturate silently,
    /// which cannot change a classification tag.
    const MAX_POSITIONS: usize = 512;

    /// Bounded position buffer — a hazard's implicated codepoint indices.
    const PosBuffer = struct {
        items: [MAX_POSITIONS]usize = undefined,
        len: usize = 0,

        fn append(self: *PosBuffer, p: usize) void {
            if (self.len >= self.items.len) return;
            self.items[self.len] = p;
            self.len += 1;
        }

        fn slice(self: *const PosBuffer) []const usize {
            return self.items[0..self.len];
        }
    };

    // ── §3 RGI ZWJ-sequence data (bundled data/emoji-zwj-sequences.txt) ───

    /// Parse one data row's leading codepoint field into buf. Returns the count
    /// of codepoints, or null if the row is a comment/blank, has an empty
    /// sequence field, or contains a malformed / over-long token run. Mirrors
    /// parse_zwj_sequences: the body is the text before '#', the sequence is the
    /// field before the first ';', tokens are space-separated hex codepoints.
    fn parseRow(raw_line: []const u8, buf: *[MAX_ROW_LEN]u32) ?usize {
        const body = if (std.mem.indexOfScalar(u8, raw_line, '#')) |idx| raw_line[0..idx] else raw_line;
        const stripped = trimAscii(body);
        if (stripped.len == 0) return null;
        var fields = std.mem.splitScalar(u8, stripped, ';');
        const seq_field = fields.next() orelse return null;
        var count: usize = 0;
        var toks = std.mem.tokenizeAny(u8, seq_field, " \t\r\n");
        while (toks.next()) |tok| {
            const cp = parseHexU32(tok) orelse return null;
            if (count >= buf.len) return null;
            buf[count] = cp;
            count += 1;
        }
        if (count == 0) return null;
        return count;
    }

    /// True iff cps is exactly a registered RGI ZWJ sequence. Scans the bundled
    /// table on each call, comparing cps against each row's parsed sequence.
    pub fn isRegisteredZwjSequence(cps: []const u32) bool {
        var buf: [MAX_ROW_LEN]u32 = undefined;
        var offset: usize = 0;
        while (nextLine(emoji_zwj_sequences_raw, &offset)) |raw_line| {
            const count = parseRow(raw_line, &buf) orelse continue;
            if (cpSlicesEqual(buf[0..count], cps)) return true;
        }
        return false;
    }

    /// True iff cp appears at some position of a registered RGI ZWJ sequence,
    /// excluding the joiner U+200D itself — the ZWJ alphabet, the canonical
    /// "what may flank a ZWJ?" predicate. Scans the bundled table on each call.
    pub fn isEmojiTarget(cp: u32) bool {
        if (cp == ZWJ) return false;
        var buf: [MAX_ROW_LEN]u32 = undefined;
        var offset: usize = 0;
        while (nextLine(emoji_zwj_sequences_raw, &offset)) |raw_line| {
            const count = parseRow(raw_line, &buf) orelse continue;
            for (buf[0..count]) |row_cp| {
                if (row_cp != ZWJ and row_cp == cp) return true;
            }
        }
        return false;
    }

    // ── §4 Core predicates ───────────────────────────────────────────────

    /// True iff cp is the ZWJ codepoint.
    pub fn isZwj(cp: u32) bool {
        return cp == ZWJ;
    }

    /// True iff cp is an emoji skin-tone modifier (U+1F3FB..U+1F3FF). The port's
    /// inline modifier range; no host emoji library is consulted.
    pub fn isEmojiModifier(cp: u32) bool {
        return cp >= 0x1F3FB and cp <= 0x1F3FF;
    }

    /// Positions of every ZWJ in input.
    fn zwjPositions(input: []const u32) PosBuffer {
        var out = PosBuffer{};
        for (input, 0..) |cp, idx| {
            if (isZwj(cp)) out.append(idx);
        }
        return out;
    }

    /// Count of skin-tone modifier codepoints.
    fn skinToneCount(input: []const u32) usize {
        var count: usize = 0;
        for (input) |cp| {
            if (isEmojiModifier(cp)) count += 1;
        }
        return count;
    }

    /// Positions of the first ZWJ in each ZWJ-ZWJ adjacent pair.
    fn doubleZwjPositions(input: []const u32) PosBuffer {
        var out = PosBuffer{};
        var idx: usize = 0;
        while (idx < input.len) : (idx += 1) {
            if (idx + 1 < input.len) {
                if (isZwj(input[idx]) and isZwj(input[idx + 1])) out.append(idx);
            }
        }
        return out;
    }

    /// A ZWJ flanked by a non-emoji codepoint (or sitting at an input edge), as
    /// (zwj_pos, offending_cp).
    const Injection = struct { zwj_pos: usize, non_emoji_cp: u32 };

    /// The first ZWJ position where either neighbour is a non-emoji codepoint. A
    /// ZWJ at an input edge (no preceding or no following codepoint) is itself an
    /// injection-class hazard, reported with offending codepoint 0.
    fn firstNonEmojiInjection(input: []const u32) ?Injection {
        var idx: usize = 0;
        while (idx < input.len) : (idx += 1) {
            if (!isZwj(input[idx])) continue;
            const prev: ?u32 = if (idx == 0) null else input[idx - 1];
            const next: ?u32 = if (idx + 1 < input.len) input[idx + 1] else null;
            if (prev) |prev_cp| {
                if (next) |next_cp| {
                    if (!isEmojiTarget(prev_cp)) {
                        return Injection{ .zwj_pos = idx, .non_emoji_cp = prev_cp };
                    } else if (!isEmojiTarget(next_cp)) {
                        return Injection{ .zwj_pos = idx, .non_emoji_cp = next_cp };
                    }
                } else {
                    // (Some prev, None next): trailing-edge ZWJ.
                    return Injection{ .zwj_pos = idx, .non_emoji_cp = 0 };
                }
            } else {
                // (None prev, _): leading-edge ZWJ.
                return Injection{ .zwj_pos = idx, .non_emoji_cp = 0 };
            }
        }
        return null;
    }

    // ── §2 Types ─────────────────────────────────────────────────────────

    /// Sub-threat enumeration, in priority order.
    pub const SubThreat = union(enum) {
        /// ZWJ-ZWJ adjacency; positions are the first ZWJ of each adjacent pair.
        double_zwj: struct { positions: PosBuffer },
        /// A ZWJ flanked by a non-emoji codepoint (or at an input edge). zwj_pos
        /// is the offending ZWJ; non_emoji_cp is the flanking codepoint (0 for an
        /// edge ZWJ).
        non_emoji_injection: struct { zwj_pos: usize, non_emoji_cp: u32 },
        /// The sequence is longer than MAX_RGI_LENGTH. length is the observed
        /// length; max_length is the cap that was exceeded.
        over_length: struct { length: usize, max_length: usize },
        /// Five or more skin-tone modifiers (the family-emoji maximum is four).
        skin_tone_overflow: struct { count: usize },
        /// ZWJs are present and no other sub-threat matched, but the sequence is
        /// not registered. chain_len is the length of the unregistered ZWJ chain.
        unregistered_sequence: struct { chain_len: usize },

        /// Human-facing classification tag for this sub-threat.
        pub fn tag(self: SubThreat) []const u8 {
            return switch (self) {
                .double_zwj => "DoubleZWJ",
                .non_emoji_injection => "NonEmojiInjection",
                .over_length => "OverLength",
                .skin_tone_overflow => "SkinToneOverflow",
                .unregistered_sequence => "UnregisteredSequence",
            };
        }

        /// Fully-qualified reason code for this sub-threat, matching the shared
        /// fixture's required_findings entry.
        pub fn reasonCode(self: SubThreat) []const u8 {
            return switch (self) {
                .double_zwj => "unicode.security.I.emoji-zwj-integrity.DoubleZWJ",
                .non_emoji_injection => "unicode.security.I.emoji-zwj-integrity.NonEmojiInjection",
                .over_length => "unicode.security.I.emoji-zwj-integrity.OverLength",
                .skin_tone_overflow => "unicode.security.I.emoji-zwj-integrity.SkinToneOverflow",
                .unregistered_sequence => "unicode.security.I.emoji-zwj-integrity.UnregisteredSequence",
            };
        }
    };

    /// Top-level classification.
    pub const Classification = union(enum) {
        /// A well-formed or non-ZWJ input.
        clear,
        /// A hazard: the fired sub-threat, the implicated positions, and the
        /// (always-empty for this detector) decoded-byte projection, kept for
        /// shape parity with the Lean Classification.hazard.
        hazard: struct { sub: SubThreat, positions: PosBuffer, decoded: []const u8 = &[_]u8{} },

        /// True iff the classification is clear.
        pub fn isClear(self: Classification) bool {
            return switch (self) {
                .clear => true,
                .hazard => false,
            };
        }

        /// Human-facing tag for a hazard, or null when clear.
        pub fn tag(self: Classification) ?[]const u8 {
            return switch (self) {
                .clear => null,
                .hazard => |h| h.sub.tag(),
            };
        }

        /// Fully-qualified reason code for a hazard, or null when clear.
        pub fn reasonCode(self: Classification) ?[]const u8 {
            return switch (self) {
                .clear => null,
                .hazard => |h| h.sub.reasonCode(),
            };
        }

        /// Implicated positions (empty when clear).
        pub fn positions(self: *const Classification) []const usize {
            switch (self.*) {
                .clear => return &[_]usize{},
                .hazard => return self.hazard.positions.slice(),
            }
        }
    };

    /// Verdict — the structured output of detect (mirrors the Lean Verdict).
    pub const Verdict = struct {
        /// The scanned input codepoints.
        input: []const u32,
        /// The classification verdict.
        classify: Classification,
        /// Positions of every ZWJ in the input.
        zwj_positions: PosBuffer,
        /// The chain length (0 when there are no ZWJs, else the input length).
        chain_length: usize,
        /// True iff the input is exactly a registered RGI ZWJ sequence.
        is_registered_rgi: bool,
        /// Count of skin-tone modifier codepoints (U+1F3FB..U+1F3FF).
        skin_tone_count: usize,
    };

    // ── §5 Top-level detection ───────────────────────────────────────────

    /// The EmojiZwjIntegrity detection function.
    pub fn detect(input: []const u32) @This().Verdict {
        const zwjs = zwjPositions(input);
        const st_count = skinToneCount(input);
        const is_rgi = isRegisteredZwjSequence(input);
        const chain_len: usize = if (zwjs.len == 0) 0 else input.len;

        if (zwjs.len == 0 and st_count <= 1) {
            return @This().Verdict{
                .input = input,
                .classify = .{ .clear = {} },
                .zwj_positions = PosBuffer{},
                .chain_length = 0,
                .is_registered_rgi = is_rgi,
                .skin_tone_count = st_count,
            };
        }

        const classification: Classification = blk: {
            if (is_rgi) {
                // Phase 3: a registered RGI sequence is always clear.
                break :blk .{ .clear = {} };
            }
            // Phase 4.1: ZWJ-ZWJ adjacency.
            const dzwj = doubleZwjPositions(input);
            if (dzwj.len != 0) {
                break :blk .{ .hazard = .{
                    .sub = .{ .double_zwj = .{ .positions = dzwj } },
                    .positions = dzwj,
                } };
            }
            // Phase 4.2: ZWJ adjacent to a non-emoji codepoint.
            if (firstNonEmojiInjection(input)) |hit| {
                var pos = PosBuffer{};
                pos.append(hit.zwj_pos);
                break :blk .{ .hazard = .{
                    .sub = .{ .non_emoji_injection = .{ .zwj_pos = hit.zwj_pos, .non_emoji_cp = hit.non_emoji_cp } },
                    .positions = pos,
                } };
            }
            // Phase 4.3: length cap.
            if (input.len > MAX_RGI_LENGTH) {
                break :blk .{ .hazard = .{
                    .sub = .{ .over_length = .{ .length = input.len, .max_length = MAX_RGI_LENGTH } },
                    .positions = PosBuffer{},
                } };
            }
            // Phase 4.4: skin-tone overflow.
            if (st_count >= 5) {
                break :blk .{ .hazard = .{
                    .sub = .{ .skin_tone_overflow = .{ .count = st_count } },
                    .positions = PosBuffer{},
                } };
            }
            // Phase 4.5: catch-all for unregistered ZWJ sequences.
            if (zwjs.len != 0) {
                break :blk .{ .hazard = .{
                    .sub = .{ .unregistered_sequence = .{ .chain_len = input.len } },
                    .positions = zwjs,
                } };
            }
            break :blk .{ .clear = {} };
        };

        return @This().Verdict{
            .input = input,
            .classify = classification,
            .zwj_positions = zwjs,
            .chain_length = chain_len,
            .is_registered_rgi = is_rgi,
            .skin_tone_count = st_count,
        };
    }
};

// ─────────────────────────────────────────────────────────────────────
// Grapheme_Cluster_Break = Extend predicate (reused by RendererDivergence).
//
// The port carries no precompiled Grapheme_Cluster_Break table, so the
// GCB = Extend class is derived from the two bundled property tables the
// standard's GCB assignment draws it from (UAX #29 §3.1): a codepoint is
// GCB = Extend iff it has Grapheme_Extend = Yes (parsed from the bundled
// data/DerivedCoreProperties.txt) or Emoji_Modifier = Yes (the port's own
// inline U+1F3FB..U+1F3FF range, reused from emoji_zwj_integrity). This
// union is byte-identical to the canonical GCB Extend range set: the joiner
// U+200D is not Grapheme_Extend (it is GCB = ZWJ, its own class) and so is
// excluded, matching the Standard. No host segmentation library is consulted.
// ─────────────────────────────────────────────────────────────────────

/// True iff cp has Grapheme_Extend = Yes per the bundled
/// data/DerivedCoreProperties.txt. Scans the embedded table's Grapheme_Extend
/// rows on each call, mirroring the port's runtime property-parse idiom (see
/// emoji_zwj_integrity.isEmoji). Each non-comment row is
/// `<range> ; <property> # <comment>`; only rows whose property is exactly
/// Grapheme_Extend are kept.
fn hasGraphemeExtendProperty(cp: u32) bool {
    var offset: usize = 0;
    while (nextLine(derived_core_properties_raw, &offset)) |raw_line| {
        const body = if (std.mem.indexOfScalar(u8, raw_line, '#')) |idx| raw_line[0..idx] else raw_line;
        const stripped = trimAscii(body);
        if (stripped.len == 0) continue;
        var fields = std.mem.splitScalar(u8, stripped, ';');
        const range_field = fields.next() orelse continue;
        const prop_field = fields.next() orelse continue;
        if (!std.mem.eql(u8, trimAscii(prop_field), "Grapheme_Extend")) continue;
        const range = trimAscii(range_field);
        if (std.mem.indexOf(u8, range, "..")) |dot_idx| {
            const lo = parseHexU32(trimAscii(range[0..dot_idx])) orelse continue;
            const hi = parseHexU32(trimAscii(range[dot_idx + 2 ..])) orelse continue;
            if (lo <= cp and cp <= hi) return true;
        } else {
            const single = parseHexU32(range) orelse continue;
            if (single == cp) return true;
        }
    }
    return false;
}

/// True iff cp has Grapheme_Cluster_Break = Extend — the combining-mark class
/// UAX #29 GB9 attaches to a preceding base. Grapheme_Extend ∪ Emoji_Modifier.
fn isGraphemeExtend(cp: u32) bool {
    return hasGraphemeExtendProperty(cp) or emoji_zwj_integrity.isEmojiModifier(cp);
}

// ─────────────────────────────────────────────────────────────────────
// UTS #39 Identifier_Status = Allowed predicate.
//
// The port carries no precompiled Identifier_Status table, so the Allowed
// set is derived at runtime from the bundled data/IdentifierStatus.txt (UCD
// 17.0.0), scanned on each call exactly as isGraphemeExtend scans
// DerivedCoreProperties.txt. Every non-comment row is
// `<range> ; Identifier_Status # comment`; only the value Allowed is listed,
// and by the table's `@missing: 0000..10FFFF; Restricted` default every code
// point not covered by an Allowed row is Restricted. The predicate therefore
// keeps rows whose value is exactly Allowed and reports membership. No host
// identifier library is consulted.
// ─────────────────────────────────────────────────────────────────────

/// True iff cp has Identifier_Status = Allowed per the bundled
/// data/IdentifierStatus.txt. Mirrors the port's runtime property-parse idiom
/// (see hasGraphemeExtendProperty): split each row on ';', keep only rows whose
/// value field is exactly Allowed, and test the code point against the row's
/// single value or `lo..hi` range.
fn isIdAllowed(cp: u32) bool {
    var offset: usize = 0;
    while (nextLine(identifier_status_raw, &offset)) |raw_line| {
        const body = if (std.mem.indexOfScalar(u8, raw_line, '#')) |idx| raw_line[0..idx] else raw_line;
        const stripped = trimAscii(body);
        if (stripped.len == 0) continue;
        var fields = std.mem.splitScalar(u8, stripped, ';');
        const range_field = fields.next() orelse continue;
        const status_field = fields.next() orelse continue;
        if (!std.mem.eql(u8, trimAscii(status_field), "Allowed")) continue;
        const range = trimAscii(range_field);
        if (std.mem.indexOf(u8, range, "..")) |dot_idx| {
            const lo = parseHexU32(trimAscii(range[0..dot_idx])) orelse continue;
            const hi = parseHexU32(trimAscii(range[dot_idx + 2 ..])) orelse continue;
            if (lo <= cp and cp <= hi) return true;
        } else {
            const single = parseHexU32(range) orelse continue;
            if (single == cp) return true;
        }
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────
// UAX #31 default-identifier admissibility predicate.
//
// The port carries no precompiled XID_Start / XID_Continue table, so the two
// derived core properties are read at runtime from the already-bundled
// data/DerivedCoreProperties.txt, scanned on each call exactly as
// hasGraphemeExtendProperty scans that same table for Grapheme_Extend. From
// them the reference chain is reproduced verbatim:
//   is_default_id_start(cp)    = XID_Start(cp) ∨ cp == 0x005F LOW LINE
//   is_default_id_continue(cp) = XID_Continue(cp)
//   is_default_identifier(cps) = cps nonempty ∧ start(cps[0]) ∧ every
//                                cps[1..] a continue
//   is_allowed_identifier(cps) = is_default_identifier(cps) ∧ every cp Allowed
// The final Allowed check reuses the port's own isIdAllowed. No host identifier
// library is consulted and no new data file is introduced.
// ─────────────────────────────────────────────────────────────────────

/// True iff cp is listed under the given DerivedCoreProperties.txt property
/// (exact value-field match). Scans the embedded table on each call, mirroring
/// hasGraphemeExtendProperty: split each row on ';', keep only rows whose value
/// field equals property, and test cp against the row's single value or `lo..hi`
/// range.
fn hasDerivedCoreProperty(cp: u32, property: []const u8) bool {
    var offset: usize = 0;
    while (nextLine(derived_core_properties_raw, &offset)) |raw_line| {
        const body = if (std.mem.indexOfScalar(u8, raw_line, '#')) |idx| raw_line[0..idx] else raw_line;
        const stripped = trimAscii(body);
        if (stripped.len == 0) continue;
        var fields = std.mem.splitScalar(u8, stripped, ';');
        const range_field = fields.next() orelse continue;
        const prop_field = fields.next() orelse continue;
        if (!std.mem.eql(u8, trimAscii(prop_field), property)) continue;
        const range = trimAscii(range_field);
        if (std.mem.indexOf(u8, range, "..")) |dot_idx| {
            const lo = parseHexU32(trimAscii(range[0..dot_idx])) orelse continue;
            const hi = parseHexU32(trimAscii(range[dot_idx + 2 ..])) orelse continue;
            if (lo <= cp and cp <= hi) return true;
        } else {
            const single = parseHexU32(range) orelse continue;
            if (single == cp) return true;
        }
    }
    return false;
}

/// True iff cp has XID_Start = Yes per the bundled data/DerivedCoreProperties.txt.
fn isXidStart(cp: u32) bool {
    return hasDerivedCoreProperty(cp, "XID_Start");
}

/// True iff cp has XID_Continue = Yes per the bundled data/DerivedCoreProperties.txt.
fn isXidContinue(cp: u32) bool {
    return hasDerivedCoreProperty(cp, "XID_Continue");
}

/// UAX #31 default identifier start: XID_Start or U+005F LOW LINE.
fn isDefaultIdStart(cp: u32) bool {
    return isXidStart(cp) or cp == 0x005F;
}

/// UAX #31 default identifier continue: XID_Continue.
fn isDefaultIdContinue(cp: u32) bool {
    return isXidContinue(cp);
}

/// UAX #31 default identifier: nonempty, the first codepoint is a default-id
/// start and every remaining codepoint is a default-id continue.
fn isDefaultIdentifier(cps: []const u32) bool {
    if (cps.len == 0) return false;
    if (!isDefaultIdStart(cps[0])) return false;
    for (cps[1..]) |cp| {
        if (!isDefaultIdContinue(cp)) return false;
    }
    return true;
}

/// Whole-string UTS #39 / UAX #31 admissibility: a default identifier whose
/// every codepoint additionally has Identifier_Status = Allowed (isIdAllowed).
fn isAllowedIdentifier(cps: []const u32) bool {
    if (!isDefaultIdentifier(cps)) return false;
    for (cps) |cp| {
        if (!isIdAllowed(cp)) return false;
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────
// RendererDivergence detector (display layer D), mirroring
// Unicode.Security.Display.RendererDivergence and its byte-faithful Rust port
// ports/rust/src/security/display/renderer_divergence.rs.
//
// An adversary crafts content that renders one way in the auditor's renderer
// (a benign glyph or an empty span) and a different way in the consumer's
// renderer (a misleading glyph, a wider glyph, or a different sequence). This
// is the "fingerprint stability" family — clear inputs render the same across
// the renderer cohort the Standard documents as stable. The detector draws a
// three-value split surfaced through the clear/hazard carrier: an input is
// clear when none of the documented variance triggers fire, else it is
// classified by the first trigger in priority order.
//
// It reuses the port's own tables — the variation-selector set (file-scope
// isVariationSelector), the grapheme Extend class (isGraphemeExtend, above),
// the RGI ZWJ registry (emoji_zwj_integrity.isRegisteredZwjSequence), and the
// strong-bidi classes (file-scope isStrongLtr / isStrongRtl from the
// rtl-injection detector) — never a host rendering or shaping library.
//
// Sub-threats (priority order):
//   1. CombiningStackOverflow    Zalgo-like combining-mark stack >= 4 on a base.
//   2. VariationSelectorVariance any variation selector present.
//   3. UnregisteredZwjVariance   ZWJ-containing input not in the RGI ZWJ set.
//   4. FullwidthVariance         a fullwidth/halfwidth codepoint present.
//   5. MixedDirectionVariance    both strong-LTR and strong-RTL codepoints.
// ─────────────────────────────────────────────────────────────────────

pub const renderer_divergence = struct {
    /// The combining-mark stack depth (on a single base) at or beyond which the
    /// input is treated as a Zalgo-style rendering-variance hazard.
    pub const MIN_COMBINING_STACK: usize = 4;

    /// The ZERO WIDTH JOINER codepoint.
    pub const ZWJ: u32 = 0x200D;

    /// Upper bound on the number of implicated positions a hazard can carry
    /// before the bounded buffer saturates. This detector reports at most one
    /// position per hazard; the cap mirrors the port's other bounded position
    /// buffers. Inputs that would exceed it saturate silently, which cannot
    /// change a classification tag.
    const MAX_POSITIONS: usize = 512;

    /// Bounded position buffer — a hazard's implicated codepoint indices.
    const PosBuffer = struct {
        items: [MAX_POSITIONS]usize = undefined,
        len: usize = 0,

        fn append(self: *PosBuffer, p: usize) void {
            if (self.len >= self.items.len) return;
            self.items[self.len] = p;
            self.len += 1;
        }

        fn slice(self: *const PosBuffer) []const usize {
            return self.items[0..self.len];
        }
    };

    // ── §3 Core predicates (all reuse the port's own tables) ──────────────
    //
    // The variation-selector set, the GCB Extend class, and the fullwidth /
    // halfwidth block are the file-scope predicates isVariationSelector /
    // isGraphemeExtend / isFullwidthHalfwidth, bound here under distinct alias
    // names so the reuse is explicit and the file-scope declarations stay
    // reachable — a same-named container method would collide with them (Zig
    // reports an ambiguous reference). isZwj is the detector's own inline check.

    /// The port's file-scope variation-selector predicate (VS ranges
    /// U+FE00..U+FE0F, U+E0100..U+E01EF, U+180B..U+180D) — the same one the
    /// variation-selector-payload detector uses.
    const vsPredicate = isVariationSelector;

    /// The port's file-scope GCB Extend predicate (Grapheme_Extend ∪
    /// Emoji_Modifier), defined above this struct.
    const gcbExtendPredicate = isGraphemeExtend;

    /// The port's file-scope Halfwidth/Fullwidth Forms predicate
    /// (U+FF01..U+FFEF), the same one the homoglyph-confusable detector uses.
    const fwPredicate = isFullwidthHalfwidth;

    /// True iff cp is the ZWJ codepoint.
    pub fn isZwj(cp: u32) bool {
        return cp == ZWJ;
    }

    // ── §4 Sub-detectors ─────────────────────────────────────────────────

    fn countVs(input: []const u32) usize {
        var count: usize = 0;
        for (input) |cp| {
            if (vsPredicate(cp)) count += 1;
        }
        return count;
    }

    fn countCombining(input: []const u32) usize {
        var count: usize = 0;
        for (input) |cp| {
            if (gcbExtendPredicate(cp)) count += 1;
        }
        return count;
    }

    fn countFullwidth(input: []const u32) usize {
        var count: usize = 0;
        for (input) |cp| {
            if (fwPredicate(cp)) count += 1;
        }
        return count;
    }

    fn inputHasZwj(input: []const u32) bool {
        for (input) |cp| {
            if (isZwj(cp)) return true;
        }
        return false;
    }

    fn countStrongLtr(input: []const u32) usize {
        var count: usize = 0;
        for (input) |cp| {
            if (isStrongLtr(cp)) count += 1;
        }
        return count;
    }

    fn countStrongRtl(input: []const u32) usize {
        var count: usize = 0;
        for (input) |cp| {
            if (isStrongRtl(cp)) count += 1;
        }
        return count;
    }

    /// Position and codepoint of the first variation selector.
    const VsHit = struct { pos: usize, cp: u32 };
    fn firstVsPos(input: []const u32) ?VsHit {
        for (input, 0..) |cp, idx| {
            if (vsPredicate(cp)) return VsHit{ .pos = idx, .cp = cp };
        }
        return null;
    }

    /// Position of the first ZWJ.
    fn firstZwjPos(input: []const u32) ?usize {
        for (input, 0..) |cp, idx| {
            if (isZwj(cp)) return idx;
        }
        return null;
    }

    /// Position and codepoint of the first fullwidth/halfwidth codepoint.
    const FwHit = struct { pos: usize, cp: u32 };
    fn firstFullwidthPos(input: []const u32) ?FwHit {
        for (input, 0..) |cp, idx| {
            if (fwPredicate(cp)) return FwHit{ .pos = idx, .cp = cp };
        }
        return null;
    }

    /// The first base position (a non-Extend codepoint) immediately followed by
    /// exactly min_stack consecutive Extend codepoints. Returns
    /// (base_pos, min_stack) on hit.
    const StackHit = struct { base_pos: usize, stack_len: usize };
    fn firstCombiningStack(input: []const u32, min_stack: usize) ?StackHit {
        for (input, 0..) |cp, idx| {
            if (!gcbExtendPredicate(cp)) {
                const start = idx + 1;
                if (start + min_stack <= input.len) {
                    var all_extend = true;
                    var k: usize = 0;
                    while (k < min_stack) : (k += 1) {
                        if (!gcbExtendPredicate(input[start + k])) {
                            all_extend = false;
                            break;
                        }
                    }
                    if (all_extend) return StackHit{ .base_pos = idx, .stack_len = min_stack };
                }
            }
        }
        return null;
    }

    // ── §2 Types ─────────────────────────────────────────────────────────

    /// Sub-threat enumeration, in priority order.
    pub const SubThreat = union(enum) {
        /// A combining-mark stack of stack_len marks on the base at base_pos.
        combining_stack_overflow: struct { base_pos: usize, stack_len: usize },
        /// A variation selector at first_vs_pos (codepoint first_vs_cp).
        variation_selector_variance: struct { first_vs_pos: usize, first_vs_cp: u32 },
        /// A ZWJ-containing input not present in the registered RGI ZWJ set.
        unregistered_zwj_variance: struct { first_zwj_pos: usize },
        /// A fullwidth/halfwidth codepoint at first_fw_pos (codepoint first_fw_cp).
        fullwidth_variance: struct { first_fw_pos: usize, first_fw_cp: u32 },
        /// Both strong-LTR and strong-RTL codepoints in one input.
        mixed_direction_variance: struct { ltr_count: usize, rtl_count: usize },

        /// Human-facing classification tag for this sub-threat.
        pub fn tag(self: SubThreat) []const u8 {
            return switch (self) {
                .combining_stack_overflow => "CombiningStackOverflow",
                .variation_selector_variance => "VariationSelectorVariance",
                .unregistered_zwj_variance => "UnregisteredZwjVariance",
                .fullwidth_variance => "FullwidthVariance",
                .mixed_direction_variance => "MixedDirectionVariance",
            };
        }

        /// Fully-qualified reason code for this sub-threat, matching the shared
        /// fixture's required_findings entry.
        pub fn reasonCode(self: SubThreat) []const u8 {
            return switch (self) {
                .combining_stack_overflow => "unicode.security.D.renderer-divergence.CombiningStackOverflow",
                .variation_selector_variance => "unicode.security.D.renderer-divergence.VariationSelectorVariance",
                .unregistered_zwj_variance => "unicode.security.D.renderer-divergence.UnregisteredZwjVariance",
                .fullwidth_variance => "unicode.security.D.renderer-divergence.FullwidthVariance",
                .mixed_direction_variance => "unicode.security.D.renderer-divergence.MixedDirectionVariance",
            };
        }
    };

    /// Top-level classification (stable = clear).
    pub const Classification = union(enum) {
        /// Rendering is consistent across the documented renderer cohort.
        clear,
        /// A documented variance mode fired: the sub-threat, the implicated
        /// positions, and the (always-empty for this detector) decoded-byte
        /// projection, kept for shape parity with the Lean Classification.hazard.
        hazard: struct { sub: SubThreat, positions: PosBuffer, decoded: []const u8 = &[_]u8{} },

        /// True iff the classification is clear (i.e. stable).
        pub fn isClear(self: Classification) bool {
            return switch (self) {
                .clear => true,
                .hazard => false,
            };
        }

        /// Human-facing tag for a hazard, or null when clear.
        pub fn tag(self: Classification) ?[]const u8 {
            return switch (self) {
                .clear => null,
                .hazard => |h| h.sub.tag(),
            };
        }

        /// Fully-qualified reason code for a hazard, or null when clear.
        pub fn reasonCode(self: Classification) ?[]const u8 {
            return switch (self) {
                .clear => null,
                .hazard => |h| h.sub.reasonCode(),
            };
        }

        /// Implicated positions (empty when clear).
        pub fn positions(self: *const Classification) []const usize {
            switch (self.*) {
                .clear => return &[_]usize{},
                .hazard => return self.hazard.positions.slice(),
            }
        }
    };

    /// Verdict — the structured output of detect (mirrors the Lean Verdict).
    pub const Verdict = struct {
        /// The scanned input codepoints.
        input: []const u32,
        /// The classification verdict.
        classify: Classification,
        /// Count of variation selectors.
        vs_count: usize,
        /// Count of combining (Extend) marks.
        combining_count: usize,
        /// Count of fullwidth/halfwidth codepoints.
        fullwidth_count: usize,
        /// Whether the input contains any ZWJ.
        has_zwj: bool,
        /// Count of strong-LTR codepoints.
        strong_ltr_count: usize,
        /// Count of strong-RTL codepoints.
        strong_rtl_count: usize,
    };

    // ── §5 Top-level detection ───────────────────────────────────────────

    /// The RendererDivergence detection function.
    pub fn detect(input: []const u32) @This().Verdict {
        const vs_count = countVs(input);
        const combining_count = countCombining(input);
        const fullwidth_count = countFullwidth(input);
        const has_zwj = inputHasZwj(input);
        const ltr_count = countStrongLtr(input);
        const rtl_count = countStrongRtl(input);

        const classification: Classification = blk: {
            // Priority 1: combining-mark stack overflow (Zalgo).
            if (firstCombiningStack(input, MIN_COMBINING_STACK)) |hit| {
                var pos = PosBuffer{};
                pos.append(hit.base_pos);
                break :blk .{ .hazard = .{
                    .sub = .{ .combining_stack_overflow = .{ .base_pos = hit.base_pos, .stack_len = hit.stack_len } },
                    .positions = pos,
                } };
            }
            // Priority 2: any variation selector triggers presentation variance.
            if (firstVsPos(input)) |hit| {
                var pos = PosBuffer{};
                pos.append(hit.pos);
                break :blk .{ .hazard = .{
                    .sub = .{ .variation_selector_variance = .{ .first_vs_pos = hit.pos, .first_vs_cp = hit.cp } },
                    .positions = pos,
                } };
            }
            // Priority 3: ZWJ-containing input not in the registered RGI set.
            if (has_zwj and !emoji_zwj_integrity.isRegisteredZwjSequence(input)) {
                if (firstZwjPos(input)) |pos_idx| {
                    var pos = PosBuffer{};
                    pos.append(pos_idx);
                    break :blk .{ .hazard = .{
                        .sub = .{ .unregistered_zwj_variance = .{ .first_zwj_pos = pos_idx } },
                        .positions = pos,
                    } };
                } else {
                    break :blk .{ .clear = {} };
                }
            }
            // Priority 4: fullwidth/halfwidth.
            if (firstFullwidthPos(input)) |hit| {
                var pos = PosBuffer{};
                pos.append(hit.pos);
                break :blk .{ .hazard = .{
                    .sub = .{ .fullwidth_variance = .{ .first_fw_pos = hit.pos, .first_fw_cp = hit.cp } },
                    .positions = pos,
                } };
            }
            // Priority 5: mixed direction.
            if (ltr_count > 0 and rtl_count > 0) {
                break :blk .{ .hazard = .{
                    .sub = .{ .mixed_direction_variance = .{ .ltr_count = ltr_count, .rtl_count = rtl_count } },
                    .positions = PosBuffer{},
                } };
            }
            break :blk .{ .clear = {} };
        };

        return @This().Verdict{
            .input = input,
            .classify = classification,
            .vs_count = vs_count,
            .combining_count = combining_count,
            .fullwidth_count = fullwidth_count,
            .has_zwj = has_zwj,
            .strong_ltr_count = ltr_count,
            .strong_rtl_count = rtl_count,
        };
    }
};

// ─────────────────────────────────────────────────────────────────────
// FilenameDisguise detector (display layer D), mirroring
// Unicode.Security.Display.FilenameDisguise and its byte-faithful Rust
// reference implementation.
//
// An adversary delivers a file whose rendered name looks like a benign type
// (document.txt) but whose actual byte extension is executable — the canonical
// attack inserts U+202E RIGHT-TO-LEFT OVERRIDE so document<RLO>txt.exe renders
// as document exe.txt. Detection is presentation- and language-agnostic: it
// surfaces every codepoint that could cause display-vs-byte divergence in the
// filename — any bidi format-control anywhere, and any fullwidth/halfwidth or
// combining (grapheme Extend) codepoint in the extension region (after the last
// dot). Native-RTL names with no bidi controls clear.
//
// It reuses the port's own tables — the bidi-format-control set (file-scope
// isBidiFormatControl from the bidi-control-balance / rtl-injection detectors),
// the grapheme Extend class (file-scope isGraphemeExtend, the same one
// RendererDivergence uses), and the fullwidth/halfwidth block (file-scope
// isFullwidthHalfwidth) — never a host filesystem or rendering library.
//
// Sub-threats (priority order):
//   1. RloFlip            any bidi format-control in the input.
//   2. WidthClassExt      a fullwidth/halfwidth codepoint in the extension.
//   3. CombiningInExt     a combining (grapheme Extend) codepoint in the extension.
//   4. MultipleExtensions >= 3 dots (advisory; e.g. legitimate .tar.gz.sig).
// ─────────────────────────────────────────────────────────────────────

pub const filename_disguise = struct {
    /// The number of dot separators at or beyond which the input is treated as a
    /// multiple-extensions advisory hazard.
    pub const MIN_MULTI_EXT_DOTS: usize = 3;

    /// Upper bound on the number of implicated positions a hazard can carry
    /// before the bounded buffer saturates. MultipleExtensions reports every dot
    /// position; the other sub-threats report a single position. Inputs that
    /// would exceed the cap saturate silently, which cannot change a
    /// classification tag.
    const MAX_POSITIONS: usize = 512;

    /// Bounded position buffer — a hazard's implicated codepoint indices.
    const PosBuffer = struct {
        items: [MAX_POSITIONS]usize = undefined,
        len: usize = 0,

        fn append(self: *PosBuffer, p: usize) void {
            if (self.len >= self.items.len) return;
            self.items[self.len] = p;
            self.len += 1;
        }

        fn slice(self: *const PosBuffer) []const usize {
            return self.items[0..self.len];
        }
    };

    // ── §2 Core predicates (all reuse the port's own tables) ──────────────
    //
    // The bidi-format-control set, the GCB Extend class, and the fullwidth /
    // halfwidth block are the file-scope predicates isBidiFormatControl /
    // isGraphemeExtend / isFullwidthHalfwidth, bound here under distinct alias
    // names so the reuse is explicit and the file-scope declarations stay
    // reachable — a same-named container method would collide with them (Zig
    // reports an ambiguous reference). isAsciiDot is the detector's own inline
    // check for U+002E FULL STOP.

    /// The port's file-scope bidi-format-control predicate (override/embedding
    /// class U+202A..U+202E and isolate class U+2066..U+2069) — the same one the
    /// bidi-control-balance and rtl-injection detectors use.
    const bidiControlPredicate = isBidiFormatControl;

    /// The port's file-scope GCB Extend predicate (Grapheme_Extend ∪
    /// Emoji_Modifier), the same one RendererDivergence uses.
    const gcbExtendPredicate = isGraphemeExtend;

    /// The port's file-scope Halfwidth/Fullwidth Forms predicate
    /// (U+FF01..U+FFEF), the same one the homoglyph-confusable detector uses.
    const fwPredicate = isFullwidthHalfwidth;

    /// True iff cp is U+002E FULL STOP (the extension separator).
    pub fn isAsciiDot(cp: u32) bool {
        return cp == 0x002E;
    }

    // ── §3 Sub-detectors ─────────────────────────────────────────────────

    /// Positions of every dot in input, into a bounded buffer.
    fn dotPositions(input: []const u32) PosBuffer {
        var buf = PosBuffer{};
        for (input, 0..) |cp, idx| {
            if (isAsciiDot(cp)) buf.append(idx);
        }
        return buf;
    }

    fn countBidiControl(input: []const u32) usize {
        var count: usize = 0;
        for (input) |cp| {
            if (bidiControlPredicate(cp)) count += 1;
        }
        return count;
    }

    /// Position and codepoint of the first bidi format-control.
    const CtlHit = struct { pos: usize, cp: u32 };
    fn firstBidiControl(input: []const u32) ?CtlHit {
        for (input, 0..) |cp, idx| {
            if (bidiControlPredicate(cp)) return CtlHit{ .pos = idx, .cp = cp };
        }
        return null;
    }

    /// Position and codepoint of the first fullwidth/halfwidth codepoint at or
    /// after start.
    const FwHit = struct { pos: usize, cp: u32 };
    fn firstFullwidthFrom(input: []const u32, start: usize) ?FwHit {
        for (input, 0..) |cp, idx| {
            if (idx >= start and fwPredicate(cp)) return FwHit{ .pos = idx, .cp = cp };
        }
        return null;
    }

    /// Position and codepoint of the first Extend codepoint at or after start.
    const ExtHit = struct { pos: usize, cp: u32 };
    fn firstExtendFrom(input: []const u32, start: usize) ?ExtHit {
        for (input, 0..) |cp, idx| {
            if (idx >= start and gcbExtendPredicate(cp)) return ExtHit{ .pos = idx, .cp = cp };
        }
        return null;
    }

    /// Count of fullwidth/halfwidth codepoints at or after start.
    fn countFullwidthFrom(input: []const u32, start: usize) usize {
        var count: usize = 0;
        for (input, 0..) |cp, idx| {
            if (idx >= start and fwPredicate(cp)) count += 1;
        }
        return count;
    }

    /// Count of Extend codepoints at or after start.
    fn countExtendFrom(input: []const u32, start: usize) usize {
        var count: usize = 0;
        for (input, 0..) |cp, idx| {
            if (idx >= start and gcbExtendPredicate(cp)) count += 1;
        }
        return count;
    }

    // ── §1 Types ─────────────────────────────────────────────────────────

    /// Sub-threat enumeration, in priority order.
    pub const SubThreat = union(enum) {
        /// A bidi format-control at position (codepoint control_cp).
        rlo_flip: struct { position: usize, control_cp: u32 },
        /// A fullwidth/halfwidth codepoint in the extension, at position.
        width_class_ext: struct { position: usize, cp: u32 },
        /// A combining (grapheme Extend) codepoint in the extension, at position.
        combining_in_ext: struct { position: usize, cp: u32 },
        /// Three or more dot separators (advisory).
        multiple_extensions: struct { dot_count: usize },

        /// Human-facing classification tag for this sub-threat.
        pub fn tag(self: SubThreat) []const u8 {
            return switch (self) {
                .rlo_flip => "RloFlip",
                .width_class_ext => "WidthClassExt",
                .combining_in_ext => "CombiningInExt",
                .multiple_extensions => "MultipleExtensions",
            };
        }

        /// Fully-qualified reason code for this sub-threat, matching the shared
        /// fixture's required_findings entry.
        pub fn reasonCode(self: SubThreat) []const u8 {
            return switch (self) {
                .rlo_flip => "unicode.security.D.filename-disguise.RloFlip",
                .width_class_ext => "unicode.security.D.filename-disguise.WidthClassExt",
                .combining_in_ext => "unicode.security.D.filename-disguise.CombiningInExt",
                .multiple_extensions => "unicode.security.D.filename-disguise.MultipleExtensions",
            };
        }
    };

    /// Top-level classification (clear = no disguise trigger present).
    pub const Classification = union(enum) {
        /// No disguise trigger present.
        clear,
        /// A disguise trigger fired: the sub-threat, the implicated positions,
        /// and the (always-empty for this detector) decoded-byte projection,
        /// kept for shape parity with the Lean Classification.hazard.
        hazard: struct { sub: SubThreat, positions: PosBuffer, decoded: []const u8 = &[_]u8{} },

        /// True iff the classification is clear.
        pub fn isClear(self: Classification) bool {
            return switch (self) {
                .clear => true,
                .hazard => false,
            };
        }

        /// Human-facing tag for a hazard, or null when clear.
        pub fn tag(self: Classification) ?[]const u8 {
            return switch (self) {
                .clear => null,
                .hazard => |h| h.sub.tag(),
            };
        }

        /// Fully-qualified reason code for a hazard, or null when clear.
        pub fn reasonCode(self: Classification) ?[]const u8 {
            return switch (self) {
                .clear => null,
                .hazard => |h| h.sub.reasonCode(),
            };
        }

        /// Implicated positions (empty when clear).
        pub fn positions(self: *const Classification) []const usize {
            switch (self.*) {
                .clear => return &[_]usize{},
                .hazard => return self.hazard.positions.slice(),
            }
        }
    };

    /// Verdict — the structured output of detect (mirrors the Lean Verdict).
    pub const Verdict = struct {
        /// The scanned input codepoints.
        input: []const u32,
        /// The classification verdict.
        classify: Classification,
        /// Positions of every dot separator.
        dot_positions: PosBuffer,
        /// Position of the last dot (the extension separator), if any.
        last_dot_pos: ?usize,
        /// Count of bidi format-controls anywhere in the input.
        bidi_control_count: usize,
        /// Count of fullwidth/halfwidth codepoints in the extension region.
        fullwidth_in_ext: usize,
        /// Count of combining (Extend) codepoints in the extension region.
        combining_in_ext: usize,
    };

    // ── §4 Top-level detection ───────────────────────────────────────────

    /// The FilenameDisguise detection function.
    pub fn detect(input: []const u32) @This().Verdict {
        const dots = dotPositions(input);
        const last_dot: ?usize = if (dots.len == 0) null else dots.items[dots.len - 1];
        const ext_start: usize = if (last_dot) |p| p + 1 else input.len;
        const bidi_count = countBidiControl(input);
        const fw_in_ext = countFullwidthFrom(input, ext_start);
        const ext_in_ext = countExtendFrom(input, ext_start);

        const classification: Classification = blk: {
            // Priority 1: any bidi format-control anywhere.
            if (firstBidiControl(input)) |hit| {
                var pos = PosBuffer{};
                pos.append(hit.pos);
                break :blk .{ .hazard = .{
                    .sub = .{ .rlo_flip = .{ .position = hit.pos, .control_cp = hit.cp } },
                    .positions = pos,
                } };
            }
            // Priority 2: fullwidth/halfwidth in the extension.
            if (firstFullwidthFrom(input, ext_start)) |hit| {
                var pos = PosBuffer{};
                pos.append(hit.pos);
                break :blk .{ .hazard = .{
                    .sub = .{ .width_class_ext = .{ .position = hit.pos, .cp = hit.cp } },
                    .positions = pos,
                } };
            }
            // Priority 3: combining mark in the extension.
            if (firstExtendFrom(input, ext_start)) |hit| {
                var pos = PosBuffer{};
                pos.append(hit.pos);
                break :blk .{ .hazard = .{
                    .sub = .{ .combining_in_ext = .{ .position = hit.pos, .cp = hit.cp } },
                    .positions = pos,
                } };
            }
            // Priority 4: three or more extensions (advisory).
            if (dots.len >= MIN_MULTI_EXT_DOTS) {
                break :blk .{ .hazard = .{
                    .sub = .{ .multiple_extensions = .{ .dot_count = dots.len } },
                    .positions = dots,
                } };
            }
            break :blk .{ .clear = {} };
        };

        return @This().Verdict{
            .input = input,
            .classify = classification,
            .dot_positions = dots,
            .last_dot_pos = last_dot,
            .bidi_control_count = bidi_count,
            .fullwidth_in_ext = fw_in_ext,
            .combining_in_ext = ext_in_ext,
        };
    }
};

// ─────────────────────────────────────────────────────────────────────
// IdentifierFormDrift detector (boundary layer X), mirroring
// Unicode.Security.Boundary.IdentifierFormDrift and its byte-faithful Rust
// reference implementation.
//
// Threat model. A two-system bypass: an identity validator and a form
// normaliser disagree about a codepoint. Stage A runs the UTS #39
// Identifier_Status check before normalisation and rejects, say, U+1D44E
// MATHEMATICAL ITALIC SMALL A (Restricted); stage B normalises first and then
// runs the same check, seeing U+0061 'a' (Allowed) and accepting. The attacker
// controls which stage processes the input and exploits the disagreement. The
// same shape covers fullwidth (U+FF21), circled (U+24B6), ligature (U+FB01),
// and Roman-numeral (U+2163) compatibility forms.
//
// The detector fires on the form transition itself — it reports the first input
// position whose Identifier_Status differs from the Identifier_Status of that
// codepoint's NFKD head, and the verdict carries the total shift count.
//
// It reuses the port's own tables — the UTS #39 Identifier_Status = Allowed
// predicate (file-scope isIdAllowed, parsing the bundled
// data/IdentifierStatus.txt) and the NFKD pipeline (file-scope toNFKD, UAX #15
// compatibility decompose + canonical reorder) — never a host normalization or
// identifier library.
//
// Sub-threat (direction-agnostic):
//   IdentifierStatusShift — the first input position whose Identifier_Status
//   differs from its NFKD-head's. There is exactly one sub-threat.
// ─────────────────────────────────────────────────────────────────────

pub const identifier_form_drift = struct {
    /// The port's file-scope UTS #39 Identifier_Status = Allowed predicate,
    /// bound here under a distinct alias so the reuse is explicit. A same-named
    /// container method would shadow the file-scope declaration.
    const idAllowedPredicate = isIdAllowed;

    /// The port's file-scope UAX #15 NFKD normaliser, aliased for the same
    /// reason. Returns null only on unbounded expansion (its buffer saturates),
    /// which nfkdHeadAllowed treats as the empty case.
    const nfkdNormalize = toNFKD;

    // ── §1 Types ─────────────────────────────────────────────────────────

    /// Sub-threat enumeration. Exactly one variant.
    pub const SubThreat = union(enum) {
        /// A codepoint at base_pos whose Identifier_Status differs from its
        /// NFKD-head's (codepoint cp).
        identifier_status_shift: struct { base_pos: usize, cp: u32 },

        /// Human-facing classification tag for this sub-threat.
        pub fn tag(self: SubThreat) []const u8 {
            return switch (self) {
                .identifier_status_shift => "IdentifierStatusShift",
            };
        }

        /// Fully-qualified reason code for this sub-threat.
        pub fn reasonCode(self: SubThreat) []const u8 {
            return switch (self) {
                .identifier_status_shift => "unicode.security.X.identifier-form-drift.IdentifierStatusShift",
            };
        }
    };

    /// Top-level classification (clear = no status shift present).
    pub const Classification = union(enum) {
        /// No status shift present.
        clear,
        /// A status shift fired: the sub-threat, the implicated positions, and
        /// the (always-empty for this detector) decoded-byte projection, kept
        /// for shape parity with the Lean Classification.hazard.
        hazard: struct { sub: SubThreat, positions: [1]usize, decoded: []const u8 = &[_]u8{} },

        /// True iff the classification is clear.
        pub fn isClear(self: Classification) bool {
            return switch (self) {
                .clear => true,
                .hazard => false,
            };
        }

        /// Human-facing tag for a hazard, or null when clear.
        pub fn tag(self: Classification) ?[]const u8 {
            return switch (self) {
                .clear => null,
                .hazard => |h| h.sub.tag(),
            };
        }

        /// Fully-qualified reason code for a hazard, or null when clear.
        pub fn reasonCode(self: Classification) ?[]const u8 {
            return switch (self) {
                .clear => null,
                .hazard => |h| h.sub.reasonCode(),
            };
        }

        /// Implicated positions (empty when clear).
        pub fn positions(self: *const Classification) []const usize {
            switch (self.*) {
                .clear => return &[_]usize{},
                .hazard => return self.hazard.positions[0..1],
            }
        }
    };

    /// Verdict — the structured output of detect (mirrors the Lean Verdict).
    pub const Verdict = struct {
        /// The scanned input codepoints.
        input: []const u32,
        /// The classification verdict.
        classify: Classification,
        /// Total count of positions whose status shifts under NFKD.
        shift_count: usize,
    };

    // ── §2 Core predicates (reuse the port's own tables) ─────────────────

    /// Identifier_Status = Allowed of the first codepoint of cp's NFKD form, or
    /// cp's own status when NFKD is empty (defensive — toNFKD is total and
    /// returns at least [cp]; it yields null only on buffer saturation, handled
    /// here as the empty case). Reuses the port's own predicate and NFKD.
    pub fn nfkdHeadAllowed(cp: u32) bool {
        if (nfkdNormalize(&[_]u32{cp})) |nfkd| {
            if (nfkd.len > 0) return idAllowedPredicate(nfkd.items[0]);
        }
        return idAllowedPredicate(cp);
    }

    // ── §3 Sub-detectors ─────────────────────────────────────────────────

    /// Position and codepoint of the first input position whose isIdAllowed
    /// differs from its NFKD-head's.
    const ShiftHit = struct { pos: usize, cp: u32 };
    fn firstStatusShift(input: []const u32) ?ShiftHit {
        for (input, 0..) |cp, idx| {
            if (!idAllowedPredicate(cp) and nfkdHeadAllowed(cp)) {
                return ShiftHit{ .pos = idx, .cp = cp };
            }
        }
        return null;
    }

    /// Total count of input positions where the per-cp status shifts under NFKD.
    fn statusShiftCount(input: []const u32) usize {
        var count: usize = 0;
        for (input) |cp| {
            if (!idAllowedPredicate(cp) and nfkdHeadAllowed(cp)) count += 1;
        }
        return count;
    }

    // ── §4 Top-level detection ───────────────────────────────────────────

    /// The IdentifierFormDrift detection function.
    pub fn detect(input: []const u32) @This().Verdict {
        const classification: Classification = if (firstStatusShift(input)) |hit| .{ .hazard = .{
            .sub = .{ .identifier_status_shift = .{ .base_pos = hit.pos, .cp = hit.cp } },
            .positions = [1]usize{hit.pos},
        } } else .{ .clear = {} };

        return @This().Verdict{
            .input = input,
            .classify = classification,
            .shift_count = statusShiftCount(input),
        };
    }
};

// ─────────────────────────────────────────────────────────────────────
// AdmissibilityFormDrift detector (boundary layer X), mirroring
// Unicode.Security.Boundary.AdmissibilityFormDrift and its byte-faithful Rust
// reference implementation.
//
// Fires on inputs whose UTS #39 whole-string isAllowedIdentifier verdict differs
// between the input and its NFKC form. This is the string-level complement of
// IdentifierFormDrift (which scans Identifier_Status against the per-codepoint
// NFKD head): here the whole-string admissibility predicate is evaluated twice —
// once on the input, once on toNFKC(input). The two are not redundant. A
// sequence of decomposed Hangul jamos passes the per-codepoint scan cleanly
// (each jamo has identity NFKD and Restricted status on both sides) but fires
// here: the jamo sequence is rejected by isAllowedIdentifier, while its NFKC
// composition into a precomposed Hangul syllable is accepted.
//
// It reuses the port's own whole-string admissibility predicate (file-scope
// isAllowedIdentifier = UAX #31 default identifier ∧ every codepoint Allowed) and
// NFKC pipeline (file-scope toNFKC), never a host normalisation or identifier
// library.
//
// Sub-threat (direction-agnostic):
//   AdmissibilityFormDrift — isAllowedIdentifier(input) !=
//   isAllowedIdentifier(toNFKC(input)). The pair of booleans is carried so the
//   verdict records which direction the drift goes; no position is reported
//   because the predicate is whole-string.
// ─────────────────────────────────────────────────────────────────────

pub const admissibility_form_drift = struct {
    /// The port's file-scope whole-string admissibility predicate, aliased here
    /// so the reuse is explicit.
    const allowedIdentifierPredicate = isAllowedIdentifier;

    /// The port's file-scope UAX #15 NFKC normaliser (NFKD + canonical
    /// recompose), aliased for the same reason. Returns null only on unbounded
    /// expansion (its buffer saturates), which detect treats defensively.
    const nfkcNormalize = toNFKC;

    // ── §1 Types ─────────────────────────────────────────────────────────

    /// Sub-threat enumeration. Exactly one variant.
    pub const SubThreat = union(enum) {
        /// The whole-string admissibility verdict differs between the input and
        /// its NFKC form. Both booleans are carried so the drift direction is
        /// recorded.
        admissibility_form_drift: struct { input_admissible: bool, nfkc_admissible: bool },

        /// Human-facing classification tag for this sub-threat.
        pub fn tag(self: SubThreat) []const u8 {
            return switch (self) {
                .admissibility_form_drift => "AdmissibilityFormDrift",
            };
        }

        /// Fully-qualified reason code for this sub-threat.
        pub fn reasonCode(self: SubThreat) []const u8 {
            return switch (self) {
                .admissibility_form_drift => "unicode.security.X.admissibility-form-drift.AdmissibilityFormDrift",
            };
        }
    };

    /// Top-level classification (clear = the admissibility verdict agrees across
    /// forms).
    pub const Classification = union(enum) {
        /// The admissibility verdict agrees across forms.
        clear,
        /// The admissibility verdict drifts across forms: the sub-threat, the
        /// implicated positions (always empty — the predicate is whole-string),
        /// and the (always-empty here) decoded-byte projection kept for shape
        /// parity with the Lean Classification.hazard.
        hazard: struct { sub: SubThreat, positions: []const usize = &[_]usize{}, decoded: []const u8 = &[_]u8{} },

        /// True iff the classification is clear.
        pub fn isClear(self: Classification) bool {
            return switch (self) {
                .clear => true,
                .hazard => false,
            };
        }

        /// Human-facing tag for a hazard, or null when clear.
        pub fn tag(self: Classification) ?[]const u8 {
            return switch (self) {
                .clear => null,
                .hazard => |h| h.sub.tag(),
            };
        }

        /// Fully-qualified reason code for a hazard, or null when clear.
        pub fn reasonCode(self: Classification) ?[]const u8 {
            return switch (self) {
                .clear => null,
                .hazard => |h| h.sub.reasonCode(),
            };
        }

        /// Implicated positions (always empty — the predicate is whole-string).
        pub fn positions(self: Classification) []const usize {
            return switch (self) {
                .clear => &[_]usize{},
                .hazard => |h| h.positions,
            };
        }
    };

    /// Verdict — the structured output of detect (mirrors the Lean Verdict).
    pub const Verdict = struct {
        /// The scanned input codepoints.
        input: []const u32,
        /// The classification verdict.
        classify: Classification,
        /// isAllowedIdentifier(input).
        input_admissible: bool,
        /// isAllowedIdentifier(toNFKC(input)).
        nfkc_admissible: bool,
    };

    // ── §2 Top-level detection ───────────────────────────────────────────

    /// The AdmissibilityFormDrift detection function.
    pub fn detect(input: []const u32) @This().Verdict {
        const in_ok = allowedIdentifierPredicate(input);
        // toNFKC is total on well-formed input and returns at least the input;
        // it yields null only on buffer saturation (unbounded compatibility
        // expansion). Such a pathological input is never a real vector; treat
        // the NFKC verdict defensively as agreement (== in_ok) so it reports
        // clear rather than crashing.
        const nfkc_ok = if (nfkcNormalize(input)) |nfkc| allowedIdentifierPredicate(nfkc.slice()) else in_ok;

        const classification: Classification = if (in_ok == nfkc_ok)
            .{ .clear = {} }
        else
            .{ .hazard = .{ .sub = .{ .admissibility_form_drift = .{
                .input_admissible = in_ok,
                .nfkc_admissible = nfkc_ok,
            } } } };

        return @This().Verdict{
            .input = input,
            .classify = classification,
            .input_admissible = in_ok,
            .nfkc_admissible = nfkc_ok,
        };
    }
};

// ─────────────────────────────────────────────────────────────────────
// SkinToneVariationForgery detector (identity layer I), mirroring
// Unicode.Security.Identity.SkinToneVariationForgery and its byte-faithful Rust
// reference implementation.
//
// Threat model. Tier A₁. An adversary places a skin-tone modifier on a codepoint
// that does NOT bear Emoji_Modifier_Base, stacks multiple skin-tones on one
// base, or forces a text-style render on an emoji-default codepoint via U+FE0E
// (VS15) — sometimes to hide a payload-bearing glyph in plain sight. Distinct
// from VariationSelectorPayload (pair-aligned VS runs that decode to bytes): this
// catches the orthogonal case of semantic VS / skin-tone misuse on a single base.
//
// It reuses the port's own emoji property tables — the skin-tone modifier set is
// the emoji-zwj-integrity detector's own isEmojiModifier predicate (U+1F3FB..
// U+1F3FF); Emoji_Modifier_Base and Emoji_Presentation are parsed from the port's
// already-bundled data/emoji-data.txt, using the same property-row scan the
// ai-watermark-detectability detector uses for its Emoji rows — never a host
// emoji library, and no new data file.
//
// Sub-threats (priority order):
//   1. StackedSkinTones      a base immediately followed by >= 2 skin-tone modifiers.
//   2. InvalidSkinToneTarget a skin-tone modifier on a non-Emoji_Modifier_Base.
//   3. ForcedTextStyle       U+FE0E on an Emoji_Presentation codepoint.
// ─────────────────────────────────────────────────────────────────────

pub const skin_tone_variation_forgery = struct {
    /// Upper bound on the number of implicated positions a hazard can carry
    /// before the bounded buffer saturates. This detector reports at most two
    /// positions per hazard (a stacked skin-tone pair); the cap mirrors the
    /// port's other bounded position buffers. Inputs that would exceed it
    /// saturate silently, which cannot change a classification tag.
    const MAX_POSITIONS: usize = 512;

    /// Bounded position buffer — a hazard's implicated codepoint indices.
    const PosBuffer = struct {
        items: [MAX_POSITIONS]usize = undefined,
        len: usize = 0,

        fn append(self: *PosBuffer, p: usize) void {
            if (self.len >= self.items.len) return;
            self.items[self.len] = p;
            self.len += 1;
        }

        fn slice(self: *const PosBuffer) []const usize {
            return self.items[0..self.len];
        }
    };

    // ── §1 Types ─────────────────────────────────────────────────────────

    /// Sub-threat enumeration, in priority order.
    pub const SubThreat = union(enum) {
        /// A base at base_pos followed by >= 2 skin-tone modifiers; modifiers
        /// carries the first two stacked skin-tone codepoints.
        stacked_skin_tones: struct { base_pos: usize, modifiers: [2]u32 },
        /// A skin-tone modifier_cp at base_pos + 1 on a non-modifier-base base_cp.
        invalid_skin_tone_target: struct { base_pos: usize, base_cp: u32, modifier_cp: u32 },
        /// A U+FE0E at base_pos + 1 forcing text style on an Emoji_Presentation
        /// base_cp.
        forced_text_style: struct { base_pos: usize, base_cp: u32 },

        /// Human-facing classification tag for this sub-threat.
        pub fn tag(self: SubThreat) []const u8 {
            return switch (self) {
                .stacked_skin_tones => "StackedSkinTones",
                .invalid_skin_tone_target => "InvalidSkinToneTarget",
                .forced_text_style => "ForcedTextStyle",
            };
        }

        /// Fully-qualified reason code for this sub-threat, matching the shared
        /// fixture's required_findings entry.
        pub fn reasonCode(self: SubThreat) []const u8 {
            return switch (self) {
                .stacked_skin_tones => "unicode.security.I.skin-tone-variation-forgery.StackedSkinTones",
                .invalid_skin_tone_target => "unicode.security.I.skin-tone-variation-forgery.InvalidSkinToneTarget",
                .forced_text_style => "unicode.security.I.skin-tone-variation-forgery.ForcedTextStyle",
            };
        }
    };

    /// Top-level classification (clear = no skin-tone / variation-selector abuse).
    pub const Classification = union(enum) {
        /// No abuse pattern present.
        clear,
        /// An abuse pattern fired: the sub-threat, the implicated positions, and
        /// the (always-empty for this detector) decoded-byte projection, kept for
        /// shape parity with the Lean Classification.hazard.
        hazard: struct { sub: SubThreat, positions: PosBuffer, decoded: []const u8 = &[_]u8{} },

        /// True iff the classification is clear.
        pub fn isClear(self: Classification) bool {
            return switch (self) {
                .clear => true,
                .hazard => false,
            };
        }

        /// Human-facing tag for a hazard, or null when clear.
        pub fn tag(self: Classification) ?[]const u8 {
            return switch (self) {
                .clear => null,
                .hazard => |h| h.sub.tag(),
            };
        }

        /// Fully-qualified reason code for a hazard, or null when clear.
        pub fn reasonCode(self: Classification) ?[]const u8 {
            return switch (self) {
                .clear => null,
                .hazard => |h| h.sub.reasonCode(),
            };
        }

        /// Implicated positions (empty when clear).
        pub fn positions(self: *const Classification) []const usize {
            switch (self.*) {
                .clear => return &[_]usize{},
                .hazard => return self.hazard.positions.slice(),
            }
        }
    };

    /// Verdict — the structured output of detect (mirrors the Lean Verdict).
    pub const Verdict = struct {
        /// The scanned input codepoints.
        input: []const u32,
        /// The classification verdict.
        classify: Classification,
        /// Count of skin-tone modifier codepoints.
        skin_tone_count: usize,
        /// Count of U+FE0E (VS15) codepoints.
        variation_selector15_count: usize,
        /// Count of U+FE0F (VS16) codepoints.
        variation_selector16_count: usize,
    };

    // ── §2 Core predicates (reuse the port's own emoji tables) ───────────

    /// The emoji-zwj-integrity detector's own skin-tone modifier predicate
    /// (U+1F3FB..U+1F3FF), aliased here so the reuse is explicit.
    const skinToneModifierPredicate = emoji_zwj_integrity.isEmojiModifier;

    /// True iff cp lies in a closed interval of the bundled data/emoji-data.txt
    /// carrying exactly the named property. Scans the embedded table on each
    /// call, mirroring the ai-watermark-detectability detector's isEmoji scan;
    /// never consults a host emoji library. Each non-comment row is
    /// `<range> ; <property> # <comment>`; only rows whose property field equals
    /// property exactly are considered.
    fn hasEmojiProperty(property: []const u8, cp: u32) bool {
        var offset: usize = 0;
        while (nextLine(emoji_data_raw, &offset)) |raw_line| {
            const body = if (std.mem.indexOfScalar(u8, raw_line, '#')) |idx| raw_line[0..idx] else raw_line;
            const stripped = trimAscii(body);
            if (stripped.len == 0) continue;
            var fields = std.mem.splitScalar(u8, stripped, ';');
            const range_field = fields.next() orelse continue;
            const prop_field = fields.next() orelse continue;
            if (!std.mem.eql(u8, trimAscii(prop_field), property)) continue;
            const range = trimAscii(range_field);
            if (std.mem.indexOf(u8, range, "..")) |dot_idx| {
                const lo = parseHexU32(trimAscii(range[0..dot_idx])) orelse continue;
                const hi = parseHexU32(trimAscii(range[dot_idx + 2 ..])) orelse continue;
                if (lo <= cp and cp <= hi) return true;
            } else {
                const single = parseHexU32(range) orelse continue;
                if (single == cp) return true;
            }
        }
        return false;
    }

    /// True iff cp is an emoji skin-tone modifier (reuses the port's predicate).
    pub fn isSkinTone(cp: u32) bool {
        return skinToneModifierPredicate(cp);
    }

    /// True iff cp has Emoji_Modifier_Base per the bundled data/emoji-data.txt.
    pub fn isSkinToneBase(cp: u32) bool {
        return hasEmojiProperty("Emoji_Modifier_Base", cp);
    }

    /// True iff cp has Emoji_Presentation per the bundled data/emoji-data.txt.
    pub fn isEmojiPresentation(cp: u32) bool {
        return hasEmojiProperty("Emoji_Presentation", cp);
    }

    /// True iff cp is U+FE0E (VS15, text-style variation selector).
    pub fn isVs15(cp: u32) bool {
        return cp == 0xFE0E;
    }

    /// True iff cp is U+FE0F (VS16, emoji-style variation selector).
    pub fn isVs16(cp: u32) bool {
        return cp == 0xFE0F;
    }

    // ── §3 Sub-detectors ─────────────────────────────────────────────────

    /// First position whose next two codepoints are both skin-tone modifiers,
    /// as (base_pos, [mod1, mod2]).
    const StackHit = struct { base_pos: usize, modifiers: [2]u32 };
    fn firstStackedSkinTones(input: []const u32) ?StackHit {
        for (input, 0..) |_, i| {
            if (i + 2 < input.len) {
                const m1 = input[i + 1];
                const m2 = input[i + 2];
                if (isSkinTone(m1) and isSkinTone(m2)) {
                    return StackHit{ .base_pos = i, .modifiers = [2]u32{ m1, m2 } };
                }
            }
        }
        return null;
    }

    /// First skin-tone modifier whose preceding codepoint is NOT
    /// Emoji_Modifier_Base, as (base_pos, base_cp, modifier_cp).
    const InvalidHit = struct { base_pos: usize, base_cp: u32, modifier_cp: u32 };
    fn firstInvalidSkinToneTarget(input: []const u32) ?InvalidHit {
        for (input, 0..) |base_cp, i| {
            if (i + 1 < input.len) {
                const cp = input[i + 1];
                if (isSkinTone(cp) and !isSkinToneBase(base_cp)) {
                    return InvalidHit{ .base_pos = i, .base_cp = base_cp, .modifier_cp = cp };
                }
            }
        }
        return null;
    }

    /// First U+FE0E whose preceding codepoint has Emoji_Presentation, as
    /// (base_pos, base_cp).
    const ForcedHit = struct { base_pos: usize, base_cp: u32 };
    fn firstForcedTextStyle(input: []const u32) ?ForcedHit {
        for (input, 0..) |base_cp, i| {
            if (i + 1 < input.len) {
                const cp = input[i + 1];
                if (isVs15(cp) and isEmojiPresentation(base_cp)) {
                    return ForcedHit{ .base_pos = i, .base_cp = base_cp };
                }
            }
        }
        return null;
    }

    fn skinToneCount(input: []const u32) usize {
        var count: usize = 0;
        for (input) |cp| {
            if (isSkinTone(cp)) count += 1;
        }
        return count;
    }

    fn vs15Count(input: []const u32) usize {
        var count: usize = 0;
        for (input) |cp| {
            if (isVs15(cp)) count += 1;
        }
        return count;
    }

    fn vs16Count(input: []const u32) usize {
        var count: usize = 0;
        for (input) |cp| {
            if (isVs16(cp)) count += 1;
        }
        return count;
    }

    // ── §4 Top-level detection ───────────────────────────────────────────

    /// The SkinToneVariationForgery detection function.
    pub fn detect(input: []const u32) @This().Verdict {
        const stc = skinToneCount(input);
        const v15 = vs15Count(input);
        const v16 = vs16Count(input);

        const classification: Classification = blk: {
            // Priority 1: a base followed by two stacked skin tones.
            if (firstStackedSkinTones(input)) |hit| {
                var pos = PosBuffer{};
                pos.append(hit.base_pos + 1);
                pos.append(hit.base_pos + 2);
                break :blk .{ .hazard = .{
                    .sub = .{ .stacked_skin_tones = .{ .base_pos = hit.base_pos, .modifiers = hit.modifiers } },
                    .positions = pos,
                } };
            }
            // Priority 2: a skin tone on a non-modifier-base.
            if (firstInvalidSkinToneTarget(input)) |hit| {
                var pos = PosBuffer{};
                pos.append(hit.base_pos + 1);
                break :blk .{ .hazard = .{
                    .sub = .{ .invalid_skin_tone_target = .{
                        .base_pos = hit.base_pos,
                        .base_cp = hit.base_cp,
                        .modifier_cp = hit.modifier_cp,
                    } },
                    .positions = pos,
                } };
            }
            // Priority 3: VS15 forcing text style on an emoji-presentation cp.
            if (firstForcedTextStyle(input)) |hit| {
                var pos = PosBuffer{};
                pos.append(hit.base_pos + 1);
                break :blk .{ .hazard = .{
                    .sub = .{ .forced_text_style = .{ .base_pos = hit.base_pos, .base_cp = hit.base_cp } },
                    .positions = pos,
                } };
            }
            break :blk .{ .clear = {} };
        };

        return @This().Verdict{
            .input = input,
            .classify = classification,
            .skin_tone_count = stc,
            .variation_selector15_count = v15,
            .variation_selector16_count = v16,
        };
    }
};

// ─────────────────────────────────────────────────────────────────────
// SourceDisplayDivergence detector (display layer D) — the aggregate
// "what a reviewer sees differs from what the machine runs" detector,
// mirroring Unicode.Security.Display.SourceDisplayDivergence.
//
// A single covert or identity trick may look individually benign, but any
// hit means the rendered source diverges from its logical content; two or
// more is a strong compound signal. This detector runs the port's own five
// constituent detectors on the same codepoint stream and aggregates: zero
// fire → clear, exactly one → pass through that family's tag, two or more →
// Compound. Every constituent fires region-agnostically — payloads inside
// string literals or comments count. This is a standalone detector: it is
// not part of the default policy scan (matching the reference), so it adds
// no Family enum entry and no policy row.
//
// It reuses the port's own constituent detectors — never a new predicate,
// data table, or host library. Each fire test mirrors exactly the predicate
// the file-scope policy `detect` uses to emit that family's finding, in the
// canonical aggregation order:
//   1. tag-block-payload           → "TagBlock"
//   2. variation-selector-payload  → "VariationSelector"
//   3. zero-width-payload          → "ZeroWidth"
//   4. bidi-control-balance        → "BidiControl"
//   5. homoglyph-confusable        → "IdentifierHomoglyph"
// ─────────────────────────────────────────────────────────────────────

pub const source_display_divergence = struct {
    // ── §1 Constituent fire tests (reuse the port's own five detectors) ──
    //
    // A constituent "fires" precisely when its own classification is
    // non-clear — i.e. when the policy `detect` would emit that family's
    // finding. Each test reuses the port's own finding-producing logic:
    // the tag-block / zero-width / bidi-control predicates via positionsWhere,
    // and the variation-selector / homoglyph finding builders directly.

    /// tag-block-payload fires iff the input carries a tag-block ASCII payload.
    fn tagBlockFired(input: []const u32) bool {
        return positionsWhere(input, isTagBlockAsciiPayload) != null;
    }

    /// variation-selector-payload fires iff its finding is present.
    fn variationSelectorFired(input: []const u32) bool {
        return variationSelectorFinding(input) != null;
    }

    /// zero-width-payload fires iff the input carries an unsanctioned
    /// zero-width codepoint. A ZWJ inside a registered emoji sequence and a
    /// ZWNJ in an RFC 5892 CONTEXTJ-valid position are present but carry
    /// meaning, so they do not make the constituent fire.
    fn zeroWidthFired(input: []const u32) bool {
        return positionsWhere(input, isZeroWidthPayload) != null and
            hasSuspiciousZeroWidth(input);
    }

    /// bidi-control-balance fires iff the input carries a bidi embedding control.
    fn bidiControlFired(input: []const u32) bool {
        // Presence over the full bidi format-control set, embeddings and
        // isolates alike. A Trojan Source payload balances its controls, since
        // an unbalanced run breaks the file it hides in, and it may use either
        // form; a predicate stopping at U+202E cannot see the isolate shape.
        return positionsWhere(input, isBidiFormatControl) != null;
    }

    /// homoglyph-confusable fires iff its finding is present. The reference
    /// runs one homoglyph detector whose priority ladder ends in a
    /// CrossScriptMix branch, so a cross-script identifier fires it even though
    /// this port reports that case under mixed-script-admissibility. Both
    /// builders are consulted, or every input whose only homoglyph signal is
    /// the script mix is missed.
    fn homoglyphFired(input: []const u32) bool {
        if (homoglyphConfusableFinding(input) != null) return true;
        // The constituent asks the script question about a source file, which
        // is not an identifier field, so the Restricted-status rung is off.
        return mixedScriptAdmissibilityFinding(input, false) != null;
    }

    // ── §2 Types ─────────────────────────────────────────────────────────

    /// Sub-threat tag — one of the five constituent family tags in canonical
    /// aggregation order, or Compound when two or more constituents fired.
    pub const SubThreat = enum {
        tag_block,
        variation_selector,
        zero_width,
        bidi_control,
        identifier_homoglyph,
        compound,

        /// Human-facing classification tag.
        pub fn tag(self: SubThreat) []const u8 {
            return switch (self) {
                .tag_block => "TagBlock",
                .variation_selector => "VariationSelector",
                .zero_width => "ZeroWidth",
                .bidi_control => "BidiControl",
                .identifier_homoglyph => "IdentifierHomoglyph",
                .compound => "Compound",
            };
        }

        /// Fully-qualified reason code for this sub-threat.
        pub fn reasonCode(self: SubThreat) []const u8 {
            return switch (self) {
                .tag_block => "unicode.security.D.source-display-divergence.TagBlock",
                .variation_selector => "unicode.security.D.source-display-divergence.VariationSelector",
                .zero_width => "unicode.security.D.source-display-divergence.ZeroWidth",
                .bidi_control => "unicode.security.D.source-display-divergence.BidiControl",
                .identifier_homoglyph => "unicode.security.D.source-display-divergence.IdentifierHomoglyph",
                .compound => "unicode.security.D.source-display-divergence.Compound",
            };
        }
    };

    /// Top-level classification (clear = no constituent fired). Positions are
    /// empty at this layer by the spec — the per-family verdicts carry them —
    /// so the aggregate carries only the sub-threat tag.
    pub const Classification = union(enum) {
        /// No constituent fired — the rendered source matches its logical content.
        clear,
        /// One or more constituents fired: the aggregated sub-threat.
        hazard: SubThreat,

        /// True iff no constituent fired.
        pub fn isClear(self: Classification) bool {
            return switch (self) {
                .clear => true,
                .hazard => false,
            };
        }

        /// Human-facing tag for a hazard, or null when clear.
        pub fn tag(self: Classification) ?[]const u8 {
            return switch (self) {
                .clear => null,
                .hazard => |sub| sub.tag(),
            };
        }

        /// Fully-qualified reason code for a hazard, or null when clear.
        pub fn reasonCode(self: Classification) ?[]const u8 {
            return switch (self) {
                .clear => null,
                .hazard => |sub| sub.reasonCode(),
            };
        }
    };

    /// Verdict — the structured output of detect.
    pub const Verdict = struct {
        /// The scanned input codepoints.
        input: []const u32,
        /// The aggregated classification.
        classify: Classification,
        /// Count of constituents that fired (0..5).
        fired_count: usize,
    };

    // ── §3 Top-level detection ───────────────────────────────────────────

    /// Aggregate the port's own five constituent detectors into one D-layer
    /// verdict. Constituents are evaluated in canonical order: tag-block,
    /// variation-selector, zero-width, bidi-control, homoglyph. Zero fired →
    /// clear; exactly one → that family's tag; two or more → Compound.
    pub fn detect(input: []const u32) @This().Verdict {
        var fires: [5]SubThreat = undefined;
        var n: usize = 0;
        if (tagBlockFired(input)) {
            fires[n] = .tag_block;
            n += 1;
        }
        if (variationSelectorFired(input)) {
            fires[n] = .variation_selector;
            n += 1;
        }
        if (zeroWidthFired(input)) {
            fires[n] = .zero_width;
            n += 1;
        }
        if (bidiControlFired(input)) {
            fires[n] = .bidi_control;
            n += 1;
        }
        if (homoglyphFired(input)) {
            fires[n] = .identifier_homoglyph;
            n += 1;
        }

        const classification: Classification = if (n == 0)
            .clear
        else if (n == 1)
            .{ .hazard = fires[0] }
        else
            .{ .hazard = .compound };

        return @This().Verdict{
            .input = input,
            .classify = classification,
            .fired_count = n,
        };
    }
};

// ─────────────────────────────────────────────────────────────────────
// Locale-case-inversion detector (Tier A2), mirroring
// Unicode.Security.Form.LocaleCaseInversion.
//
// Detects inputs whose lowercase fold inverts across locales — the
// homograph-via-locale attack (CVE-2007-6692, CVE-2021-30245). Compares
// per-position lowerCodepoint under each locale against the default (Turkish
// before Lithuanian) rather than diffing whole-string toLower, so the
// SpecialCasing context predicates evaluate with full context.
// ─────────────────────────────────────────────────────────────────────

pub const LocaleCaseInversionResult = struct {
    sub_threat: ?[]const u8 = null,
    positions: [1]usize = undefined,
    position_count: usize = 0,
};

// First input position whose lowercase mapping under `locale` differs from the
// default-locale mapping. A single codepoint's lowercase is at most a short
// slice — the special-row slice comes straight from the static table, and the
// simple-lowercase fallback fits a one-element scratch buffer.
fn firstLocaleDivergence(locale: CasingLocale, input: []const u32) ?usize {
    var i: usize = 0;
    while (i < input.len) : (i += 1) {
        const prefix = input[0..i];
        const suffix = input[i + 1 ..];
        var default_scratch: [1]u32 = undefined;
        var locale_scratch: [1]u32 = undefined;
        const default_lower = if (findSpecialLower(.default, prefix, suffix, input[i])) |lower|
            lower
        else default_blk: {
            default_scratch[0] = simpleLowercase(input[i]);
            break :default_blk default_scratch[0..1];
        };
        const locale_lower = if (findSpecialLower(locale, prefix, suffix, input[i])) |lower|
            lower
        else locale_blk: {
            locale_scratch[0] = simpleLowercase(input[i]);
            break :locale_blk locale_scratch[0..1];
        };
        if (!cpSlicesEqual(default_lower, locale_lower)) return i;
    }
    return null;
}

/// Detect an input whose lowercase fold inverts across locales. Turkish
/// divergence takes priority; Lithuanian is reached only when no Turkish
/// divergence is found.
pub fn localeCaseInversionDetect(input: []const u32) LocaleCaseInversionResult {
    var result = LocaleCaseInversionResult{};
    if (firstLocaleDivergence(.turkish, input)) |pos| {
        result.sub_threat = "TurkishCaseDivergence";
        result.positions[0] = pos;
        result.position_count = 1;
        return result;
    }
    if (firstLocaleDivergence(.lithuanian, input)) |pos| {
        result.sub_threat = "LithuanianCaseDivergence";
        result.positions[0] = pos;
        result.position_count = 1;
        return result;
    }
    return result;
}

// ─────────────────────────────────────────────────────────────────────
// CaseExpansionMismatch detector (form layer F), mirroring
// Unicode.Security.Form.CaseExpansionMismatch and the verified Rust port.
//
// Detects text whose default-locale case mapping changes the codepoint count.
// A receiver that fixes a username column and stores toUpper(username) overflows
// when the user picks "ßßßßßßßß" (8 in → 16 stored); a receiver that checks
// len(stored) == len(input) rejects valid case-insensitive logins whose names
// expand under folding. Examples: U+00DF ß → "SS", U+FB01 ﬁ → "FI", U+0130 İ →
// toLower "i̇" (i + U+0307). Distinct from LocaleCaseInversion (mapping that
// changes ACROSS locales): this fires on shapes whose mapping is locale-stable
// but length-changing under the default locale itself.
//
// Each position is mapped through the port's own upperCodepoint / lowerCodepoint
// (which evaluate the SpecialCasing context predicates), never a host casing
// library. Sub-threats, priority order:
//   1. UpperExpansion — first position whose default upperCodepoint yields > 1 cp.
//   2. LowerExpansion — first position whose default lowerCodepoint yields > 1 cp
//      (reached only when no upper expansion fires first).
// ─────────────────────────────────────────────────────────────────────

pub const case_expansion_mismatch = struct {
    // ── §1 Per-position expansion scan ───────────────────────────────────

    /// The default-locale uppercase expansion length at position `i`, evaluating
    /// the SpecialCasing context (preceding codepoints, following ones).
    fn upperLenAt(input: []const u32, i: usize) usize {
        var scratch: [1]u32 = undefined;
        return upperCodepoint(.default, input[0..i], input[i + 1 ..], input[i], &scratch).len;
    }

    /// The default-locale lowercase expansion length at position `i`.
    fn lowerLenAt(input: []const u32, i: usize) usize {
        var scratch: [1]u32 = undefined;
        return lowerCodepoint(.default, input[0..i], input[i + 1 ..], input[i], &scratch).len;
    }

    /// First position whose default uppercase mapping expands to > 1 codepoint,
    /// as (base_pos, cp, expansion_len).
    fn firstUpperExpansion(input: []const u32) ?struct { base_pos: usize, cp: u32, expansion_len: usize } {
        for (input, 0..) |cp, i| {
            const len = upperLenAt(input, i);
            if (len > 1) return .{ .base_pos = i, .cp = cp, .expansion_len = len };
        }
        return null;
    }

    /// First position whose default lowercase mapping expands to > 1 codepoint.
    fn firstLowerExpansion(input: []const u32) ?struct { base_pos: usize, cp: u32, expansion_len: usize } {
        for (input, 0..) |cp, i| {
            const len = lowerLenAt(input, i);
            if (len > 1) return .{ .base_pos = i, .cp = cp, .expansion_len = len };
        }
        return null;
    }

    /// Number of positions whose default uppercase mapping expands.
    fn upperExpansionCount(input: []const u32) usize {
        var acc: usize = 0;
        var i: usize = 0;
        while (i < input.len) : (i += 1) {
            if (upperLenAt(input, i) > 1) acc += 1;
        }
        return acc;
    }

    /// Number of positions whose default lowercase mapping expands.
    fn lowerExpansionCount(input: []const u32) usize {
        var acc: usize = 0;
        var i: usize = 0;
        while (i < input.len) : (i += 1) {
            if (lowerLenAt(input, i) > 1) acc += 1;
        }
        return acc;
    }

    /// Maximum case-mapped expansion length across all positions (upper or
    /// lower); 0 for empty input.
    fn maxExpansionLen(input: []const u32) usize {
        var acc: usize = 0;
        var i: usize = 0;
        while (i < input.len) : (i += 1) {
            const u = upperLenAt(input, i);
            const l = lowerLenAt(input, i);
            const m = if (u > l) u else l;
            if (m > acc) acc = m;
        }
        return acc;
    }

    // ── §2 Types ─────────────────────────────────────────────────────────

    /// Sub-threats this detector can fire, in priority order.
    pub const SubThreat = union(enum) {
        /// A codepoint whose default uppercase mapping expands, at base_pos.
        upper_expansion: struct { base_pos: usize, cp: u32, expansion_len: usize },
        /// A codepoint whose default lowercase mapping expands, at base_pos.
        lower_expansion: struct { base_pos: usize, cp: u32, expansion_len: usize },

        /// Human-facing classification tag for this sub-threat.
        pub fn tag(self: SubThreat) []const u8 {
            return switch (self) {
                .upper_expansion => "UpperExpansion",
                .lower_expansion => "LowerExpansion",
            };
        }

        /// Fully-qualified reason code for this sub-threat, matching the shared
        /// fixture's required_findings entry.
        pub fn reasonCode(self: SubThreat) []const u8 {
            return switch (self) {
                .upper_expansion => "unicode.security.F.case-expansion-mismatch.UpperExpansion",
                .lower_expansion => "unicode.security.F.case-expansion-mismatch.LowerExpansion",
            };
        }
    };

    /// Top-level classification.
    pub const Classification = union(enum) {
        /// No case-mapped expansion present.
        clear,
        /// An expansion fired: the sub-threat, its implicated positions, and any
        /// decoded bytes (always empty for this detector — the field mirrors the
        /// spec's Classification.hazard shape). One expansion implicates exactly
        /// one position, so the buffer is single-slot.
        hazard: struct { sub: SubThreat, positions: [1]usize, decoded: []const u8 = &[_]u8{} },

        /// True iff the input is clear.
        pub fn isClear(self: Classification) bool {
            return switch (self) {
                .clear => true,
                .hazard => false,
            };
        }

        /// Human-facing tag for a hazard, or null when clear.
        pub fn tag(self: Classification) ?[]const u8 {
            return switch (self) {
                .clear => null,
                .hazard => |h| h.sub.tag(),
            };
        }

        /// Fully-qualified reason code for a hazard, or null when clear.
        pub fn reasonCode(self: Classification) ?[]const u8 {
            return switch (self) {
                .clear => null,
                .hazard => |h| h.sub.reasonCode(),
            };
        }

        /// Implicated positions (empty when clear).
        pub fn positions(self: *const Classification) []const usize {
            switch (self.*) {
                .clear => return &[_]usize{},
                .hazard => return self.hazard.positions[0..],
            }
        }
    };

    /// Verdict — the structured output of detect. The expansion summaries expose
    /// how many positions expand under each mapping and the widest expansion, so
    /// a caller can size the storage-overflow / length-mismatch pressure a
    /// case-folding receiver would see.
    pub const Verdict = struct {
        /// The scanned input codepoints.
        input: []const u32,
        /// The classification verdict.
        classify: Classification,
        /// Count of positions whose default uppercase mapping expands.
        upper_expansion_count: usize,
        /// Count of positions whose default lowercase mapping expands.
        lower_expansion_count: usize,
        /// Maximum case-mapped expansion length across all positions.
        max_expansion_len: usize,
    };

    // ── §3 Top-level detection ───────────────────────────────────────────

    /// The CaseExpansionMismatch detection function. Fires UpperExpansion on the
    /// first position whose default uppercase mapping expands; otherwise
    /// LowerExpansion on the first position whose default lowercase mapping
    /// expands; otherwise Clear.
    pub fn detect(input: []const u32) @This().Verdict {
        const classification: Classification = if (firstUpperExpansion(input)) |hit|
            .{ .hazard = .{
                .sub = .{ .upper_expansion = .{
                    .base_pos = hit.base_pos,
                    .cp = hit.cp,
                    .expansion_len = hit.expansion_len,
                } },
                .positions = .{hit.base_pos},
            } }
        else if (firstLowerExpansion(input)) |hit|
            .{ .hazard = .{
                .sub = .{ .lower_expansion = .{
                    .base_pos = hit.base_pos,
                    .cp = hit.cp,
                    .expansion_len = hit.expansion_len,
                } },
                .positions = .{hit.base_pos},
            } }
        else
            .{ .clear = {} };
        return @This().Verdict{
            .input = input,
            .classify = classification,
            .upper_expansion_count = upperExpansionCount(input),
            .lower_expansion_count = lowerExpansionCount(input),
            .max_expansion_len = maxExpansionLen(input),
        };
    }
};

// ─────────────────────────────────────────────────────────────────────
// Normalization-bomb detector (F1), mirroring
// Unicode.Security.Form.NormalizationBomb.
//
// Detects inputs whose NFD or NFKD expansion exceeds documented bounds — the
// classic normalization-expansion DoS. A small input that expands to a very
// large normalized form exhausts memory/CPU at the receiving layer (Arabic
// ligature U+FDFA → 18 codepoints under NFKD). Three priority-ordered checks:
// a per-codepoint blow-up scan, an overall NFKD ratio, an overall NFD ratio.
// Ratios are expressed in hundredths to avoid floats.
// ─────────────────────────────────────────────────────────────────────

// Maximum allowed NFKD expansion per single codepoint. Hangul ≤ 3, Greek
// extended forms 4, the largest non-FDFA Arabic ligature (FDFB) 8; anything
// greater than 8 is flagged.
const MAX_NFKD_PER_CP: usize = 8;

// Overall-sequence NFD expansion ratio threshold, in hundredths (300 = 3×).
// Pure Hangul sits at exactly 300 and stays clear under strict `>`.
const NFD_RATIO_PCT: usize = 300;

// Overall-sequence NFKD expansion ratio threshold, in hundredths (400 = 4×).
const NFKD_RATIO_PCT: usize = 400;

pub const NormalizationBombResult = struct {
    sub_threat: ?[]const u8 = null,
    positions: [1]usize = undefined,
    position_count: usize = 0,
};

// First position whose single-codepoint NFKD expansion exceeds
// `MAX_NFKD_PER_CP`. A single codepoint never overflows the bounded buffer, so
// a null expansion counts as length 0 (which cannot exceed the bound anyway).
fn firstBlowupCp(input: []const u32) ?usize {
    var i: usize = 0;
    while (i < input.len) : (i += 1) {
        const expand = if (toNFKD(&[_]u32{input[i]})) |buf| buf.slice().len else 0;
        if (expand > MAX_NFKD_PER_CP) return i;
    }
    return null;
}

/// Detect a normalization-expansion bomb. Priority: per-codepoint blow-up,
/// then overall NFKD ratio, then overall NFD ratio. An unmeasurable (overflowed)
/// whole-input expansion is treated as ratio 100% — no hazard.
pub fn normalizationBombDetect(input: []const u32) NormalizationBombResult {
    var result = NormalizationBombResult{};
    if (firstBlowupCp(input)) |pos| {
        result.sub_threat = "SingleCpBlowup";
        result.positions[0] = pos;
        result.position_count = 1;
        return result;
    }
    if (input.len == 0) return result;
    const nfkd_len = if (toNFKD(input)) |buf| buf.slice().len else input.len;
    if (nfkd_len * 100 / input.len > NFKD_RATIO_PCT) {
        result.sub_threat = "NfkdHighExpansion";
        return result;
    }
    const nfd_len = if (toNFD(input)) |buf| buf.slice().len else input.len;
    if (nfd_len * 100 / input.len > NFD_RATIO_PCT) {
        result.sub_threat = "NfdHighExpansion";
        return result;
    }
    return result;
}

pub const NfcIdempotenceWitnessResult = struct {
    sub_threat: ?[]const u8 = null,
    positions: [1]usize = undefined,
    position_count: usize = 0,
};

// First index at which two sequences diverge (in element, or one ends);
// null when identical.
fn nfcFirstDivergence(a: []const u32, b: []const u32) ?usize {
    const common = @min(a.len, b.len);
    var i: usize = 0;
    while (i < common) : (i += 1) {
        if (a[i] != b[i]) return i;
    }
    if (a.len != b.len) return common;
    return null;
}

/// Detect an input that is not in canonical (NFC), or not in compatibility
/// (NFKC), form. NFC divergence takes priority over NFKC. A normalization
/// overflow of the bounded buffer (impossible for the small inputs here) is
/// treated as clear.
pub fn nfcIdempotenceWitnessDetect(input: []const u32) NfcIdempotenceWitnessResult {
    var result = NfcIdempotenceWitnessResult{};
    const nfc = toNFC(input) orelse return result;
    if (nfcFirstDivergence(input, nfc.slice())) |pos| {
        result.sub_threat = "NonNfcForm";
        result.positions[0] = pos;
        result.position_count = 1;
        return result;
    }
    const nfkc = toNFKC(input) orelse return result;
    if (nfcFirstDivergence(input, nfkc.slice())) |pos| {
        result.sub_threat = "NonNfkcCompatForm";
        result.positions[0] = pos;
        result.position_count = 1;
        return result;
    }
    return result;
}

pub const WidthClassConfusionResult = struct {
    sub_threat: ?[]const u8 = null,
    positions: [1]usize = undefined,
    position_count: usize = 0,
};

// True iff the NFKD head of `cp` carries a different East Asian Width class.
// A normalization overflow of the bounded buffer is treated as no fold.
fn hasWidthFold(cp: u32) bool {
    const folded = toNFKD(&[_]u32{cp}) orelse return false;
    const head = folded.slice();
    if (head.len == 0) return false;
    return eastAsianWidth(head[0]) != eastAsianWidth(cp);
}

// First position whose codepoint has class `want` and folds away from it.
fn firstWidthFold(input: []const u32, want: east_asian_width_data.Width) ?usize {
    for (input, 0..) |cp, index| {
        if (eastAsianWidth(cp) == want and hasWidthFold(cp)) return index;
    }
    return null;
}

/// Detect UAX #11 East Asian Width class confusion. A Fullwidth (EAW = F) or
/// Halfwidth (EAW = H) codepoint whose NFKD head carries a different EAW class
/// is a compatibility-fold homograph:
///
///   U+FF21 'Ａ' (F)  ->  U+0041 'A' (Na)
///   U+FF71 'ｱ' (H)  ->  U+30A2 'ア' (W)
///
/// The two-system bypass: a validator that whitelists ASCII rejects Ａ, while a
/// downstream NFKC step at storage or comparison time folds it to plain A, so
/// ＡＤＭＩＮ claims the username ADMIN. Distinct from renderer divergence's
/// FullwidthVariance, which fires on F-class codepoints for renderer-cohort
/// reasons; this is the NFKC-fold verdict and both can fire independently.
/// Hangul syllables decompose to jamos that are still W class, so pure Hangul
/// stays clear. A Fullwidth fold takes priority over a Halfwidth one, matching
/// the reference's sub-threat order.
///
/// Direct port of Unicode/Security/Form/WidthClassConfusion.lean.
pub fn widthClassConfusionDetect(input: []const u32) WidthClassConfusionResult {
    var result = WidthClassConfusionResult{};
    if (firstWidthFold(input, .f)) |pos| {
        result.sub_threat = "FullwidthFold";
        result.positions[0] = pos;
        result.position_count = 1;
        return result;
    }
    if (firstWidthFold(input, .h)) |pos| {
        result.sub_threat = "HalfwidthFold";
        result.positions[0] = pos;
        result.position_count = 1;
        return result;
    }
    return result;
}

fn ctCpSlicesEqual(a: []const u32, b: []const u32) bool {
    if (a.len != b.len) return false;
    var acc: u32 = 0;
    for (a, b) |left, right| {
        acc |= left ^ right;
    }
    return acc == 0;
}

fn isCombiningMark(cp: u32) bool {
    return (cp >= 0x0300 and cp <= 0x036F) or
        (cp >= 0x1AB0 and cp <= 0x1AFF) or
        (cp >= 0x1DC0 and cp <= 0x1DFF) or
        (cp >= 0x20D0 and cp <= 0x20FF) or
        (cp >= 0xFE20 and cp <= 0xFE2F);
}

// True iff the input is not already in NFC, which is the rung's definition in
// Unicode.Security.Identity.HomoglyphConfusable: `toNFC input ≠ input`. An
// input that renders as its own composed form carries no swap, whatever its
// individual codepoints look like.
//
// The predicate is the comparison itself rather than a structural stand-in for
// it. Adjacency tests over the raw codepoints cannot decide it: canonical
// ordering is a stable sort on Canonical_Combining_Class, so two marks of equal
// class never reorder however their codepoint values compare, and whether a
// mark composes with the character before it is a question for the composition
// table.
//
// An input whose normalization overflows the fixed skeleton buffer is reported
// as carrying no swap, the same reading every other buffer-bounded detector in
// this port takes.
fn hasDecompositionSwap(input: []const u32) bool {
    const nfc = toNFC(input) orelse return false;
    const composed = nfc.slice();
    if (composed.len != input.len) return true;
    for (input, composed) |original, normalized| {
        if (original != normalized) return true;
    }
    return false;
}

fn composeHangulPair(first: u32, second: u32) bool {
    const s_base = 0xAC00;
    const l_base = 0x1100;
    const v_base = 0x1161;
    const t_base = 0x11A7;
    const l_count = 19;
    const v_count = 21;
    const t_count = 28;
    const n_count = v_count * t_count;
    const s_count = l_count * n_count;

    const is_l = first >= l_base and first < l_base + l_count;
    const is_v = second >= v_base and second < v_base + v_count;
    if (is_l and is_v) return true;

    const is_lv = first >= s_base and first < s_base + s_count and (first - s_base) % t_count == 0;
    const is_t = second > t_base and second < t_base + t_count;
    return is_lv and is_t;
}

// ─────────────────────────────────────────────────────────────────────
// UTS #39 §5.1 restriction levels, mirroring Unicode/Restriction.lean.
//
// Script resolution reads the vendored Scripts.txt and ScriptExtensions.txt:
// a codepoint's Script_Extensions where the file gives one, otherwise the
// abbreviation of its primary Script. The abbreviation vocabulary is exactly
// the set occurring in ScriptExtensions.txt, which is what
// Unicode/ResolvedScripts.lean models as its ScriptAbbrev enum, so a primary
// script outside it resolves to nothing on both sides. Returning a singleton
// there instead would make every unknown-script codepoint look Single-Script,
// putting restrictionLevel one rung too strict and hiding RestrictionLow.
//
// The tables are scanned per lookup from the embedded text, matching how
// isIdAllowed reads IdentifierStatus.txt in this port.
// ─────────────────────────────────────────────────────────────────────

pub const RestrictionLevel = enum {
    ascii_only,
    single_script,
    highly_restrictive,
    moderately_restrictive,
    minimally_restrictive,
    unrestricted,
};

// A resolved script set. Abbreviations are exactly four ASCII bytes, and a
// ScriptExtensions row lists at most a couple of dozen.
const ScriptSet = struct {
    items: [32][4]u8 = undefined,
    len: usize = 0,

    fn add(self: *ScriptSet, tag: []const u8) void {
        if (tag.len != 4 or self.len >= self.items.len) return;
        if (self.contains(tag)) return;
        var slot: [4]u8 = undefined;
        @memcpy(&slot, tag[0..4]);
        self.items[self.len] = slot;
        self.len += 1;
    }

    fn contains(self: *const ScriptSet, tag: []const u8) bool {
        if (tag.len != 4) return false;
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            if (std.mem.eql(u8, &self.items[i], tag)) return true;
        }
        return false;
    }

    fn intersects(self: *const ScriptSet, other: *const ScriptSet) bool {
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            if (other.contains(&self.items[i])) return true;
        }
        return false;
    }
};

fn coveredSet(tags: []const []const u8) ScriptSet {
    var set = ScriptSet{};
    for (tags) |tag| set.add(tag);
    return set;
}

// The value field of the row covering cp in a "RANGE ; VALUE" table.
fn scriptRowValue(raw: []const u8, cp: u32) ?[]const u8 {
    var offset: usize = 0;
    while (nextLine(raw, &offset)) |raw_line| {
        const body = if (std.mem.indexOfScalar(u8, raw_line, '#')) |idx| raw_line[0..idx] else raw_line;
        const stripped = trimAscii(body);
        if (stripped.len == 0) continue;
        var fields = std.mem.splitScalar(u8, stripped, ';');
        const range_field = fields.next() orelse continue;
        const value_field = fields.next() orelse continue;
        const range = trimAscii(range_field);
        var lo: u32 = 0;
        var hi: u32 = 0;
        if (std.mem.indexOf(u8, range, "..")) |dot_idx| {
            lo = parseHexU32(trimAscii(range[0..dot_idx])) orelse continue;
            hi = parseHexU32(trimAscii(range[dot_idx + 2 ..])) orelse continue;
        } else {
            lo = parseHexU32(range) orelse continue;
            hi = lo;
        }
        if (lo <= cp and cp <= hi) return trimAscii(value_field);
    }
    return null;
}

fn scriptOf(cp: u32) []const u8 {
    return scriptRowValue(scripts_raw, cp) orelse "Unknown";
}

// The four-letter abbreviation for a Script long name, from the "sc" rows of
// PropertyValueAliases.txt.
fn scriptLongToAbbrev(long: []const u8) ?[]const u8 {
    var offset: usize = 0;
    while (nextLine(property_value_aliases_raw, &offset)) |raw_line| {
        const body = if (std.mem.indexOfScalar(u8, raw_line, '#')) |idx| raw_line[0..idx] else raw_line;
        var fields = std.mem.splitScalar(u8, body, ';');
        const prop = trimAscii(fields.next() orelse continue);
        if (!std.mem.eql(u8, prop, "sc")) continue;
        const abbrev = trimAscii(fields.next() orelse continue);
        const name = trimAscii(fields.next() orelse continue);
        if (std.mem.eql(u8, name, long)) return abbrev;
    }
    return null;
}

// True iff the abbreviation occurs anywhere in ScriptExtensions.txt, which is
// the resolver's whole vocabulary.
fn isKnownScriptAbbrev(abbrev: []const u8) bool {
    var offset: usize = 0;
    while (nextLine(script_extensions_raw, &offset)) |raw_line| {
        const body = if (std.mem.indexOfScalar(u8, raw_line, '#')) |idx| raw_line[0..idx] else raw_line;
        const stripped = trimAscii(body);
        if (stripped.len == 0) continue;
        var fields = std.mem.splitScalar(u8, stripped, ';');
        _ = fields.next() orelse continue;
        const value_field = fields.next() orelse continue;
        var tags = std.mem.tokenizeAny(u8, trimAscii(value_field), " \t");
        while (tags.next()) |tag| {
            if (std.mem.eql(u8, tag, abbrev)) return true;
        }
    }
    return false;
}

// ── DerivedJoiningType.txt — RFC 5892 Appendix A.1 support ────────────────

// Joining_Type for one codepoint, as its single-letter token. The file shares
// the "RANGE ; VALUE" shape the script tables use, so it reuses the same row
// scan. The @missing line declares Non_Joining over the whole space, so an
// unlisted codepoint is 'U'.
fn joiningTypeOf(cp: u32) u8 {
    const value = scriptRowValue(derived_joining_type_raw, cp) orelse return 'U';
    const token = trimAscii(value);
    if (token.len != 1) return 'U';
    return switch (token[0]) {
        'C', 'D', 'L', 'R', 'T' => token[0],
        else => 'U',
    };
}

// True iff cp has Canonical_Combining_Class 9, the Virama used to request an
// explicit conjunct in scripts like Devanagari.
fn isViramaCodepoint(cp: u32) bool {
    return canonicalCombiningClass(cp) == 9;
}

// The Joining_Type of the first non-Transparent codepoint before i.
fn joiningTypeBefore(input: []const u32, i: usize) ?u8 {
    var j = i;
    while (j > 0) {
        j -= 1;
        const jt = joiningTypeOf(input[j]);
        if (jt != 'T') return jt;
    }
    return null;
}

// The Joining_Type of the first non-Transparent codepoint after i.
fn joiningTypeAfter(input: []const u32, i: usize) ?u8 {
    var j = i + 1;
    while (j < input.len) : (j += 1) {
        const jt = joiningTypeOf(input[j]);
        if (jt != 'T') return jt;
    }
    return null;
}

// True iff the ZWNJ at index i occupies a position where it is orthographically
// required, by RFC 5892 Appendix A.1: it follows a Virama, which is how a
// Devanagari conjunct is suppressed, or it sits between a left- or dual-joining
// character and a right- or dual-joining one, skipping Transparent characters
// on both sides, which is how a Persian word boundary is written inside a
// cursive run.
//
// A ZWNJ outside such a position carries no orthographic duty and stays
// reportable.
fn isLegitimateZwnjContext(input: []const u32, i: usize) bool {
    if (i > 0 and isViramaCodepoint(input[i - 1])) return true;
    const left = joiningTypeBefore(input, i) orelse return false;
    const right = joiningTypeAfter(input, i) orelse return false;
    const left_joins = left == 'L' or left == 'D';
    const right_joins = right == 'R' or right == 'D';
    return left_joins and right_joins;
}

// True iff the ZWJ at index i is flanked by two codepoints that both
// participate in some registered RGI emoji ZWJ sequence. Strictly narrower than
// "is an emoji": a codepoint carrying the Emoji property but appearing in no
// registered sequence does not sanction a ZWJ beside it. A ZWJ in head or tail
// position is never legitimate.
fn isLegitimateZwjContext(input: []const u32, i: usize) bool {
    if (i == 0 or i + 1 >= input.len) return false;
    return emoji_zwj_integrity.isEmojiTarget(input[i - 1]) and
        emoji_zwj_integrity.isEmojiTarget(input[i + 1]);
}

// True iff at least one zero-width codepoint of input is unsanctioned. A ZWJ
// inside a registered emoji sequence and a ZWNJ in an RFC 5892 CONTEXTJ-valid
// position both carry meaning a reader depends on, so they are recorded as
// present but do not make the family fire.
fn hasSuspiciousZeroWidth(input: []const u32) bool {
    for (input, 0..) |cp, i| {
        if (!isZeroWidthPayload(cp)) continue;
        const sanctioned = (cp == 0x200D and isLegitimateZwjContext(input, i)) or
            (cp == 0x200C and isLegitimateZwnjContext(input, i));
        if (!sanctioned) return true;
    }
    return false;
}

fn resolveScripts(cp: u32) ScriptSet {
    var set = ScriptSet{};
    if (scriptRowValue(script_extensions_raw, cp)) |value| {
        var tags = std.mem.tokenizeAny(u8, value, " \t");
        while (tags.next()) |tag| set.add(tag);
        return set;
    }
    const abbrev = scriptLongToAbbrev(scriptOf(cp)) orelse return set;
    if (!isKnownScriptAbbrev(abbrev)) return set;
    set.add(abbrev);
    return set;
}

fn isIgnoredForIntersection(cp: u32) bool {
    const script = scriptOf(cp);
    return std.mem.eql(u8, script, "Common") or std.mem.eql(u8, script, "Inherited");
}

fn stringScriptUnion(input: []const u32) ScriptSet {
    var union_set = ScriptSet{};
    for (input) |cp| {
        if (isIgnoredForIntersection(cp)) continue;
        const resolved = resolveScripts(cp);
        var i: usize = 0;
        while (i < resolved.len) : (i += 1) union_set.add(&resolved.items[i]);
    }
    return union_set;
}

fn stringResolvedScriptsLen(input: []const u32) usize {
    var acc = ScriptSet{};
    var started = false;
    for (input) |cp| {
        if (isIgnoredForIntersection(cp)) continue;
        const resolved = resolveScripts(cp);
        if (!started) {
            acc = resolved;
            started = true;
            continue;
        }
        var next = ScriptSet{};
        var i: usize = 0;
        while (i < acc.len) : (i += 1) {
            if (resolved.contains(&acc.items[i])) next.add(&acc.items[i]);
        }
        acc = next;
    }
    return if (started) acc.len else 0;
}

fn isAsciiOnly(input: []const u32) bool {
    for (input) |cp| {
        if (cp >= 0x80) return false;
    }
    return true;
}

fn isSingleScript(input: []const u32) bool {
    return !isAsciiOnly(input) and stringResolvedScriptsLen(input) > 0;
}

fn allWithinCovered(input: []const u32, covered: *const ScriptSet) bool {
    for (input) |cp| {
        if (isIgnoredForIntersection(cp)) continue;
        const resolved = resolveScripts(cp);
        if (resolved.len == 0 or !resolved.intersects(covered)) return false;
    }
    return true;
}

fn isCoveredCjk(input: []const u32) bool {
    const japanese = coveredSet(&[_][]const u8{ "Latn", "Hani", "Hira", "Kana" });
    const chinese = coveredSet(&[_][]const u8{ "Latn", "Hani", "Bopo" });
    const korean = coveredSet(&[_][]const u8{ "Latn", "Hani", "Hang" });
    return allWithinCovered(input, &japanese) or
        allWithinCovered(input, &chinese) or
        allWithinCovered(input, &korean);
}

fn isHighlyRestrictive(input: []const u32) bool {
    return isSingleScript(input) or isCoveredCjk(input);
}

// Every codepoint resolves to Latin or to one fixed other Recommended script,
// with that other script neither Cyrillic nor Greek.
fn isModeratelyRestrictiveShape(input: []const u32) bool {
    var other: ?[4]u8 = null;
    const latin = coveredSet(&[_][]const u8{"Latn"});
    for (input) |cp| {
        if (isIgnoredForIntersection(cp)) continue;
        const resolved = resolveScripts(cp);
        if (resolved.len == 0) return false;
        if (resolved.intersects(&latin)) continue;
        const s = resolved.items[0];
        if (std.mem.eql(u8, &s, "Cyrl") or std.mem.eql(u8, &s, "Grek")) return false;
        if (other) |committed| {
            if (!std.mem.eql(u8, &committed, &s)) return false;
        } else {
            other = s;
        }
    }
    return other != null;
}

fn isMinimallyRestrictive(input: []const u32) bool {
    for (input) |cp| {
        if (!isIdAllowed(cp)) return false;
    }
    return true;
}

fn restrictionLevel(input: []const u32) RestrictionLevel {
    if (isAsciiOnly(input)) return .ascii_only;
    if (isSingleScript(input)) return .single_script;
    if (isHighlyRestrictive(input)) return .highly_restrictive;
    if (isModeratelyRestrictiveShape(input)) return .moderately_restrictive;
    if (isMinimallyRestrictive(input)) return .minimally_restrictive;
    return .unrestricted;
}

fn hasCrossScriptMix(input: []const u32) bool {
    return stringScriptUnion(input).len >= 2 and !isHighlyRestrictive(input);
}

fn isDefaultIgnorableCodepoint(cp: u32) bool {
    return cp == 0x00AD or
        cp == 0x034F or
        cp == 0x061C or
        (cp >= 0x115F and cp <= 0x1160) or
        (cp >= 0x17B4 and cp <= 0x17B5) or
        (cp >= 0x180B and cp <= 0x180F) or
        (cp >= 0x200B and cp <= 0x200F) or
        (cp >= 0x202A and cp <= 0x202E) or
        (cp >= 0x2060 and cp <= 0x206F) or
        (cp >= 0xFE00 and cp <= 0xFE0F) or
        cp == 0xFEFF or
        (cp >= 0xFFF0 and cp <= 0xFFF8) or
        (cp >= 0xE0000 and cp <= 0xE0FFF);
}

fn isWhiteSpaceCodepoint(cp: u32) bool {
    return cp == 0x0009 or
        cp == 0x000A or
        cp == 0x000B or
        cp == 0x000C or
        cp == 0x000D or
        cp == 0x0020 or
        cp == 0x0085 or
        cp == 0x00A0 or
        cp == 0x1680 or
        (cp >= 0x2000 and cp <= 0x200A) or
        cp == 0x2028 or
        cp == 0x2029 or
        cp == 0x202F or
        cp == 0x205F or
        cp == 0x3000;
}

fn nextLine(raw: []const u8, offset: *usize) ?[]const u8 {
    if (offset.* >= raw.len) return null;
    const start = offset.*;
    const newline = std.mem.indexOfScalarPos(u8, raw, start, '\n') orelse raw.len;
    offset.* = if (newline == raw.len) raw.len else newline + 1;
    return raw[start..newline];
}

fn trimAscii(value: []const u8) []const u8 {
    var start: usize = 0;
    var end: usize = value.len;
    while (start < end and std.ascii.isWhitespace(value[start])) : (start += 1) {}
    while (end > start and std.ascii.isWhitespace(value[end - 1])) : (end -= 1) {}
    return value[start..end];
}

fn isNoncharacter(cp: u32) bool {
    if (cp >= 0xFDD0 and cp <= 0xFDEF) return true;
    if (cp > 0x10FFFF) return false;
    const low16 = cp & 0xFFFF;
    return low16 == 0xFFFE or low16 == 0xFFFF;
}

fn isC0Control(cp: u32) bool {
    return (cp <= 0x1F and cp != 0x09 and cp != 0x0A and cp != 0x0D) or cp == 0x7F;
}

fn isC1Control(cp: u32) bool {
    return cp >= 0x80 and cp <= 0x9F;
}

const Utf8RejectKind = enum {
    overlong_encoding,
    surrogate_codepoint,
    codepoint_beyond_max,
    truncated_sequence,
    invalid_start_byte,
    invalid_continuation_byte,
};

const Utf8Invalid = struct {
    offset: usize,
    kind: Utf8RejectKind,
};

const Endian = enum {
    big,
    little,
};

const DecodeFailure = struct {
    offset: usize,
    sub_threat: []const u8,
};

const DecodeResult = struct {
    len: usize,
    failure: ?DecodeFailure = null,
};

fn malformedDecodeVerdict(
    profile: Profile,
    mode: Mode,
    family: Family,
    code: []const u8,
    sub_threat: []const u8,
    detail: []const u8,
    offset: usize,
    decoded_buffer: []u32,
) Verdict {
    var findings = FindingList{};
    var positions: [MaxFindingPositions]usize = undefined;
    positions[0] = offset;
    findings.append(.{
        .code = code,
        .family = family,
        .severity = 2,
        .positions = positions,
        .position_count = 1,
        .sub_threat = sub_threat,
        .detail = detail,
    });
    return .{
        .input = decoded_buffer[0..0],
        .profile = profile,
        .mode = mode,
        .action = decide(profile, mode, findings),
        .findings = findings,
    };
}

fn firstInvalidUtf8Offset(bytes: anytype) ?Utf8Invalid {
    var in_sequence = false;
    var remaining: u8 = 0;
    var accum: u32 = 0;
    var min_cp: u32 = 0;
    var seq_start: usize = 0;

    for (bytes, 0..) |byte, index| {
        const n: u32 = byte;
        if (!in_sequence) {
            seq_start = index;
            if (n < 0x80) {
                continue;
            } else if (n < 0xC2) {
                return .{ .offset = index, .kind = .invalid_start_byte };
            } else if (n < 0xE0) {
                in_sequence = true;
                remaining = 1;
                accum = n & 0x1F;
                min_cp = 0x80;
            } else if (n < 0xF0) {
                in_sequence = true;
                remaining = 2;
                accum = n & 0x0F;
                min_cp = 0x800;
            } else if (n < 0xF5) {
                in_sequence = true;
                remaining = 3;
                accum = n & 0x07;
                min_cp = 0x10000;
            } else {
                return .{ .offset = index, .kind = .invalid_start_byte };
            }
            continue;
        }

        if (n < 0x80 or n >= 0xC0) {
            return .{ .offset = index, .kind = .invalid_continuation_byte };
        }
        const next = (accum << 6) | (n & 0x3F);
        if (remaining == 1) {
            if (next < min_cp) {
                return .{ .offset = seq_start, .kind = .overlong_encoding };
            }
            if (next >= 0xD800 and next <= 0xDFFF) {
                return .{ .offset = index, .kind = .surrogate_codepoint };
            }
            if (next > 0x10FFFF) {
                return .{ .offset = index, .kind = .codepoint_beyond_max };
            }
            in_sequence = false;
            remaining = 0;
            accum = 0;
            min_cp = 0;
        } else {
            remaining -= 1;
            accum = next;
        }
    }

    if (in_sequence) {
        return .{ .offset = bytes.len, .kind = .truncated_sequence };
    }
    return null;
}

/// Structural UTF-8 validity under the strict RFC 3629 decoder state
/// machine: `bytes` is valid exactly when the shared
/// `firstInvalidUtf8Offset` scanner finds no rejection. Overlong forms,
/// surrogate codepoints, codepoints beyond U+10FFFF, truncated
/// sequences, and stray start/continuation bytes are all rejected. The
/// byte-layer refinements in `opaque_blob.zig` layer on this predicate.
pub fn isValidUtf8(bytes: []const u8) bool {
    return firstInvalidUtf8Offset(bytes) == null;
}

fn decodeUtf8ToCodepoints(bytes: []const u8, out: []u32) usize {
    var out_len: usize = 0;
    var index: usize = 0;
    while (index < bytes.len) {
        const b0 = bytes[index];
        var cp: u32 = 0;
        var width: usize = 1;
        if (b0 < 0x80) {
            cp = b0;
        } else if (b0 < 0xE0) {
            cp = (@as(u32, b0 & 0x1F) << 6) | @as(u32, bytes[index + 1] & 0x3F);
            width = 2;
        } else if (b0 < 0xF0) {
            cp = (@as(u32, b0 & 0x0F) << 12) |
                (@as(u32, bytes[index + 1] & 0x3F) << 6) |
                @as(u32, bytes[index + 2] & 0x3F);
            width = 3;
        } else {
            cp = (@as(u32, b0 & 0x07) << 18) |
                (@as(u32, bytes[index + 1] & 0x3F) << 12) |
                (@as(u32, bytes[index + 2] & 0x3F) << 6) |
                @as(u32, bytes[index + 3] & 0x3F);
            width = 4;
        }
        if (out_len < out.len) {
            out[out_len] = cp;
            out_len += 1;
        }
        index += width;
    }
    return out_len;
}

fn decodeUtf16ToCodepoints(bytes: []const u8, out: []u32, endian: Endian) DecodeResult {
    var out_len: usize = 0;
    var offset: usize = 0;
    while (offset < bytes.len) {
        if (offset + 2 > bytes.len) {
            return .{ .len = 0, .failure = .{ .offset = bytes.len, .sub_threat = "TruncatedCodeUnit" } };
        }

        const unit = readU16(bytes, offset, endian);
        const unit_offset = offset;
        offset += 2;

        if (unit >= 0xD800 and unit <= 0xDBFF) {
            if (offset + 2 > bytes.len) {
                return .{ .len = 0, .failure = .{ .offset = bytes.len, .sub_threat = "TruncatedSurrogatePair" } };
            }
            const low = readU16(bytes, offset, endian);
            if (low < 0xDC00 or low > 0xDFFF) {
                return .{ .len = 0, .failure = .{ .offset = offset, .sub_threat = "InvalidSurrogatePair" } };
            }
            if (out_len < out.len) {
                out[out_len] = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00);
                out_len += 1;
            }
            offset += 2;
        } else if (unit >= 0xDC00 and unit <= 0xDFFF) {
            return .{ .len = 0, .failure = .{ .offset = unit_offset, .sub_threat = "LoneSurrogate" } };
        } else {
            if (out_len < out.len) {
                out[out_len] = unit;
                out_len += 1;
            }
        }
    }
    return .{ .len = out_len };
}

fn decodeUtf32ToCodepoints(bytes: []const u8, out: []u32, endian: Endian) DecodeResult {
    if (bytes.len % 4 != 0) {
        return .{ .len = 0, .failure = .{ .offset = bytes.len, .sub_threat = "TruncatedCodeUnit" } };
    }

    var out_len: usize = 0;
    var offset: usize = 0;
    while (offset < bytes.len) : (offset += 4) {
        const cp = readU32(bytes, offset, endian);
        if (cp >= 0xD800 and cp <= 0xDFFF) {
            return .{ .len = 0, .failure = .{ .offset = offset, .sub_threat = "SurrogateCodepoint" } };
        }
        if (cp > 0x10FFFF) {
            return .{ .len = 0, .failure = .{ .offset = offset, .sub_threat = "CodepointBeyondMax" } };
        }
        if (out_len < out.len) {
            out[out_len] = cp;
            out_len += 1;
        }
    }
    return .{ .len = out_len };
}

fn readU16(bytes: []const u8, offset: usize, endian: Endian) u32 {
    if (endian == .big) {
        return (@as(u32, bytes[offset]) << 8) | @as(u32, bytes[offset + 1]);
    }
    return @as(u32, bytes[offset]) | (@as(u32, bytes[offset + 1]) << 8);
}

fn readU32(bytes: []const u8, offset: usize, endian: Endian) u32 {
    if (endian == .big) {
        return (@as(u32, bytes[offset]) << 24) |
            (@as(u32, bytes[offset + 1]) << 16) |
            (@as(u32, bytes[offset + 2]) << 8) |
            @as(u32, bytes[offset + 3]);
    }
    return @as(u32, bytes[offset]) |
        (@as(u32, bytes[offset + 1]) << 8) |
        (@as(u32, bytes[offset + 2]) << 16) |
        (@as(u32, bytes[offset + 3]) << 24);
}

fn utf8RejectTag(kind: Utf8RejectKind) []const u8 {
    return switch (kind) {
        .overlong_encoding => "OverlongEncoding",
        .surrogate_codepoint => "SurrogateCodepoint",
        .codepoint_beyond_max => "CodepointBeyondMax",
        .truncated_sequence => "TruncatedSequence",
        .invalid_start_byte => "InvalidStartByte",
        .invalid_continuation_byte => "InvalidContinuationByte",
    };
}

fn malformedUtf8ReasonCode(kind: Utf8RejectKind) []const u8 {
    return switch (kind) {
        .overlong_encoding => "unicode.security.C.malformed-utf8.OverlongEncoding",
        .surrogate_codepoint => "unicode.security.C.malformed-utf8.SurrogateCodepoint",
        .codepoint_beyond_max => "unicode.security.C.malformed-utf8.CodepointBeyondMax",
        .truncated_sequence => "unicode.security.C.malformed-utf8.TruncatedSequence",
        .invalid_start_byte => "unicode.security.C.malformed-utf8.InvalidStartByte",
        .invalid_continuation_byte => "unicode.security.C.malformed-utf8.InvalidContinuationByte",
    };
}

/// Surrogate-reassembly sub-threat tag for a strict-UTF-8 rejection kind.
/// These tags DIFFER from the malformed-utf8 tags: a covert byte stream
/// disguised inside a codepoint list is a distinct threat from a raw
/// malformed wire encoding. Mirrors `subThreatOfRejectKind` in
/// `Unicode/Security/Covert/SurrogateReassembly.lean`.
fn surrogateReassemblyTag(kind: Utf8RejectKind) []const u8 {
    return switch (kind) {
        .overlong_encoding => "Overlong",
        .surrogate_codepoint => "Cesu8",
        .truncated_sequence => "Truncated",
        .invalid_start_byte => "InvalidStartByte",
        .invalid_continuation_byte => "InvalidContinuation",
        .codepoint_beyond_max => "CodepointBeyondMax",
    };
}

fn surrogateReassemblyReasonCode(kind: Utf8RejectKind) []const u8 {
    return switch (kind) {
        .overlong_encoding => "unicode.security.C.surrogate-reassembly.Overlong",
        .surrogate_codepoint => "unicode.security.C.surrogate-reassembly.Cesu8",
        .truncated_sequence => "unicode.security.C.surrogate-reassembly.Truncated",
        .invalid_start_byte => "unicode.security.C.surrogate-reassembly.InvalidStartByte",
        .invalid_continuation_byte => "unicode.security.C.surrogate-reassembly.InvalidContinuation",
        .codepoint_beyond_max => "unicode.security.C.surrogate-reassembly.CodepointBeyondMax",
    };
}

/// Byte-stream gate from `Unicode/Security/RunAll.lean`: true iff every entry
/// fits in one octet. The scan orchestrator uses this to skip the family on
/// codepoint-array input, exactly as `runAll` does.
fn looksLikeByteStream(input: []const u32) bool {
    for (input) |cp| {
        if (cp >= 0x100) return false;
    }
    return true;
}

/// Detect a malformed UTF-8 byte stream, mirroring the Lean module
/// `SurrogateReassembly.detect`. The strict validator treats each codepoint
/// as a byte; any value > 0xFF is rejected identically to the Lean `toBytes`
/// clamp to 0xFF (both are invalid UTF-8 at every position), so no separate
/// clamp is needed. Returns the first rejection, or null for a well-formed
/// stream. The byte-stream gate lives in the scan orchestrator
/// (`looksLikeByteStream`), mirroring `runAll`.
fn surrogateReassemblyDetect(input: []const u32) ?Utf8Invalid {
    return firstInvalidUtf8Offset(input);
}

/// Scan-orchestrator wrapper. Mirrors `runAll`: SurrogateReassembly only
/// applies to byte-stream-shaped input (every codepoint <= 0xFF); on
/// codepoint-array input the family is skipped. The first rejection is
/// projected onto a covert-layer sub-threat at its byte offset.
fn surrogateReassemblyFinding(input: []const u32) ?Finding {
    if (!looksLikeByteStream(input)) return null;
    const invalid = surrogateReassemblyDetect(input) orelse return null;
    var positions: [MaxFindingPositions]usize = undefined;
    positions[0] = invalid.offset;
    return .{
        .code = surrogateReassemblyReasonCode(invalid.kind),
        .family = .surrogate_reassembly,
        .severity = 2,
        .positions = positions,
        .position_count = 1,
        .sub_threat = surrogateReassemblyTag(invalid.kind),
        .detail = "surrogate-reassembly",
    };
}

fn malformedUtf16ReasonCode(sub_threat: []const u8) []const u8 {
    if (std.mem.eql(u8, sub_threat, "TruncatedCodeUnit")) {
        return "unicode.security.C.malformed-utf16.TruncatedCodeUnit";
    }
    if (std.mem.eql(u8, sub_threat, "LoneSurrogate")) {
        return "unicode.security.C.malformed-utf16.LoneSurrogate";
    }
    if (std.mem.eql(u8, sub_threat, "InvalidSurrogatePair")) {
        return "unicode.security.C.malformed-utf16.InvalidSurrogatePair";
    }
    return "unicode.security.C.malformed-utf16.TruncatedSurrogatePair";
}

fn malformedUtf32ReasonCode(sub_threat: []const u8) []const u8 {
    if (std.mem.eql(u8, sub_threat, "TruncatedCodeUnit")) {
        return "unicode.security.C.malformed-utf32.TruncatedCodeUnit";
    }
    if (std.mem.eql(u8, sub_threat, "SurrogateCodepoint")) {
        return "unicode.security.C.malformed-utf32.SurrogateCodepoint";
    }
    return "unicode.security.C.malformed-utf32.CodepointBeyondMax";
}

// ─────────────────────────────────────────────────────────────────────
// NFKD / NFKC / NFC known-answer tests (UAX #15).  Mirrors the Rust
// identity port's `nfkc_nfkd_tests`.
// ─────────────────────────────────────────────────────────────────────

fn expectNormalization(
    comptime func: fn ([]const u32) ?CpBuffer,
    input: []const u32,
    expected: []const u32,
) !void {
    const result = func(input) orelse return error.NormalizationFailed;
    try std.testing.expect(cpSlicesEqual(result.slice(), expected));
}

test "toNFKC known vectors" {
    // ﬁ ligature (U+FB01) → "fi".
    try expectNormalization(toNFKC, &[_]u32{0xFB01}, &[_]u32{ 0x66, 0x69 });
    // ① circled digit one (U+2460) → "1".
    try expectNormalization(toNFKC, &[_]u32{0x2460}, &[_]u32{0x31});
    // Fullwidth A (U+FF21) → "A".
    try expectNormalization(toNFKC, &[_]u32{0xFF21}, &[_]u32{0x41});
    // Precomposed é (U+00E9) stays é under NFKC.
    try expectNormalization(toNFKC, &[_]u32{0x00E9}, &[_]u32{0x00E9});
    // Decomposed e + combining acute → é under NFKC.
    try expectNormalization(toNFKC, &[_]u32{ 0x0065, 0x0301 }, &[_]u32{0x00E9});
    // Hangul jamo L+V+T → precomposed syllable 한 (U+D55C).
    try expectNormalization(toNFKC, &[_]u32{ 0x1112, 0x1161, 0x11AB }, &[_]u32{0xD55C});
    // Plain ASCII unchanged.
    try expectNormalization(toNFKC, &[_]u32{ 0x48, 0x69 }, &[_]u32{ 0x48, 0x69 });
}

test "toNFKD known vectors" {
    // Fullwidth A → "A" (compatibility decomposition, no recomposition).
    try expectNormalization(toNFKD, &[_]u32{0xFF21}, &[_]u32{0x41});
    // ﬁ → "fi".
    try expectNormalization(toNFKD, &[_]u32{0xFB01}, &[_]u32{ 0x66, 0x69 });
    // Precomposed é → e + combining acute under NFKD.
    try expectNormalization(toNFKD, &[_]u32{0x00E9}, &[_]u32{ 0x0065, 0x0301 });
}

test "toNFC recomposition" {
    // Decomposed e + combining acute → precomposed é under NFC.
    try expectNormalization(toNFC, &[_]u32{ 0x0065, 0x0301 }, &[_]u32{0x00E9});
    // Hangul jamo L+V+T → precomposed syllable 한 under NFC.
    try expectNormalization(toNFC, &[_]u32{ 0x1112, 0x1161, 0x11AB }, &[_]u32{0xD55C});
}

test "toNFC honors UAX #15 D115 blocking" {
    // Matches the Lean spec Unicode.Normalization.Compose.stepCompose: a
    // starter candidate is blocked from the active starter by any buffered
    // non-starter between them. Hangul L + combining grave (CCC 230) + V —
    // the grave blocks the L+V syllable composition across it.
    try expectNormalization(toNFC, &[_]u32{ 0x1100, 0x0300, 0x1161 }, &[_]u32{ 0x1100, 0x0300, 0x1161 });
    // The same jamo without the intervening mark compose to U+AC00.
    try expectNormalization(toNFC, &[_]u32{ 0x1100, 0x1161 }, &[_]u32{0xAC00});
    // A + below(CCC 220) + grave(CCC 230): the higher-CCC grave is not
    // blocked and composes to À; the lower-CCC mark stays buffered.
    try expectNormalization(toNFC, &[_]u32{ 0x0041, 0x0316, 0x0300 }, &[_]u32{ 0x00C0, 0x0316 });
}

fn expectToLower(locale: CasingLocale, input: []const u32, expected: []const u32) !void {
    const result = toLower(locale, input) orelse return error.ToLowerFailed;
    try std.testing.expect(cpSlicesEqual(result.slice(), expected));
}

test "toLower ground-truth theorems" {
    // Mirrors the toLower_* theorems in Unicode/Casing.lean.
    try expectToLower(.default, &[_]u32{ 0x48, 0x65, 0x6C, 0x6C, 0x6F }, &[_]u32{ 0x68, 0x65, 0x6C, 0x6C, 0x6F });
    try expectToLower(.default, &[_]u32{0x0049}, &[_]u32{0x0069});
    try expectToLower(.turkish, &[_]u32{0x0049}, &[_]u32{0x0131});
    try expectToLower(.azeri, &[_]u32{0x0049}, &[_]u32{0x0131});
    try expectToLower(.turkish, &[_]u32{0x0130}, &[_]u32{0x0069});
    try expectToLower(.default, &[_]u32{0x0130}, &[_]u32{ 0x0069, 0x0307 });
}

fn expectBip39Sub(input: []const u32, expected: []const u8) !void {
    const result = bip39CanonicalDetect(input);
    try std.testing.expect(result.sub_threat != null);
    try std.testing.expect(std.mem.eql(u8, result.sub_threat.?, expected));
}

test "bip39 canonical detect spot-checks" {
    // Mirrors the detect ground-truth vectors in
    // Unicode/Security/Crypto/Bip39Canonical.lean.
    const abandon = [_]u32{ 0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E };
    const about = [_]u32{ 0x61, 0x62, 0x6F, 0x75, 0x74 };
    const sp = [_]u32{0x20};

    const trailing = abandon ++ sp;
    try expectBip39Sub(&trailing, "TrailingWhitespace");
    try std.testing.expect(bip39CanonicalDetect(&trailing).positions[0] == 7);

    const mixed = [_]u32{ 0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E };
    try expectBip39Sub(&mixed, "MixedCase");
    const double_space = abandon ++ sp ++ sp ++ about;
    try expectBip39Sub(&double_space, "WhitespaceAnomaly");
    const leading = sp ++ abandon;
    try expectBip39Sub(&leading, "WhitespaceAnomaly");
    try expectBip39Sub(&[_]u32{0xFB00}, "NonNFKD");
    try expectBip39Sub(&[_]u32{ 0x61, 0x00A0, 0x62 }, "NonNFKD");
    try expectBip39Sub(&[_]u32{ 0x71, 0x7A, 0x71, 0x7A }, "WordlistMismatch");

    const empty = [_]u32{};
    const empty_result = bip39CanonicalDetect(&empty);
    try std.testing.expect(empty_result.sub_threat == null);
    try std.testing.expect(std.mem.eql(u8, empty_result.language, "english"));

    // Eleven "abandon" words plus "about": a well-formed 12-word English mnemonic.
    const mnemonic = ((abandon ++ sp) ** 11) ++ about;
    const verdict = bip39CanonicalDetect(&mnemonic);
    try std.testing.expect(verdict.sub_threat == null);
    try std.testing.expect(std.mem.eql(u8, verdict.language, "english"));
    try std.testing.expect(verdict.word_count == 12);
}

fn expectLocaleCaseSub(input: []const u32, expected: ?[]const u8) !void {
    const result = localeCaseInversionDetect(input);
    if (expected) |want| {
        try std.testing.expect(result.sub_threat != null);
        try std.testing.expect(std.mem.eql(u8, result.sub_threat.?, want));
    } else {
        try std.testing.expect(result.sub_threat == null);
    }
}

test "locale-case-inversion detect spot-checks" {
    // Mirrors the detect_* ground-truth theorems in
    // Unicode/Security/Form/LocaleCaseInversion.lean.
    try expectLocaleCaseSub(&[_]u32{}, null);
    try expectLocaleCaseSub(&[_]u32{ 0x48, 0x65, 0x6C, 0x6C, 0x6F }, null);
    try expectLocaleCaseSub(&[_]u32{0x0049}, "TurkishCaseDivergence");
    try std.testing.expect(localeCaseInversionDetect(&[_]u32{0x0049}).positions[0] == 0);
    try expectLocaleCaseSub(&[_]u32{0x0130}, "TurkishCaseDivergence");
    try expectLocaleCaseSub(&[_]u32{ 0x0049, 0x0300 }, "TurkishCaseDivergence");
    try expectLocaleCaseSub(&[_]u32{ 0x004A, 0x0300 }, "LithuanianCaseDivergence");
}

fn expectNormalizationBombSub(input: []const u32, expected: ?[]const u8) !void {
    const result = normalizationBombDetect(input);
    if (expected) |want| {
        try std.testing.expect(result.sub_threat != null);
        try std.testing.expect(std.mem.eql(u8, result.sub_threat.?, want));
    } else {
        try std.testing.expect(result.sub_threat == null);
    }
}

test "normalization-bomb detect spot-checks" {
    // Mirrors the detect_* ground-truth theorems in
    // Unicode/Security/Form/NormalizationBomb.lean.
    try expectNormalizationBombSub(&[_]u32{}, null);
    try expectNormalizationBombSub(&[_]u32{ 0x48, 0x65, 0x6C, 0x6C, 0x6F }, null);
    try expectNormalizationBombSub(&[_]u32{0xD55C}, null); // NFD ratio exactly 300, not > 300
    try expectNormalizationBombSub(&[_]u32{0x2460}, null); // circled one, NFKD 1×
    try expectNormalizationBombSub(&[_]u32{0xFDFA}, "SingleCpBlowup");
    try std.testing.expect(normalizationBombDetect(&[_]u32{0xFDFA}).positions[0] == 0);
    try expectNormalizationBombSub(&[_]u32{0xFDFB}, "NfkdHighExpansion");
    try expectNormalizationBombSub(&[_]u32{0x1F82}, "NfdHighExpansion");
}

fn expectNfcIdempotenceWitnessSub(input: []const u32, expected: ?[]const u8) !void {
    const result = nfcIdempotenceWitnessDetect(input);
    if (expected) |want| {
        try std.testing.expect(result.sub_threat != null);
        try std.testing.expect(std.mem.eql(u8, result.sub_threat.?, want));
    } else {
        try std.testing.expect(result.sub_threat == null);
    }
}

test "nfc-idempotence-witness detect spot-checks" {
    // Mirrors the detect_* ground-truth theorems in
    // Unicode/Security/Form/NfcIdempotenceWitness.lean.
    try expectNfcIdempotenceWitnessSub(&[_]u32{}, null);
    try expectNfcIdempotenceWitnessSub(&[_]u32{ 0x48, 0x65, 0x6C, 0x6C, 0x6F }, null);
    try expectNfcIdempotenceWitnessSub(&[_]u32{0x00E9}, null); // precomposed é
    try expectNfcIdempotenceWitnessSub(&[_]u32{ 0x0065, 0x0301 }, "NonNfcForm"); // e + combining acute
    try std.testing.expect(nfcIdempotenceWitnessDetect(&[_]u32{ 0x0065, 0x0301 }).positions[0] == 0);
    try expectNfcIdempotenceWitnessSub(&[_]u32{0xFB01}, "NonNfkcCompatForm"); // fi ligature
}

// ── hash-input-stability (crypto layer) ─────────────────────────────────

const His = hash_input_stability;

fn expectHashStable(input: []const u32, expected: []const u32) !void {
    const stable = His.hashStable(input);
    try std.testing.expect(cpSlicesEqual(stable.slice(), expected));
}

test "hash-input-stability hash_stable spot checks" {
    // Mirrors the §4 hash_stable spot checks in
    // Unicode/Security/Crypto/HashInputStability.lean and its Rust port.
    try expectHashStable(&[_]u32{}, &[_]u32{});
    try expectHashStable(&[_]u32{ 0x61, 0x62, 0x63 }, &[_]u32{ 0x61, 0x62, 0x63 });
    // Idempotence: hash_stable(hash_stable(x)) == hash_stable(x).
    const once = His.hashStable(&[_]u32{ 0x61, 0x62, 0x63 });
    const twice = His.hashStable(once.slice());
    try std.testing.expect(cpSlicesEqual(once.slice(), twice.slice()));
    try expectHashStable(&[_]u32{ 0x61, 0x20 }, &[_]u32{0x61}); // trailing space
    try expectHashStable(&[_]u32{ 0x61, 0x09 }, &[_]u32{0x61}); // trailing tab
    try expectHashStable(&[_]u32{ 0x61, 0x0A }, &[_]u32{0x61}); // trailing LF
    try expectHashStable(&[_]u32{ 0x61, 0x0D, 0x0A }, &[_]u32{0x61}); // trailing CRLF
    try expectHashStable(&[_]u32{ 0x61, 0x20, 0x62 }, &[_]u32{ 0x61, 0x20, 0x62 }); // internal space kept
    try expectHashStable(&[_]u32{ 0x0065, 0x0301 }, &[_]u32{0x00E9}); // NFC composes
    try expectHashStable(&[_]u32{ 0x61, 0x00A0 }, &[_]u32{ 0x61, 0x00A0 }); // trailing NBSP kept
}

fn hisTag(input: []const u32) ?[]const u8 {
    return His.detect(input).classify.tag();
}

fn hisCtxTag(ctx: His.Context, input: []const u32) ?[]const u8 {
    return His.detectWithContext(ctx, input).classify.tag();
}

fn expectCtxHazard(ctx: His.Context, input: []const u32, want_tag: []const u8, want_pos: []const usize) !void {
    const v = His.detectWithContext(ctx, input);
    try std.testing.expect(v.classify.tag() != null);
    try std.testing.expectEqualStrings(want_tag, v.classify.tag().?);
    try std.testing.expectEqualSlices(usize, want_pos, v.classify.positions());
}

test "hash-input-stability detect spot checks" {
    // Mirrors the §8 detect spot checks (shared context-free fixture vectors in
    // the shared hash_input_stability.json detector fixture).
    try std.testing.expect(His.detect(&[_]u32{}).classify.isClear()); // empty-clear
    try std.testing.expect(His.detect(&[_]u32{ 0x61, 0x62, 0x63 }).classify.isClear()); // ascii-idempotent-clear

    const trailing_space = His.detect(&[_]u32{ 0x61, 0x20 }); // trailing-space
    try std.testing.expectEqualStrings("TrailingWhitespace", trailing_space.classify.tag().?);
    try std.testing.expect(trailing_space.stable_size == 1);
    try std.testing.expectEqualSlices(usize, &[_]usize{1}, trailing_space.classify.positions());

    const trailing_crlf = His.detect(&[_]u32{ 0x61, 0x0D, 0x0A }); // trailing-crlf
    try std.testing.expectEqualStrings("TrailingWhitespace", trailing_crlf.classify.tag().?);
    try std.testing.expect(trailing_crlf.stable_size == 1);

    const drift = His.detect(&[_]u32{ 0x0065, 0x0301 }); // decomposed-e-acute-normalization-drift
    try std.testing.expectEqualStrings("NormalizationDrift", drift.classify.tag().?);
    try std.testing.expectEqualSlices(usize, &[_]usize{0}, drift.classify.positions());

    try std.testing.expect(His.detect(&[_]u32{0x00E9}).classify.isClear()); // precomposed-e-acute-clear
    // priority-trailing-over-nfc: decomposed "é " — TrailingWhitespace wins.
    try std.testing.expectEqualStrings("TrailingWhitespace", hisTag(&[_]u32{ 0x0065, 0x0301, 0x20 }).?);
    try std.testing.expect(His.detect(&[_]u32{ 0x61, 0x20, 0x62 }).classify.isClear()); // internal-space-clear
}

test "hash-input-stability context probe vectors" {
    // Every Context-bearing vector transcribed verbatim from the Rust
    // #[test] module's Context comment block plus its #[test] functions
    // (the shared JSON fixture schema cannot express a Context).

    // detect_with_context(default) == detect.
    {
        const d = His.detect(&[_]u32{ 0x61, 0x62, 0x63 });
        const c = His.detectWithContext(His.Context{}, &[_]u32{ 0x61, 0x62, 0x63 });
        try std.testing.expectEqual(d.classify.isClear(), c.classify.isClear());
        try std.testing.expect(d.stable_size == c.stable_size);
    }

    // declared_encoding = Some("utf-16"), [0x61,0x62,0x63] → EncodingMismatch, [0].
    try expectCtxHazard(.{ .declared_encoding = "utf-16" }, &[_]u32{ 0x61, 0x62, 0x63 }, "EncodingMismatch", &[_]usize{0});
    // declared_encoding = Some("utf-8"), [0x61,0xD800,0x62] → EncodingMismatch, [1] (invalid surrogate).
    try expectCtxHazard(.{ .declared_encoding = "utf-8" }, &[_]u32{ 0x61, 0xD800, 0x62 }, "EncodingMismatch", &[_]usize{1});
    // declared_encoding = Some("utf-8"), [0x61,0x110000,0x62] → EncodingMismatch, [1] (out of range).
    try expectCtxHazard(.{ .declared_encoding = "utf-8" }, &[_]u32{ 0x61, 0x110000, 0x62 }, "EncodingMismatch", &[_]usize{1});
    // declared_encoding = Some("UTF-8"|"utf-8"|"UTF8"|"utf8"), [0x61,0x62,0x63] → clear.
    for ([_][]const u8{ "UTF-8", "utf-8", "UTF8", "utf8" }) |label| {
        try std.testing.expect(hisCtxTag(.{ .declared_encoding = label }, &[_]u32{ 0x61, 0x62, 0x63 }) == null);
    }

    // rfc_rule = Pgp4880TrailingWhitespace, [0x61,0x20] → SignedMessageRule, [1].
    try expectCtxHazard(.{ .rfc_rule = .pgp4880_trailing_whitespace }, &[_]u32{ 0x61, 0x20 }, "SignedMessageRule", &[_]usize{1});
    // rfc_rule = Pgp9580LineEnding, [0x61,0x0A,0x62] → SignedMessageRule, [1] (bare LF).
    try expectCtxHazard(.{ .rfc_rule = .pgp9580_line_ending }, &[_]u32{ 0x61, 0x0A, 0x62 }, "SignedMessageRule", &[_]usize{1});
    // rfc_rule = Pgp9580LineEnding, [0x61,0x62,0x63,0x0D,0x0A,0x64,0x65,0x66] → clear (CRLF).
    try std.testing.expect(hisCtxTag(.{ .rfc_rule = .pgp9580_line_ending }, &[_]u32{ 0x61, 0x62, 0x63, 0x0D, 0x0A, 0x64, 0x65, 0x66 }) == null);
    // rfc_rule = Rfc8785NfcRequirement, [0x0065,0x0301] → SignedMessageRule, [0].
    try expectCtxHazard(.{ .rfc_rule = .rfc8785_nfc_requirement }, &[_]u32{ 0x0065, 0x0301 }, "SignedMessageRule", &[_]usize{0});
    // rfc_rule = Rfc8259ControlChar, [0x61,0x01,0x62] → SignedMessageRule, [1].
    try expectCtxHazard(.{ .rfc_rule = .rfc8259_control_char }, &[_]u32{ 0x61, 0x01, 0x62 }, "SignedMessageRule", &[_]usize{1});
    // rfc_rule = Rfc7515JwsBase64Url, [0x41,0x2B,0x42] → SignedMessageRule, [1] ('+').
    try expectCtxHazard(.{ .rfc_rule = .rfc7515_jws_base64_url }, &[_]u32{ 0x41, 0x2B, 0x42 }, "SignedMessageRule", &[_]usize{1});
    // rfc_rule = Rfc7515JwsBase64Url, [0x41,0x61,0x30,0x2D,0x5F,0x7A,0x5A,0x39] → clear.
    try std.testing.expect(hisCtxTag(.{ .rfc_rule = .rfc7515_jws_base64_url }, &[_]u32{ 0x41, 0x61, 0x30, 0x2D, 0x5F, 0x7A, 0x5A, 0x39 }) == null);
    // rfc_rule = Rfc6376DkimRelaxed, [0x61,0x20,0x20,0x62] → SignedMessageRule, [2].
    try expectCtxHazard(.{ .rfc_rule = .rfc6376_dkim_relaxed }, &[_]u32{ 0x61, 0x20, 0x20, 0x62 }, "SignedMessageRule", &[_]usize{2});
    // rfc_rule = Rfc6376DkimRelaxed, [0x61,0x20,0x62] → clear (single space).
    try std.testing.expect(hisCtxTag(.{ .rfc_rule = .rfc6376_dkim_relaxed }, &[_]u32{ 0x61, 0x20, 0x62 }) == null);
    // rfc_rule = Rfc5751SmimeLineEnding, [0x61,0x0A,0x62] → SignedMessageRule, [1] (bare LF).
    try expectCtxHazard(.{ .rfc_rule = .rfc5751_smime_line_ending }, &[_]u32{ 0x61, 0x0A, 0x62 }, "SignedMessageRule", &[_]usize{1});

    // as_written = Some([0x61,0x62,0x63]), input [0x61,0x62,0x64] → AuditLogReinterpretation, [2].
    try expectCtxHazard(.{ .as_written = &[_]u32{ 0x61, 0x62, 0x63 } }, &[_]u32{ 0x61, 0x62, 0x64 }, "AuditLogReinterpretation", &[_]usize{2});
    // as_written = Some([0x61,0x62,0x63]), input [0x61,0x62,0x63] → clear.
    try std.testing.expect(hisCtxTag(.{ .as_written = &[_]u32{ 0x61, 0x62, 0x63 } }, &[_]u32{ 0x61, 0x62, 0x63 }) == null);
    // server_bytes = Some([0x61,0x62,0x64]), input [0x61,0x62,0x63] → WebhookSignatureDrift, [2].
    try expectCtxHazard(.{ .server_bytes = &[_]u32{ 0x61, 0x62, 0x64 } }, &[_]u32{ 0x61, 0x62, 0x63 }, "WebhookSignatureDrift", &[_]usize{2});
    // server_bytes = Some([0x61,0x62,0x63]), input [0x61,0x62,0x63] → clear.
    try std.testing.expect(hisCtxTag(.{ .server_bytes = &[_]u32{ 0x61, 0x62, 0x63 } }, &[_]u32{ 0x61, 0x62, 0x63 }) == null);

    // declared_encoding = Some("utf-16") + rfc_rule = Pgp9580LineEnding,
    // [0x0065,0x0301,0x0A] → EncodingMismatch (priority over rfc).
    try std.testing.expectEqualStrings("EncodingMismatch", hisCtxTag(.{ .declared_encoding = "utf-16", .rfc_rule = .pgp9580_line_ending }, &[_]u32{ 0x0065, 0x0301, 0x0A }).?);
    // server_bytes = Some([0x61,0x62,0x65]) + as_written = Some([0x61,0x62,0x66]),
    // input [0x61,0x62,0x63] → WebhookSignatureDrift (priority over audit).
    try std.testing.expectEqualStrings("WebhookSignatureDrift", hisCtxTag(.{ .server_bytes = &[_]u32{ 0x61, 0x62, 0x65 }, .as_written = &[_]u32{ 0x61, 0x62, 0x66 } }, &[_]u32{ 0x61, 0x62, 0x63 }).?);
    // rfc_rule = Pgp4880TrailingWhitespace, [0x61,0x20] → SignedMessageRule (priority over trailing).
    try std.testing.expectEqualStrings("SignedMessageRule", hisCtxTag(.{ .rfc_rule = .pgp4880_trailing_whitespace }, &[_]u32{ 0x61, 0x20 }).?);
}

test "hash-input-stability RfcRule tag round-trip" {
    // Mirrors rfc_rule_tag_roundtrip: from_tag(tag()) == rule for every rule.
    const rules = [_]His.RfcRule{
        .pgp4880_trailing_whitespace,
        .pgp9580_line_ending,
        .rfc8785_nfc_requirement,
        .rfc8259_control_char,
        .rfc7515_jws_base64_url,
        .rfc6376_dkim_relaxed,
        .rfc5751_smime_line_ending,
    };
    for (rules) |rule| {
        try std.testing.expectEqual(@as(?His.RfcRule, rule), His.RfcRule.fromTag(rule.tag()));
    }
    try std.testing.expectEqual(@as(?His.RfcRule, null), His.RfcRule.fromTag("nope"));
}

// ── ai-watermark-detectability (crypto layer) ───────────────────────────

const Aw = ai_watermark_detectability;

fn awTag(input: []const u32) ?[]const u8 {
    return Aw.detect(input).classify.tag();
}

fn expectAwTag(input: []const u32, want: []const u8) !void {
    const t = awTag(input);
    try std.testing.expect(t != null);
    try std.testing.expectEqualStrings(want, t.?);
}

test "ai-watermark-detectability probe spot checks" {
    // Mirrors the §4 probe spot-check theorems in
    // Unicode/Security/Crypto/AiWatermarkDetectability.lean and its Rust port.
    try std.testing.expect(Aw.isNnbsp(0x202F));
    try std.testing.expect(!Aw.isNnbsp(0x20));
    try std.testing.expect(!Aw.isNnbsp(0x3000));

    try std.testing.expect(Aw.isZwj(0x200D));
    try std.testing.expect(!Aw.isZwj(0x200B));
    try std.testing.expect(!Aw.isZwj(0x200C));

    try std.testing.expect(Aw.isVariationSelector(0xFE00));
    try std.testing.expect(Aw.isVariationSelector(0xFE0F));
    try std.testing.expect(Aw.isVariationSelector(0xE0100));
    try std.testing.expect(!Aw.isVariationSelector(0x61));
    try std.testing.expect(!Aw.isVariationSelector(0x200D));

    try std.testing.expect(Aw.isDefaultIgnorable(0x200B));
    try std.testing.expect(Aw.isDefaultIgnorable(0x200D));
    try std.testing.expect(Aw.isDefaultIgnorable(0x00AD));
    try std.testing.expect(!Aw.isDefaultIgnorable(0x202F));
    try std.testing.expect(!Aw.isDefaultIgnorable(0x61));

    try std.testing.expect(Aw.isEmoji(0x1F600));
    try std.testing.expect(!Aw.isEmoji(0x200D));
    try std.testing.expect(!Aw.isEmoji(0x61));

    try std.testing.expect(!Aw.isAdjacentToEmoji(&[_]u32{ 0x61, 0xFE0F, 0x62 }, 1));
    try std.testing.expect(Aw.isAdjacentToEmoji(&[_]u32{ 0x1F600, 0xFE0F }, 1));
    try std.testing.expect(Aw.isAdjacentToEmoji(&[_]u32{ 0xFE0F, 0x1F600 }, 0));
}

test "ai-watermark-detectability detect spot checks" {
    // Mirrors the §6 detect spot checks (shared context-free fixture vectors in
    // the shared ai_watermark_detectability.json detector fixture).
    try std.testing.expect(Aw.detect(&[_]u32{}).classify.isClear()); // empty-clear
    try std.testing.expect(Aw.detect(&[_]u32{ 0x61, 0x62, 0x63 }).classify.isClear()); // ascii-clear
    try std.testing.expect(Aw.detect(&[_]u32{ 0x4E2D, 0x6587 }).classify.isClear()); // han-clear

    {
        const v = Aw.detect(&[_]u32{ 0x61, 0x202F, 0x62 }); // nnbsp-boundary
        try std.testing.expectEqualStrings("NnbspBoundary", v.classify.tag().?);
        try std.testing.expectEqualSlices(usize, &[_]usize{1}, v.classify.positions());
        try std.testing.expect(v.marker_count == 1);
    }
    {
        const v = Aw.detect(&[_]u32{ 0x61, 0xFE0F, 0x62 }); // vs-in-plain-text
        try std.testing.expectEqualStrings("VariationSelectorCarrier", v.classify.tag().?);
        try std.testing.expect(v.marker_count == 1);
    }
    try std.testing.expect(Aw.detect(&[_]u32{ 0x1F600, 0xFE0F }).classify.isClear()); // vs-after-emoji-clear
    {
        const v = Aw.detect(&[_]u32{ 0x61, 0x200D, 0x62 }); // zwj-in-plain-text
        try std.testing.expectEqualStrings("ZwjNonEmoji", v.classify.tag().?);
        try std.testing.expect(v.marker_count == 1);
    }
    try std.testing.expect(Aw.detect(&[_]u32{ 0x1F469, 0x200D, 0x1F52C }).classify.isClear()); // zwj-emoji-sequence-clear
    {
        const v = Aw.detect(&[_]u32{ 0x61, 0x00AD, 0x62 }); // soft-hyphen-default-ignorable
        try std.testing.expectEqualStrings("DefaultIgnorableCarrier", v.classify.tag().?);
        try std.testing.expect(v.marker_count == 1);
    }
    {
        const v = Aw.detect(&[_]u32{ 0x61, 0x200B, 0x62 }); // zwsp-default-ignorable
        try std.testing.expectEqualStrings("DefaultIgnorableCarrier", v.classify.tag().?);
        try std.testing.expect(v.marker_count == 1);
    }
    try expectAwTag(&[_]u32{ 0x61, 0x202F, 0x00AD, 0x62 }, "Unknown"); // priority unknown over nnbsp+di
    try expectAwTag(&[_]u32{ 0x61, 0xFE0F, 0x200D, 0x62 }, "Unknown"); // priority unknown over vs+zwj
    {
        const v = Aw.detect(&[_]u32{ 0x61, 0x202F, 0x62, 0x202F, 0x63 }); // multiple-nnbsp-aggregates
        try std.testing.expectEqualStrings("NnbspBoundary", v.classify.tag().?);
        try std.testing.expect(v.marker_count == 2);
        try std.testing.expectEqualSlices(usize, &[_]usize{ 1, 3 }, v.classify.positions());
    }
}

test "ai-watermark-detectability refinement probes" {
    // Mirrors the §7 refinement-probe and priority theorems.
    {
        const v = Aw.detect(&[_]u32{ 0x61, 0x202F, 0x62, 0x202F, 0x63, 0x202F, 0x64 }); // adversarial-arithmetic-nnbsp
        try std.testing.expectEqualStrings("Adversarial", v.classify.tag().?);
        try std.testing.expect(v.marker_count == 3);
    }
    try expectAwTag(&[_]u32{ 0x61, 0x202F, 0x62, 0x202F, 0x63 }, "NnbspBoundary"); // two below adversarial threshold
    {
        const v = Aw.detect(&[_]u32{ 0x61, 0x200B, 0x62, 0x200B, 0x63, 0x200B, 0x64 }); // gpt5-zwsp-modulo
        try std.testing.expectEqualStrings("Gpt5ZwspModulo", v.classify.tag().?);
        try std.testing.expect(v.marker_count == 3);
    }
    try expectAwTag(&[_]u32{ 0x61, 0x200B, 0x62, 0x200B, 0x63 }, "DefaultIgnorableCarrier"); // two below modulo threshold
    {
        const v = Aw.detect(&[_]u32{ 0x201C, 0x61, 0x62, 0x63, 0x201D }); // smart-quote-alternation
        try std.testing.expectEqualStrings("SmartQuoteAlternation", v.classify.tag().?);
        try std.testing.expect(v.marker_count == 2);
    }
    try std.testing.expect(Aw.detect(&[_]u32{ 0x201C, 0x61, 0x22, 0x201D }).classify.isClear()); // smart-quote-with-straight-clear
    {
        const v = Aw.detect(&[_]u32{ 0x61, 0x62, 0x20, 0x2014, 0x20, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66 }); // em-dash-pattern
        try std.testing.expectEqualStrings("EmDashPattern", v.classify.tag().?);
        try std.testing.expect(v.marker_count == 2);
    }
    try std.testing.expect(Aw.detect(&[_]u32{ 0x61, 0x62, 0x2D, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66 }).classify.isClear()); // em-dash-with-hyphen-clear
    {
        const v = Aw.detect(&[_]u32{ 0x64, 0x65, 0x6C, 0x76, 0x65 }); // statistical-token-delve
        try std.testing.expectEqualStrings("StatisticalTokenChoice", v.classify.tag().?);
        try std.testing.expect(v.marker_count == 1);
    }
    {
        const v = Aw.detect(&[_]u32{ 0x3B, 0x20, 0x6D, 0x6F, 0x72, 0x65, 0x6F, 0x76, 0x65, 0x72, 0x2C, 0x20 }); // statistical-token-moreover-embedded
        try std.testing.expectEqualStrings("StatisticalTokenChoice", v.classify.tag().?);
        try std.testing.expectEqualSlices(usize, &[_]usize{2}, v.classify.positions());
    }
    {
        const v = Aw.detect(&[_]u32{ 0x61, 0x202F, 0x00AD, 0x62 }); // unknown-nnbsp-plus-di
        try std.testing.expectEqualStrings("Unknown", v.classify.tag().?);
        try std.testing.expect(v.marker_count == 2);
    }
    {
        const v = Aw.detect(&[_]u32{ 0x61, 0xFE0F, 0x200D, 0x62 }); // unknown-vs-plus-zwj
        try std.testing.expectEqualStrings("Unknown", v.classify.tag().?);
        try std.testing.expect(v.marker_count == 2);
    }
    {
        const v = Aw.detect(&[_]u32{ 0x61, 0x202F, 0x200D, 0x62 }); // unknown-nnbsp-plus-zwj
        try std.testing.expectEqualStrings("Unknown", v.classify.tag().?);
        try std.testing.expect(v.marker_count == 2);
    }
    try expectAwTag(&[_]u32{ 0x61, 0x202F, 0x62 }, "NnbspBoundary"); // single-category skips unknown
    try expectAwTag(&[_]u32{ 0x61, 0x202F, 0x62, 0x202F, 0x63, 0x202F, 0x64 }, "Adversarial"); // priority adversarial over nnbsp
    try expectAwTag(&[_]u32{ 0x61, 0x200B, 0x62, 0x200B, 0x63, 0x200B, 0x64 }, "Gpt5ZwspModulo"); // priority zwsp modulo over di
}

test "ai-watermark-detectability tolerance vectors" {
    // The two Context-tolerance vectors from the Rust #[test] module
    // (detect_zwsp_jittered_*), plus the default-context identity.
    // ZWSPs at 1, 3, 6 (gaps 2, 3). Bare detect (tolerance 0) falls through to
    // defaultIgnorableCarrier.
    const jittered = [_]u32{ 0x61, 0x200B, 0x62, 0x200B, 0x63, 0x64, 0x200B, 0x65 };
    try expectAwTag(&jittered, "DefaultIgnorableCarrier");

    // With zwsp_modulo_tolerance = 1 the same input fires gpt5ZwspModulo.
    const tolerant = Aw.detectWithContext(.{ .zwsp_modulo_tolerance = 1 }, &jittered);
    try std.testing.expectEqualStrings("Gpt5ZwspModulo", tolerant.classify.tag().?);

    // detect_with_context(default) == detect.
    const d = Aw.detect(&[_]u32{ 0x61, 0x202F, 0x62 });
    const c = Aw.detectWithContext(.{}, &[_]u32{ 0x61, 0x202F, 0x62 });
    try std.testing.expectEqual(d.classify.isClear(), c.classify.isClear());
    try std.testing.expectEqualStrings(d.classify.tag().?, c.classify.tag().?);
}

test "ai-watermark-detectability cue-class coverage" {
    // Mirrors every_cue_class_is_probed and unknown_has_no_cue_class.
    const classes = [_]Aw.CueClass{ .green_list_bias, .pseudorandom_seq, .semantic_drift };
    const sub_threats = [_]Aw.SubThreat{
        .{ .nnbsp_boundary = .{ .marker_count = 0 } },
        .{ .variation_selector_carrier = .{ .marker_count = 0 } },
        .{ .zwj_non_emoji = .{ .marker_count = 0 } },
        .{ .default_ignorable_carrier = .{ .marker_count = 0 } },
        .{ .gpt5_zwsp_modulo = .{ .first_pos = 0 } },
        .{ .em_dash_pattern = .{ .first_pos = 0 } },
        .{ .smart_quote_alternation = .{ .first_pos = 0 } },
        .{ .statistical_token_choice = .{ .first_pos = 0 } },
        .{ .adversarial = .{ .impersonated_scheme = "", .first_pos = 0 } },
    };
    for (classes) |cls| {
        var probed = false;
        for (sub_threats) |st| {
            if (st.cueClass()) |c| {
                if (c == cls) probed = true;
            }
        }
        try std.testing.expect(probed);
    }
    try std.testing.expectEqual(@as(?Aw.CueClass, null), (Aw.SubThreat{ .unknown = .{ .anomaly_marker = 0 } }).cueClass());
}

// ── case-expansion-mismatch (form layer) ─────────────────────────────────

const Cem = case_expansion_mismatch;

test "case-expansion-mismatch shared fixture vectors" {
    // Mirrors the detect_* theorems in
    // Unicode/Security/Form/CaseExpansionMismatch.lean and its Rust port. Every
    // vector below is a row of the shared context-free case-expansion-mismatch
    // detector fixture (codepoints in the JSON are decimal).

    // empty-clear.
    {
        const v = Cem.detect(&[_]u32{});
        try std.testing.expect(v.classify.isClear());
        try std.testing.expectEqual(@as(?[]const u8, null), v.classify.reasonCode());
        try std.testing.expect(v.max_expansion_len == 0);
    }

    // ascii-hello-clear: "Hello" — every ASCII codepoint case-maps to one cp.
    {
        const v = Cem.detect(&[_]u32{ 0x48, 0x65, 0x6C, 0x6C, 0x6F });
        try std.testing.expect(v.classify.isClear());
        try std.testing.expect(v.max_expansion_len == 1);
    }

    // sharp-s-upper: ß (U+00DF) toUpper → "SS".
    {
        const v = Cem.detect(&[_]u32{0x00DF});
        try std.testing.expectEqualStrings("UpperExpansion", v.classify.tag().?);
        try std.testing.expectEqualStrings(
            "unicode.security.F.case-expansion-mismatch.UpperExpansion",
            v.classify.reasonCode().?,
        );
        try std.testing.expectEqualSlices(usize, &[_]usize{0}, v.classify.positions());
        try std.testing.expect(v.upper_expansion_count == 1);
        try std.testing.expect(v.max_expansion_len == 2);
    }

    // fi-ligature-upper: ﬁ (U+FB01) toUpper → "FI".
    {
        const v = Cem.detect(&[_]u32{0xFB01});
        try std.testing.expectEqualStrings(
            "unicode.security.F.case-expansion-mismatch.UpperExpansion",
            v.classify.reasonCode().?,
        );
    }

    // ffi-ligature-upper: ﬃ (U+FB03) toUpper → "FFI" (length 3).
    {
        const v = Cem.detect(&[_]u32{0xFB03});
        try std.testing.expectEqualStrings("UpperExpansion", v.classify.tag().?);
        try std.testing.expect(v.max_expansion_len == 3);
    }

    // dotted-I-lower: İ (U+0130) has no upper expansion (upper is identity), so
    // the scan falls through to the lower mapping → "i + U+0307".
    {
        const v = Cem.detect(&[_]u32{0x0130});
        try std.testing.expectEqualStrings("LowerExpansion", v.classify.tag().?);
        try std.testing.expectEqualStrings(
            "unicode.security.F.case-expansion-mismatch.LowerExpansion",
            v.classify.reasonCode().?,
        );
        try std.testing.expect(v.lower_expansion_count == 1);
    }
}

test "case-expansion-mismatch reports first-expansion position" {
    // A leading ASCII then ß: the upper expansion is reported at position 1.
    const v = Cem.detect(&[_]u32{ 0x61, 0x00DF });
    try std.testing.expectEqualStrings("UpperExpansion", v.classify.tag().?);
    try std.testing.expectEqualSlices(usize, &[_]usize{1}, v.classify.positions());
}

// ── stream-safe-violation (form layer) ──────────────────────────────────

const Ssv = stream_safe_violation;

const ACUTE: u32 = 0x0301;

/// Build "a" (U+0061) followed by n combining acute accents (U+0301).
fn aPlusMarks(comptime n: usize) [1 + n]u32 {
    var v: [1 + n]u32 = undefined;
    v[0] = 0x61;
    var i: usize = 0;
    while (i < n) : (i += 1) v[1 + i] = ACUTE;
    return v;
}

test "stream-safe-violation shared fixture vectors" {
    // Mirrors the detect_* theorems in
    // Unicode/Security/Form/StreamSafeViolation.lean and its Rust port. Every
    // vector below is a row of the shared context-free fixture
    // (the shared stream_safe_violation.json detector fixture).

    // empty-clear.
    {
        const v = Ssv.detect(&[_]u32{});
        try std.testing.expect(v.classify.isClear());
        try std.testing.expectEqual(@as(?[]const u8, null), v.classify.tag());
        try std.testing.expect(v.max_run_len == 0);
        try std.testing.expect(v.overrun_count == 0);
        try std.testing.expect(v.total_non_starters == 0);
    }

    // ascii-hello-clear: "Hello" — every codepoint is a starter.
    {
        const v = Ssv.detect(&[_]u32{ 0x48, 0x65, 0x6C, 0x6C, 0x6F });
        try std.testing.expect(v.classify.isClear());
        try std.testing.expect(v.max_run_len == 0);
        try std.testing.expect(v.total_non_starters == 0);
    }

    // one-combine-clear: a starter plus a single combining mark.
    {
        const v = Ssv.detect(&[_]u32{ 0x61, ACUTE });
        try std.testing.expect(v.classify.isClear());
        try std.testing.expect(v.max_run_len == 1);
        try std.testing.expect(v.overrun_count == 0);
        try std.testing.expect(v.total_non_starters == 1);
    }
}

test "stream-safe-violation 30/31 boundary" {
    // thirty-marks-boundary-clear: exactly 30 marks after a starter stays clear
    // under strict `>`.
    {
        const input = aPlusMarks(30);
        const v = Ssv.detect(&input);
        try std.testing.expect(v.classify.isClear());
        try std.testing.expectEqual(@as(?[]const u8, null), v.classify.tag());
        try std.testing.expect(v.max_run_len == 30);
        try std.testing.expect(v.overrun_count == 0);
        try std.testing.expect(v.total_non_starters == 30);
    }

    // thirtyone-marks-overrun: 31 marks after a starter fires StreamSafeOverrun
    // with firstOverrun = (1, 31) and positions [1].
    {
        const input = aPlusMarks(31);
        const v = Ssv.detect(&input);
        try std.testing.expect(!v.classify.isClear());
        try std.testing.expectEqualStrings("StreamSafeOverrun", v.classify.tag().?);
        try std.testing.expectEqualStrings(
            "unicode.security.F.stream-safe-violation.StreamSafeOverrun",
            v.classify.reasonCode().?,
        );
        try std.testing.expectEqualSlices(usize, &[_]usize{1}, v.classify.positions());
        try std.testing.expectEqual(
            @as(usize, 1),
            v.classify.hazard.sub.stream_safe_overrun.base_pos,
        );
        try std.testing.expectEqual(
            @as(usize, 31),
            v.classify.hazard.sub.stream_safe_overrun.run_len,
        );
        try std.testing.expect(v.max_run_len == 31);
        try std.testing.expect(v.overrun_count == 1);
        try std.testing.expect(v.total_non_starters == 31);
    }
}

test "stream-safe-violation run-inventory structure" {
    // A bare non-starter run that opens at index 0 records its start as 0.
    {
        var input: [31]u32 = undefined;
        for (&input) |*c| c.* = ACUTE;
        const v = Ssv.detect(&input);
        try std.testing.expectEqualStrings("StreamSafeOverrun", v.classify.tag().?);
        try std.testing.expectEqualSlices(usize, &[_]usize{0}, v.classify.positions());
        try std.testing.expect(v.max_run_len == 31);
        try std.testing.expect(v.total_non_starters == 31);
    }

    // Two separate runs, each under the limit, stay clear but both count in the
    // totals: "a" + 30 marks + "b" + 30 marks (len 62).
    {
        var input: [62]u32 = undefined;
        input[0] = 0x61;
        var i: usize = 1;
        while (i <= 30) : (i += 1) input[i] = ACUTE;
        input[31] = 0x62;
        i = 32;
        while (i < 62) : (i += 1) input[i] = ACUTE;
        const v = Ssv.detect(&input);
        try std.testing.expect(v.classify.isClear());
        try std.testing.expect(v.max_run_len == 30);
        try std.testing.expect(v.overrun_count == 0);
        try std.testing.expect(v.total_non_starters == 60);
    }

    // The first overrun wins: a short run before a long run does not shadow it,
    // and the reported base_pos is the long run's start: "a" + 5 marks + "b" +
    // 31 marks — the run starting at index 7 fires.
    {
        var input: [38]u32 = undefined;
        input[0] = 0x61;
        var i: usize = 1;
        while (i <= 5) : (i += 1) input[i] = ACUTE;
        input[6] = 0x62;
        i = 7;
        while (i < 38) : (i += 1) input[i] = ACUTE;
        const v = Ssv.detect(&input);
        try std.testing.expectEqualStrings("StreamSafeOverrun", v.classify.tag().?);
        try std.testing.expectEqualSlices(usize, &[_]usize{7}, v.classify.positions());
        try std.testing.expect(v.max_run_len == 31);
        try std.testing.expect(v.overrun_count == 1);
        try std.testing.expect(v.total_non_starters == 36);
    }
}

// ── emoji-zwj-integrity (identity layer) ─────────────────────────────────

const Ezwj = emoji_zwj_integrity;

fn ezwjReason(input: []const u32) ?[]const u8 {
    return Ezwj.detect(input).classify.reasonCode();
}

fn expectEzwjReason(input: []const u32, want: []const u8) !void {
    const r = ezwjReason(input);
    try std.testing.expect(r != null);
    try std.testing.expectEqualStrings(want, r.?);
}

test "emoji-zwj-integrity data-layer sanity" {
    // Mirrors the Rust data-layer sanity #[test]s.
    try std.testing.expect(Ezwj.isEmojiModifier(0x1F3FB));
    try std.testing.expect(Ezwj.isEmojiModifier(0x1F3FF));
    try std.testing.expect(!Ezwj.isEmojiModifier(0x1F3FA));
    try std.testing.expect(!Ezwj.isEmojiModifier(0x1F600));

    // U+2764 HEAVY BLACK HEART appears in couple-with-heart RGI sequences.
    try std.testing.expect(Ezwj.isEmojiTarget(0x2764));
    // U+1F468 MAN appears in family/couple RGI sequences.
    try std.testing.expect(Ezwj.isEmojiTarget(0x1F468));
    // U+1F600 GRINNING FACE appears in no registered RGI ZWJ sequence.
    try std.testing.expect(!Ezwj.isEmojiTarget(0x1F600));
    // The joiner itself is excluded from the alphabet.
    try std.testing.expect(!Ezwj.isEmojiTarget(Ezwj.ZWJ));

    // MAN + ZWJ + LAPTOP (man technologist) is a registered RGI sequence.
    try std.testing.expect(Ezwj.isRegisteredZwjSequence(&[_]u32{ 0x1F468, 0x200D, 0x1F4BB }));
    // MAN + ZWJ + WOMAN is not a registered RGI sequence.
    try std.testing.expect(!Ezwj.isRegisteredZwjSequence(&[_]u32{ 0x1F468, 0x200D, 0x1F469 }));
}

test "emoji-zwj-integrity shared fixture vectors" {
    // The 12 rows of the shared context-free fixture
    // (the shared emoji_zwj_integrity.json detector fixture), inputs given as
    // codepoints. Clear rows assert isClear; hazard rows assert the fully
    // qualified reason code from required_findings.

    // empty-clear.
    {
        const v = Ezwj.detect(&[_]u32{});
        try std.testing.expect(v.classify.isClear());
        try std.testing.expectEqual(@as(?[]const u8, null), v.classify.tag());
        try std.testing.expectEqualSlices(usize, &[_]usize{}, v.classify.positions());
        try std.testing.expect(v.chain_length == 0);
        try std.testing.expect(v.skin_tone_count == 0);
    }
    // ascii-hello-clear.
    try std.testing.expect(Ezwj.detect(&[_]u32{ 72, 101, 108, 108, 111 }).classify.isClear());
    // plain-emoji-clear.
    try std.testing.expect(Ezwj.detect(&[_]u32{128512}).classify.isClear());
    // one-skintone-clear.
    {
        const v = Ezwj.detect(&[_]u32{ 128075, 127995 });
        try std.testing.expect(v.classify.isClear());
        try std.testing.expect(v.skin_tone_count == 1);
    }
    // family-of-four-rgi-clear.
    {
        const v = Ezwj.detect(&[_]u32{ 128104, 8205, 128105, 8205, 128103, 8205, 128102 });
        try std.testing.expect(v.classify.isClear());
        try std.testing.expect(v.is_registered_rgi);
    }
    // man-technologist-rgi-clear.
    try std.testing.expect(Ezwj.detect(&[_]u32{ 128104, 8205, 128187 }).classify.isClear());
    // double-zwj-hazard.
    try expectEzwjReason(&[_]u32{ 128512, 8205, 8205, 128512 }, "unicode.security.I.emoji-zwj-integrity.DoubleZWJ");
    // non-emoji-injection-ascii-hazard.
    try expectEzwjReason(&[_]u32{ 128512, 8205, 97 }, "unicode.security.I.emoji-zwj-integrity.NonEmojiInjection");
    // grinning-laptop-non-emoji-injection-hazard.
    try expectEzwjReason(&[_]u32{ 128512, 8205, 128187 }, "unicode.security.I.emoji-zwj-integrity.NonEmojiInjection");
    // skin-tone-overflow-hazard.
    try expectEzwjReason(&[_]u32{ 128075, 127995, 127996, 127997, 127998, 127999 }, "unicode.security.I.emoji-zwj-integrity.SkinToneOverflow");
    // unregistered-man-woman-hazard.
    try expectEzwjReason(&[_]u32{ 128104, 8205, 128105 }, "unicode.security.I.emoji-zwj-integrity.UnregisteredSequence");
    // over-length-chain-hazard.
    try expectEzwjReason(
        &[_]u32{ 128104, 8205, 128104, 8205, 128104, 8205, 128104, 8205, 128104, 8205, 128104, 8205, 128104, 8205, 128104, 8205, 128104 },
        "unicode.security.I.emoji-zwj-integrity.OverLength",
    );
}

test "emoji-zwj-integrity detect spot checks" {
    // The 11 Rust §5 detect spot checks (one per Lean theorem).

    // detect_empty_clear.
    {
        const v = Ezwj.detect(&[_]u32{});
        try std.testing.expect(v.classify.isClear());
        try std.testing.expectEqual(@as(?[]const u8, null), v.classify.tag());
        try std.testing.expectEqualSlices(usize, &[_]usize{}, v.zwj_positions.slice());
        try std.testing.expect(v.chain_length == 0);
        try std.testing.expect(v.skin_tone_count == 0);
    }
    // detect_ascii_clear.
    try std.testing.expect(Ezwj.detect(&[_]u32{ 0x48, 0x65, 0x6C, 0x6C, 0x6F }).classify.isClear());
    // detect_plain_emoji_clear.
    try std.testing.expect(Ezwj.detect(&[_]u32{0x1F600}).classify.isClear());
    // detect_one_skintone_clear.
    {
        const v = Ezwj.detect(&[_]u32{ 0x1F44B, 0x1F3FB });
        try std.testing.expect(v.classify.isClear());
        try std.testing.expect(v.skin_tone_count == 1);
    }
    // detect_family_rgi_clear.
    {
        const v = Ezwj.detect(&[_]u32{ 0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466 });
        try std.testing.expect(v.classify.isClear());
        try std.testing.expect(v.is_registered_rgi);
    }
    // detect_double_zwj.
    {
        const v = Ezwj.detect(&[_]u32{ 0x1F600, 0x200D, 0x200D, 0x1F600 });
        try std.testing.expectEqualStrings("DoubleZWJ", v.classify.tag().?);
        try std.testing.expectEqualSlices(usize, &[_]usize{1}, v.classify.positions());
    }
    // detect_non_emoji_injection.
    {
        const v = Ezwj.detect(&[_]u32{ 0x1F600, 0x200D, 0x0061 });
        try std.testing.expectEqualStrings("NonEmojiInjection", v.classify.tag().?);
    }
    // detect_skin_tone_overflow.
    {
        const v = Ezwj.detect(&[_]u32{ 0x1F44B, 0x1F3FB, 0x1F3FC, 0x1F3FD, 0x1F3FE, 0x1F3FF });
        try std.testing.expectEqualStrings("SkinToneOverflow", v.classify.tag().?);
        try std.testing.expect(v.skin_tone_count == 5);
    }
    // detect_man_laptop_registered_clear.
    try std.testing.expect(Ezwj.detect(&[_]u32{ 0x1F468, 0x200D, 0x1F4BB }).classify.isClear());
    // detect_unregistered.
    {
        const v = Ezwj.detect(&[_]u32{ 0x1F468, 0x200D, 0x1F469 });
        try std.testing.expectEqualStrings("UnregisteredSequence", v.classify.tag().?);
    }
    // detect_grinning_laptop_non_emoji_injection.
    try std.testing.expectEqualStrings("NonEmojiInjection", Ezwj.detect(&[_]u32{ 0x1F600, 0x200D, 0x1F4BB }).classify.tag().?);
}

test "emoji-zwj-integrity structural checks" {
    // The 3 Rust structural checks that follow from the priority ladder.

    // over_length_fires_past_cap — 9 men joined by 8 ZWJs = 17 codepoints.
    {
        var input: [17]u32 = undefined;
        var w: usize = 0;
        var i: usize = 0;
        while (i < 9) : (i += 1) {
            if (i > 0) {
                input[w] = 0x200D;
                w += 1;
            }
            input[w] = 0x1F468;
            w += 1;
        }
        try std.testing.expect(w == 17);
        const v = Ezwj.detect(&input);
        try std.testing.expectEqualStrings("OverLength", v.classify.tag().?);
        try std.testing.expect(v.classify.hazard.sub.over_length.length == 17);
        try std.testing.expect(v.classify.hazard.sub.over_length.max_length == Ezwj.MAX_RGI_LENGTH);
        try std.testing.expectEqualSlices(usize, &[_]usize{}, v.classify.positions());
    }

    // trailing_zwj_is_injection — a ZWJ at the trailing edge of input.
    {
        const v = Ezwj.detect(&[_]u32{ 0x1F468, 0x200D });
        try std.testing.expectEqualStrings("NonEmojiInjection", v.classify.tag().?);
        try std.testing.expectEqualSlices(usize, &[_]usize{1}, v.classify.positions());
        try std.testing.expect(v.classify.hazard.sub.non_emoji_injection.non_emoji_cp == 0);
    }

    // double_zwj_beats_unregistered — man ZWJ ZWJ boy: adjacent ZWJs present.
    {
        const v = Ezwj.detect(&[_]u32{ 0x1F468, 0x200D, 0x200D, 0x1F466 });
        try std.testing.expectEqualStrings("DoubleZWJ", v.classify.tag().?);
    }
}

// ── renderer-divergence (display layer D) ────────────────────────────────

const Rd = renderer_divergence;

fn rdReason(input: []const u32) ?[]const u8 {
    return Rd.detect(input).classify.reasonCode();
}

fn expectRdReason(input: []const u32, want: []const u8) !void {
    const r = rdReason(input);
    try std.testing.expect(r != null);
    try std.testing.expectEqualStrings(want, r.?);
}

test "renderer-divergence GCB Extend predicate reuse" {
    // The derived GCB = Extend class (Grapheme_Extend ∪ Emoji_Modifier) is
    // byte-identical to the canonical GCB Extend range set; a spot check of the
    // ranges the fixtures exercise plus the ZWJ exclusion.
    try std.testing.expect(isGraphemeExtend(0x0301)); // COMBINING ACUTE ACCENT
    try std.testing.expect(isGraphemeExtend(0x0304)); // COMBINING MACRON
    try std.testing.expect(isGraphemeExtend(0x1F3FB)); // EMOJI MODIFIER FITZPATRICK-1
    try std.testing.expect(!isGraphemeExtend(0x0061)); // LATIN SMALL LETTER A
    try std.testing.expect(!isGraphemeExtend(0x200D)); // ZWJ is GCB = ZWJ, not Extend
    // The variation-selector predicate reused from the port is the 3-range one.
    try std.testing.expect(Rd.vsPredicate(0xFE0F));
    try std.testing.expect(Rd.vsPredicate(0x180B));
    try std.testing.expect(Rd.vsPredicate(0xE0100));
    try std.testing.expect(!Rd.vsPredicate(0x1F600));
}

test "renderer-divergence shared fixture vectors" {
    // The 9 rows of the shared context-free fixture
    // (the shared renderer_divergence.json detector fixture), inputs given as
    // codepoints. Clear rows assert isClear; hazard rows assert the fully
    // qualified reason code from required_findings.

    // empty-clear.
    {
        const v = Rd.detect(&[_]u32{});
        try std.testing.expect(v.classify.isClear());
        try std.testing.expectEqual(@as(?[]const u8, null), v.classify.tag());
        try std.testing.expectEqualSlices(usize, &[_]usize{}, v.classify.positions());
    }
    // ascii-hello-clear.
    try std.testing.expect(Rd.detect(&[_]u32{ 72, 101, 108, 108, 111 }).classify.isClear());
    // han-clear.
    try std.testing.expect(Rd.detect(&[_]u32{ 20013, 25991 }).classify.isClear());
    // family-of-four-rgi-clear.
    {
        const v = Rd.detect(&[_]u32{ 128104, 8205, 128105, 8205, 128103, 8205, 128102 });
        try std.testing.expect(v.classify.isClear());
        try std.testing.expect(v.has_zwj);
    }
    // variation-selector-variance.
    try expectRdReason(&[_]u32{ 128512, 65039 }, "unicode.security.D.renderer-divergence.VariationSelectorVariance");
    // unregistered-zwj-variance.
    try expectRdReason(&[_]u32{ 128104, 8205, 128105 }, "unicode.security.D.renderer-divergence.UnregisteredZwjVariance");
    // combining-stack-overflow-zalgo.
    try expectRdReason(&[_]u32{ 97, 769, 770, 771, 772 }, "unicode.security.D.renderer-divergence.CombiningStackOverflow");
    // fullwidth-variance.
    try expectRdReason(&[_]u32{65313}, "unicode.security.D.renderer-divergence.FullwidthVariance");
    // mixed-direction-variance.
    try expectRdReason(&[_]u32{ 65, 66, 1488, 1489 }, "unicode.security.D.renderer-divergence.MixedDirectionVariance");
}

test "renderer-divergence detect spot checks" {
    // The 9 Rust §5 detect spot checks (one per Lean theorem).

    // detect_empty_clear.
    try std.testing.expect(Rd.detect(&[_]u32{}).classify.isClear());
    // detect_ascii_clear.
    try std.testing.expect(Rd.detect(&[_]u32{ 0x48, 0x65, 0x6C, 0x6C, 0x6F }).classify.isClear());
    // detect_han_clear.
    try std.testing.expect(Rd.detect(&[_]u32{ 0x4E2D, 0x6587 }).classify.isClear());
    // detect_vs_variance — a single VS (FE0F) after an emoji.
    try std.testing.expectEqualStrings("VariationSelectorVariance", Rd.detect(&[_]u32{ 0x1F600, 0xFE0F }).classify.tag().?);
    // detect_rgi_family_clear — a registered RGI family ZWJ sequence.
    {
        const v = Rd.detect(&[_]u32{ 0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466 });
        try std.testing.expect(v.classify.isClear());
        try std.testing.expect(v.has_zwj);
    }
    // detect_unregistered_zwj_variance — man + ZWJ + woman, not in RGI.
    try std.testing.expectEqualStrings("UnregisteredZwjVariance", Rd.detect(&[_]u32{ 0x1F468, 0x200D, 0x1F469 }).classify.tag().?);
    // detect_zalgo_variance — a 4-deep combining stack.
    {
        const v = Rd.detect(&[_]u32{ 0x0061, 0x0301, 0x0302, 0x0303, 0x0304 });
        try std.testing.expectEqualStrings("CombiningStackOverflow", v.classify.tag().?);
        try std.testing.expectEqualSlices(usize, &[_]usize{0}, v.classify.positions());
        try std.testing.expect(v.combining_count == 4);
    }
    // detect_fullwidth_variance — fullwidth 'A'.
    try std.testing.expectEqualStrings("FullwidthVariance", Rd.detect(&[_]u32{0xFF21}).classify.tag().?);
    // detect_mixed_direction — Latin + Hebrew in one input.
    {
        const v = Rd.detect(&[_]u32{ 0x41, 0x42, 0x05D0, 0x05D1 });
        try std.testing.expectEqualStrings("MixedDirectionVariance", v.classify.tag().?);
        try std.testing.expect(v.strong_ltr_count > 0 and v.strong_rtl_count > 0);
    }
}

test "renderer-divergence structural checks" {
    // The 2 Rust priority-ladder structural checks.

    // combining_stack_beats_vs — a combining stack outranks a later VS.
    {
        const v = Rd.detect(&[_]u32{ 0x0061, 0x0301, 0x0302, 0x0303, 0x0304, 0xFE0F });
        try std.testing.expectEqualStrings("CombiningStackOverflow", v.classify.tag().?);
        try std.testing.expect(v.classify.hazard.sub.combining_stack_overflow.base_pos == 0);
        try std.testing.expect(v.classify.hazard.sub.combining_stack_overflow.stack_len == Rd.MIN_COMBINING_STACK);
    }

    // three_marks_below_threshold — exactly three marks is below the threshold.
    {
        const v = Rd.detect(&[_]u32{ 0x0061, 0x0301, 0x0302, 0x0303 });
        const t = v.classify.tag();
        try std.testing.expect(t == null or !std.mem.eql(u8, t.?, "CombiningStackOverflow"));
    }
}

// ── filename-disguise (display layer D) ──────────────────────────────────

const Fd = filename_disguise;

fn fdReason(input: []const u32) ?[]const u8 {
    return Fd.detect(input).classify.reasonCode();
}

fn fdTag(input: []const u32) ?[]const u8 {
    return Fd.detect(input).classify.tag();
}

fn expectFdReason(input: []const u32, want: []const u8) !void {
    const r = fdReason(input);
    try std.testing.expect(r != null);
    try std.testing.expectEqualStrings(want, r.?);
}

test "filename-disguise predicate reuse" {
    // The detector reuses the port's own file-scope predicates, aliased inside
    // the struct: the bidi-format-control set, the GCB Extend class, and the
    // Halfwidth/Fullwidth Forms block. Spot-check each alias plus the exclusions.
    try std.testing.expect(Fd.bidiControlPredicate(0x202E)); // RIGHT-TO-LEFT OVERRIDE
    try std.testing.expect(Fd.bidiControlPredicate(0x2067)); // RIGHT-TO-LEFT ISOLATE
    try std.testing.expect(Fd.bidiControlPredicate(0x2069)); // POP DIRECTIONAL ISOLATE
    try std.testing.expect(!Fd.bidiControlPredicate(0x0041)); // LATIN CAPITAL LETTER A
    try std.testing.expect(Fd.gcbExtendPredicate(0x0301)); // COMBINING ACUTE ACCENT
    try std.testing.expect(!Fd.gcbExtendPredicate(0x0061)); // LATIN SMALL LETTER A
    try std.testing.expect(Fd.fwPredicate(0xFF25)); // FULLWIDTH LATIN CAPITAL LETTER E
    try std.testing.expect(!Fd.fwPredicate(0x0045)); // LATIN CAPITAL LETTER E
    try std.testing.expect(Fd.isAsciiDot(0x002E)); // FULL STOP
    try std.testing.expect(!Fd.isAsciiDot(0x0041));
}

test "filename-disguise shared fixture vectors" {
    // The 10 rows of the shared context-free fixture, inputs given as decimal
    // codepoints. Clear rows assert isClear; hazard rows assert the fully
    // qualified reason code from required_findings.

    // empty-clear.
    {
        const v = Fd.detect(&[_]u32{});
        try std.testing.expect(v.classify.isClear());
        try std.testing.expectEqual(@as(?[]const u8, null), v.classify.tag());
        try std.testing.expectEqualSlices(usize, &[_]usize{}, v.classify.positions());
    }
    // plain-document-txt-clear.
    try std.testing.expect(Fd.detect(&[_]u32{ 100, 111, 99, 117, 109, 101, 110, 116, 46, 116, 120, 116 }).classify.isClear());
    // no-extension-clear.
    try std.testing.expect(Fd.detect(&[_]u32{ 102, 111, 111 }).classify.isClear());
    // archive-tar-gz-clear.
    try std.testing.expect(Fd.detect(&[_]u32{ 97, 114, 99, 104, 105, 118, 101, 46, 116, 97, 114, 46, 103, 122 }).classify.isClear());
    // hebrew-native-rtl-clear.
    try std.testing.expect(Fd.detect(&[_]u32{ 1488, 1489, 1490, 46, 116, 120, 116 }).classify.isClear());
    // rlo-flip-hazard.
    try expectFdReason(&[_]u32{ 100, 111, 99, 117, 109, 101, 110, 116, 8238, 116, 120, 116, 46, 101, 120, 101 }, "unicode.security.D.filename-disguise.RloFlip");
    // isolate-flip-hazard.
    try expectFdReason(&[_]u32{ 100, 111, 99, 8295, 116, 120, 116, 46, 101, 120, 101, 8297 }, "unicode.security.D.filename-disguise.RloFlip");
    // fullwidth-ext-hazard.
    try expectFdReason(&[_]u32{ 102, 105, 108, 101, 46, 65317, 65336, 65317 }, "unicode.security.D.filename-disguise.WidthClassExt");
    // combining-in-ext-hazard.
    try expectFdReason(&[_]u32{ 102, 105, 108, 101, 46, 101, 769, 120, 101 }, "unicode.security.D.filename-disguise.CombiningInExt");
    // triple-extension-hazard.
    try expectFdReason(&[_]u32{ 115, 101, 116, 117, 112, 46, 116, 97, 114, 46, 103, 122, 46, 115, 105, 103 }, "unicode.security.D.filename-disguise.MultipleExtensions");
}

test "filename-disguise detect spot checks" {
    // The 10 Rust §5 detect spot checks (one per Lean theorem).

    // detect_empty_clear.
    try std.testing.expect(Fd.detect(&[_]u32{}).classify.isClear());
    // detect_plain_txt_clear — "document.txt", last dot at index 8.
    {
        const v = Fd.detect(&[_]u32{ 0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x2E, 0x74, 0x78, 0x74 });
        try std.testing.expect(v.classify.isClear());
        try std.testing.expectEqual(@as(?usize, 8), v.last_dot_pos);
    }
    // detect_no_extension_clear — "foo", no dot.
    {
        const v = Fd.detect(&[_]u32{ 0x66, 0x6F, 0x6F });
        try std.testing.expect(v.classify.isClear());
        try std.testing.expectEqual(@as(?usize, null), v.last_dot_pos);
    }
    // detect_tar_gz_clear — "archive.tar.gz" (2 dots, below the multi-ext bound).
    try std.testing.expect(Fd.detect(&[_]u32{ 0x61, 0x72, 0x63, 0x68, 0x69, 0x76, 0x65, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A }).classify.isClear());
    // detect_rlo_flip — "document<RLO>txt.exe", control at index 8.
    {
        const v = Fd.detect(&[_]u32{ 0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x202E, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65 });
        try std.testing.expectEqualStrings("RloFlip", v.classify.tag().?);
        try std.testing.expectEqualSlices(usize, &[_]usize{8}, v.classify.positions());
    }
    // detect_fullwidth_exe — "file.ＥＸＥ".
    try std.testing.expectEqualStrings("WidthClassExt", fdTag(&[_]u32{ 0x66, 0x69, 0x6C, 0x65, 0x2E, 0xFF25, 0xFF38, 0xFF25 }).?);
    // detect_combining_in_ext — combining acute in the extension.
    try std.testing.expectEqualStrings("CombiningInExt", fdTag(&[_]u32{ 0x66, 0x69, 0x6C, 0x65, 0x2E, 0x65, 0x0301, 0x78, 0x65 }).?);
    // detect_triple_extension — "setup.tar.gz.sig".
    {
        const v = Fd.detect(&[_]u32{ 0x73, 0x65, 0x74, 0x75, 0x70, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A, 0x2E, 0x73, 0x69, 0x67 });
        try std.testing.expectEqualStrings("MultipleExtensions", v.classify.tag().?);
        // MultipleExtensions carries every dot position.
        try std.testing.expectEqualSlices(usize, &[_]usize{ 5, 9, 12 }, v.classify.positions());
    }
    // detect_hebrew_clear — native Hebrew name, no bidi controls.
    try std.testing.expect(Fd.detect(&[_]u32{ 0x05D0, 0x05D1, 0x05D2, 0x2E, 0x74, 0x78, 0x74 }).classify.isClear());
    // detect_isolate_flip — RLI/PDI isolate variant, also RloFlip.
    try std.testing.expectEqualStrings("RloFlip", fdTag(&[_]u32{ 0x64, 0x6F, 0x63, 0x2067, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65, 0x2069 }).?);
}

test "filename-disguise structural checks" {
    // The 1 Rust priority-ladder structural check.

    // bidi_beats_fullwidth — a bidi control outranks a fullwidth extension.
    {
        const v = Fd.detect(&[_]u32{ 0x202E, 0x66, 0x2E, 0xFF25 });
        try std.testing.expectEqualStrings("RloFlip", v.classify.tag().?);
        try std.testing.expect(v.classify.hazard.sub.rlo_flip.position == 0);
        // The fullwidth codepoint is still counted in the extension region.
        try std.testing.expect(v.fullwidth_in_ext == 1);
        try std.testing.expect(v.bidi_control_count == 1);
    }
}

const Ifd = identifier_form_drift;

fn ifdTag(input: []const u32) ?[]const u8 {
    return Ifd.detect(input).classify.tag();
}

fn ifdReason(input: []const u32) ?[]const u8 {
    return Ifd.detect(input).classify.reasonCode();
}

fn expectIfdReason(input: []const u32, want: []const u8) !void {
    const r = ifdReason(input);
    try std.testing.expect(r != null);
    try std.testing.expectEqualStrings(want, r.?);
}

test "identifier-form-drift predicate reuse" {
    // The detector reuses the port's own file-scope predicates, aliased inside
    // the struct: the UTS #39 Identifier_Status = Allowed set and the UAX #15
    // NFKD normaliser. Spot-check each alias.
    try std.testing.expect(Ifd.idAllowedPredicate(0x0061)); // 'a' — Allowed
    try std.testing.expect(Ifd.idAllowedPredicate(0x03B1)); // Greek α — Allowed
    try std.testing.expect(!Ifd.idAllowedPredicate(0x1D44E)); // math italic a — Restricted
    try std.testing.expect(!Ifd.idAllowedPredicate(0xFF21)); // fullwidth A — Restricted
    // NFKD head of U+1D44E is U+0061 'a' (Allowed); of U+FF21 is U+0041 'A'.
    try std.testing.expect(Ifd.nfkdHeadAllowed(0x1D44E));
    try std.testing.expect(Ifd.nfkdHeadAllowed(0xFF21));
    // Allowed codepoints with identity NFKD keep their Allowed head.
    try std.testing.expect(Ifd.nfkdHeadAllowed(0x0061));
    try std.testing.expect(Ifd.nfkdHeadAllowed(0x03B1));
}

test "identifier-form-drift shared fixture vectors" {
    // The 8 rows of the shared context-free fixture, inputs given as decimal
    // codepoints. Clear rows assert isClear; hazard rows assert the fully
    // qualified reason code from required_findings.

    // empty-clear.
    {
        const v = Ifd.detect(&[_]u32{});
        try std.testing.expect(v.classify.isClear());
        try std.testing.expectEqual(@as(?[]const u8, null), v.classify.tag());
        try std.testing.expectEqualSlices(usize, &[_]usize{}, v.classify.positions());
    }
    // ascii-hello-clear (72,101,108,108,111).
    try std.testing.expect(Ifd.detect(&[_]u32{ 72, 101, 108, 108, 111 }).classify.isClear());
    // greek-alpha-clear (945).
    try std.testing.expect(Ifd.detect(&[_]u32{945}).classify.isClear());
    // math-italic-a-shift (119886 = U+1D44E).
    try expectIfdReason(&[_]u32{119886}, "unicode.security.X.identifier-form-drift.IdentifierStatusShift");
    // fullwidth-A-shift (65313 = U+FF21).
    try expectIfdReason(&[_]u32{65313}, "unicode.security.X.identifier-form-drift.IdentifierStatusShift");
    // circled-A-shift (9398 = U+24B6).
    try expectIfdReason(&[_]u32{9398}, "unicode.security.X.identifier-form-drift.IdentifierStatusShift");
    // fi-ligature-shift (64257 = U+FB01).
    try expectIfdReason(&[_]u32{64257}, "unicode.security.X.identifier-form-drift.IdentifierStatusShift");
    // roman-iv-shift (8547 = U+2163).
    try expectIfdReason(&[_]u32{8547}, "unicode.security.X.identifier-form-drift.IdentifierStatusShift");
}

test "identifier-form-drift detect spot checks" {
    // The Rust §5 detect spot checks (one per Lean theorem).

    // detect_empty_clear.
    try std.testing.expect(Ifd.detect(&[_]u32{}).classify.isClear());
    // detect_ascii_clear — "Hello"; every ASCII letter is Allowed, identity NFKD.
    {
        const v = Ifd.detect(&[_]u32{ 0x48, 0x65, 0x6C, 0x6C, 0x6F });
        try std.testing.expect(v.classify.isClear());
        try std.testing.expectEqual(@as(usize, 0), v.shift_count);
    }
    // detect_greek_alpha_clear — α is Allowed with identity NFKD.
    try std.testing.expect(Ifd.detect(&[_]u32{0x03B1}).classify.isClear());
    // detect_math_italic_a_shift — U+1D44E Restricted, NFKD head U+0061 Allowed.
    {
        const v = Ifd.detect(&[_]u32{0x1D44E});
        try std.testing.expectEqualStrings("IdentifierStatusShift", v.classify.tag().?);
        try std.testing.expectEqualSlices(usize, &[_]usize{0}, v.classify.positions());
        try std.testing.expectEqual(@as(usize, 1), v.shift_count);
    }
    // detect_fullwidth_A_shift — U+FF21 Restricted, NFKD head U+0041 Allowed.
    try std.testing.expectEqualStrings("IdentifierStatusShift", ifdTag(&[_]u32{0xFF21}).?);
    // detect_circled_A_shift — U+24B6 → Restricted → Allowed (A).
    try std.testing.expectEqualStrings("IdentifierStatusShift", ifdTag(&[_]u32{0x24B6}).?);
    // detect_fi_ligature_shift — U+FB01 'ﬁ' → Restricted → Allowed (f).
    try std.testing.expectEqualStrings("IdentifierStatusShift", ifdTag(&[_]u32{0xFB01}).?);
    // detect_roman_iv_shift — U+2163 ROMAN NUMERAL FOUR → Restricted → Allowed (I).
    try std.testing.expectEqualStrings("IdentifierStatusShift", ifdTag(&[_]u32{0x2163}).?);
}

test "identifier-form-drift reports first shift position" {
    // A shift embedded mid-string reports the first shifting position, not 0.
    // "ab" + U+1D44E: positions 0,1 are Allowed/identity, position 2 shifts.
    const v = Ifd.detect(&[_]u32{ 0x61, 0x62, 0x1D44E });
    try std.testing.expectEqualSlices(usize, &[_]usize{2}, v.classify.positions());
    try std.testing.expectEqual(@as(usize, 1), v.shift_count);
}

// ── admissibility-form-drift (boundary layer X) ───────────────────────────

const Afd = admissibility_form_drift;

fn afdTag(input: []const u32) ?[]const u8 {
    return Afd.detect(input).classify.tag();
}

fn afdReason(input: []const u32) ?[]const u8 {
    return Afd.detect(input).classify.reasonCode();
}

fn expectAfdReason(input: []const u32, want: []const u8) !void {
    const r = afdReason(input);
    try std.testing.expect(r != null);
    try std.testing.expectEqualStrings(want, r.?);
}

test "admissibility-form-drift predicate reuse" {
    // The detector reuses the port's own whole-string admissibility predicate,
    // built here over XID_Start / XID_Continue parsed from the bundled
    // data/DerivedCoreProperties.txt plus the file-scope isIdAllowed, and the
    // port's own NFKC pipeline. Spot-check the XID and admissibility layers.
    try std.testing.expect(isXidStart(0x0041)); // 'A' — XID_Start
    try std.testing.expect(isXidStart(0x03B1)); // Greek α — XID_Start
    try std.testing.expect(!isXidStart(0x0030)); // '0' — XID_Continue but not Start
    try std.testing.expect(isXidContinue(0x0030)); // '0' — XID_Continue
    try std.testing.expect(!isXidStart(0x005F)); // '_' — not XID_Start …
    try std.testing.expect(isDefaultIdStart(0x005F)); // … but a default-id start
    // "admin" is a whole-string allowed identifier; a lone digit is not (no
    // default-id start); the ﬁ ligature is a default identifier but Restricted.
    try std.testing.expect(isAllowedIdentifier(&[_]u32{ 0x61, 0x64, 0x6D, 0x69, 0x6E }));
    try std.testing.expect(!isAllowedIdentifier(&[_]u32{0x0030}));
    try std.testing.expect(!isAllowedIdentifier(&[_]u32{0xFB01}));
    // NFKC of the ﬁ ligature is "fi", an allowed identifier.
    const nfkc = toNFKC(&[_]u32{0xFB01}).?;
    try std.testing.expect(isAllowedIdentifier(nfkc.slice()));
}

test "admissibility-form-drift shared fixture vectors" {
    // The 4 rows of the shared context-free fixture, inputs given as decimal
    // codepoints. Clear rows assert isClear; hazard rows assert the fully
    // qualified reason code from required_findings.

    // empty-clear (both admissibility calls false → agree).
    {
        const v = Afd.detect(&[_]u32{});
        try std.testing.expect(v.classify.isClear());
        try std.testing.expectEqual(@as(?[]const u8, null), v.classify.tag());
        try std.testing.expectEqualSlices(usize, &[_]usize{}, v.classify.positions());
    }
    // ascii-admin-clear (97,100,109,105,110) — admissible on both sides.
    {
        const v = Afd.detect(&[_]u32{ 97, 100, 109, 105, 110 });
        try std.testing.expect(v.classify.isClear());
        try std.testing.expect(v.input_admissible);
        try std.testing.expect(v.nfkc_admissible);
    }
    // fi-ligature-drift (64257 = U+FB01) — Restricted input, admissible NFKC.
    try expectAfdReason(&[_]u32{64257}, "unicode.security.X.admissibility-form-drift.AdmissibilityFormDrift");
    // jamo-sequence-drift (4370,4449,4523 = U+1112,U+1161,U+11AB).
    try expectAfdReason(&[_]u32{ 4370, 4449, 4523 }, "unicode.security.X.admissibility-form-drift.AdmissibilityFormDrift");
}

test "admissibility-form-drift detect spot checks" {
    // The Rust §2 detect spot checks (one per Lean theorem).

    // detect_empty_clear — both admissibility calls return false, so they agree.
    try std.testing.expect(Afd.detect(&[_]u32{}).classify.isClear());
    // detect_ascii_clear — "admin"; admissible on both sides (NFKC is identity).
    {
        const v = Afd.detect(&[_]u32{ 0x61, 0x64, 0x6D, 0x69, 0x6E });
        try std.testing.expect(v.classify.isClear());
        try std.testing.expect(v.input_admissible);
        try std.testing.expect(v.nfkc_admissible);
    }
    // detect_fi_ligature_drift — U+FB01 is Restricted (inadmissible), but NFKC
    // decomposes it to "fi" (admissible). Drift fires.
    {
        const v = Afd.detect(&[_]u32{0xFB01});
        try std.testing.expectEqualStrings("AdmissibilityFormDrift", v.classify.tag().?);
        try std.testing.expect(!v.input_admissible);
        try std.testing.expect(v.nfkc_admissible);
    }
    // detect_jamo_sequence_drift — decomposed Hangul jamos are inadmissible, but
    // NFKC composes them to U+D55C 한 (admissible).
    try std.testing.expectEqualStrings("AdmissibilityFormDrift", afdTag(&[_]u32{ 0x1112, 0x1161, 0x11AB }).?);
}

// ── skin-tone-variation-forgery (identity layer I) ────────────────────────

const Stvf = skin_tone_variation_forgery;

fn stvfTag(input: []const u32) ?[]const u8 {
    return Stvf.detect(input).classify.tag();
}

fn stvfReason(input: []const u32) ?[]const u8 {
    return Stvf.detect(input).classify.reasonCode();
}

fn expectStvfReason(input: []const u32, want: []const u8) !void {
    const r = stvfReason(input);
    try std.testing.expect(r != null);
    try std.testing.expectEqualStrings(want, r.?);
}

test "skin-tone-variation-forgery predicate reuse" {
    // The skin-tone modifier set is the emoji-zwj-integrity detector's own
    // isEmojiModifier predicate (U+1F3FB..U+1F3FF); Emoji_Modifier_Base and
    // Emoji_Presentation parse the port's already-bundled data/emoji-data.txt.
    try std.testing.expect(Stvf.isSkinTone(0x1F3FB));
    try std.testing.expect(Stvf.isSkinTone(0x1F3FF));
    try std.testing.expect(!Stvf.isSkinTone(0x1F3FA));
    try std.testing.expect(!Stvf.isSkinTone(0x1F600));
    // Waving hand U+1F44B is Emoji_Modifier_Base; grinning face U+1F600 is not.
    try std.testing.expect(Stvf.isSkinToneBase(0x1F44B));
    try std.testing.expect(!Stvf.isSkinToneBase(0x1F600));
    try std.testing.expect(!Stvf.isSkinToneBase(0x0041));
    // Grinning face U+1F600 has Emoji_Presentation; ASCII 'A' does not.
    try std.testing.expect(Stvf.isEmojiPresentation(0x1F600));
    try std.testing.expect(!Stvf.isEmojiPresentation(0x0041));
    // The variation selectors.
    try std.testing.expect(Stvf.isVs15(0xFE0E));
    try std.testing.expect(!Stvf.isVs15(0xFE0F));
    try std.testing.expect(Stvf.isVs16(0xFE0F));
    try std.testing.expect(!Stvf.isVs16(0xFE0E));
}

test "skin-tone-variation-forgery shared fixture vectors" {
    // The 8 rows of the shared context-free fixture, inputs given as decimal
    // codepoints. Clear rows assert isClear; hazard rows assert the fully
    // qualified reason code from required_findings.

    // empty-clear.
    {
        const v = Stvf.detect(&[_]u32{});
        try std.testing.expect(v.classify.isClear());
        try std.testing.expectEqual(@as(?[]const u8, null), v.classify.tag());
        try std.testing.expectEqualSlices(usize, &[_]usize{}, v.classify.positions());
    }
    // ascii-clear (72,101 = "He").
    try std.testing.expect(Stvf.detect(&[_]u32{ 72, 101 }).classify.isClear());
    // plain-emoji-clear (128512 = U+1F600).
    try std.testing.expect(Stvf.detect(&[_]u32{128512}).classify.isClear());
    // wave-single-skin-tone-clear (128075,127995) — modifier base + one skin tone.
    try std.testing.expect(Stvf.detect(&[_]u32{ 128075, 127995 }).classify.isClear());
    // stacked-skin-tones (128075,127995,127996).
    try expectStvfReason(&[_]u32{ 128075, 127995, 127996 }, "unicode.security.I.skin-tone-variation-forgery.StackedSkinTones");
    // invalid-target-ascii (65,127995).
    try expectStvfReason(&[_]u32{ 65, 127995 }, "unicode.security.I.skin-tone-variation-forgery.InvalidSkinToneTarget");
    // invalid-target-smiley (128512,127995).
    try expectStvfReason(&[_]u32{ 128512, 127995 }, "unicode.security.I.skin-tone-variation-forgery.InvalidSkinToneTarget");
    // forced-text-style (128512,65038 = U+1F600,U+FE0E).
    try expectStvfReason(&[_]u32{ 128512, 65038 }, "unicode.security.I.skin-tone-variation-forgery.ForcedTextStyle");
}

test "skin-tone-variation-forgery detect spot checks" {
    // The Rust §5 detect spot checks (one per Lean theorem).

    // detect_empty_clear.
    try std.testing.expect(Stvf.detect(&[_]u32{}).classify.isClear());
    // detect_ascii_clear — "He".
    try std.testing.expect(Stvf.detect(&[_]u32{ 0x48, 0x65 }).classify.isClear());
    // detect_plain_emoji_clear — grinning face.
    try std.testing.expect(Stvf.detect(&[_]u32{0x1F600}).classify.isClear());
    // detect_wave_skin_tone_clear — waving hand (a modifier base) + one skin tone.
    {
        const v = Stvf.detect(&[_]u32{ 0x1F44B, 0x1F3FB });
        try std.testing.expect(v.classify.isClear());
        try std.testing.expectEqual(@as(usize, 1), v.skin_tone_count);
    }
    // detect_stacked_skin_tones — waving hand + two skin tones.
    {
        const v = Stvf.detect(&[_]u32{ 0x1F44B, 0x1F3FB, 0x1F3FC });
        try std.testing.expectEqualStrings("StackedSkinTones", v.classify.tag().?);
        try std.testing.expectEqualSlices(usize, &[_]usize{ 1, 2 }, v.classify.positions());
    }
    // detect_invalid_target_ascii — skin tone on ASCII 'A'.
    {
        const v = Stvf.detect(&[_]u32{ 0x0041, 0x1F3FB });
        try std.testing.expectEqualStrings("InvalidSkinToneTarget", v.classify.tag().?);
        try std.testing.expectEqualSlices(usize, &[_]usize{1}, v.classify.positions());
    }
    // detect_invalid_target_smiley — skin tone on grinning face (not a modifier base).
    try std.testing.expectEqualStrings("InvalidSkinToneTarget", stvfTag(&[_]u32{ 0x1F600, 0x1F3FB }).?);
    // detect_forced_text_style — VS15 on grinning face (Emoji_Presentation).
    {
        const v = Stvf.detect(&[_]u32{ 0x1F600, 0xFE0E });
        try std.testing.expectEqualStrings("ForcedTextStyle", v.classify.tag().?);
        try std.testing.expectEqual(@as(usize, 1), v.variation_selector15_count);
    }
}

test "skin-tone-variation-forgery priority and counts" {
    // Stacked skin tones outrank the invalid-target and forced-text checks:
    // U+1F600 (not a modifier base) + two skin tones fires StackedSkinTones,
    // not InvalidSkinToneTarget, and reports positions [1,2].
    {
        const v = Stvf.detect(&[_]u32{ 0x1F600, 0x1F3FB, 0x1F3FC });
        try std.testing.expectEqualStrings("StackedSkinTones", v.classify.tag().?);
        try std.testing.expectEqualSlices(usize, &[_]usize{ 1, 2 }, v.classify.positions());
        try std.testing.expectEqual(@as(usize, 2), v.skin_tone_count);
    }
    // VS16 (U+FE0F) is counted but never fires a hazard on its own.
    {
        const v = Stvf.detect(&[_]u32{ 0x1F600, 0xFE0F });
        try std.testing.expect(v.classify.isClear());
        try std.testing.expectEqual(@as(usize, 1), v.variation_selector16_count);
        try std.testing.expectEqual(@as(usize, 0), v.variation_selector15_count);
    }
}

// ── source-display-divergence (display layer D, aggregator) ──────────────

const Sdd = source_display_divergence;

fn sddReason(input: []const u32) ?[]const u8 {
    return Sdd.detect(input).classify.reasonCode();
}

fn expectSddReason(input: []const u32, want: []const u8) !void {
    const r = sddReason(input);
    try std.testing.expect(r != null);
    try std.testing.expectEqualStrings(want, r.?);
}

test "source-display-divergence shared fixture vectors" {
    // The shared context-free fixture rows, inputs given as decimal codepoints.
    // Clear rows assert isClear; hazard rows assert the fully qualified reason
    // code from required_findings.

    // empty-clear.
    {
        const v = Sdd.detect(&[_]u32{});
        try std.testing.expect(v.classify.isClear());
        try std.testing.expectEqual(@as(?[]const u8, null), v.classify.tag());
        try std.testing.expectEqual(@as(usize, 0), v.fired_count);
    }
    // ascii-hello-clear — "Hello world".
    try std.testing.expect(Sdd.detect(&[_]u32{ 72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100 }).classify.isClear());
    // ascii-source-clear — "let x = 1;".
    try std.testing.expect(Sdd.detect(&[_]u32{ 108, 101, 116, 32, 120, 32, 61, 32, 49, 59 }).classify.isClear());
    // tag-block-passthrough — tag-encoded "AB".
    try expectSddReason(&[_]u32{ 917569, 917570 }, "unicode.security.D.source-display-divergence.TagBlock");
    // variation-selector-passthrough — A + VS16.
    try expectSddReason(&[_]u32{ 65, 65039 }, "unicode.security.D.source-display-divergence.VariationSelector");
    // zero-width-passthrough — H + ZWSP + i.
    try expectSddReason(&[_]u32{ 72, 8203, 105 }, "unicode.security.D.source-display-divergence.ZeroWidth");
    // bidi-control-passthrough — RLO + A.
    try expectSddReason(&[_]u32{ 8238, 65 }, "unicode.security.D.source-display-divergence.BidiControl");
    // homoglyph-passthrough — "Nether<Cyrillic е>um".
    try expectSddReason(&[_]u32{ 78, 101, 116, 104, 101, 114, 1077, 117, 109 }, "unicode.security.D.source-display-divergence.IdentifierHomoglyph");
    // compound-vs-zwsp — A + VS16 + ZWSP.
    try expectSddReason(&[_]u32{ 65, 65039, 8203 }, "unicode.security.D.source-display-divergence.Compound");
    // compound-tag-zwsp — tag "AB" + ZWSP.
    try expectSddReason(&[_]u32{ 917569, 917570, 8203 }, "unicode.security.D.source-display-divergence.Compound");
}

test "source-display-divergence detect spot checks" {
    // The Rust §5 detect spot checks (one per Lean theorem), inputs as hex.

    // clear: empty, "Hello world", "let x = 1;".
    {
        const v = Sdd.detect(&[_]u32{});
        try std.testing.expect(v.classify.isClear());
        try std.testing.expectEqual(@as(?[]const u8, null), v.classify.tag());
    }
    try std.testing.expect(Sdd.detect(&[_]u32{ 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64 }).classify.isClear());
    try std.testing.expect(Sdd.detect(&[_]u32{ 0x6C, 0x65, 0x74, 0x20, 0x78, 0x20, 0x3D, 0x20, 0x31, 0x3B }).classify.isClear());

    // single-fire pass-through — each constituent in isolation reports its tag.
    {
        // tag-encoded "AB".
        const v = Sdd.detect(&[_]u32{ 0xE0041, 0xE0042 });
        try std.testing.expectEqualStrings("TagBlock", v.classify.tag().?);
        try std.testing.expectEqual(@as(usize, 1), v.fired_count);
    }
    try std.testing.expectEqualStrings("VariationSelector", Sdd.detect(&[_]u32{ 0x0041, 0xFE0F }).classify.tag().?);
    try std.testing.expectEqualStrings("ZeroWidth", Sdd.detect(&[_]u32{ 0x0048, 0x200B, 0x69 }).classify.tag().?);
    try std.testing.expectEqualStrings("BidiControl", Sdd.detect(&[_]u32{ 0x202E, 0x41 }).classify.tag().?);
    try std.testing.expectEqualStrings("IdentifierHomoglyph", Sdd.detect(&[_]u32{ 0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D }).classify.tag().?);

    // two-or-more is Compound.
    {
        // A + VS16 + ZWSP — two constituents fire.
        const v = Sdd.detect(&[_]u32{ 0x0041, 0xFE0F, 0x200B });
        try std.testing.expectEqualStrings("Compound", v.classify.tag().?);
        try std.testing.expectEqual(@as(usize, 2), v.fired_count);
    }
    // tag "AB" + ZWSP — two constituents fire.
    try std.testing.expectEqualStrings("Compound", Sdd.detect(&[_]u32{ 0xE0041, 0xE0042, 0x200B }).classify.tag().?);
}
