const std = @import("std");
const confusables_data = @import("confusables_data.zig");
const case_folding_data = @import("case_folding_data.zig");
const normalization_data = @import("normalization_data.zig");
const bidi_class_data = @import("bidi_class_data.zig");
const casing_data = @import("casing_data.zig");
const bip39_data = @import("bip39_data.zig");

const known_attack_targets_raw = @embedFile("data/KnownAttackTargets.txt");
const standardized_variants_raw = @embedFile("data/StandardizedVariants.txt");
const emoji_variation_sequences_raw = @embedFile("data/emoji-variation-sequences.txt");
const emoji_data_raw = @embedFile("data/emoji-data.txt");
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
    positions: [16]usize,
    position_count: usize,
    sub_threat: []const u8,
    detail: []const u8,
};

pub const MaxFindings = 11;

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
        .gateway_header, .domain_name, .dns_label, .source_code => .{
            .level = .restrictive,
            .quarantine = false,
        },
        .url => .{ .level = .moderate, .quarantine = false },
        .username => .{ .level = .moderate, .quarantine = true },
        .display_name, .chat_message => .{ .level = .minimal, .quarantine = true },
        .opaque_secret, .binary_blob => .{ .level = .minimal, .quarantine = false },
    };
}

pub fn scan(profile: Profile, mode: Mode, input: []const u32) Verdict {
    const findings = detect(input);
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
        var positions: [16]usize = undefined;
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

fn detect(input: []const u32) FindingList {
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

    if (positionsWhere(input, isZeroWidthPayload)) |positions| {
        findings.append(.{
            .code = "unicode.security.C.zero-width-payload.BareZeroWidth",
            .family = .zero_width_payload,
            .severity = 2,
            .positions = positions.items,
            .position_count = positions.len,
            .sub_threat = "BareZeroWidth",
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
    if (mixedScriptAdmissibilityFinding(input)) |finding| {
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
        .restrictive, .moderate => switch (family) {
            .malformed_utf8, .malformed_utf16, .malformed_utf32, .tag_block_payload, .variation_selector_payload, .zero_width_payload, .surrogate_reassembly, .bidi_control_balance, .noncharacter_control, .homoglyph_confusable, .mixed_script_admissibility, .rtl_injection, .confusable_bidi_compound, .covert_display_compound => true,
        },
        .minimal => family == .malformed_utf8 or family == .malformed_utf16 or family == .malformed_utf32 or family == .surrogate_reassembly or family == .bidi_control_balance or family == .noncharacter_control,
    };
}

const Positions = struct {
    items: [16]usize,
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

fn isZeroWidthPayload(cp: u32) bool {
    return cp == 0x200B or cp == 0x200C or cp == 0x200D or cp == 0x2060 or cp == 0xFEFF;
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

// The specific script-collision sub-threat, matching the Lean source of truth:
// Latin/Cyrillic and Latin/Greek are named explicitly (Cyrillic before Greek);
// every other multi-script mix is ScriptMixOther.
fn mixedScriptSubthreat(input: []const u32) []const u8 {
    var has_latin = false;
    var has_greek = false;
    var has_cyrillic = false;
    for (input) |cp| {
        if (isLatinScript(cp)) has_latin = true;
        if (isGreekScript(cp)) has_greek = true;
        if (isCyrillicScript(cp)) has_cyrillic = true;
    }
    if (has_latin and has_cyrillic) return "LatinCyrillic";
    if (has_latin and has_greek) return "LatinGreek";
    return "ScriptMixOther";
}

fn mixedScriptAdmissibilityFinding(input: []const u32) ?Finding {
    if (!hasCrossScriptMix(input)) return null;
    const positions = fullSpanPositions(input);
    const sub = mixedScriptSubthreat(input);
    const code = if (std.mem.eql(u8, sub, "LatinCyrillic"))
        "unicode.security.I.mixed-script-admissibility.LatinCyrillic"
    else if (std.mem.eql(u8, sub, "LatinGreek"))
        "unicode.security.I.mixed-script-admissibility.LatinGreek"
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
    if (std.mem.eql(u8, sub_threat, "RloInLTRField")) {
        return "unicode.security.D.rtl-injection.RloInLTRField";
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
    var positions: [16]usize = undefined;
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

// Detect right-to-left injection in an LTR-declared field. Priority mirrors
// the spec exactly: (1) any bidi format-control anywhere fires
// RloInLTRField; otherwise (2) a leading strong-RTL codepoint fires
// FieldTakeover; otherwise (3) mid-stream strong-RTL is classified by run
// length (>= 4 is MixedOverflow, shorter is StrongRTLInLTR).
fn rtlInjectionFinding(input: []const u32) ?Finding {
    for (input, 0..) |cp, index| {
        if (isBidiFormatControl(cp)) return rtlInjectionAt("RloInLTRField", index);
    }

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
    var positions: [16]usize = undefined;
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
    var positions: [16]usize = undefined;
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

fn hasDecompositionSwap(input: []const u32) bool {
    if (input.len < 2) return false;
    for (1..input.len) |index| {
        const previous = input[index - 1];
        const current = input[index];
        if (isCombiningMark(current) and !isCombiningMark(previous)) return true;
        if (isCombiningMark(previous) and isCombiningMark(current) and previous > current) return true;
        if (composeHangulPair(previous, current)) return true;
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

fn hasCrossScriptMix(input: []const u32) bool {
    var has_latin = false;
    var has_greek = false;
    var has_cyrillic = false;
    for (input) |cp| {
        if (isLatinScript(cp)) has_latin = true;
        if (isGreekScript(cp)) has_greek = true;
        if (isCyrillicScript(cp)) has_cyrillic = true;
    }
    const count = @as(u8, @intFromBool(has_latin)) +
        @as(u8, @intFromBool(has_greek)) +
        @as(u8, @intFromBool(has_cyrillic));
    return count >= 2;
}

fn isLatinScript(cp: u32) bool {
    return (cp >= 0x0041 and cp <= 0x005A) or
        (cp >= 0x0061 and cp <= 0x007A) or
        (cp >= 0x00C0 and cp <= 0x024F) or
        (cp >= 0x1E00 and cp <= 0x1EFF);
}

fn isGreekScript(cp: u32) bool {
    return (cp >= 0x0370 and cp <= 0x03FF) or
        (cp >= 0x1F00 and cp <= 0x1FFF);
}

fn isCyrillicScript(cp: u32) bool {
    return (cp >= 0x0400 and cp <= 0x052F) or
        (cp >= 0x2DE0 and cp <= 0x2DFF) or
        (cp >= 0xA640 and cp <= 0xA69F);
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
    var positions: [16]usize = undefined;
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
    var positions: [16]usize = undefined;
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
    // fixtures/security/detectors/hash_input_stability.json).
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
    // fixtures/security/detectors/ai_watermark_detectability.json).
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
    // (fixtures/security/detectors/stream_safe_violation.json).

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
