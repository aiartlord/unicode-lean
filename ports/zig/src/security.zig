const std = @import("std");
const confusables_data = @import("confusables_data.zig");
const case_folding_data = @import("case_folding_data.zig");
const normalization_data = @import("normalization_data.zig");
const bidi_class_data = @import("bidi_class_data.zig");

const known_attack_targets_raw = @embedFile("data/KnownAttackTargets.txt");
const standardized_variants_raw = @embedFile("data/StandardizedVariants.txt");
const emoji_variation_sequences_raw = @embedFile("data/emoji-variation-sequences.txt");
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
