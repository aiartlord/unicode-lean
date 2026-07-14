const std = @import("std");
const contract_options = @import("contract_options");
const security = @import("unicode_security");

const Contract = struct {
    schema: u32,
    contract: []const u8,
    cases: []Case,
};

const Case = struct {
    name: []const u8,
    profile: []const u8,
    mode: []const u8,
    input: []u32,
    action: []const u8,
    required_findings: [][]const u8,
};

const DecodeContract = struct {
    schema: u32,
    contract: []const u8,
    cases: []DecodeCase,
};

const DecodeCase = struct {
    name: []const u8,
    encoding: []const u8 = "utf-8",
    profile: []const u8,
    mode: []const u8,
    input_bytes: []u8,
    input: []u32,
    action: []const u8,
    required_findings: [][]const u8,
    required_positions: []RequiredPosition,
};

const RequiredPosition = struct {
    code: []const u8,
    positions: []usize,
};

const VerdictContract = struct {
    schema: u32,
    contract: []const u8,
    cases: []VerdictCase,
};

const VerdictCase = struct {
    name: []const u8,
    profile: []const u8,
    mode: []const u8,
    input: []u32,
    verdict: ExpectedVerdict,
};

const ExpectedVerdict = struct {
    action: []const u8,
    profile: []const u8,
    mode: []const u8,
    input: []u32,
    findings: []ExpectedFinding,
    normalized: ?[]u32,
};

const ExpectedFinding = struct {
    code: []const u8,
    family: []const u8,
    severity: u8,
    positions: []usize,
    sub_threat: []const u8,
    detail: []const u8,
};

const DetectorFixture = struct {
    schema: u32,
    family: []const u8,
    cases: []DetectorCase,
};

const DetectorCase = struct {
    name: []const u8,
    input: []u32,
    required_findings: [][]const u8,
};

test "shared policy contract fixture" {
    const allocator = std.testing.allocator;
    const data = contract_options.policy_contract_json;

    const parsed = try std.json.parseFromSlice(Contract, allocator, data, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u32, 1), parsed.value.schema);
    try std.testing.expect(std.mem.eql(
        u8,
        parsed.value.contract,
        "unicode-security-policy-v0",
    ));

    for (parsed.value.cases) |case| {
        const profile = security.Profile.fromTag(case.profile) orelse {
            std.debug.print("unknown profile in fixture: {s}\n", .{case.profile});
            return error.UnknownProfile;
        };
        const mode = security.Mode.fromTag(case.mode) orelse {
            std.debug.print("unknown mode in fixture: {s}\n", .{case.mode});
            return error.UnknownMode;
        };
        const expected_action = security.Action.fromTag(case.action) orelse {
            std.debug.print("unknown action in fixture: {s}\n", .{case.action});
            return error.UnknownAction;
        };

        const verdict = security.scan(profile, mode, case.input);
        if (verdict.action != expected_action) {
            std.debug.print(
                "{s}: action mismatch, got {any}, expected {any}\n",
                .{ case.name, verdict.action, expected_action },
            );
        }
        try std.testing.expectEqual(expected_action, verdict.action);

        for (case.required_findings) |code| {
            if (!verdict.findings.containsCode(code)) {
                std.debug.print("{s}: missing finding {s}\n", .{ case.name, code });
            }
            try std.testing.expect(verdict.findings.containsCode(code));
        }
    }
}

test "shared verdict JSON contract fixture" {
    const allocator = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(
        VerdictContract,
        allocator,
        contract_options.verdict_contract_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u32, 1), parsed.value.schema);
    try std.testing.expect(std.mem.eql(
        u8,
        parsed.value.contract,
        "unicode-security-verdict-v0",
    ));

    for (parsed.value.cases) |case| {
        const profile = security.Profile.fromTag(case.profile) orelse return error.UnknownProfile;
        const mode = security.Mode.fromTag(case.mode) orelse return error.UnknownMode;
        const verdict = security.scan(profile, mode, case.input);
        try expectVerdict(case.name, verdict, case.verdict);

        var rendered_buffer: [4096]u8 = undefined;
        var rendered_writer: std.Io.Writer = .fixed(&rendered_buffer);
        try security.writeVerdictJson(&rendered_writer, verdict);
        var expected_buffer: [4096]u8 = undefined;
        var expected_writer: std.Io.Writer = .fixed(&expected_buffer);
        try std.json.Stringify.value(case.verdict, .{}, &expected_writer);
        try std.testing.expectEqualStrings(expected_writer.buffered(), rendered_writer.buffered());
    }
}

test "shared decode contract fixture" {
    const allocator = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(
        DecodeContract,
        allocator,
        contract_options.decode_contract_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u32, 1), parsed.value.schema);
    try std.testing.expect(std.mem.eql(
        u8,
        parsed.value.contract,
        "unicode-security-decode-v0",
    ));

    for (parsed.value.cases) |case| {
        const profile = security.Profile.fromTag(case.profile) orelse return error.UnknownProfile;
        const mode = security.Mode.fromTag(case.mode) orelse return error.UnknownMode;
        const expected_action = security.Action.fromTag(case.action) orelse return error.UnknownAction;
        var decoded_buffer: [64]u32 = undefined;
        const verdict = security.scanUtf8(profile, mode, case.input_bytes, decoded_buffer[0..]);

        if (verdict.action != expected_action) {
            std.debug.print("{s}: action mismatch\n", .{case.name});
        }
        try std.testing.expectEqual(expected_action, verdict.action);
        try std.testing.expect(std.mem.eql(u32, verdict.input, case.input));

        for (case.required_findings) |code| {
            if (!verdict.findings.containsCode(code)) {
                std.debug.print("{s}: missing finding {s}\n", .{ case.name, code });
            }
            try std.testing.expect(verdict.findings.containsCode(code));
        }
        for (case.required_positions) |expected| {
            if (!positionsMatchCode(verdict.findings, expected.code, expected.positions)) {
                std.debug.print("{s}: positions mismatch for {s}\n", .{ case.name, expected.code });
            }
            try std.testing.expect(positionsMatchCode(verdict.findings, expected.code, expected.positions));
        }
    }
}

test "shared multi-encoding decode contract fixture" {
    const allocator = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(
        DecodeContract,
        allocator,
        contract_options.multiencoding_decode_contract_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u32, 1), parsed.value.schema);
    try std.testing.expect(std.mem.eql(
        u8,
        parsed.value.contract,
        "unicode-security-multiencoding-decode-v0",
    ));

    for (parsed.value.cases) |case| {
        const profile = security.Profile.fromTag(case.profile) orelse return error.UnknownProfile;
        const mode = security.Mode.fromTag(case.mode) orelse return error.UnknownMode;
        const expected_action = security.Action.fromTag(case.action) orelse return error.UnknownAction;
        var decoded_buffer: [64]u32 = undefined;
        const verdict = try scanEncodedCase(case.encoding, profile, mode, case.input_bytes, decoded_buffer[0..]);

        if (verdict.action != expected_action) {
            std.debug.print("{s}: action mismatch\n", .{case.name});
        }
        try std.testing.expectEqual(expected_action, verdict.action);
        try std.testing.expect(std.mem.eql(u32, verdict.input, case.input));

        for (case.required_findings) |code| {
            if (!verdict.findings.containsCode(code)) {
                std.debug.print("{s}: missing finding {s}\n", .{ case.name, code });
            }
            try std.testing.expect(verdict.findings.containsCode(code));
        }
        for (case.required_positions) |expected| {
            if (!positionsMatchCode(verdict.findings, expected.code, expected.positions)) {
                std.debug.print("{s}: positions mismatch for {s}\n", .{ case.name, expected.code });
            }
            try std.testing.expect(positionsMatchCode(verdict.findings, expected.code, expected.positions));
        }
    }
}

test "shared detector fixtures" {
    try checkDetectorFixture(contract_options.tag_block_payload_json);
    try checkDetectorFixture(contract_options.variation_selector_payload_json);
    try checkDetectorFixture(contract_options.zero_width_payload_json);
    try checkDetectorFixture(contract_options.bidi_control_balance_json);
    try checkDetectorFixture(contract_options.noncharacter_control_json);
    try checkDetectorFixture(contract_options.homoglyph_confusable_json);
    try checkDetectorFixture(contract_options.mixed_script_admissibility_json);
}

fn positionsMatchCode(findings: security.FindingList, code: []const u8, expected: []const usize) bool {
    for (findings.items[0..findings.len]) |finding| {
        if (std.mem.eql(u8, finding.code, code)) {
            return std.mem.eql(usize, finding.positions[0..finding.position_count], expected);
        }
    }
    return false;
}

fn scanEncodedCase(
    encoding: []const u8,
    profile: security.Profile,
    mode: security.Mode,
    input_bytes: []const u8,
    decoded_buffer: []u32,
) !security.Verdict {
    if (std.mem.eql(u8, encoding, "utf-8")) {
        return security.scanUtf8(profile, mode, input_bytes, decoded_buffer);
    }
    if (std.mem.eql(u8, encoding, "utf-16be")) {
        return security.scanUtf16Be(profile, mode, input_bytes, decoded_buffer);
    }
    if (std.mem.eql(u8, encoding, "utf-16le")) {
        return security.scanUtf16Le(profile, mode, input_bytes, decoded_buffer);
    }
    if (std.mem.eql(u8, encoding, "utf-32be")) {
        return security.scanUtf32Be(profile, mode, input_bytes, decoded_buffer);
    }
    if (std.mem.eql(u8, encoding, "utf-32le")) {
        return security.scanUtf32Le(profile, mode, input_bytes, decoded_buffer);
    }
    return error.UnknownEncoding;
}

fn expectVerdict(name: []const u8, actual: security.Verdict, expected: ExpectedVerdict) !void {
    if (!std.mem.eql(u8, actual.action.tag(), expected.action)) {
        std.debug.print("{s}: action mismatch\n", .{name});
    }
    try std.testing.expect(std.mem.eql(u8, actual.action.tag(), expected.action));
    try std.testing.expect(std.mem.eql(u8, actual.profile.tag(), expected.profile));
    try std.testing.expect(std.mem.eql(u8, actual.mode.tag(), expected.mode));
    try std.testing.expect(std.mem.eql(u32, actual.input, expected.input));
    try std.testing.expectEqual(expected.findings.len, actual.findings.len);
    for (expected.findings, 0..) |expected_finding, index| {
        const actual_finding = actual.findings.items[index];
        try std.testing.expect(std.mem.eql(u8, actual_finding.code, expected_finding.code));
        try std.testing.expect(std.mem.eql(u8, actual_finding.family.tag(), expected_finding.family));
        try std.testing.expectEqual(expected_finding.severity, actual_finding.severity);
        try std.testing.expect(std.mem.eql(
            usize,
            actual_finding.positions[0..actual_finding.position_count],
            expected_finding.positions,
        ));
        try std.testing.expect(std.mem.eql(u8, actual_finding.sub_threat, expected_finding.sub_threat));
        try std.testing.expect(std.mem.eql(u8, actual_finding.detail, expected_finding.detail));
    }
    try std.testing.expect(actual.normalized == null);
    try std.testing.expect(expected.normalized == null);
}

fn checkDetectorFixture(data: []const u8) !void {
    const allocator = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(
        DetectorFixture,
        allocator,
        data,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u32, 1), parsed.value.schema);
    for (parsed.value.cases) |case| {
        const verdict = security.scan(.gateway_header, .observe, case.input);
        for (case.required_findings) |code| {
            if (!verdict.findings.containsCode(code)) {
                std.debug.print("{s}: missing finding {s}\n", .{ case.name, code });
            }
            try std.testing.expect(verdict.findings.containsCode(code));
        }
        if (case.required_findings.len == 0 and containsFamily(verdict.findings, parsed.value.family)) {
            std.debug.print("{s}: unexpected finding for family {s}\n", .{ case.name, parsed.value.family });
            return error.UnexpectedDetectorFinding;
        }
    }
}

fn containsFamily(findings: security.FindingList, family: []const u8) bool {
    for (findings.items[0..findings.len]) |finding| {
        if (std.mem.eql(u8, finding.family.tag(), family)) {
            return true;
        }
    }
    return false;
}
