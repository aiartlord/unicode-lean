const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const module = b.addModule("unicode_security", .{
        .root_source_file = b.path("src/security.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .name = "unicode_security",
        .root_module = module,
    });
    b.installArtifact(lib);

    const test_module = b.createModule(.{
        .root_source_file = b.path("test/policy_contract.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_module.addImport("unicode_security", module);

    const contract_options = b.addOptions();
    contract_options.addOption(
        []const u8,
        "policy_contract_json",
        readFixture(b, "testdata/fixtures/security/policy_contract.json"),
    );
    contract_options.addOption(
        []const u8,
        "verdict_contract_json",
        readFixture(b, "testdata/fixtures/security/verdict_contract.json"),
    );
    contract_options.addOption(
        []const u8,
        "decode_contract_json",
        readFixture(b, "testdata/fixtures/security/decode_contract.json"),
    );
    contract_options.addOption(
        []const u8,
        "multiencoding_decode_contract_json",
        readFixture(b, "testdata/fixtures/security/decode_multiencoding_contract.json"),
    );
    contract_options.addOption(
        []const u8,
        "tag_block_payload_json",
        readFixture(b, "testdata/fixtures/security/detectors/tag_block_payload.json"),
    );
    contract_options.addOption(
        []const u8,
        "zero_width_payload_json",
        readFixture(b, "testdata/fixtures/security/detectors/zero_width_payload.json"),
    );
    contract_options.addOption(
        []const u8,
        "variation_selector_payload_json",
        readFixture(b, "testdata/fixtures/security/detectors/variation_selector_payload.json"),
    );
    contract_options.addOption(
        []const u8,
        "bidi_control_balance_json",
        readFixture(b, "testdata/fixtures/security/detectors/bidi_control_balance.json"),
    );
    contract_options.addOption(
        []const u8,
        "noncharacter_control_json",
        readFixture(b, "testdata/fixtures/security/detectors/noncharacter_control.json"),
    );
    contract_options.addOption(
        []const u8,
        "homoglyph_confusable_json",
        readFixture(b, "testdata/fixtures/security/detectors/homoglyph_confusable.json"),
    );
    contract_options.addOption(
        []const u8,
        "mixed_script_admissibility_json",
        readFixture(b, "testdata/fixtures/security/detectors/mixed_script_admissibility.json"),
    );
    test_module.addOptions("contract_options", contract_options);

    const tests = b.addTest(.{
        .name = "unicode_security_tests",
        .root_module = test_module,
    });

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run runtime-port tests");
    test_step.dependOn(&run_tests.step);
}

fn readFixture(b: *std.Build, path: []const u8) []const u8 {
    const lazy_path = b.path(path);
    return std.Io.Dir.cwd().readFileAlloc(
        b.graph.io,
        lazy_path.getPath(b),
        b.allocator,
        .limited(64 * 1024),
    ) catch |err| std.debug.panic("failed to read fixture {s}: {s}", .{ path, @errorName(err) });
}
