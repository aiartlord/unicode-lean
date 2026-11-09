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
    // The differential corpus is several megabytes; embedding it as a build
    // option makes the compiler materialise the whole string literal, so the
    // test reads it from disk at run time instead and only the path is baked in.
    contract_options.addOption(
        []const u8,
        "differential_corpus_path",
        b.pathFromRoot("testdata/fixtures/security/differential_corpus.json"),
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
    contract_options.addOption(
        []const u8,
        "rtl_injection_json",
        readFixture(b, "testdata/fixtures/security/detectors/rtl_injection.json"),
    );
    test_module.addOptions("contract_options", contract_options);

    const tests = b.addTest(.{
        .name = "unicode_security_tests",
        .root_module = test_module,
    });

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run runtime-port tests");
    test_step.dependOn(&run_tests.step);

    // Unit tests defined inside the security module itself (e.g. the
    // NFKD/NFKC/NFC known-answer vectors) run from a dedicated test
    // artifact rooted at the module source, since the contract test above
    // only discovers tests declared in its own root file.
    const unit_tests = b.addTest(.{
        .name = "unicode_security_unit_tests",
        .root_module = module,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    test_step.dependOn(&run_unit_tests.step);

    // Byte-layer refinement tests (opaque-blob + validated-utf8) live in
    // their own source file and run from a dedicated test artifact rooted
    // at that file, since the artifacts above only discover tests in their
    // own root graphs.
    const opaque_blob_module = b.createModule(.{
        .root_source_file = b.path("src/opaque_blob.zig"),
        .target = target,
        .optimize = optimize,
    });
    const opaque_blob_tests = b.addTest(.{
        .name = "unicode_opaque_blob_tests",
        .root_module = opaque_blob_module,
    });
    const run_opaque_blob_tests = b.addRunArtifact(opaque_blob_tests);
    test_step.dependOn(&run_opaque_blob_tests.step);

    // UAX #14 line breaking is its own module, so a consumer that wants
    // segmentation and not the security monitor links only what it uses. Its
    // tests live in their own root file, since the artifacts above discover
    // only tests in their own graphs.
    const line_break_module = b.addModule("unicode_line_break", .{
        .root_source_file = b.path("src/line_break.zig"),
        .target = target,
        .optimize = optimize,
    });

    const line_break_test_module = b.createModule(.{
        .root_source_file = b.path("test/line_break.zig"),
        .target = target,
        .optimize = optimize,
    });
    line_break_test_module.addImport("line_break", line_break_module);

    const line_break_options = b.addOptions();
    // The corpus is over a megabyte; baking it in as a build option would make
    // the compiler materialise the whole string literal, so the test reads it
    // from disk at run time and only the path is baked in.
    line_break_options.addOption(
        []const u8,
        "corpus_path",
        b.pathFromRoot("testdata/LineBreakTest.txt"),
    );
    line_break_test_module.addOptions("line_break_options", line_break_options);

    const line_break_tests = b.addTest(.{
        .name = "unicode_line_break_tests",
        .root_module = line_break_test_module,
    });
    const run_line_break_tests = b.addRunArtifact(line_break_tests);
    test_step.dependOn(&run_line_break_tests.step);

    // UAX #29 grapheme clustering is its own module for the same reason, and
    // its tests live in their own root file. It reads the line breaker's
    // Extended_Pictographic table, which is a source-level import rather than a
    // module dependency, so only its own test root needs wiring here.
    const grapheme_module = b.addModule("unicode_grapheme", .{
        .root_source_file = b.path("src/grapheme.zig"),
        .target = target,
        .optimize = optimize,
    });

    const grapheme_test_module = b.createModule(.{
        .root_source_file = b.path("test/grapheme.zig"),
        .target = target,
        .optimize = optimize,
    });
    grapheme_test_module.addImport("grapheme", grapheme_module);

    const grapheme_options = b.addOptions();
    // The corpus is read from disk at run time for the reason the line-break
    // corpus is: baking it in as a build option would make the compiler
    // materialise the whole string literal.
    grapheme_options.addOption(
        []const u8,
        "corpus_path",
        b.pathFromRoot("testdata/GraphemeBreakTest.txt"),
    );
    grapheme_test_module.addOptions("grapheme_options", grapheme_options);

    const grapheme_tests = b.addTest(.{
        .name = "unicode_grapheme_tests",
        .root_module = grapheme_test_module,
    });
    const run_grapheme_tests = b.addRunArtifact(grapheme_tests);
    test_step.dependOn(&run_grapheme_tests.step);
}

fn readFixture(b: *std.Build, path: []const u8) []const u8 {
    const lazy_path = b.path(path);
    return std.Io.Dir.cwd().readFileAlloc(
        b.graph.io,
        lazy_path.getPath(b),
        b.allocator,
        // The hand-written contracts are tens of kilobytes, and every fixture
        // here is embedded in the test binary as a build option; the generated
        // differential corpus is read at run time instead.
        .limited(2 * 1024 * 1024),
    ) catch |err| std.debug.panic("failed to read fixture {s}: {s}", .{ path, @errorName(err) });
}
