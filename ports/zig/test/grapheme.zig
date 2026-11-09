const std = @import("std");
const grapheme_options = @import("grapheme_options");
const grapheme = @import("grapheme");
const vector_cases = @import("vector_cases.zig");
const corpus = @import("segmentation_corpus.zig");

// UAX #29 default extended grapheme cluster segmentation.
//
// Validates the port's cluster breaker against the official Unicode
// GraphemeBreakTest.txt (bundled under testdata/ so the port stays
// self-contained), plus the shared vector fixture every other port replays and
// targeted cases for shapes a boundary mask does not state.
//
// The two corpus gates are the ones the line-break suite runs: agree with every
// published row, and separately account for the whole file so a row lost
// between the file and the fold fails rather than shrinking the denominator.
// The corpus reader itself is shared with that suite.

const Gcb = grapheme.Gcb;
const Incb = grapheme.Incb;

fn readCorpus(allocator: std.mem.Allocator) ![]corpus.Row {
    return corpus.readCorpus(allocator, grapheme_options.corpus_path);
}

// What the corpus must be before it can judge anything: every row carries one
// more flag than code points, and the vendored copy carries every row the
// canonical file did. Without the second check a row lost between the two would
// shrink the denominator instead of failing.
test "the grapheme corpus is well formed" {
    const allocator = std.testing.allocator;
    const rows = try readCorpus(allocator);
    defer corpus.freeRows(allocator, rows);

    try std.testing.expectEqual(@as(usize, 0), corpus.raggedRows(rows));
    try std.testing.expectEqual(grapheme.published_row_count, rows.len);
}

// Hand-written vectors cannot establish a segmentation algorithm: its rules
// read context on both sides of a boundary and the answer depends on state
// carried from earlier in the sequence, so a wrong rule survives any vector a
// person would pick.
test "the cluster breaker agrees with every published row" {
    const allocator = std.testing.allocator;
    const rows = try readCorpus(allocator);
    defer corpus.freeRows(allocator, rows);

    var disagreements: usize = 0;
    var first_line: usize = 0;
    for (rows) |row| {
        const produced = try grapheme.graphemeBreaks(allocator, row.codepoints);
        defer allocator.free(produced);
        if (!std.mem.eql(bool, produced, row.expected)) {
            if (disagreements == 0) first_line = row.line;
            disagreements += 1;
        }
    }
    if (disagreements != 0) {
        // A conformance red is only actionable if it says which row disagreed.
        std.debug.print(
            "{d} of {d} rows disagree; first at corpus line {d}\n",
            .{ disagreements, rows.len, first_line },
        );
    }
    try std.testing.expectEqual(@as(usize, 0), disagreements);
}

// One case per UAX #29 rule, the same bytes every port replays, so no port
// carries a weaker set of rule checks than another. The published corpus above
// is the authority; these name which rule each boundary exercises.
test "the shared grapheme vectors replay" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqualStrings(
        "uax29-grapheme-cluster",
        vector_cases.grapheme_algorithm,
    );
    try std.testing.expect(vector_cases.grapheme_cases.len > 0);
    for (vector_cases.grapheme_cases) |entry| {
        const produced = try grapheme.graphemeBreaks(allocator, entry.input);
        defer allocator.free(produced);
        if (!std.mem.eql(bool, produced, entry.breaks)) {
            // A red is only actionable if it says which rule disagreed.
            std.debug.print("{s}: {s}\n", .{ entry.rule, entry.name });
        }
        try std.testing.expect(std.mem.eql(bool, produced, entry.breaks));
    }
}

// Both gates count the same published file, so they cannot drift apart.
test "the grapheme corpus and the vectors agree on the row count" {
    try std.testing.expectEqual(
        grapheme.published_row_count,
        vector_cases.grapheme_published_row_count,
    );
}

test "the output carries one flag per boundary" {
    const allocator = std.testing.allocator;
    for (0..8) |length| {
        const cps = try allocator.alloc(u32, length);
        defer allocator.free(cps);
        for (0..length) |index| cps[index] = @intCast(0x61 + index);
        const breaks = try grapheme.graphemeBreaks(allocator, cps);
        defer allocator.free(breaks);
        try std.testing.expectEqual(length + 1, breaks.len);
        try std.testing.expectEqual(true, breaks[breaks.len - 1]); // GB2
        if (length > 0) try std.testing.expectEqual(true, breaks[0]); // GB1
    }
}

/// Whether the breaker produces `expected` for `cps`.
fn expectMask(cps: []const u32, expected: []const bool) !void {
    const allocator = std.testing.allocator;
    const produced = try grapheme.graphemeBreaks(allocator, cps);
    defer allocator.free(produced);
    try std.testing.expect(std.mem.eql(bool, produced, expected));
}

test "carriage return line feed is one cluster" {
    // GB3: CR times LF, with the surrounding boundaries from GB4 and GB5.
    try expectMask(&[_]u32{ 0x0D, 0x0A }, &[_]bool{ true, false, true });
}

test "a combining mark joins its base" {
    // GB9: x Extend.
    try expectMask(&[_]u32{ 0x65, 0x0301 }, &[_]bool{ true, false, true });
}

test "an emoji zero-width-joiner sequence is one cluster" {
    // GB11: ExtPict Extend* ZWJ x ExtPict, twice over.
    try expectMask(
        &[_]u32{ 0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467 },
        &[_]bool{ true, false, false, false, false, true },
    );
}

test "regional indicators pair off" {
    // GB12/GB13: an odd-parity run extends, so four indicators are two pairs.
    try expectMask(
        &[_]u32{ 0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8 },
        &[_]bool{ true, false, true, false, true },
    );
}

test "an Indic conjunct holds together across its linker" {
    // GB9c: Consonant (Extend | Linker)* Linker (Extend | Linker)* x Consonant.
    try expectMask(
        &[_]u32{ 0x0915, 0x094D, 0x0916 },
        &[_]bool{ true, false, false, true },
    );
}

// The cluster split is a shape the boundary masks do not state.
test "a sequence splits into its clusters" {
    const allocator = std.testing.allocator;

    const clusters = try grapheme.graphemeClusters(
        allocator,
        &[_]u32{ 0x65, 0x0301, 0x61 },
    );
    defer {
        for (clusters) |cluster| allocator.free(cluster);
        allocator.free(clusters);
    }
    try std.testing.expectEqual(@as(usize, 2), clusters.len);
    try std.testing.expect(std.mem.eql(u32, clusters[0], &[_]u32{ 0x65, 0x0301 }));
    try std.testing.expect(std.mem.eql(u32, clusters[1], &[_]u32{0x61}));
}

test "an emoji sequence is one cluster and a flag pair another" {
    const allocator = std.testing.allocator;

    const zwj = try grapheme.graphemeClusters(
        allocator,
        &[_]u32{ 0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467 },
    );
    defer {
        for (zwj) |cluster| allocator.free(cluster);
        allocator.free(zwj);
    }
    try std.testing.expectEqual(@as(usize, 1), zwj.len);

    const flags = try grapheme.graphemeClusters(
        allocator,
        &[_]u32{ 0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8 },
    );
    defer {
        for (flags) |cluster| allocator.free(cluster);
        allocator.free(flags);
    }
    try std.testing.expectEqual(@as(usize, 2), flags.len);
}

test "an empty sequence carries one boundary and no cluster" {
    const allocator = std.testing.allocator;

    const breaks = try grapheme.graphemeBreaks(allocator, &[_]u32{});
    defer allocator.free(breaks);
    try std.testing.expectEqual(@as(usize, 1), breaks.len);
    try std.testing.expectEqual(true, breaks[0]);

    const clusters = try grapheme.graphemeClusters(allocator, &[_]u32{});
    defer allocator.free(clusters);
    try std.testing.expectEqual(@as(usize, 0), clusters.len);
}

test "the properties the rules read" {
    try std.testing.expectEqual(Gcb.cr, grapheme.graphemeClusterBreak(0x000D));
    try std.testing.expectEqual(Gcb.lf, grapheme.graphemeClusterBreak(0x000A));
    try std.testing.expectEqual(Gcb.extend, grapheme.graphemeClusterBreak(0x0301));
    try std.testing.expectEqual(Gcb.zwj, grapheme.graphemeClusterBreak(0x200D));
    try std.testing.expectEqual(
        Gcb.regional_indicator,
        grapheme.graphemeClusterBreak(0x1F1EF),
    );
    try std.testing.expectEqual(
        Gcb.spacing_mark,
        grapheme.graphemeClusterBreak(0x093E),
    );
    try std.testing.expectEqual(Gcb.l, grapheme.graphemeClusterBreak(0x1100));
    // A code point no range covers takes the @missing Other default.
    try std.testing.expectEqual(Gcb.other, grapheme.graphemeClusterBreak(0x0061));

    // GB9c reads Indic_Conjunct_Break: U+094D DEVANAGARI SIGN VIRAMA is the
    // Linker and U+0915 DEVANAGARI LETTER KA a Consonant.
    try std.testing.expectEqual(Incb.linker, grapheme.indicConjunctBreak(0x094D));
    try std.testing.expectEqual(
        Incb.consonant,
        grapheme.indicConjunctBreak(0x0915),
    );
    try std.testing.expectEqual(Incb.extend, grapheme.indicConjunctBreak(0x0300));
    try std.testing.expectEqual(Incb.none, grapheme.indicConjunctBreak(0x0061));
}

test "Extended_Pictographic comes from the line breaker's table" {
    // GB11 and LB30b read the one table in line_break_data.zig.
    try std.testing.expect(grapheme.isExtendedPictographic(0x1F466));
    try std.testing.expect(!grapheme.isExtendedPictographic(0x0061));
}
