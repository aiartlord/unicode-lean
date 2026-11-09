const std = @import("std");
const line_break_options = @import("line_break_options");
const line_break = @import("line_break");
const vector_cases = @import("vector_cases.zig");
const corpus = @import("segmentation_corpus.zig");

// UAX #14 default line breaking.
//
// Validates the port's line breaker against the official Unicode
// LineBreakTest.txt (bundled under testdata/ so the port stays
// self-contained), plus targeted vectors pinning the individual rules and the
// output shape the Lean lineBreaks_length theorem fixes. Every break
// opportunity (÷) and non-break (×) in the official file must be reproduced
// exactly.
//
// The corpus reader is shared with the grapheme suite: both published corpora
// write the same alternating markers and code points.

const Lb = line_break.Lb;

fn readCorpus(allocator: std.mem.Allocator) ![]corpus.Row {
    return corpus.readCorpus(allocator, line_break_options.corpus_path);
}

// What the corpus must be before it can judge anything: every row carries one
// more flag than code points, and the vendored copy carries every row the
// canonical file did. Without the second check a row lost between the two would
// shrink the denominator instead of failing.
test "the line-break corpus is well formed" {
    const allocator = std.testing.allocator;
    const rows = try readCorpus(allocator);
    defer corpus.freeRows(allocator, rows);

    try std.testing.expectEqual(@as(usize, 0), corpus.raggedRows(rows));
    try std.testing.expectEqual(line_break.published_row_count, rows.len);
}

// Hand-written vectors cannot establish a segmentation algorithm: its rules
// read context on both sides of a boundary and the answer depends on state
// carried from earlier in the sequence, so a wrong rule survives any vector a
// person would pick. Agreeing with all of them is also the evidence the two
// departures declared at line_break.zig's head needed -- slice-bounded reads in
// place of the Lean's positional lits[i]!, and dropping its write-only
// spSinceNoSp snapshot field.
test "the line breaker agrees with every published row" {
    const allocator = std.testing.allocator;
    const rows = try readCorpus(allocator);
    defer corpus.freeRows(allocator, rows);

    var disagreements: usize = 0;
    var first_line: usize = 0;
    for (rows) |row| {
        const produced = try line_break.lineBreaks(allocator, row.codepoints);
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

// One case per UAX #14 rule, the same bytes every port replays, so no port
// carries a weaker set of rule checks than another. The published corpus above
// is the authority; these name which rule each boundary exercises.
test "the shared line-break vectors replay" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqualStrings(
        "uax14-line-break",
        vector_cases.line_break_algorithm,
    );
    try std.testing.expect(vector_cases.line_break_cases.len > 0);
    for (vector_cases.line_break_cases) |entry| {
        const produced = try line_break.lineBreaks(allocator, entry.input);
        defer allocator.free(produced);
        if (!std.mem.eql(bool, produced, entry.breaks)) {
            // A red is only actionable if it says which rule disagreed.
            std.debug.print("{s}: {s}\n", .{ entry.rule, entry.name });
        }
        try std.testing.expect(std.mem.eql(bool, produced, entry.breaks));
    }
}

// Both gates count the same published file, so they cannot drift apart.
test "the corpus and the vectors agree on the row count" {
    try std.testing.expectEqual(
        line_break.published_row_count,
        vector_cases.line_break_published_row_count,
    );
}

test "the output carries one flag per boundary" {
    // The Lean lineBreaks_length theorem: cps.len + 1 flags.
    const allocator = std.testing.allocator;
    for (0..8) |length| {
        const cps = try allocator.alloc(u32, length);
        defer allocator.free(cps);
        for (0..length) |index| cps[index] = @intCast(0x61 + index);
        const breaks = try line_break.lineBreaks(allocator, cps);
        defer allocator.free(breaks);
        try std.testing.expectEqual(length + 1, breaks.len);
    }
}

/// Whether the breaker produces `expected` for `cps`.
fn expectMask(cps: []const u32, expected: []const bool) !void {
    const allocator = std.testing.allocator;
    const produced = try line_break.lineBreaks(allocator, cps);
    defer allocator.free(produced);
    try std.testing.expect(std.mem.eql(bool, produced, expected));
}

test "start of text never breaks and end always does" {
    const allocator = std.testing.allocator;
    const breaks = try line_break.lineBreaks(allocator, &[_]u32{ 0x61, 0x62 });
    defer allocator.free(breaks);
    try std.testing.expectEqual(false, breaks[0]); // LB2
    try std.testing.expectEqual(true, breaks[breaks.len - 1]); // LB3
}

test "a word is one run" {
    // LB28 keeps letters together.
    try expectMask(&[_]u32{ 0x61, 0x62 }, &[_]bool{ false, false, true });
}

test "a mandatory break character breaks after itself" {
    // LB4: BK divides. U+000C FORM FEED is class BK.
    try expectMask(
        &[_]u32{ 0x61, 0x000C, 0x62 },
        &[_]bool{ false, false, true, true },
    );
}

test "carriage return line feed is not split" {
    // LB5: CR times LF, then a mandatory break after the pair.
    try expectMask(
        &[_]u32{ 0x0D, 0x0A, 0x61 },
        &[_]bool{ false, false, true, true },
    );
}

test "a combining mark takes the class of its base" {
    // LB9: X CM behaves as X, so no break falls inside the pair.
    try expectMask(&[_]u32{ 0x61, 0x0301 }, &[_]bool{ false, false, true });
}

test "a word joiner glues both sides" {
    // LB11: before WJ and after WJ.
    try expectMask(
        &[_]u32{ 0x61, 0x2060, 0x62 },
        &[_]bool{ false, false, false, true },
    );
}

test "a space before a number opening period breaks" {
    // LB15c: SP divides IS NU -- "a .35" breaks before the period.
    try expectMask(
        &[_]u32{ 0x61, 0x20, 0x2E, 0x33, 0x35 },
        &[_]bool{ false, false, true, false, false, true },
    );
}

test "regional indicators pair off" {
    // LB30a: an even-length RI run takes no break inside a pair, and a second
    // pair may start a new line.
    try expectMask(
        &[_]u32{ 0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8 },
        &[_]bool{ false, false, true, false, true },
    );
}

test "an emoji modifier stays on its base" {
    // LB30b: EB times EM.
    try expectMask(&[_]u32{ 0x1F466, 0x1F3FB }, &[_]bool{ false, false, true });
}

test "a space opens the next run" {
    // LB18 breaks after a space, so the space stays with the word before it.
    const allocator = std.testing.allocator;
    const runs = try line_break.lineRuns(allocator, &[_]u32{ 0x61, 0x20, 0x62 });
    defer {
        for (runs) |run| allocator.free(run);
        allocator.free(runs);
    }
    try std.testing.expectEqual(@as(usize, 2), runs.len);
    try std.testing.expect(std.mem.eql(u32, runs[0], &[_]u32{ 0x61, 0x20 }));
    try std.testing.expect(std.mem.eql(u32, runs[1], &[_]u32{0x62}));
}

test "a numeric chain holds together" {
    // LB25: "1,000" is one run across the SY separator.
    const allocator = std.testing.allocator;
    const runs = try line_break.lineRuns(
        allocator,
        &[_]u32{ 0x31, 0x2C, 0x30, 0x30, 0x30 },
    );
    defer {
        for (runs) |run| allocator.free(run);
        allocator.free(runs);
    }
    try std.testing.expectEqual(@as(usize, 1), runs.len);
}

test "LB1 resolves the tailorable classes" {
    // U+3041 HIRAGANA LETTER SMALL A is CJ, resolving to NS.
    try std.testing.expectEqual(Lb.cj, line_break.rawClass(0x3041));
    try std.testing.expectEqual(Lb.ns, line_break.resolvedClass(0x3041));
    // U+00A7 SECTION SIGN is AI, resolving to AL.
    try std.testing.expectEqual(Lb.ai, line_break.rawClass(0x00A7));
    try std.testing.expectEqual(Lb.al, line_break.resolvedClass(0x00A7));
    // A surrogate code point is SG, resolving to AL.
    try std.testing.expectEqual(Lb.sg, line_break.rawClass(0xD800));
    try std.testing.expectEqual(Lb.al, line_break.resolvedClass(0xD800));
    // U+05EB lies in the Hebrew block's unassigned gap, which no range covers,
    // so it takes the @missing XX default and LB1 reads it as AL.
    try std.testing.expectEqual(Lb.xx, line_break.rawClass(0x05EB));
    try std.testing.expectEqual(Lb.al, line_break.resolvedClass(0x05EB));
}

test "LB1 resolves SA by General_Category" {
    // U+0E31 THAI CHARACTER MAI HAN-AKAT is SA with General_Category Mn, so LB1
    // reads it as CM; U+0E01 THAI CHARACTER KO KAI is SA with category Lo, so
    // LB1 reads it as AL.
    try std.testing.expectEqual(Lb.sa, line_break.rawClass(0x0E31));
    try std.testing.expectEqual(Lb.cm, line_break.resolvedClass(0x0E31));
    try std.testing.expectEqual(Lb.sa, line_break.rawClass(0x0E01));
    try std.testing.expectEqual(Lb.al, line_break.resolvedClass(0x0E01));
}

test "the East_Asian_Width table is the port's own" {
    // The line breaker reads east_asian_width_data.zig rather than a second
    // copy of the same property. U+FF21 FULLWIDTH LATIN CAPITAL LETTER A is F,
    // U+0041 is Na, and a code point the file omits is N by its @missing line.
    try std.testing.expectEqual(line_break.Width.f, line_break.eastAsianWidth(0xFF21));
    try std.testing.expectEqual(line_break.Width.na, line_break.eastAsianWidth(0x0041));
}

test "Extended_Pictographic is carried here" {
    // The one table for the property lives beside the line breaker, and GB11
    // reads it through grapheme.isExtendedPictographic.
    try std.testing.expect(line_break.isExtendedPictographic(0x1F466));
    try std.testing.expect(!line_break.isExtendedPictographic(0x0061));
}
