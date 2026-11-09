//! The reader the segmentation suites share.
//!
//! Both published corpora -- LineBreakTest.txt and GraphemeBreakTest.txt --
//! write the same alternating boundary markers and hex code points, so the
//! reading is here and each suite passes the path its build baked in.

const std = @import("std");

/// The markers the published break corpora write at each boundary, as raw
/// UTF-8 bytes so the parse is independent of the source file's own encoding:
///   DIVIDE (U+00F7 "÷") = 0xC3 0xB7  -> break
///   MULTIPLY (U+00D7 "×") = 0xC3 0x97 -> no break
pub const break_marker = "\xC3\xB7";
pub const no_break_marker = "\xC3\x97";

/// One published case: its line in the file, its code points and its expected
/// boundary mask.
pub const Row = struct {
    line: usize,
    codepoints: []u32,
    expected: []bool,
};

/// Release every row and the slice holding them.
pub fn freeRows(allocator: std.mem.Allocator, rows: []Row) void {
    for (rows) |row| {
        allocator.free(row.codepoints);
        allocator.free(row.expected);
    }
    allocator.free(rows);
}

/// Parse one data line into its code points and expected mask.
///
/// A line is a sequence of alternating boundary markers and hex code points,
/// beginning and ending with a marker: e.g. "× 0061 ÷ 0062 ÷". The markers form
/// the expected mask (÷ -> true, × -> false) of length codepoints.len + 1; the
/// hex tokens are the code points.
pub fn parseRow(
    allocator: std.mem.Allocator,
    body: []const u8,
) !struct { codepoints: []u32, expected: []bool } {
    var codepoints: std.ArrayList(u32) = .empty;
    errdefer codepoints.deinit(allocator);
    var expected: std.ArrayList(bool) = .empty;
    errdefer expected.deinit(allocator);

    var tokens = std.mem.tokenizeAny(u8, body, " \t\r");
    while (tokens.next()) |token| {
        if (std.mem.eql(u8, token, break_marker)) {
            try expected.append(allocator, true);
        } else if (std.mem.eql(u8, token, no_break_marker)) {
            try expected.append(allocator, false);
        } else {
            const cp = try std.fmt.parseInt(u32, token, 16);
            try codepoints.append(allocator, cp);
        }
    }

    return .{
        .codepoints = try codepoints.toOwnedSlice(allocator),
        .expected = try expected.toOwnedSlice(allocator),
    };
}

/// Every data row of a vendored corpus. Read at run time: a corpus is up to
/// well over a megabyte, and the port already takes that route for its other
/// large fixture rather than making the compiler materialise it whole.
pub fn readCorpus(allocator: std.mem.Allocator, path: []const u8) ![]Row {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        path,
        allocator,
        .limited(16 * 1024 * 1024),
    );
    defer allocator.free(bytes);

    var rows: std.ArrayList(Row) = .empty;
    errdefer {
        for (rows.items) |row| {
            allocator.free(row.codepoints);
            allocator.free(row.expected);
        }
        rows.deinit(allocator);
    }

    var lines = std.mem.splitScalar(u8, bytes, '\n');
    var number: usize = 0;
    while (lines.next()) |raw| {
        number += 1;
        const without_comment = if (std.mem.indexOfScalar(u8, raw, '#')) |idx|
            raw[0..idx]
        else
            raw;
        const body = std.mem.trim(u8, without_comment, " \t\r");
        if (body.len == 0) continue;

        const parsed = try parseRow(allocator, body);
        try rows.append(allocator, .{
            .line = number,
            .codepoints = parsed.codepoints,
            .expected = parsed.expected,
        });
    }
    return rows.toOwnedSlice(allocator);
}

/// How many rows carry a flag count that is not one per boundary. Without this
/// a corpus could not judge anything.
pub fn raggedRows(rows: []const Row) usize {
    var ragged: usize = 0;
    for (rows) |row| {
        if (row.expected.len != row.codepoints.len + 1) ragged += 1;
    }
    return ragged;
}
