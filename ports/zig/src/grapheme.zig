//! UAX #29 default extended grapheme cluster segmentation.
//!
//! A port of the Lean algorithm
//! `Unicode.Segmentation.GraphemeBreak.graphemeBreaks`, whose
//! `graphemeBreaks_eq_spec` theorem relates it to the declarative UAX #29
//! GB1-GB999 specification. The state fields, rule order and transitions below
//! mirror that reference: the first matching rule wins, and the trailing GB999
//! breaks every otherwise-unmatched pair.
//!
//! Where a cluster boundary falls is a property of a sequence rather than of a
//! code point, so the entry point returns one flag per boundary position: a
//! sequence of n code points yields n + 1 flags, entry 0 the GB1 start-of-text
//! break and entry n the GB2 end-of-text break, both always true.
//!
//! Three pieces of left context carry what the rules read, each a field of
//! `State`: the previous code point's class, the GB11 emoji-pictograph window,
//! and the GB9c Indic-conjunct window, plus the regional-indicator run length
//! GB12 and GB13 count parity over. Where the Lean carries an optional previous
//! class, this module carries a Zig optional, so an absent neighbour is
//! unrepresentable as a present one.
//!
//! Grapheme_Cluster_Break and Indic_Conjunct_Break come from
//! `grapheme_data.zig`. The third property the rules read,
//! Extended_Pictographic, is the one LB30b reads, so GB11 calls
//! `line_break.isExtendedPictographic` rather than a second copy of that table.
//! So this module takes code points and needs no data directory.

const std = @import("std");

const data = @import("grapheme_data.zig");
const line_break = @import("line_break.zig");
const range_lookup = @import("range_lookup.zig");

pub const Gcb = data.Gcb;
pub const Incb = data.Incb;

/// How many data rows the pinned corpus carries, counted from the canonical
/// GraphemeBreakTest.txt at generation. The corpus gate asserts the rows it
/// reads from the vendored copy against this.
pub const published_row_count = data.published_row_count;

const lookup = range_lookup.lookup;

// ── property lookups ────────────────────────────────────────────────────────

/// The Grapheme_Cluster_Break class of `cp`, `.other` when no range covers it
/// -- the default GraphemeBreakProperty.txt's own @missing header declares.
pub fn graphemeClusterBreak(cp: u32) Gcb {
    return lookup(data.GcbRange, Gcb, &data.grapheme_cluster_break, cp) orelse .other;
}

/// The Indic_Conjunct_Break class of `cp`, `.none` when no range covers it --
/// the default DerivedCoreProperties.txt's own @missing header declares.
pub fn indicConjunctBreak(cp: u32) Incb {
    return lookup(data.IncbRange, Incb, &data.indic_conjunct_break, cp) orelse .none;
}

/// Whether `cp` has the Extended_Pictographic property, which GB11 reads. The
/// table is the one LB30b reads.
pub fn isExtendedPictographic(cp: u32) bool {
    return line_break.isExtendedPictographic(cp);
}

// ── the left-hand context a boundary decision reads ─────────────────────────

/// The GB11 window: whether the scan has just passed an Extended_Pictographic,
/// and whether a ZWJ has followed it.
pub const EpicState = enum {
    /// No relevant prefix.
    none,
    /// An Extended_Pictographic followed by zero or more Extend.
    after_ep,
    /// An Extended_Pictographic Extend* ZWJ, the prefix GB11 fires on.
    after_ep_zwj,
};

/// The GB9c window: whether the scan has passed an Indic_Conjunct_Break
/// consonant, and whether a linker has followed it.
pub const InCbState = enum {
    /// No relevant prefix.
    none,
    /// A Consonant followed by zero or more Extend, with no Linker yet.
    consonant,
    /// A Consonant (Extend | Linker)* Linker (Extend | Linker)*, the prefix
    /// GB9c fires on.
    linker,
};

/// The running scan state, mirroring the Lean `State`.
pub const State = struct {
    /// Class of the previous code point, null only before the first one is
    /// read, which is the condition GB1 tests.
    prev_class: ?Gcb = null,
    /// The GB11 window.
    epic_state: EpicState = .none,
    /// The GB9c window.
    in_cb_state: InCbState = .none,
    /// Length of the current regional-indicator run, whose parity GB12 and
    /// GB13 read.
    ri_run: u32 = 0,
};

// ── the rule cascade ────────────────────────────────────────────────────────

/// Whether a cluster boundary falls immediately before `cp`, given the running
/// state. UAX #29 GB1 through GB999 in canonical order.
pub fn breaksBefore(cp: u32, s: State) bool {
    const pc = s.prev_class orelse return true; // GB1: start of text
    const bc = graphemeClusterBreak(cp);
    const in_cb = indicConjunctBreak(cp);
    const is_ep = isExtendedPictographic(cp);

    // GB3
    if (pc == .cr and bc == .lf) return false;
    // GB4
    switch (pc) {
        .control, .cr, .lf => return true,
        else => {},
    }
    // GB5
    switch (bc) {
        .control, .cr, .lf => return true,
        else => {},
    }
    // GB6
    if (pc == .l and (bc == .l or bc == .v or bc == .lv or bc == .lvt)) return false;
    // GB7
    if ((pc == .lv or pc == .v) and (bc == .v or bc == .t)) return false;
    // GB8
    if ((pc == .lvt or pc == .t) and bc == .t) return false;
    // GB9
    if (bc == .extend or bc == .zwj) return false;
    // GB9a
    if (bc == .spacing_mark) return false;
    // GB9b
    if (pc == .prepend) return false;
    // GB9c: Consonant (Extend | Linker)* Linker (Extend | Linker)* x Consonant
    if (s.in_cb_state == .linker and in_cb == .consonant) return false;
    // GB11: ExtPict Extend* ZWJ x ExtPict
    if (s.epic_state == .after_ep_zwj and is_ep) return false;
    // GB12 / GB13: an odd-parity regional-indicator run extends
    if (bc == .regional_indicator and s.ri_run % 2 == 1) return false;
    // GB999
    return true;
}

/// The state after consuming `cp`. Mirrors the Lean `advance`, which computes
/// the update independently of the break decision so the caller records the
/// break and moves on.
pub fn advance(cp: u32, s: State) State {
    const bc = graphemeClusterBreak(cp);
    const in_cb = indicConjunctBreak(cp);
    const is_ep = isExtendedPictographic(cp);

    const epic_state: EpicState = if (is_ep)
        .after_ep
    else if (s.epic_state == .after_ep and bc == .extend)
        .after_ep
    else if (s.epic_state == .after_ep and bc == .zwj)
        .after_ep_zwj
    else
        .none;

    const in_cb_state: InCbState = if (in_cb == .consonant)
        .consonant
    else if (s.in_cb_state == .consonant and in_cb == .linker)
        .linker
    else if (s.in_cb_state == .consonant and in_cb == .extend)
        .consonant
    else if (s.in_cb_state == .linker and in_cb == .linker)
        .linker
    else if (s.in_cb_state == .linker and in_cb == .extend)
        .linker
    else
        .none;

    return .{
        .prev_class = bc,
        .epic_state = epic_state,
        .in_cb_state = in_cb_state,
        .ri_run = if (bc == .regional_indicator) s.ri_run + 1 else 0,
    };
}

// ── entry points ────────────────────────────────────────────────────────────

/// One cluster-boundary flag per boundary of the code point sequence, so a
/// sequence of n code points yields n + 1 flags. The caller owns the returned
/// slice.
///
/// Entry 0 is the GB1 start-of-text break and entry n the GB2 end-of-text
/// break, both always true.
pub fn graphemeBreaks(
    allocator: std.mem.Allocator,
    cps: []const u32,
) std.mem.Allocator.Error![]bool {
    const out = try allocator.alloc(bool, cps.len + 1);
    var s = State{};
    for (cps, 0..) |cp, index| {
        out[index] = breaksBefore(cp, s);
        s = advance(cp, s);
    }
    out[cps.len] = true; // GB2
    return out;
}

/// The code points between consecutive boundaries -- the clusters a renderer
/// treats as single user-perceived characters. The caller owns the returned
/// slices and the slice holding them.
pub fn graphemeClusters(
    allocator: std.mem.Allocator,
    cps: []const u32,
) std.mem.Allocator.Error![][]u32 {
    const breaks = try graphemeBreaks(allocator, cps);
    defer allocator.free(breaks);

    var clusters: std.ArrayList([]u32) = .empty;
    errdefer {
        for (clusters.items) |cluster| allocator.free(cluster);
        clusters.deinit(allocator);
    }
    var start: usize = 0;
    for (0..cps.len) |index| {
        if (breaks[index + 1]) {
            const cluster = try allocator.dupe(u32, cps[start .. index + 1]);
            errdefer allocator.free(cluster);
            try clusters.append(allocator, cluster);
            start = index + 1;
        }
    }
    return clusters.toOwnedSlice(allocator);
}
