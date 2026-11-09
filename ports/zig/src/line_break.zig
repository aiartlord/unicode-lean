//! UAX #14 default line breaking.
//!
//! A port of the Lean algorithm `Unicode.Segmentation.LineBreak.lineBreaks`,
//! whose `lineBreaks_length` theorem fixes the output shape: one
//! break-opportunity flag per boundary position. The rule order, rule bodies,
//! and snapshot fields below mirror that reference -- LB2 through LB31 in
//! UAX #14 R7's canonical order, first match winning, the trailing LB31
//! breaking every otherwise-unmatched pair.
//!
//! Where a line may break is a property of a sequence rather than of a code
//! point, so the entry point returns a flag per boundary instead of a predicate
//! over code points. A sequence of n code points yields n + 1 flags: entry 0 is
//! false, since LB2 forbids a break at the start of text, and entry n is true
//! per LB3, which requires one at the end.
//!
//! Three mechanisms carry the context the rules read:
//!
//! * LB1 is applied at lookup time by `resolvedClass`, which folds the
//!   tailorable AI, CJ, SA, SG and XX into the algorithm's working alphabet. SA
//!   needs General_Category to choose between CM and AL.
//! * LB9 -- treat X CM* / X ZWJ* as X -- is realised through `Snapshot`, whose
//!   fields hold the most recent class that was not CM or ZWJ. LB10, treating a
//!   leftover CM or ZWJ as AL, is the fallback taken when no such class exists.
//! * The rules naming a third character -- LB15b, LB15c, the LB25 bracket and
//!   the fourth LB28a sub-rule -- read the slice beginning at the position
//!   being decided.
//!
//! Two departures from the Lean. Its positional reads are `lits[i]!` and
//! `cps[i]!`, panicking accessors; here every read is bounded by the slice
//! length the caller already holds, so no access can leave the sequence. And
//! its `spSinceNoSp` snapshot field is written by its fold and read by no rule,
//! so this port omits it.
//!
//! Where the Lean carries an optional neighbour, this module carries a Zig
//! optional, so an absent neighbour is unrepresentable as a present one.
//!
//! Line_Break, General_Category and Extended_Pictographic come from
//! `line_break_data.zig`; East_Asian_Width, which LB19a, LB25 and LB30 read,
//! comes from the port's existing `east_asian_width_data.zig` rather than a
//! second copy of the same table. So this module takes code points and needs no
//! data directory.

const std = @import("std");

const data = @import("line_break_data.zig");
const eaw = @import("east_asian_width_data.zig");
const range_lookup = @import("range_lookup.zig");

pub const Lb = data.Lb;
pub const Gc = data.Gc;
pub const Width = eaw.Width;

/// How many data rows the pinned corpus carries, counted from the canonical
/// LineBreakTest.txt at generation. The corpus gate asserts the rows it reads
/// from the vendored copy against this.
pub const published_row_count = data.published_row_count;

/// One character as the algorithm reads it: its code point and its
/// LB1-resolved class.
pub const Classified = struct {
    cp: u32,
    class: Lb,
};

// ── property lookups ────────────────────────────────────────────────────────

const lookup = range_lookup.lookup;

/// The raw Line_Break class of `cp`, before LB1. A code point no range covers
/// is `.xx`, the default LineBreak.txt's own @missing header declares.
pub fn rawClass(cp: u32) Lb {
    return lookup(data.LbRange, Lb, &data.line_break, cp) orelse .xx;
}

/// The General_Category of `cp`, `.cn` when no range covers it -- the default
/// UnicodeData.txt declares for an unassigned code point.
pub fn generalCategory(cp: u32) Gc {
    return lookup(data.GcRange, Gc, &data.general_category, cp) orelse .cn;
}

/// The East_Asian_Width of `cp`, `.n` when the file omits it. The source file's
/// @missing line declares N over the whole code point space, so a miss is `.n`
/// by declaration rather than by fallback.
pub fn eastAsianWidth(cp: u32) Width {
    return lookup(eaw.Range, Width, &eaw.explicit, cp) orelse .n;
}

/// Whether `cp` has the Extended_Pictographic property, which LB30b reads.
pub fn isExtendedPictographic(cp: u32) bool {
    const table = &data.extended_pictographic;
    var lo: usize = 0;
    var hi: usize = table.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const range = table[mid];
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

// ── LB1, the tailoring applied at lookup ────────────────────────────────────

/// The Line_Break class `cp` carries once LB1 has tailored it.
///
/// AI, SG and XX resolve to AL; CJ to NS; SA to CM when the code point is a
/// non-spacing or spacing combining mark and to AL otherwise. Every other class
/// is already in the working alphabet.
pub fn resolvedClass(cp: u32) Lb {
    const raw = rawClass(cp);
    return switch (raw) {
        .ai, .sg, .xx => .al,
        .cj => .ns,
        // LB1 reads only the two combining-mark categories here; an enclosing
        // mark is not among them.
        .sa => switch (generalCategory(cp)) {
            .mn, .mc => .cm,
            else => .al,
        },
        else => raw,
    };
}

// ── class sets the rules name ───────────────────────────────────────────────

/// Whether LB9 absorbs this class into the character before it.
fn isCmZwj(class: Lb) bool {
    return class == .cm or class == .zwj;
}

/// Whether a preceding class blocks LB9's absorption, so a following CM or ZWJ
/// stands on its own and LB10 reads it as AL.
fn blocksAbsorb(class: Lb) bool {
    return switch (class) {
        .bk, .cr, .lf, .nl, .sp, .zw => true,
        else => false,
    };
}

/// Whether the class is QU and the code point is initial punctuation, the
/// refinement LB15a reads.
fn isPiQuote(cp: u32, class: Lb) bool {
    return class == .qu and generalCategory(cp) == .pi;
}

/// Whether the class is QU and the code point is final punctuation, the
/// refinement LB15b reads.
fn isPfQuote(cp: u32, class: Lb) bool {
    return class == .qu and generalCategory(cp) == .pf;
}

/// U+2010 HYPHEN, which LB20a and LB21a name explicitly because UCD 17.0 moved
/// it from class HY to class HH.
const hyphen_u2010: u32 = 0x2010;

/// U+25CC DOTTED CIRCLE, which LB28a reads as a stand-in cluster base.
const dotted_circle: u32 = 0x25CC;

/// Whether `cp` is East_Asian_Width F, W or H, the set LB25 and LB30 read.
fn isEastAsianFullWide(cp: u32) bool {
    return switch (eastAsianWidth(cp)) {
        .f, .w, .h => true,
        else => false,
    };
}

/// Whether `cp` counts as East Asian for LB19a's tailoring, which treats
/// Ambiguous as East Asian alongside Fullwidth, Wide and Halfwidth. Wider than
/// `isEastAsianFullWide`.
fn isEastAsianOrAmbiguous(cp: u32) bool {
    return switch (eastAsianWidth(cp)) {
        .f, .w, .h, .a => true,
        else => false,
    };
}

/// Whether the effective class is present and among `classes`.
fn effIn(effective: ?Lb, classes: []const Lb) bool {
    const value = effective orelse return false;
    for (classes) |class| {
        if (value == class) return true;
    }
    return false;
}

// ── the left-hand context a boundary decision reads ─────────────────────────

/// The classes and code points of the most recent characters LB9 did not
/// absorb, plus the running counters the rules keep. Mirrors the Lean
/// `EffSnapshot`.
pub const Snapshot = struct {
    /// Class of the most recent character that was not CM or ZWJ.
    eff_prev: ?Lb = null,
    /// Its code point -- LB20a, LB21a and LB28a name U+2010 and U+25CC.
    eff_prev_cp: ?u32 = null,
    /// Class of the most recent character that was not CM, ZWJ or SP.
    eff_prev_no_sp: ?Lb = null,
    /// Class of the second most recent such character.
    eff_prev_prev: ?Lb = null,
    /// Its code point.
    eff_prev_prev_cp: ?u32 = null,
    /// Whether an LB15a initial-punctuation quote window is open.
    in_pi_quote_window: bool = false,
    /// Length of the current regional-indicator run, for LB30a.
    ri_run: u32 = 0,
    /// Whether an LB25 numeric chain is open.
    in_nu_chain: bool = false,
};

/// The class a CM or ZWJ takes from what it attaches to under LB9, or AL under
/// LB10 when nothing absorbs it.
fn effectiveClass(class: Lb, eff_prev: ?Lb) Lb {
    if (!isCmZwj(class)) return class;
    const previous = eff_prev orelse return .al;
    return if (blocksAbsorb(previous)) .al else class;
}

/// Fold one character into the context. A character LB9 absorbs leaves the
/// context untouched, which is what makes the neighbours it records effective
/// rather than literal. Mirrors the Lean `buildSnapshots` step.
pub fn advance(s: Snapshot, cp: u32, class: Lb) Snapshot {
    const effective = effectiveClass(class, s.eff_prev);
    if (isCmZwj(effective)) return s;

    // LB15a opens its window only where an initial-punctuation quote stands
    // outside a word; a space carries an open window forward.
    const left_context_opens = s.eff_prev == null or
        effIn(s.eff_prev, &[_]Lb{ .bk, .cr, .lf, .nl, .op, .qu, .gl, .sp, .zw });
    const in_pi_quote_window = if (isPiQuote(cp, effective) and left_context_opens)
        true
    else if (effective == .sp)
        s.in_pi_quote_window
    else
        false;

    const in_nu_chain = if (effective == .nu)
        true
    else if (s.in_nu_chain)
        switch (effective) {
            .sy, .is, .cl, .cp, .pr => true,
            else => false,
        }
    else
        false;

    return .{
        .eff_prev = effective,
        .eff_prev_cp = cp,
        .eff_prev_no_sp = if (effective == .sp) s.eff_prev_no_sp else effective,
        .eff_prev_prev = s.eff_prev,
        .eff_prev_prev_cp = s.eff_prev_cp,
        .in_pi_quote_window = in_pi_quote_window,
        .ri_run = if (effective == .ri) s.ri_run + 1 else 0,
        .in_nu_chain = in_nu_chain,
    };
}

// ── lookahead ───────────────────────────────────────────────────────────────

/// The class at the head of a suffix, or null past its end.
fn headClass(ahead: []const Classified) ?Lb {
    if (ahead.len == 0) return null;
    return ahead[0].class;
}

/// LB15b holds when the final quote is last, or when what follows it cannot
/// itself open a line.
fn finalQuoteCloses(ahead: []const Classified) bool {
    if (ahead.len == 0) return true;
    return switch (ahead[0].class) {
        .sp, .gl, .wj, .cl, .qu, .cp, .ex, .is, .sy, .bk, .cr, .lf, .nl, .zw => true,
        else => false,
    };
}

/// The fourth LB28a sub-rule looks past any CM or ZWJ the cluster absorbs, so
/// the character it tests is the first significant one ahead.
fn nextSignificantIsVf(ahead: []const Classified) bool {
    for (ahead) |entry| {
        if (!isCmZwj(entry.class)) return entry.class == .vf;
    }
    return false;
}

// ── the rule cascade ────────────────────────────────────────────────────────

/// Whether a line break opportunity falls immediately before the head of
/// `suffix`, given the character before it and the context accumulated from
/// everything earlier.
///
/// `suffix` begins at the position being decided, so its head is the current
/// character and its tail supplies every lookahead the rules take.
pub fn breaksBefore(prev: Classified, suffix: []const Classified, s: Snapshot) bool {
    if (suffix.len == 0) return true; // LB3
    const prev_cp = prev.cp;
    const prev_class = prev.class;
    const current_cp = suffix[0].cp;
    const current_class = suffix[0].class;
    const ahead = suffix[1..];

    const eff = effectiveClass(current_class, s.eff_prev);
    const left: ?Lb = if (isCmZwj(prev_class)) s.eff_prev else prev_class;

    // LB4
    if (prev_class == .bk) return true;
    // LB5
    if (prev_class == .cr and current_class == .lf) return false;
    if (prev_class == .cr or prev_class == .lf or prev_class == .nl) return true;
    // LB6
    switch (current_class) {
        .bk, .cr, .lf, .nl => return false,
        else => {},
    }
    // LB7
    if (current_class == .sp or current_class == .zw) return false;
    // LB8
    if (s.eff_prev_no_sp == .zw) return true;
    // LB8a
    if (prev_class == .zwj) return false;
    // LB9
    if (isCmZwj(current_class)) {
        if (s.eff_prev) |previous| {
            if (!blocksAbsorb(previous)) return false;
        }
    }
    // LB11
    if (eff == .wj or effIn(left, &[_]Lb{.wj})) return false;
    // LB12
    if (effIn(left, &[_]Lb{.gl})) return false;
    // LB12a
    if (eff == .gl and !effIn(left, &[_]Lb{ .sp, .ba, .hy, .hh })) return false;
    // LB15c, which UCD 17.0 orders above LB13 and LB15d: break before an IS
    // that opens a number and follows a space, as in "equals .35".
    if (prev_class == .sp and eff == .is and headClass(ahead) == .nu) return true;
    // LB13
    switch (eff) {
        .cl, .cp, .ex, .is, .sy => return false,
        else => {},
    }
    // LB14
    if (s.eff_prev_no_sp == .op) return false;
    // LB15a
    if (s.in_pi_quote_window) return false;
    // LB15b
    if (isPfQuote(current_cp, eff) and finalQuoteCloses(ahead)) return false;
    // LB15d
    if (eff == .is) return false;
    // LB16
    if (eff == .ns and (s.eff_prev_no_sp == .cl or s.eff_prev_no_sp == .cp)) return false;
    // LB17
    if (eff == .b2 and s.eff_prev_no_sp == .b2) return false;
    // LB18
    if (prev_class == .sp) return true;
    // LB19 and LB19a. A quote neither breaks before nor after, except on the
    // OUTER side of an initial or final punctuation quote standing in
    // contiguous East Asian content -- there the default break applies, so a
    // line may break at the quote boundary. The inner side stays unbroken,
    // being the boundary inside the quote's own scope.
    if (eff == .qu) {
        const next_east_asian = ahead.len > 0 and isEastAsianOrAmbiguous(ahead[0].cp);
        const open_quote_in_east_asian = isPiQuote(current_cp, eff) and
            isEastAsianOrAmbiguous(prev_cp) and
            isEastAsianOrAmbiguous(current_cp) and next_east_asian;
        if (!open_quote_in_east_asian) return false;
    }
    if (effIn(left, &[_]Lb{.qu})) {
        var close_quote_in_east_asian = false;
        if (s.eff_prev_cp) |quote_cp| {
            if (s.eff_prev_prev_cp) |before_quote| {
                close_quote_in_east_asian = isPfQuote(quote_cp, .qu) and
                    isEastAsianOrAmbiguous(before_quote) and
                    isEastAsianOrAmbiguous(quote_cp) and
                    isEastAsianOrAmbiguous(current_cp);
            }
        }
        if (!close_quote_in_east_asian) return false;
    }
    // LB20
    if (eff == .cb or effIn(left, &[_]Lb{.cb})) return true;

    // LB20.1 and LB20a both require the hyphen's own left context to be outside
    // a word, the same start-of-segment set.
    const hyphen_left_context_opens = s.eff_prev_prev == null or
        effIn(s.eff_prev_prev, &[_]Lb{ .bk, .cr, .lf, .nl, .sp, .zw, .cb, .gl });
    // LB20.1, UCD 17.0: an explicit hyphen joins a following letter only where
    // its own left context is outside a word. A mid-word HH falls through to
    // LB31.
    if (effIn(left, &[_]Lb{.hh}) and (eff == .al or eff == .hl) and
        hyphen_left_context_opens) return false;
    // LB20a, with UCD 17.0's right side broadened to HL beside AL.
    if (eff == .al or eff == .hl) {
        const hyphen_carries_left = s.eff_prev == .hy or s.eff_prev == .hh or
            s.eff_prev_cp == hyphen_u2010;
        if (hyphen_carries_left and hyphen_left_context_opens) return false;
    }
    // LB21
    switch (eff) {
        .ba, .hy, .hh, .ns => return false,
        else => {},
    }
    if (effIn(left, &[_]Lb{.bb})) return false;
    // LB21a: an HL letter followed by an HY hyphen or U+2010 glues to what comes
    // next unless that is itself HL. A BA does not glue here.
    if (s.eff_prev_prev == .hl and eff != .hl and
        (s.eff_prev == .hy or s.eff_prev_cp == hyphen_u2010)) return false;
    // LB21b
    if (eff == .hl and effIn(left, &[_]Lb{.sy})) return false;
    // LB22
    if (eff == .in) return false;
    // LB23
    if (eff == .nu and effIn(left, &[_]Lb{ .al, .hl })) return false;
    if ((eff == .al or eff == .hl) and effIn(left, &[_]Lb{.nu})) return false;
    // LB23a
    if ((eff == .id or eff == .eb or eff == .em) and effIn(left, &[_]Lb{.pr})) return false;
    if (eff == .po and effIn(left, &[_]Lb{ .id, .eb, .em })) return false;
    // LB24
    if ((eff == .al or eff == .hl) and effIn(left, &[_]Lb{ .pr, .po })) return false;
    if ((eff == .pr or eff == .po) and effIn(left, &[_]Lb{ .al, .hl })) return false;
    // LB25, closing an open numeric chain with a CL or CP suffix and a following
    // PO or PR.
    if (s.in_nu_chain) {
        switch (eff) {
            .cl, .cp, .po, .pr => return false,
            else => {},
        }
    }
    // LB25, opening a chain
    if (eff == .nu and effIn(left, &[_]Lb{ .pr, .po, .hy, .op, .is })) return false;
    // LB25, chain body
    if (eff == .nu and effIn(left, &[_]Lb{.nu})) return false;
    // LB25, extending an open chain across a SY
    if (eff == .nu and effIn(left, &[_]Lb{.sy}) and s.in_nu_chain) return false;
    // LB25, bracketed prefix: a PR joins an OP only when the OP itself opens a
    // number, and neither is East Asian Fullwidth, Wide or Halfwidth.
    if (eff == .op and effIn(left, &[_]Lb{.pr}) and
        !isEastAsianFullWide(current_cp) and headClass(ahead) == .nu)
    {
        if (s.eff_prev_cp) |previous| {
            if (!isEastAsianFullWide(previous)) return false;
        }
    }
    // LB26
    if (effIn(left, &[_]Lb{.jl}) and
        (eff == .jl or eff == .jv or eff == .h2 or eff == .h3)) return false;
    if (effIn(left, &[_]Lb{ .jv, .h2 }) and (eff == .jv or eff == .jt)) return false;
    if (effIn(left, &[_]Lb{ .jt, .h3 }) and eff == .jt) return false;
    // LB27
    if (effIn(left, &[_]Lb{ .jl, .jv, .jt, .h2, .h3 }) and
        (eff == .in or eff == .po)) return false;
    if (effIn(left, &[_]Lb{.pr}) and
        (eff == .jl or eff == .jv or eff == .jt or eff == .h2 or eff == .h3)) return false;
    // LB28
    if ((eff == .al or eff == .hl) and effIn(left, &[_]Lb{ .al, .hl })) return false;

    // LB28a, the aksara cluster rules. U+25CC DOTTED CIRCLE carries class AL and
    // stands in for a cluster base throughout.
    const left_is_aksara_base = effIn(left, &[_]Lb{ .ak, .as }) or
        (s.eff_prev_cp == dotted_circle and s.eff_prev == .al);
    if (effIn(left, &[_]Lb{.ap}) and
        (eff == .ak or eff == .as or current_cp == dotted_circle)) return false;
    if (left_is_aksara_base and (eff == .vf or eff == .vi)) return false;
    if (s.eff_prev == .vi and
        (s.eff_prev_prev == .ak or s.eff_prev_prev == .as or
            s.eff_prev_prev_cp == dotted_circle) and
        (eff == .ak or current_cp == dotted_circle)) return false;
    if (left_is_aksara_base and
        (eff == .ak or eff == .as or current_cp == dotted_circle) and
        nextSignificantIsVf(ahead)) return false;
    // LB29
    if ((eff == .al or eff == .hl) and effIn(left, &[_]Lb{.is})) return false;
    // LB30, where the bracket must not be East Asian Fullwidth, Wide or
    // Halfwidth.
    if (eff == .op and effIn(left, &[_]Lb{ .al, .hl, .nu }) and
        !isEastAsianFullWide(current_cp)) return false;
    if ((eff == .al or eff == .hl or eff == .nu) and effIn(left, &[_]Lb{.cp}) and
        !isEastAsianFullWide(prev_cp)) return false;
    // LB30a
    if (eff == .ri and s.ri_run % 2 == 1) return false;
    // LB30b
    if (eff == .em and effIn(left, &[_]Lb{.eb})) return false;
    if (eff == .em) {
        if (s.eff_prev_cp) |previous| {
            if (isExtendedPictographic(previous) and generalCategory(previous) == .cn) {
                return false;
            }
        }
    }
    // LB31
    return true;
}

// ── entry points ────────────────────────────────────────────────────────────

/// One break-opportunity flag per boundary of the code point sequence, so a
/// sequence of n code points yields n + 1 flags -- the shape the Lean
/// `lineBreaks_length` theorem fixes. The caller owns the returned slice.
///
/// Entry 0 is false -- LB2 forbids a break at the start of text -- and entry n
/// is true per LB3, which requires one at the end.
pub fn lineBreaks(allocator: std.mem.Allocator, cps: []const u32) std.mem.Allocator.Error![]bool {
    const pairs = try allocator.alloc(Classified, cps.len);
    defer allocator.free(pairs);
    for (cps, 0..) |cp, index| {
        pairs[index] = .{ .cp = cp, .class = resolvedClass(cp) };
    }

    const out = try allocator.alloc(bool, cps.len + 1);
    var s = Snapshot{};
    for (0..pairs.len) |index| {
        out[index] = if (index == 0)
            false // LB2
        else
            breaksBefore(pairs[index - 1], pairs[index..], s);
        s = advance(s, pairs[index].cp, pairs[index].class);
    }
    out[cps.len] = true; // LB3
    return out;
}

/// The code point sequence split at every break opportunity -- the runs a
/// renderer may place on separate lines. The caller owns the returned slices
/// and the slice holding them.
pub fn lineRuns(allocator: std.mem.Allocator, cps: []const u32) std.mem.Allocator.Error![][]u32 {
    const breaks = try lineBreaks(allocator, cps);
    defer allocator.free(breaks);

    var runs: std.ArrayList([]u32) = .empty;
    errdefer {
        for (runs.items) |run| allocator.free(run);
        runs.deinit(allocator);
    }
    var start: usize = 0;
    for (0..cps.len) |index| {
        if (breaks[index + 1]) {
            const run = try allocator.dupe(u32, cps[start .. index + 1]);
            errdefer allocator.free(run);
            try runs.append(allocator, run);
            start = index + 1;
        }
    }
    return runs.toOwnedSlice(allocator);
}
