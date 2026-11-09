//! Lookup over a generated property range table.
//!
//! Every segmentation property in this port is emitted as the same shape -- an
//! array of `{ start, end, class }` sorted by start -- so the UAX #14 line
//! breaker and the UAX #29 cluster breaker read their tables through the one
//! search here.

/// The class of the one range covering `cp`, or null when no range does.
///
/// Each table is sorted by start and its ranges are disjoint, so the covering
/// range is unique and a binary search finds it. That is what makes the search
/// agree with the linear first-match of the Lean reference: with one covering
/// range, whichever the search finds is the one a scan in file order would have
/// found first.
pub fn lookup(
    comptime Range: type,
    comptime Class: type,
    table: []const Range,
    cp: u32,
) ?Class {
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
            return range.class;
        }
    }
    return null;
}
