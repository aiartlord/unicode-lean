// ─────────────────────────────────────────────────────────────────────────────
//                                  // segmentation // range-table
// ─────────────────────────────────────────────────────────────────────────────
//
// The one range lookup both segmentation algorithms read their generated
// property tables through.
//
// A UCD property is a list of inclusive code point ranges, each carrying a
// class. The generated tables hold each property as three parallel columns of
// primitives rather than one array of structures: an array literal of several
// thousand aggregates is a type-checking cost the compiler pays on every build,
// while a literal of `UInt32` and `UInt8` elements is laid down as static data.
//
// Every generated table is sorted by lower bound and coalesced, so the range
// covering a code point is unique and a binary search finds the same row a
// linear scan in file order would have found first.

/// One property as three parallel columns: the inclusive bounds of each range
/// and the raw value of the class it carries.
///
/// The three columns have equal length, and `lo[i] <= hi[i] < lo[i + 1]` holds
/// for every adjacent pair — the generator rejects an overlap rather than
/// emitting one.
struct RangeTable {
    /// Lower bound of each range, ascending.
    let lo: [UInt32]
    /// Upper bound of each range, inclusive.
    let hi: [UInt32]
    /// Raw value of the class each range carries.
    let cls: [UInt8]
}

/// The raw class value of the range covering `cp`, or `nil` when no range does.
///
/// A property whose `@missing` header declares a default has that default
/// supplied by the caller, so this answers only the question the table can.
func rangeClass(_ table: RangeTable, _ cp: UInt32) -> UInt8? {
    var low = 0
    var high = table.lo.count
    while low < high {
        let mid = low + (high - low) / 2
        if cp < table.lo[mid] {
            high = mid
        } else if cp > table.hi[mid] {
            low = mid + 1
        } else {
            return table.cls[mid]
        }
    }
    return nil
}

/// A boolean property as two parallel columns of inclusive bounds, ascending
/// and disjoint.
struct FlagTable {
    /// Lower bound of each range, ascending.
    let lo: [UInt32]
    /// Upper bound of each range, inclusive.
    let hi: [UInt32]
}

/// True iff some range of `table` covers `cp`.
func flagCovers(_ table: FlagTable, _ cp: UInt32) -> Bool {
    var low = 0
    var high = table.lo.count
    while low < high {
        let mid = low + (high - low) / 2
        if cp < table.lo[mid] {
            high = mid
        } else if cp > table.hi[mid] {
            low = mid + 1
        } else {
            return true
        }
    }
    return false
}
