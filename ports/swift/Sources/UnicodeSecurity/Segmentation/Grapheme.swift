// ─────────────────────────────────────────────────────────────────────────────
//                                     // segmentation // grapheme
// ─────────────────────────────────────────────────────────────────────────────
//
// UAX #29 default extended grapheme cluster segmentation.
//
// A port of the Lean algorithm Unicode.Segmentation.GraphemeBreak.graphemeBreaks,
// whose graphemeBreaks_eq_spec theorem relates it to the declarative UAX #29
// GB1-GB999 specification. The state fields, rule order and transitions below
// mirror that reference: the first matching rule wins, and the trailing GB999
// breaks every otherwise-unmatched pair.
//
// Where a cluster boundary falls is a property of a sequence rather than of a
// code point, so the entry point returns one flag per boundary position: a
// sequence of n code points yields n + 1 flags, entry 0 the GB1 start-of-text
// break and entry n the GB2 end-of-text break, both always true.
//
// Three pieces of left context carry what the rules read, each a field of
// `GraphemeState`: the previous code point's class, the GB11 emoji-pictograph
// window, and the GB9c Indic-conjunct window, plus the regional-indicator run
// length GB12 and GB13 count parity over. Where the Lean carries an optional
// previous class, this file carries an optional, which is the same shape Swift
// writes it in.
//
// Two of the three properties the rules read come from the generated tables in
// GraphemeTables.swift. The third, Extended_Pictographic, is the table LB30b
// already reads: GB11 calls `isExtendedPictographic` rather than carrying a
// second copy. So this file takes code points and needs no data directory.

/// The GB11 left-context window: whether the scan has just passed an
/// Extended_Pictographic, and whether a ZWJ has followed it.
private enum PictographWindow {
    /// No relevant prefix.
    case outside
    /// An Extended_Pictographic followed by zero or more Extend.
    case afterPictograph
    /// An Extended_Pictographic Extend* ZWJ, the prefix GB11 fires on.
    case afterPictographZwj
}

/// The GB9c left-context window: whether the scan has passed an
/// Indic_Conjunct_Break consonant, and whether a linker has followed it.
private enum ConjunctWindow {
    /// No relevant prefix.
    case outside
    /// A Consonant followed by zero or more Extend, with no Linker yet.
    case consonant
    /// A Consonant (Extend | Linker)* Linker (Extend | Linker)*, the prefix
    /// GB9c fires on.
    case linker
}

/// The running scan state, mirroring the Lean State.
private struct GraphemeState {
    /// The Grapheme_Cluster_Break class of the previous code point. `nil` only
    /// before the first one is read, which is the condition GB1 tests.
    var prevClass: GraphemeClusterBreak?

    /// The GB11 window.
    var pictograph = PictographWindow.outside
    /// The GB9c window.
    var conjunct = ConjunctWindow.outside

    /// The length of the current regional-indicator run, whose parity GB12 and
    /// GB13 read.
    var riRun: UInt32 = 0
}

/// True iff a cluster boundary falls immediately before `cp`, given the running
/// state. UAX #29 GB1 through GB999 in canonical order.
private func shouldBreakBeforeCluster(
    _ cp: UInt32, _ s: GraphemeState
) -> Bool {
    guard let pc: GraphemeClusterBreak = s.prevClass else {
        return true  // GB1: start of text
    }
    // The two classes are annotated rather than inferred so a comparison
    // against a case this type does not carry names this type. Several
    // Grapheme_Cluster_Break value names — `spacingMark`, `control` — are also
    // cases of the standard library's `Unicode.GeneralCategory`, and a
    // mis-spelled case then resolves against that type and reports a mismatch
    // between two unrelated enums rather than a missing case.
    let bc: GraphemeClusterBreak = graphemeClusterBreak(cp)
    let incb: IndicConjunctBreak = indicConjunctBreak(cp)
    let isPictograph = isExtendedPictographic(cp)

    // GB3
    if pc == .cr && bc == .lf { return false }
    // GB4
    if pc == .control || pc == .cr || pc == .lf { return true }
    // GB5
    if bc == .control || bc == .cr || bc == .lf { return true }
    // GB6
    if pc == .l && (bc == .l || bc == .v || bc == .lv || bc == .lvt) {
        return false
    }
    // GB7
    if (pc == .lv || pc == .v) && (bc == .v || bc == .t) { return false }
    // GB8
    if (pc == .lvt || pc == .t) && bc == .t { return false }
    // GB9
    if bc == .extend || bc == .zwj { return false }
    // GB9a
    if bc == .spacingMark { return false }
    // GB9b
    if pc == .prepend { return false }
    // GB9c: Consonant (Extend | Linker)* Linker (Extend | Linker)* x Consonant
    if s.conjunct == .linker && incb == .consonant { return false }
    // GB11: ExtPict Extend* ZWJ x ExtPict
    if s.pictograph == .afterPictographZwj && isPictograph { return false }
    // GB12 / GB13: an odd-parity regional-indicator run extends
    if bc == .regionalIndicator && s.riRun % 2 == 1 { return false }
    // GB999
    return true
}

/// Fold one code point into the context. Mirrors the Lean advance, which
/// computes the update independently of the break decision so the caller
/// records the break and moves on.
private func advanceCluster(
    _ cp: UInt32, _ s: GraphemeState
) -> GraphemeState {
    let bc: GraphemeClusterBreak = graphemeClusterBreak(cp)
    let incb: IndicConjunctBreak = indicConjunctBreak(cp)
    let isPictograph = isExtendedPictographic(cp)

    var pictograph = PictographWindow.outside
    if isPictograph {
        pictograph = .afterPictograph
    } else if s.pictograph == .afterPictograph && bc == .extend {
        pictograph = .afterPictograph
    } else if s.pictograph == .afterPictograph && bc == .zwj {
        pictograph = .afterPictographZwj
    }

    var conjunct = ConjunctWindow.outside
    if incb == .consonant {
        conjunct = .consonant
    } else if s.conjunct == .consonant && incb == .linker {
        conjunct = .linker
    } else if s.conjunct == .consonant && incb == .extend {
        conjunct = .consonant
    } else if s.conjunct == .linker && incb == .linker {
        conjunct = .linker
    } else if s.conjunct == .linker && incb == .extend {
        conjunct = .linker
    }

    var out = GraphemeState()
    out.prevClass = bc
    out.pictograph = pictograph
    out.conjunct = conjunct
    out.riRun = bc == .regionalIndicator ? s.riRun + 1 : 0
    return out
}

/// One cluster-boundary flag per boundary of the code point sequence, so a
/// sequence of n code points yields n + 1 flags.
///
/// Entry 0 is the GB1 start-of-text break and entry n the GB2 end-of-text
/// break, both always true.
public func graphemeBreaks(_ cps: [UInt32]) -> [Bool] {
    var out: [Bool] = []
    out.reserveCapacity(cps.count + 1)
    var s = GraphemeState()
    for cp in cps {
        out.append(shouldBreakBeforeCluster(cp, s))
        s = advanceCluster(cp, s)
    }
    out.append(true)  // GB2
    return out
}

/// The code points between consecutive boundaries — the clusters a renderer
/// treats as single user-perceived characters.
public func graphemeClusters(_ cps: [UInt32]) -> [[UInt32]] {
    let breaks = graphemeBreaks(cps)
    var out: [[UInt32]] = []
    var current: [UInt32] = []
    for (index, cp) in cps.enumerated() {
        if breaks[index] && !current.isEmpty {
            out.append(current)
            current = []
        }
        current.append(cp)
    }
    if !current.isEmpty { out.append(current) }
    return out
}
