// ─────────────────────────────────────────────────────────────────────────────
//                                   // segmentation // line-break
// ─────────────────────────────────────────────────────────────────────────────
//
// UAX #14 default line breaking over code point sequences.
//
// A port of the Lean algorithm Unicode.Segmentation.LineBreak.lineBreaks, whose
// lineBreaks_length theorem fixes the output shape: one break-opportunity flag
// per boundary position. The rule order, rule bodies, and snapshot fields below
// mirror that reference — LB2 through LB31 in UAX #14 R7's canonical order,
// first match winning, the trailing LB31 breaking every otherwise-unmatched
// pair.
//
// Where a line may break is a property of a sequence rather than of a code
// point, so the entry point returns a flag per boundary instead of a predicate
// over code points.
//
// Three mechanisms carry the context the rules read:
//
//   - LB1 is applied at lookup time by `resolvedLineBreakClass`, which folds
//     the tailorable AI, CJ, SA, SG and XX into the algorithm's working
//     alphabet. SA needs General_Category to choose between CM and AL.
//   - LB9 — treat X CM* / X ZWJ* as X — is realised through `Snapshot`, whose
//     fields hold the most recent class that was not CM or ZWJ. LB10, treating
//     a leftover CM or ZWJ as AL, is the fallback taken when no such class
//     exists.
//   - The rules naming a third character — LB15b, LB15c, the LB25 bracket and
//     the fourth LB28a sub-rule — read forward from the position being decided.
//
// Two departures from the Lean. Its positional reads are `lits[i]!` and
// `cps[i]!`, panicking accessors; here every read is bounded by the array
// length the caller already holds, so no access can leave the sequence. And its
// `spSinceNoSp` snapshot field is written by its fold and read by no rule, so
// this port omits it.
//
// Where the Lean carries an optional neighbour, this file carries an optional
// value, which is the same shape Swift writes it in. A class and the code point
// it came from are set together, so one optional covers the pair.
//
// The two properties UAX #14 needs beyond the Line_Break class come from
// different places. General_Category — for LB1's SA resolution, the Pi/Pf quote
// refinement and LB30b — is generated into LineBreakTables.swift.
// East_Asian_Width — for LB19a, LB25 and LB30 — is the security layer's own
// `eastAsianWidth` over its digest-pinned EastAsianWidth.txt: a Swift module is
// one namespace, so this file calls it rather than carrying a second copy.

/// One character as the algorithm reads it: its code point and its LB1-resolved
/// class.
private struct Classified {
    let cp: UInt32
    let cls: LineBreakClass
}

/// The Line_Break class `cp` carries once LB1 has tailored it.
///
/// AI, SG and XX resolve to AL; CJ to NS; SA to CM when the code point is a
/// non-spacing or spacing combining mark and to AL otherwise. Every other class
/// is already in the working alphabet.
public func resolvedLineBreakClass(_ cp: UInt32) -> LineBreakClass {
    let raw = rawLineBreakClass(cp)
    switch raw {
    case .ai, .sg, .xx:
        return .al
    case .cj:
        return .ns
    case .sa:
        // LB1 reads only the two combining-mark categories here; an enclosing
        // mark is not among them.
        let category = generalCategory(cp)
        return (category == .mn || category == .mc) ? .cm : .al
    default:
        return raw
    }
}

/// True iff LB9 absorbs this class into the character before it.
private func isCmZwj(_ cls: LineBreakClass) -> Bool {
    cls == .cm || cls == .zwj
}

/// True iff a preceding class blocks LB9's absorption, so a following CM or ZWJ
/// stands on its own and LB10 reads it as AL.
private func blocksAbsorb(_ cls: LineBreakClass) -> Bool {
    cls == .bk || cls == .cr || cls == .lf || cls == .nl || cls == .sp
        || cls == .zw
}

/// True iff the class is QU and the code point is initial punctuation, the
/// refinement LB15a reads.
private func isPiQuote(_ cp: UInt32, _ cls: LineBreakClass) -> Bool {
    cls == .qu && generalCategory(cp) == .pi
}

/// True iff the class is QU and the code point is final punctuation, the
/// refinement LB15b reads.
private func isPfQuote(_ cp: UInt32, _ cls: LineBreakClass) -> Bool {
    cls == .qu && generalCategory(cp) == .pf
}

/// U+2010 HYPHEN, which LB20a and LB21a name explicitly because UCD 17.0 moved
/// it from class HY to class HH.
private let hyphenU2010: UInt32 = 0x2010

/// U+25CC DOTTED CIRCLE, which LB28a reads as a stand-in cluster base.
private let dottedCircle: UInt32 = 0x25CC

/// True iff `cp` is East_Asian_Width F, W or H, the set LB25 and LB30 read.
private func isEastAsianFullWide(_ cp: UInt32) -> Bool {
    let width = eastAsianWidth(Int(cp))
    return width == .f || width == .w || width == .h
}

/// True iff `cp` counts as East Asian for LB19a's tailoring, which treats
/// Ambiguous as East Asian alongside Fullwidth, Wide and Halfwidth. Wider than
/// `isEastAsianFullWide`.
private func isEastAsianOrAmbiguous(_ cp: UInt32) -> Bool {
    let width = eastAsianWidth(Int(cp))
    return width == .f || width == .w || width == .h || width == .a
}

/// True iff the effective class is present and among `classes`.
private func effIn(_ effective: LineBreakClass?, _ classes: LineBreakClass...)
    -> Bool
{
    guard let effective = effective else { return false }
    return classes.contains(effective)
}

/// The left-hand context a boundary decision reads: the classes and code points
/// of the most recent characters LB9 did not absorb, plus the running counters
/// the rules keep. Mirrors the Lean EffSnapshot.
private struct Snapshot {
    /// The class of the most recent character that was not CM or ZWJ, and its
    /// code point — LB20a, LB21a and LB28a name U+2010 and U+25CC. One optional
    /// covers both, since `advance` sets them together.
    var effPrev: (cls: LineBreakClass, cp: UInt32)?

    /// The class of the most recent character that was not CM, ZWJ or SP.
    var effPrevNoSP: LineBreakClass?

    /// The class of the second most recent such character, and its code point.
    var effPrevPrev: (cls: LineBreakClass, cp: UInt32)?

    /// Whether an LB15a initial-punctuation quote window is open.
    var inPiQuoteWindow = false
    /// The length of the current regional-indicator run, for LB30a.
    var riRun: UInt32 = 0
    /// Whether an LB25 numeric chain is open.
    var inNuChain = false
}

/// The class a CM or ZWJ takes from what it attaches to under LB9, or AL under
/// LB10 when nothing absorbs it.
private func effectiveClass(
    _ cls: LineBreakClass, _ effPrev: LineBreakClass?
) -> LineBreakClass {
    if !isCmZwj(cls) { return cls }
    guard let effPrev = effPrev else { return .al }
    return blocksAbsorb(effPrev) ? .al : cls
}

/// Fold one character into the context. A character LB9 absorbs leaves the
/// context untouched, which is what makes the neighbours it records effective
/// rather than literal. Mirrors the Lean buildSnapshots step.
private func advance(
    _ s: Snapshot, _ cp: UInt32, _ cls: LineBreakClass
) -> Snapshot {
    let effective = effectiveClass(cls, s.effPrev?.cls)
    if isCmZwj(effective) { return s }

    // LB15a opens its window only where an initial-punctuation quote stands
    // outside a word; a space carries an open window forward.
    let leftContextOpens = s.effPrev == nil
        || effIn(s.effPrev?.cls, .bk, .cr, .lf, .nl, .op, .qu, .gl, .sp, .zw)
    var inPiQuoteWindow = false
    if isPiQuote(cp, effective) && leftContextOpens {
        inPiQuoteWindow = true
    } else if effective == .sp {
        inPiQuoteWindow = s.inPiQuoteWindow
    }

    var inNuChain = false
    if effective == .nu {
        inNuChain = true
    } else if s.inNuChain {
        inNuChain = effective == .sy || effective == .`is` || effective == .cl
            || effective == .cp || effective == .pr
    }

    var out = Snapshot()
    out.effPrev = (cls: effective, cp: cp)
    out.effPrevPrev = s.effPrev
    out.inPiQuoteWindow = inPiQuoteWindow
    out.inNuChain = inNuChain
    out.effPrevNoSP = effective == .sp ? s.effPrevNoSP : effective
    out.riRun = effective == .ri ? s.riRun + 1 : 0
    return out
}

/// True iff LB15b holds: the final quote is last, or what follows it cannot
/// itself open a line.
private func finalQuoteCloses(_ ahead: ArraySlice<Classified>) -> Bool {
    guard let head = ahead.first else { return true }
    switch head.cls {
    case .sp, .gl, .wj, .cl, .qu, .cp, .ex, .`is`, .sy, .bk, .cr, .lf, .nl,
         .zw:
        return true
    default:
        return false
    }
}

/// What the fourth LB28a sub-rule tests: it looks past any CM or ZWJ the cluster
/// absorbs, so the character it reads is the first significant one ahead.
private func nextSignificantIsVF(_ ahead: ArraySlice<Classified>) -> Bool {
    for entry in ahead where !isCmZwj(entry.cls) {
        return entry.cls == .vf
    }
    return false
}

/// True iff a line break opportunity falls immediately before the head of
/// `suffix`, given the character before it and the context accumulated from
/// everything earlier.
///
/// `suffix` begins at the position being decided, so its head is the current
/// character and its tail supplies every lookahead the rules take.
private func breaksBefore(
    _ prev: Classified, _ suffix: ArraySlice<Classified>, _ s: Snapshot
) -> Bool {
    guard let current = suffix.first else { return true }  // LB3
    let prevCP = prev.cp
    let prevClass = prev.cls
    let currentCP = current.cp
    let currentClass = current.cls
    let ahead = suffix.dropFirst()

    let eff = effectiveClass(currentClass, s.effPrev?.cls)
    let left: LineBreakClass? = isCmZwj(prevClass) ? s.effPrev?.cls : prevClass

    // LB4
    if prevClass == .bk { return true }
    // LB5
    if prevClass == .cr && currentClass == .lf { return false }
    if prevClass == .cr || prevClass == .lf || prevClass == .nl { return true }
    // LB6
    if currentClass == .bk || currentClass == .cr || currentClass == .lf
        || currentClass == .nl {
        return false
    }
    // LB7
    if currentClass == .sp || currentClass == .zw { return false }
    // LB8
    if s.effPrevNoSP == .zw { return true }
    // LB8a
    if prevClass == .zwj { return false }
    // LB9
    if isCmZwj(currentClass), let effPrev = s.effPrev,
        !blocksAbsorb(effPrev.cls) {
        return false
    }
    // LB11
    if eff == .wj || effIn(left, .wj) { return false }
    // LB12
    if effIn(left, .gl) { return false }
    // LB12a
    if eff == .gl && !effIn(left, .sp, .ba, .hy, .hh) { return false }
    // LB15c, which UCD 17.0 orders above LB13 and LB15d: break before an IS
    // that opens a number and follows a space, as in "equals .35".
    if prevClass == .sp && eff == .`is` && ahead.first?.cls == .nu {
        return true
    }
    // LB13
    if eff == .cl || eff == .cp || eff == .ex || eff == .`is` || eff == .sy {
        return false
    }
    // LB14
    if s.effPrevNoSP == .op { return false }
    // LB15a
    if s.inPiQuoteWindow { return false }
    // LB15b
    if isPfQuote(currentCP, eff) && finalQuoteCloses(ahead) { return false }
    // LB15d
    if eff == .`is` { return false }
    // LB16
    if eff == .ns && (s.effPrevNoSP == .cl || s.effPrevNoSP == .cp) {
        return false
    }
    // LB17
    if eff == .b2 && s.effPrevNoSP == .b2 { return false }
    // LB18
    if prevClass == .sp { return true }
    // LB19 and LB19a. A quote neither breaks before nor after, except on the
    // OUTER side of an initial or final punctuation quote standing in
    // contiguous East Asian content — there the default break applies, so a
    // line may break at the quote boundary. The inner side stays unbroken,
    // being the boundary inside the quote's own scope.
    if eff == .qu {
        let nextEastAsian = ahead.first.map { isEastAsianOrAmbiguous($0.cp) }
            ?? false
        let openQuoteInEastAsian = isPiQuote(currentCP, eff)
            && isEastAsianOrAmbiguous(prevCP)
            && isEastAsianOrAmbiguous(currentCP) && nextEastAsian
        if !openQuoteInEastAsian { return false }
    }
    if effIn(left, .qu) {
        var closeQuoteInEastAsian = false
        if let effPrev = s.effPrev {
            let prevPrevEastAsian =
                (s.effPrevPrev.map { isEastAsianOrAmbiguous($0.cp) } ?? false)
            closeQuoteInEastAsian = isPfQuote(effPrev.cp, .qu)
                && prevPrevEastAsian
                && isEastAsianOrAmbiguous(effPrev.cp)
                && isEastAsianOrAmbiguous(currentCP)
        }
        if !closeQuoteInEastAsian { return false }
    }
    // LB20
    if eff == .cb || effIn(left, .cb) { return true }

    // LB20.1 and LB20a both require the hyphen's own left context to be outside
    // a word, the same start-of-segment set.
    let hyphenLeftContextOpens = s.effPrevPrev == nil
        || effIn(s.effPrevPrev?.cls, .bk, .cr, .lf, .nl, .sp, .zw, .cb, .gl)
    // LB20.1, UCD 17.0: an explicit hyphen joins a following letter only where
    // its own left context is outside a word. A mid-word HH falls through to
    // LB31.
    if effIn(left, .hh) && (eff == .al || eff == .hl)
        && hyphenLeftContextOpens {
        return false
    }
    // LB20a, with UCD 17.0's right side broadened to HL beside AL.
    if eff == .al || eff == .hl {
        let hyphenCarriesLeft = s.effPrev.map {
            $0.cls == .hy || $0.cls == .hh || $0.cp == hyphenU2010
        } ?? false
        if hyphenCarriesLeft && hyphenLeftContextOpens { return false }
    }
    // LB21
    if eff == .ba || eff == .hy || eff == .hh || eff == .ns { return false }
    if effIn(left, .bb) { return false }
    // LB21a: an HL letter followed by an HY hyphen or U+2010 glues to what comes
    // next unless that is itself HL. A BA does not glue here.
    if s.effPrevPrev?.cls == .hl && eff != .hl {
        let hyphenIsHyOr2010 = s.effPrev.map {
            $0.cls == .hy || $0.cp == hyphenU2010
        } ?? false
        if hyphenIsHyOr2010 { return false }
    }
    // LB21b
    if eff == .hl && effIn(left, .sy) { return false }
    // LB22
    if eff == .`in` { return false }
    // LB23
    if eff == .nu && effIn(left, .al, .hl) { return false }
    if (eff == .al || eff == .hl) && effIn(left, .nu) { return false }
    // LB23a
    if (eff == .id || eff == .eb || eff == .em) && effIn(left, .pr) {
        return false
    }
    if eff == .po && effIn(left, .id, .eb, .em) { return false }
    // LB24
    if (eff == .al || eff == .hl) && effIn(left, .pr, .po) { return false }
    if (eff == .pr || eff == .po) && effIn(left, .al, .hl) { return false }
    // LB25, closing an open numeric chain with a CL or CP suffix and a following
    // PO or PR.
    if s.inNuChain && (eff == .cl || eff == .cp || eff == .po || eff == .pr) {
        return false
    }
    // LB25, opening a chain
    if eff == .nu && effIn(left, .pr, .po, .hy, .op, .`is`) { return false }
    // LB25, chain body
    if eff == .nu && effIn(left, .nu) { return false }
    // LB25, extending an open chain across a SY
    if eff == .nu && effIn(left, .sy) && s.inNuChain { return false }
    // LB25, bracketed prefix: a PR joins an OP only when the OP itself opens a
    // number, and neither is East Asian Fullwidth, Wide or Halfwidth.
    if eff == .op, effIn(left, .pr), !isEastAsianFullWide(currentCP),
        let effPrev = s.effPrev, !isEastAsianFullWide(effPrev.cp),
        ahead.first?.cls == .nu {
        return false
    }
    // LB26
    if effIn(left, .jl) && (eff == .jl || eff == .jv || eff == .h2
        || eff == .h3) {
        return false
    }
    if effIn(left, .jv, .h2) && (eff == .jv || eff == .jt) { return false }
    if effIn(left, .jt, .h3) && eff == .jt { return false }
    // LB27
    if effIn(left, .jl, .jv, .jt, .h2, .h3)
        && (eff == .`in` || eff == .po) {
        return false
    }
    if effIn(left, .pr) && (eff == .jl || eff == .jv || eff == .jt
        || eff == .h2 || eff == .h3) {
        return false
    }
    // LB28
    if (eff == .al || eff == .hl) && effIn(left, .al, .hl) { return false }

    // LB28a, the aksara cluster rules. U+25CC DOTTED CIRCLE carries class AL and
    // stands in for a cluster base throughout.
    let leftIsAksaraBase = effIn(left, .ak, .`as`)
        || (s.effPrev.map { $0.cp == dottedCircle && $0.cls == .al } ?? false)
    if effIn(left, .ap)
        && (eff == .ak || eff == .`as` || currentCP == dottedCircle) {
        return false
    }
    if leftIsAksaraBase && (eff == .vf || eff == .vi) { return false }
    if s.effPrev?.cls == .vi,
        effIn(s.effPrevPrev?.cls, .ak, .`as`)
            || s.effPrevPrev?.cp == dottedCircle,
        eff == .ak || currentCP == dottedCircle {
        return false
    }
    if leftIsAksaraBase
        && (eff == .ak || eff == .`as` || currentCP == dottedCircle)
        && nextSignificantIsVF(ahead) {
        return false
    }
    // LB29
    if (eff == .al || eff == .hl) && effIn(left, .`is`) { return false }
    // LB30, where the bracket must not be East Asian Fullwidth, Wide or
    // Halfwidth.
    if eff == .op && effIn(left, .al, .hl, .nu)
        && !isEastAsianFullWide(currentCP) {
        return false
    }
    if (eff == .al || eff == .hl || eff == .nu) && effIn(left, .cp)
        && !isEastAsianFullWide(prevCP) {
        return false
    }
    // LB30a
    if eff == .ri && s.riRun % 2 == 1 { return false }
    // LB30b
    if eff == .em && effIn(left, .eb) { return false }
    if eff == .em, let effPrev = s.effPrev,
        isExtendedPictographic(effPrev.cp),
        generalCategory(effPrev.cp) == .cn {
        return false
    }
    // LB31
    return true
}

/// One break-opportunity flag per boundary of the code point sequence, so a
/// sequence of n code points yields n + 1 flags — the shape the Lean
/// lineBreaks_length theorem fixes.
///
/// Entry 0 is `false` — LB2 forbids a break at the start of text — and entry n
/// is `true` per LB3, which requires one at the end.
public func lineBreaks(_ cps: [UInt32]) -> [Bool] {
    let pairs = cps.map {
        Classified(cp: $0, cls: resolvedLineBreakClass($0))
    }
    var out: [Bool] = []
    out.reserveCapacity(pairs.count + 1)
    var s = Snapshot()
    for index in pairs.indices {
        if index == 0 {
            out.append(false)  // LB2
        } else {
            out.append(breaksBefore(pairs[index - 1], pairs[index...], s))
        }
        s = advance(s, pairs[index].cp, pairs[index].cls)
    }
    out.append(true)  // LB3
    return out
}

/// The code point sequence split at every break opportunity — the runs a
/// renderer may place on separate lines.
public func lineRuns(_ cps: [UInt32]) -> [[UInt32]] {
    let breaks = lineBreaks(cps)
    var out: [[UInt32]] = []
    var current: [UInt32] = []
    for (index, cp) in cps.enumerated() {
        current.append(cp)
        if breaks[index + 1] {
            out.append(current)
            current = []
        }
    }
    if !current.isEmpty { out.append(current) }
    return out
}
