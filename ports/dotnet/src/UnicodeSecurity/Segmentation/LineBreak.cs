// UAX #14 default line breaking over code point sequences.
//
// A port of the Lean algorithm Unicode.Segmentation.LineBreak.lineBreaks,
// whose lineBreaks_length theorem fixes the output shape: one
// break-opportunity flag per boundary position. The rule order, rule bodies
// and snapshot fields below mirror that reference -- LB2 through LB31 in
// UAX #14 R7's canonical order, first match winning, the trailing LB31
// breaking every otherwise-unmatched pair.
//
// Where a line may break is a property of a sequence rather than of a code
// point, so the entry point returns a flag per boundary instead of a
// predicate over code points.
//
// Three mechanisms carry the context the rules read:
//
//   - LB1 is applied at lookup time by ResolvedClass, which folds the
//     tailorable AI, CJ, SA, SG and XX into the algorithm's working
//     alphabet. SA needs General_Category to choose between CM and AL.
//   - LB9 -- treat X CM* / X ZWJ* as X -- is realised through Snapshot,
//     whose fields hold the most recent class that was not CM or ZWJ. LB10,
//     treating a leftover CM or ZWJ as AL, is the fallback taken when no
//     such class exists.
//   - The rules naming a third character -- LB15b, LB15c, the LB25 bracket
//     and the fourth LB28a sub-rule -- read forward from the position being
//     decided.
//
// Two departures from the Lean. Its positional reads are lits[i]! and
// cps[i]!, panicking accessors; here every read is bounded by the length the
// caller already holds, so no access can leave the sequence. And its
// spSinceNoSp snapshot field is written by its fold and read by no rule, so
// this port omits it.
//
// The two properties UAX #14 needs beyond the Line_Break class --
// General_Category for LB1's SA resolution, the Pi/Pf quote refinement and
// LB30b, and East_Asian_Width for LB19a, LB25 and LB30 -- come from the
// generated tables in LineBreakTables.cs, so this class takes code points
// and needs no data directory.

namespace UnicodeSecurity.Segmentation;

/// <summary>
/// UAX #14 default line breaking: where a sequence of code points offers a
/// line break opportunity.
/// </summary>
public static class LineBreak
{
    /// <summary>
    /// U+2010 HYPHEN, which LB20a and LB21a name explicitly because UCD
    /// 17.0 moved it from class <c>HY</c> to class <c>HH</c>.
    /// </summary>
    private const uint HyphenU2010 = 0x2010;

    /// <summary>
    /// U+25CC DOTTED CIRCLE, which LB28a reads as a stand-in cluster base.
    /// </summary>
    private const uint DottedCircle = 0x25CC;

    /// <summary>One character as the algorithm reads it.</summary>
    private readonly struct Classified(uint cp, Lb cls)
    {
        /// <summary>The code point.</summary>
        public uint Cp { get; } = cp;

        /// <summary>Its LB1-resolved Line_Break class.</summary>
        public Lb Class { get; } = cls;
    }

    /// <summary>
    /// The left-hand context a boundary decision reads: the classes and code
    /// points of the most recent characters LB9 did not absorb, plus the
    /// running counters the rules keep. Mirrors the Lean
    /// <c>EffSnapshot</c>.
    /// </summary>
    private readonly struct Snapshot
    {
        /// <summary>
        /// The class of the most recent character that was not CM or ZWJ.
        /// </summary>
        public Lb? EffPrev { get; init; }

        /// <summary>
        /// Its code point, which LB20a, LB21a and LB28a read because they
        /// name U+2010 and U+25CC.
        /// </summary>
        public uint EffPrevCp { get; init; }

        /// <summary>
        /// The class of the most recent character that was not CM, ZWJ or
        /// SP.
        /// </summary>
        public Lb? EffPrevNoSp { get; init; }

        /// <summary>
        /// The class of the second most recent character LB9 did not absorb.
        /// </summary>
        public Lb? EffPrevPrev { get; init; }

        /// <summary>Its code point.</summary>
        public uint EffPrevPrevCp { get; init; }

        /// <summary>
        /// Whether an LB15a initial-punctuation quote window is open.
        /// </summary>
        public bool InPiQuoteWindow { get; init; }

        /// <summary>
        /// The length of the current regional-indicator run, for LB30a.
        /// </summary>
        public uint RiRun { get; init; }

        /// <summary>Whether an LB25 numeric chain is open.</summary>
        public bool InNuChain { get; init; }
    }

    /// <summary>
    /// The Line_Break class <paramref name="cp"/> carries once LB1 has
    /// tailored it. AI, SG and XX resolve to AL; CJ to NS; SA to CM when the
    /// code point is a non-spacing or spacing combining mark and to AL
    /// otherwise. Every other class is already in the working alphabet.
    /// </summary>
    public static Lb ResolvedClass(uint cp)
    {
        var raw = LineBreakTables.RawClass(cp);
        switch (raw)
        {
            case Lb.Ai:
            case Lb.Sg:
            case Lb.Xx:
                return Lb.Al;
            case Lb.Cj:
                return Lb.Ns;
            case Lb.Sa:
                // LB1 reads only the two combining-mark categories here; an
                // enclosing mark is not among them.
                var category = LineBreakTables.CategoryOf(cp);
                return category is Gc.Mn or Gc.Mc ? Lb.Cm : Lb.Al;
            default:
                return raw;
        }
    }

    /// <summary>
    /// Whether LB9 absorbs this class into the character before it.
    /// </summary>
    private static bool IsCmZwj(Lb cls) => cls is Lb.Cm or Lb.Zwj;

    /// <summary>
    /// Whether a preceding class blocks LB9's absorption, so a following CM
    /// or ZWJ stands on its own and LB10 reads it as AL.
    /// </summary>
    private static bool BlocksAbsorb(Lb cls) =>
        cls is Lb.Bk or Lb.Cr or Lb.Lf or Lb.Nl or Lb.Sp or Lb.Zw;

    /// <summary>
    /// Whether the class is QU and the code point is initial punctuation,
    /// the refinement LB15a reads.
    /// </summary>
    private static bool IsPiQuote(uint cp, Lb cls) =>
        cls == Lb.Qu && LineBreakTables.CategoryOf(cp) == Gc.Pi;

    /// <summary>
    /// Whether the class is QU and the code point is final punctuation, the
    /// refinement LB15b reads.
    /// </summary>
    private static bool IsPfQuote(uint cp, Lb cls) =>
        cls == Lb.Qu && LineBreakTables.CategoryOf(cp) == Gc.Pf;

    /// <summary>
    /// Whether <paramref name="cp"/> is East_Asian_Width F, W or H, the set
    /// LB25 and LB30 read.
    /// </summary>
    private static bool IsEastAsianFullWide(uint cp) =>
        LineBreakTables.WidthOf(cp) is Eaw.F or Eaw.W or Eaw.H;

    /// <summary>
    /// Whether <paramref name="cp"/> counts as East Asian for LB19a's
    /// tailoring, which treats Ambiguous as East Asian alongside Fullwidth,
    /// Wide and Halfwidth. Wider than
    /// <see cref="IsEastAsianFullWide(uint)"/>.
    /// </summary>
    private static bool IsEastAsianOrAmbiguous(uint cp) =>
        LineBreakTables.WidthOf(cp) is Eaw.F or Eaw.W or Eaw.H or Eaw.A;

    /// <summary>
    /// Whether the effective class is present and among
    /// <paramref name="classes"/>.
    /// </summary>
    private static bool EffIn(Lb? effective, params ReadOnlySpan<Lb> classes)
    {
        if (effective is not { } cls)
        {
            return false;
        }

        foreach (var candidate in classes)
        {
            if (cls == candidate)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// The class a CM or ZWJ takes from what it attaches to under LB9, or AL
    /// under LB10 when nothing absorbs it.
    /// </summary>
    private static Lb EffectiveClass(Lb cls, Lb? effPrev)
    {
        if (!IsCmZwj(cls))
        {
            return cls;
        }

        if (effPrev is not { } previous)
        {
            return Lb.Al;
        }

        return BlocksAbsorb(previous) ? Lb.Al : cls;
    }

    /// <summary>
    /// One character folded into the context. A character LB9 absorbs leaves
    /// the context untouched, which is what makes the neighbours it records
    /// effective rather than literal. Mirrors the Lean
    /// <c>buildSnapshots</c> step.
    /// </summary>
    private static Snapshot Advance(Snapshot s, uint cp, Lb cls)
    {
        var effective = EffectiveClass(cls, s.EffPrev);
        if (IsCmZwj(effective))
        {
            return s;
        }

        // LB15a opens its window only where an initial-punctuation quote
        // stands outside a word; a space carries an open window forward.
        var leftContextOpens = s.EffPrev is null || EffIn(
            s.EffPrev,
            Lb.Bk, Lb.Cr, Lb.Lf, Lb.Nl, Lb.Op, Lb.Qu, Lb.Gl, Lb.Sp, Lb.Zw);
        var inPiQuoteWindow = false;
        if (IsPiQuote(cp, effective) && leftContextOpens)
        {
            inPiQuoteWindow = true;
        }
        else if (effective == Lb.Sp)
        {
            inPiQuoteWindow = s.InPiQuoteWindow;
        }

        var inNuChain = false;
        if (effective == Lb.Nu)
        {
            inNuChain = true;
        }
        else if (s.InNuChain)
        {
            inNuChain = effective is Lb.Sy or Lb.Is or Lb.Cl or Lb.Cp or Lb.Pr;
        }

        return new Snapshot
        {
            EffPrev = effective,
            EffPrevCp = cp,
            EffPrevPrev = s.EffPrev,
            EffPrevPrevCp = s.EffPrevCp,
            EffPrevNoSp = effective == Lb.Sp ? s.EffPrevNoSp : effective,
            InPiQuoteWindow = inPiQuoteWindow,
            RiRun = effective == Lb.Ri ? s.RiRun + 1 : 0,
            InNuChain = inNuChain,
        };
    }

    /// <summary>
    /// Whether LB15b holds: the final quote is last, or what follows it
    /// cannot itself open a line.
    /// </summary>
    private static bool FinalQuoteCloses(Classified[] pairs, int ahead)
    {
        if (ahead >= pairs.Length)
        {
            return true;
        }

        return pairs[ahead].Class
            is Lb.Sp or Lb.Gl or Lb.Wj or Lb.Cl or Lb.Qu or Lb.Cp or Lb.Ex
            or Lb.Is or Lb.Sy or Lb.Bk or Lb.Cr or Lb.Lf or Lb.Nl or Lb.Zw;
    }

    /// <summary>
    /// What the fourth LB28a sub-rule tests. It looks past any CM or ZWJ the
    /// cluster absorbs, so the character it reads is the first significant
    /// one ahead.
    /// </summary>
    private static bool NextSignificantIsVf(Classified[] pairs, int ahead)
    {
        for (var at = ahead; at < pairs.Length; at++)
        {
            if (!IsCmZwj(pairs[at].Class))
            {
                return pairs[at].Class == Lb.Vf;
            }
        }

        return false;
    }

    /// <summary>
    /// The class at the head of the suffix starting at
    /// <paramref name="ahead"/>, or null where the suffix is empty.
    /// </summary>
    private static Lb? HeadClass(Classified[] pairs, int ahead) =>
        ahead < pairs.Length ? pairs[ahead].Class : null;

    /// <summary>
    /// Whether a line break opportunity falls immediately before the
    /// character at <paramref name="at"/>, given the character before it and
    /// the context accumulated from everything earlier. The characters from
    /// <paramref name="at"/> onward supply every lookahead the rules take.
    /// </summary>
    private static bool BreaksBefore(
        Classified prev, Classified[] pairs, int at, Snapshot s)
    {
        if (at >= pairs.Length)
        {
            return true; // LB3
        }

        var prevCp = prev.Cp;
        var prevClass = prev.Class;
        var currentCp = pairs[at].Cp;
        var currentClass = pairs[at].Class;
        var ahead = at + 1;

        var eff = EffectiveClass(currentClass, s.EffPrev);
        Lb? left = IsCmZwj(prevClass) ? s.EffPrev : prevClass;

        // LB4
        if (prevClass == Lb.Bk)
        {
            return true;
        }

        // LB5
        if (prevClass == Lb.Cr && currentClass == Lb.Lf)
        {
            return false;
        }

        if (prevClass is Lb.Cr or Lb.Lf or Lb.Nl)
        {
            return true;
        }

        // LB6
        if (currentClass is Lb.Bk or Lb.Cr or Lb.Lf or Lb.Nl)
        {
            return false;
        }

        // LB7
        if (currentClass is Lb.Sp or Lb.Zw)
        {
            return false;
        }

        // LB8
        if (s.EffPrevNoSp == Lb.Zw)
        {
            return true;
        }

        // LB8a
        if (prevClass == Lb.Zwj)
        {
            return false;
        }

        // LB9
        if (IsCmZwj(currentClass) && s.EffPrev is { } absorbing
            && !BlocksAbsorb(absorbing))
        {
            return false;
        }

        // LB11
        if (eff == Lb.Wj || EffIn(left, Lb.Wj))
        {
            return false;
        }

        // LB12
        if (EffIn(left, Lb.Gl))
        {
            return false;
        }

        // LB12a
        if (eff == Lb.Gl && !EffIn(left, Lb.Sp, Lb.Ba, Lb.Hy, Lb.Hh))
        {
            return false;
        }

        // LB15c, which UCD 17.0 orders above LB13 and LB15d: break before an
        // IS that opens a number and follows a space, as in "equals .35".
        if (prevClass == Lb.Sp && eff == Lb.Is
            && HeadClass(pairs, ahead) == Lb.Nu)
        {
            return true;
        }

        // LB13
        if (eff is Lb.Cl or Lb.Cp or Lb.Ex or Lb.Is or Lb.Sy)
        {
            return false;
        }

        // LB14
        if (s.EffPrevNoSp == Lb.Op)
        {
            return false;
        }

        // LB15a
        if (s.InPiQuoteWindow)
        {
            return false;
        }

        // LB15b
        if (IsPfQuote(currentCp, eff) && FinalQuoteCloses(pairs, ahead))
        {
            return false;
        }

        // LB15d
        if (eff == Lb.Is)
        {
            return false;
        }

        // LB16
        if (eff == Lb.Ns && (s.EffPrevNoSp == Lb.Cl || s.EffPrevNoSp == Lb.Cp))
        {
            return false;
        }

        // LB17
        if (eff == Lb.B2 && s.EffPrevNoSp == Lb.B2)
        {
            return false;
        }

        // LB18
        if (prevClass == Lb.Sp)
        {
            return true;
        }

        // LB19 and LB19a. A quote neither breaks before nor after, except on
        // the OUTER side of an initial or final punctuation quote standing in
        // contiguous East Asian content -- there the default break applies, so
        // a line may break at the quote boundary. The inner side stays
        // unbroken, being the boundary inside the quote's own scope.
        if (eff == Lb.Qu)
        {
            var nextEastAsian = ahead < pairs.Length
                && IsEastAsianOrAmbiguous(pairs[ahead].Cp);
            var openQuoteInEastAsian = IsPiQuote(currentCp, eff)
                && IsEastAsianOrAmbiguous(prevCp)
                && IsEastAsianOrAmbiguous(currentCp)
                && nextEastAsian;
            if (!openQuoteInEastAsian)
            {
                return false;
            }
        }

        if (EffIn(left, Lb.Qu))
        {
            var closeQuoteInEastAsian = false;
            if (s.EffPrev is not null)
            {
                var quoteCp = s.EffPrevCp;
                closeQuoteInEastAsian = IsPfQuote(quoteCp, Lb.Qu)
                    && s.EffPrevPrev is not null
                    && IsEastAsianOrAmbiguous(s.EffPrevPrevCp)
                    && IsEastAsianOrAmbiguous(quoteCp)
                    && IsEastAsianOrAmbiguous(currentCp);
            }

            if (!closeQuoteInEastAsian)
            {
                return false;
            }
        }

        // LB20
        if (eff == Lb.Cb || EffIn(left, Lb.Cb))
        {
            return true;
        }

        // LB20.1 and LB20a both require the hyphen's own left context to be
        // outside a word, the same start-of-segment set.
        var hyphenLeftContextOpens = s.EffPrevPrev is null || EffIn(
            s.EffPrevPrev,
            Lb.Bk, Lb.Cr, Lb.Lf, Lb.Nl, Lb.Sp, Lb.Zw, Lb.Cb, Lb.Gl);

        // LB20.1, UCD 17.0: an explicit hyphen joins a following letter only
        // where its own left context is outside a word. A mid-word HH falls
        // through to LB31.
        if (EffIn(left, Lb.Hh) && (eff is Lb.Al or Lb.Hl)
            && hyphenLeftContextOpens)
        {
            return false;
        }

        // LB20a, with UCD 17.0's right side broadened to HL beside AL.
        if (eff is Lb.Al or Lb.Hl)
        {
            var hyphenCarriesLeft = s.EffPrev is Lb.Hy or Lb.Hh
                || (s.EffPrev is not null && s.EffPrevCp == HyphenU2010);
            if (hyphenCarriesLeft && hyphenLeftContextOpens)
            {
                return false;
            }
        }

        // LB21
        if (eff is Lb.Ba or Lb.Hy or Lb.Hh or Lb.Ns)
        {
            return false;
        }

        if (EffIn(left, Lb.Bb))
        {
            return false;
        }

        // LB21a: an HL letter followed by an HY hyphen or U+2010 glues to what
        // comes next unless that is itself HL. A BA does not glue here.
        if (s.EffPrevPrev == Lb.Hl && eff != Lb.Hl)
        {
            var hyphenIsHyOr2010 = s.EffPrev == Lb.Hy
                || (s.EffPrev is not null && s.EffPrevCp == HyphenU2010);
            if (hyphenIsHyOr2010)
            {
                return false;
            }
        }

        // LB21b
        if (eff == Lb.Hl && EffIn(left, Lb.Sy))
        {
            return false;
        }

        // LB22
        if (eff == Lb.In)
        {
            return false;
        }

        // LB23
        if (eff == Lb.Nu && EffIn(left, Lb.Al, Lb.Hl))
        {
            return false;
        }

        if ((eff is Lb.Al or Lb.Hl) && EffIn(left, Lb.Nu))
        {
            return false;
        }

        // LB23a
        if ((eff is Lb.Id or Lb.Eb or Lb.Em) && EffIn(left, Lb.Pr))
        {
            return false;
        }

        if (eff == Lb.Po && EffIn(left, Lb.Id, Lb.Eb, Lb.Em))
        {
            return false;
        }

        // LB24
        if ((eff is Lb.Al or Lb.Hl) && EffIn(left, Lb.Pr, Lb.Po))
        {
            return false;
        }

        if ((eff is Lb.Pr or Lb.Po) && EffIn(left, Lb.Al, Lb.Hl))
        {
            return false;
        }

        // LB25, closing an open numeric chain with a CL or CP suffix and a
        // following PO or PR.
        if (s.InNuChain && eff is Lb.Cl or Lb.Cp or Lb.Po or Lb.Pr)
        {
            return false;
        }

        // LB25, opening a chain
        if (eff == Lb.Nu && EffIn(left, Lb.Pr, Lb.Po, Lb.Hy, Lb.Op, Lb.Is))
        {
            return false;
        }

        // LB25, chain body
        if (eff == Lb.Nu && EffIn(left, Lb.Nu))
        {
            return false;
        }

        // LB25, extending an open chain across a SY
        if (eff == Lb.Nu && EffIn(left, Lb.Sy) && s.InNuChain)
        {
            return false;
        }

        // LB25, bracketed prefix: a PR joins an OP only when the OP itself
        // opens a number, and neither is East Asian Fullwidth, Wide or
        // Halfwidth.
        if (eff == Lb.Op && EffIn(left, Lb.Pr)
            && !IsEastAsianFullWide(currentCp)
            && s.EffPrev is not null && !IsEastAsianFullWide(s.EffPrevCp)
            && HeadClass(pairs, ahead) == Lb.Nu)
        {
            return false;
        }

        // LB26
        if (EffIn(left, Lb.Jl) && eff is Lb.Jl or Lb.Jv or Lb.H2 or Lb.H3)
        {
            return false;
        }

        if (EffIn(left, Lb.Jv, Lb.H2) && eff is Lb.Jv or Lb.Jt)
        {
            return false;
        }

        if (EffIn(left, Lb.Jt, Lb.H3) && eff == Lb.Jt)
        {
            return false;
        }

        // LB27
        if (EffIn(left, Lb.Jl, Lb.Jv, Lb.Jt, Lb.H2, Lb.H3)
            && eff is Lb.In or Lb.Po)
        {
            return false;
        }

        if (EffIn(left, Lb.Pr)
            && eff is Lb.Jl or Lb.Jv or Lb.Jt or Lb.H2 or Lb.H3)
        {
            return false;
        }

        // LB28
        if ((eff is Lb.Al or Lb.Hl) && EffIn(left, Lb.Al, Lb.Hl))
        {
            return false;
        }

        // LB28a, the aksara cluster rules. U+25CC DOTTED CIRCLE carries class
        // AL and stands in for a cluster base throughout.
        var leftIsAksaraBase = EffIn(left, Lb.Ak, Lb.As)
            || (s.EffPrevCp == DottedCircle && s.EffPrev == Lb.Al);
        if (EffIn(left, Lb.Ap)
            && (eff is Lb.Ak or Lb.As || currentCp == DottedCircle))
        {
            return false;
        }

        if (leftIsAksaraBase && eff is Lb.Vf or Lb.Vi)
        {
            return false;
        }

        if (s.EffPrev == Lb.Vi
            && (EffIn(s.EffPrevPrev, Lb.Ak, Lb.As)
                || (s.EffPrevPrev is not null
                    && s.EffPrevPrevCp == DottedCircle))
            && (eff == Lb.Ak || currentCp == DottedCircle))
        {
            return false;
        }

        if (leftIsAksaraBase
            && (eff is Lb.Ak or Lb.As || currentCp == DottedCircle)
            && NextSignificantIsVf(pairs, ahead))
        {
            return false;
        }

        // LB29
        if ((eff is Lb.Al or Lb.Hl) && EffIn(left, Lb.Is))
        {
            return false;
        }

        // LB30, where the bracket must not be East Asian Fullwidth, Wide or
        // Halfwidth.
        if (eff == Lb.Op && EffIn(left, Lb.Al, Lb.Hl, Lb.Nu)
            && !IsEastAsianFullWide(currentCp))
        {
            return false;
        }

        if ((eff is Lb.Al or Lb.Hl or Lb.Nu) && EffIn(left, Lb.Cp)
            && !IsEastAsianFullWide(prevCp))
        {
            return false;
        }

        // LB30a
        if (eff == Lb.Ri && s.RiRun % 2 == 1)
        {
            return false;
        }

        // LB30b
        if (eff == Lb.Em && EffIn(left, Lb.Eb))
        {
            return false;
        }

        if (eff == Lb.Em && s.EffPrev is not null)
        {
            var previous = s.EffPrevCp;
            if (LineBreakTables.IsExtendedPictographic(previous)
                && LineBreakTables.CategoryOf(previous) == Gc.Cn)
            {
                return false;
            }
        }

        // LB31
        return true;
    }

    /// <summary>
    /// One break-opportunity flag per boundary of the code point sequence, so
    /// a sequence of n code points yields n + 1 flags -- the shape the Lean
    /// <c>lineBreaks_length</c> theorem fixes. Entry 0 is false, LB2
    /// forbidding a break at the start of text, and entry n is true per LB3,
    /// which requires one at the end.
    /// </summary>
    public static bool[] LineBreaks(IReadOnlyList<int> cps)
    {
        var pairs = new Classified[cps.Count];
        for (var i = 0; i < cps.Count; i++)
        {
            var cp = (uint)cps[i];
            pairs[i] = new Classified(cp, ResolvedClass(cp));
        }

        var breaks = new bool[pairs.Length + 1];
        var s = default(Snapshot);
        for (var i = 0; i < pairs.Length; i++)
        {
            breaks[i] = i != 0 && BreaksBefore(pairs[i - 1], pairs, i, s);
            s = Advance(s, pairs[i].Cp, pairs[i].Class);
        }

        breaks[pairs.Length] = true; // LB3
        return breaks;
    }

    /// <summary>
    /// The code point sequence split at every break opportunity -- the runs a
    /// renderer may place on separate lines.
    /// </summary>
    public static List<List<int>> LineRuns(IReadOnlyList<int> cps)
    {
        var breaks = LineBreaks(cps);
        var runs = new List<List<int>>();
        var current = new List<int>();
        for (var i = 0; i < cps.Count; i++)
        {
            current.Add(cps[i]);
            if (breaks[i + 1])
            {
                runs.Add(current);
                current = [];
            }
        }

        if (current.Count > 0)
        {
            runs.Add(current);
        }

        return runs;
    }
}
