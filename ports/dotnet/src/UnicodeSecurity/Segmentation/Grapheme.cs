// UAX #29 default extended grapheme cluster segmentation.
//
// A transcription of the Lean algorithm
// Unicode.Segmentation.GraphemeBreak.graphemeBreaks by way of
// ports/rust/src/segmentation/grapheme.rs. The active Lean tree proves
// graphemeBreaks_eq_spec, relating that algorithm to the declarative UAX #29
// GB1-GB999 specification. The state fields, rule order, and transitions below
// mirror that reference exactly.
//
// The property tables (GraphemeTables) are grouped by property value as in the
// UCD source, not globally sorted by code point, so lookups scan linearly for
// the covering range — mirroring the verified Lean find?. Each class is a
// partition, so at most one range covers a code point and the first match is
// the only match.

namespace UnicodeSecurity.Segmentation;

/// <summary>UAX #29 default extended grapheme cluster segmentation.</summary>
public static class Grapheme
{
    /// <summary>
    /// Grapheme_Cluster_Break class of <paramref name="cp"/>,
    /// <see cref="Gcb.Other"/> when uncovered.
    /// </summary>
    public static Gcb LookupGcb(uint cp)
    {
        foreach (var (first, last, cls) in GraphemeTables.GcbRanges)
        {
            if (first <= cp && cp <= last)
            {
                return cls;
            }
        }
        return Gcb.Other;
    }

    /// <summary>
    /// Indic_Conjunct_Break class of <paramref name="cp"/>,
    /// <see cref="Incb.None"/> when uncovered.
    /// </summary>
    public static Incb LookupIncb(uint cp)
    {
        foreach (var (first, last, cls) in GraphemeTables.IncbRanges)
        {
            if (first <= cp && cp <= last)
            {
                return cls;
            }
        }
        return Incb.None;
    }

    /// <summary>Whether <paramref name="cp"/> has the Extended_Pictographic property.</summary>
    public static bool IsExtPict(uint cp)
    {
        foreach (var (first, last) in GraphemeTables.ExtPictRanges)
        {
            if (first <= cp && cp <= last)
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>GB11 left-context state: mirrors the Lean EPicState.</summary>
    private enum EpicState { None, AfterEp, AfterEpZwj }

    /// <summary>GB9c left-context state: mirrors the Lean InCBState.</summary>
    private enum IncbState { None, Consonant, Linker }

    /// <summary>Running scan state, mirroring the Lean State.</summary>
    private readonly struct State
    {
        public readonly Gcb? PrevClass;
        public readonly EpicState Epic;
        public readonly IncbState Incb;
        public readonly uint RiRun;

        public State(Gcb? prevClass, EpicState epic, IncbState incb, uint riRun)
        {
            PrevClass = prevClass;
            Epic = epic;
            Incb = incb;
            RiRun = riRun;
        }

        public static State Initial() => new(null, EpicState.None, IncbState.None, 0);
    }

    /// <summary>
    /// Whether a grapheme cluster break occurs immediately before
    /// <paramref name="cp"/> given the running state. Implements UAX #29
    /// GB1-GB999 in canonical order; first match wins, the trailing GB999
    /// breaks every otherwise-unmatched pair.
    /// </summary>
    private static bool ShouldBreakBefore(uint cp, in State s)
    {
        var bc = LookupGcb(cp);
        var incb = LookupIncb(cp);
        var isEp = IsExtPict(cp);
        if (s.PrevClass is not Gcb pc)
        {
            return true; // GB1: sot ÷
        }
        if (pc == Gcb.Cr && bc == Gcb.Lf)
        {
            return false; // GB3: CR × LF
        }
        if (pc == Gcb.Control || pc == Gcb.Cr || pc == Gcb.Lf)
        {
            return true; // GB4: (Control | CR | LF) ÷
        }
        if (bc == Gcb.Control || bc == Gcb.Cr || bc == Gcb.Lf)
        {
            return true; // GB5: ÷ (Control | CR | LF)
        }
        if (pc == Gcb.L && (bc == Gcb.L || bc == Gcb.V || bc == Gcb.Lv || bc == Gcb.Lvt))
        {
            return false; // GB6: L × (L | V | LV | LVT)
        }
        if ((pc == Gcb.Lv || pc == Gcb.V) && (bc == Gcb.V || bc == Gcb.T))
        {
            return false; // GB7: (LV | V) × (V | T)
        }
        if ((pc == Gcb.Lvt || pc == Gcb.T) && bc == Gcb.T)
        {
            return false; // GB8: (LVT | T) × T
        }
        if (bc == Gcb.Extend || bc == Gcb.Zwj)
        {
            return false; // GB9: × (Extend | ZWJ)
        }
        if (bc == Gcb.SpacingMark)
        {
            return false; // GB9a: × SpacingMark
        }
        if (pc == Gcb.Prepend)
        {
            return false; // GB9b: Prepend ×
        }
        if (s.Incb == IncbState.Linker && incb == Incb.Consonant)
        {
            return false; // GB9c: Consonant (Extend|Linker)* Linker (Extend|Linker)* × Consonant
        }
        if (s.Epic == EpicState.AfterEpZwj && isEp)
        {
            return false; // GB11: ExtPict Extend* ZWJ × ExtPict
        }
        if (bc == Gcb.RegionalIndicator && s.RiRun % 2 == 1)
        {
            return false; // GB12/GB13: odd-parity RI run extends
        }
        return true; // GB999: Any ÷ Any
    }

    /// <summary>Update the running state after consuming <paramref name="cp"/>. Mirrors the Lean advance.</summary>
    private static State Advance(uint cp, in State s)
    {
        var bc = LookupGcb(cp);
        var incb = LookupIncb(cp);
        var isEp = IsExtPict(cp);
        EpicState epic;
        if (isEp)
        {
            epic = EpicState.AfterEp;
        }
        else if (s.Epic == EpicState.AfterEp && bc == Gcb.Extend)
        {
            epic = EpicState.AfterEp;
        }
        else if (s.Epic == EpicState.AfterEp && bc == Gcb.Zwj)
        {
            epic = EpicState.AfterEpZwj;
        }
        else
        {
            epic = EpicState.None;
        }
        IncbState incbState;
        if (incb == Incb.Consonant)
        {
            incbState = IncbState.Consonant;
        }
        else if (s.Incb == IncbState.Consonant && incb == Incb.Linker)
        {
            incbState = IncbState.Linker;
        }
        else if (s.Incb == IncbState.Consonant && incb == Incb.Extend)
        {
            incbState = IncbState.Consonant;
        }
        else if (s.Incb == IncbState.Linker && incb == Incb.Linker)
        {
            incbState = IncbState.Linker;
        }
        else if (s.Incb == IncbState.Linker && incb == Incb.Extend)
        {
            incbState = IncbState.Linker;
        }
        else
        {
            incbState = IncbState.None;
        }
        var riRun = bc == Gcb.RegionalIndicator ? s.RiRun + 1 : 0;
        return new State(bc, epic, incbState, riRun);
    }

    /// <summary>
    /// Boundary mask of length <c>cps.Count + 1</c>. Entry <c>i</c> is
    /// <c>true</c> when a grapheme cluster break occurs immediately before
    /// position <c>i</c> — entry <c>0</c> is the GB1 start-of-text break, entry
    /// <c>cps.Count</c> the GB2 end-of-text break, both always <c>true</c>.
    /// Mirrors the Lean graphemeBreaks.
    /// </summary>
    public static bool[] GraphemeBreaks(IReadOnlyList<int> cps)
    {
        var bs = new bool[cps.Count + 1];
        var s = State.Initial();
        for (var i = 0; i < cps.Count; i++)
        {
            var cp = (uint)cps[i];
            bs[i] = ShouldBreakBefore(cp, s);
            s = Advance(cp, s);
        }
        bs[cps.Count] = true; // GB2: eot ÷
        return bs;
    }

    /// <summary>
    /// Split <paramref name="cps"/> into grapheme clusters (the code points
    /// between consecutive boundaries).
    /// </summary>
    public static List<List<int>> GraphemeClusters(IReadOnlyList<int> cps)
    {
        var breaks = GraphemeBreaks(cps);
        var outClusters = new List<List<int>>();
        var cur = new List<int>();
        for (var i = 0; i < cps.Count; i++)
        {
            if (breaks[i] && cur.Count > 0)
            {
                outClusters.Add(cur);
                cur = new List<int>();
            }
            cur.Add(cps[i]);
        }
        if (cur.Count > 0)
        {
            outClusters.Add(cur);
        }
        return outClusters;
    }
}
