namespace UnicodeSecurity;

// filename-disguise (D layer) — detection of filename/extension disguise attacks
// where the visible extension differs from the byte extension (display-layer
// detector).
//
// Direct port of the verified Rust reference implementation, itself a
// byte-faithful transliteration of Unicode/Security/Display/FilenameDisguise.lean.
//
// Threat model. An adversary delivers a file whose rendered name looks like a
// benign type (document.txt) but whose actual byte extension is executable — the
// canonical attack inserts U+202E RIGHT-TO-LEFT OVERRIDE so document<RLO>txt.exe
// renders as document exe.txt.
//
// Detection is presentation- and language-agnostic: it surfaces every codepoint
// that could cause display-vs-byte divergence in the filename — any bidi
// format-control anywhere, and any fullwidth/halfwidth or combining (grapheme
// Extend) codepoint in the extension region (after the last dot). Native-RTL
// names with no bidi controls clear. It reuses the port's own predicates (the
// bidi-format-control set, the grapheme Extend class from the UAX #29 segmenter,
// and the fullwidth range), never a host filesystem or rendering library.
//
// Sub-threats (priority order):
//   1. RloFlip            any bidi format-control in the input.
//   2. WidthClassExt      a fullwidth/halfwidth codepoint in the extension.
//   3. CombiningInExt     a combining (Extend) codepoint in the extension.
//   4. MultipleExtensions >= 3 dots (advisory; e.g. legitimate .tar.gz.sig).
public static partial class Security
{
    public static class FilenameDisguise
    {
        // ─────────────────────────────────────────────────────────────────
        // §1 Types
        // ─────────────────────────────────────────────────────────────────

        /// <summary>Sub-threat enumeration for FilenameDisguise, in priority
        /// order. Each variant overrides <see cref="Tag"/>, so the fixture-row
        /// tag is resolved polymorphically with no catch-all.</summary>
        public abstract record SubThreat
        {
            /// <summary>Fixture-row tag string for this sub-threat (matches the
            /// Lean SubThreat.tag).</summary>
            public abstract string Tag { get; }
        }

        /// <summary>A bidi format-control at <see cref="Position"/> (codepoint
        /// <see cref="ControlCp"/>).</summary>
        public sealed record RloFlip(int Position, int ControlCp) : SubThreat
        {
            public override string Tag => "RloFlip";
        }

        /// <summary>A fullwidth/halfwidth codepoint in the extension at
        /// <see cref="Position"/> (codepoint <see cref="Cp"/>).</summary>
        public sealed record WidthClassExt(int Position, int Cp) : SubThreat
        {
            public override string Tag => "WidthClassExt";
        }

        /// <summary>A combining (grapheme Extend) codepoint in the extension at
        /// <see cref="Position"/> (codepoint <see cref="Cp"/>).</summary>
        public sealed record CombiningInExt(int Position, int Cp) : SubThreat
        {
            public override string Tag => "CombiningInExt";
        }

        /// <summary>Three or more dot separators (advisory).
        /// <see cref="DotCount"/> is the number of dots.</summary>
        public sealed record MultipleExtensions(int DotCount) : SubThreat
        {
            public override string Tag => "MultipleExtensions";
        }

        /// <summary>Top-level classification (no disguise trigger =
        /// <see cref="Clear"/>).</summary>
        public abstract record Classification
        {
            /// <summary>True iff the classification is Clear.</summary>
            public abstract bool IsClear { get; }

            /// <summary>Human-facing tag for a hazard, or null when clear.</summary>
            public abstract string? Tag { get; }

            /// <summary>Implicated positions (empty when clear).</summary>
            public abstract IReadOnlyList<int> Positions { get; }

            /// <summary>Fully-qualified reason code
            /// (unicode.security.D.filename-disguise.&lt;tag&gt;) routed through
            /// the port's shared reason-code machinery, or null when
            /// clear.</summary>
            public string? ReasonCode =>
                Tag is null ? null : Security.ReasonCode(Family.FilenameDisguise, Tag);
        }

        /// <summary>No disguise trigger present.</summary>
        public sealed record Clear : Classification
        {
            public override bool IsClear => true;
            public override string? Tag => null;
            public override IReadOnlyList<int> Positions => System.Array.Empty<int>();
        }

        /// <summary>A disguise trigger fired: the sub-threat, the implicated
        /// positions, and the (always-empty for this detector) decoded-byte
        /// projection, kept for shape parity with the Lean
        /// Classification.hazard.</summary>
        public sealed record Hazard(
            SubThreat Sub,
            IReadOnlyList<int> HazardPositions,
            IReadOnlyList<int> Decoded) : Classification
        {
            public override bool IsClear => false;
            public override string? Tag => Sub.Tag;
            public override IReadOnlyList<int> Positions => HazardPositions;
        }

        /// <summary>The structured output of <see cref="Detect"/> (mirrors the
        /// Lean Verdict).</summary>
        public sealed record Verdict(
            IReadOnlyList<int> Input,
            Classification Classify,
            IReadOnlyList<int> DotPositions,
            int? LastDotPos,
            int BidiControlCount,
            int FullwidthInExt,
            int CombiningInExtCount);

        // ─────────────────────────────────────────────────────────────────
        // §2 Core predicates
        // ─────────────────────────────────────────────────────────────────

        /// <summary>True iff <paramref name="cp"/> is U+002E FULL STOP (the
        /// extension separator).</summary>
        public static bool IsAsciiDot(int cp) => cp == 0x002E;

        /// <summary>True iff <paramref name="cp"/> is in the Halfwidth and
        /// Fullwidth Forms block (reuses the homoglyph detector's
        /// IsFullwidthHalfwidth, which is exactly U+FF01..U+FFEF).</summary>
        public static bool IsFullwidthHalfwidth(int cp) => Security.IsFullwidthHalfwidth(cp);

        /// <summary>True iff <paramref name="cp"/> is a bidi format-control
        /// (reuses the port's own IsBidiFormatControl predicate — the
        /// LRE/RLE/LRO/RLO/PDF/LRI/RLI/FSI/PDI set).</summary>
        public static bool IsBidiFormatControl(int cp) => Security.IsBidiFormatControl(cp);

        /// <summary>True iff <paramref name="cp"/> has
        /// Grapheme_Cluster_Break = Extend (reuses the UAX #29 segmenter's GCB
        /// table).</summary>
        public static bool IsGraphemeExtend(int cp) =>
            Segmentation.Grapheme.LookupGcb((uint)cp) == Segmentation.Gcb.Extend;

        // ─────────────────────────────────────────────────────────────────
        // §3 Sub-detectors
        // ─────────────────────────────────────────────────────────────────

        /// <summary>Positions of every dot in <paramref name="input"/>.</summary>
        private static List<int> DotPositions(IReadOnlyList<int> input)
        {
            var positions = new List<int>();
            for (var idx = 0; idx < input.Count; idx++)
            {
                if (IsAsciiDot(input[idx])) positions.Add(idx);
            }
            return positions;
        }

        /// <summary>Position and codepoint of the first bidi format-control, or
        /// null when none is present.</summary>
        private static (int Pos, int Cp)? FirstBidiControl(IReadOnlyList<int> input)
        {
            for (var idx = 0; idx < input.Count; idx++)
            {
                if (IsBidiFormatControl(input[idx])) return (idx, input[idx]);
            }
            return null;
        }

        /// <summary>Position and codepoint of the first fullwidth/halfwidth
        /// codepoint at or after <paramref name="start"/>, or null when none is
        /// present.</summary>
        private static (int Pos, int Cp)? FirstFullwidthFrom(IReadOnlyList<int> input, int start)
        {
            for (var idx = 0; idx < input.Count; idx++)
            {
                if (idx >= start && IsFullwidthHalfwidth(input[idx])) return (idx, input[idx]);
            }
            return null;
        }

        /// <summary>Position and codepoint of the first Extend codepoint at or
        /// after <paramref name="start"/>, or null when none is present.</summary>
        private static (int Pos, int Cp)? FirstExtendFrom(IReadOnlyList<int> input, int start)
        {
            for (var idx = 0; idx < input.Count; idx++)
            {
                if (idx >= start && IsGraphemeExtend(input[idx])) return (idx, input[idx]);
            }
            return null;
        }

        /// <summary>Count of fullwidth/halfwidth codepoints at or after
        /// <paramref name="start"/>.</summary>
        private static int CountFullwidthFrom(IReadOnlyList<int> input, int start)
        {
            var count = 0;
            for (var idx = 0; idx < input.Count; idx++)
            {
                if (idx >= start && IsFullwidthHalfwidth(input[idx])) count++;
            }
            return count;
        }

        /// <summary>Count of Extend codepoints at or after
        /// <paramref name="start"/>.</summary>
        private static int CountExtendFrom(IReadOnlyList<int> input, int start)
        {
            var count = 0;
            for (var idx = 0; idx < input.Count; idx++)
            {
                if (idx >= start && IsGraphemeExtend(input[idx])) count++;
            }
            return count;
        }

        private static int CountBidiControl(IReadOnlyList<int> input)
        {
            var count = 0;
            foreach (var cp in input)
            {
                if (IsBidiFormatControl(cp)) count++;
            }
            return count;
        }

        // ─────────────────────────────────────────────────────────────────
        // §4 Top-level detection
        // ─────────────────────────────────────────────────────────────────

        /// <summary>The FilenameDisguise detection function.</summary>
        public static Verdict Detect(IReadOnlyList<int> input)
        {
            var dots = DotPositions(input);
            int? lastDot = dots.Count == 0 ? null : dots[dots.Count - 1];
            var extStart = lastDot is int p ? p + 1 : input.Count;
            var bidiCount = CountBidiControl(input);
            var fwInExt = CountFullwidthFrom(input, extStart);
            var extInExt = CountExtendFrom(input, extStart);

            Classification classification;
            // Priority 1: any bidi format-control.
            if (FirstBidiControl(input) is (int ctlPos, int ctlCp))
            {
                classification = new Hazard(
                    new RloFlip(ctlPos, ctlCp),
                    new List<int> { ctlPos },
                    new List<int>());
            }
            // Priority 2: fullwidth/halfwidth in the extension.
            else if (FirstFullwidthFrom(input, extStart) is (int fwPos, int fwCp))
            {
                classification = new Hazard(
                    new WidthClassExt(fwPos, fwCp),
                    new List<int> { fwPos },
                    new List<int>());
            }
            // Priority 3: combining mark in the extension.
            else if (FirstExtendFrom(input, extStart) is (int exPos, int exCp))
            {
                classification = new Hazard(
                    new CombiningInExt(exPos, exCp),
                    new List<int> { exPos },
                    new List<int>());
            }
            // Priority 4: three or more extensions (advisory).
            else if (dots.Count >= 3)
            {
                classification = new Hazard(
                    new MultipleExtensions(dots.Count),
                    new List<int>(dots),
                    new List<int>());
            }
            else
            {
                classification = new Clear();
            }

            return new Verdict(
                input.ToList(),
                classification,
                dots,
                lastDot,
                bidiCount,
                fwInExt,
                extInExt);
        }
    }
}
