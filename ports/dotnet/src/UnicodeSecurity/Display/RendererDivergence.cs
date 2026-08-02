namespace UnicodeSecurity;

// renderer-divergence (D layer) — detection of codepoint/sequence shapes known
// to render differently across font + terminal + browser stacks (display-layer
// detector).
//
// Direct port of the verified Rust reference implementation, itself a
// byte-faithful transliteration of Unicode/Security/Display/RendererDivergence.lean.
//
// Threat model. An adversary crafts content that renders one way in the
// auditor's renderer (a benign glyph or an empty span) and a different way in
// the consumer's renderer (a misleading glyph, a wider glyph, or a different
// sequence). This is the "fingerprint stability" family — clear inputs render
// the same across the renderer cohort the Standard documents as stable.
//
// What the detector draws. A heuristic three-value split, surfaced through the
// universal clear/hazard carrier: an input is clear when none of the documented
// variance triggers fire, and otherwise is classified by the first trigger in
// priority order — combining-mark stack overflow, variation-selector presence,
// an unregistered ZWJ shape, fullwidth/halfwidth display, or mixed direction. It
// reuses the port's own tables (the variation-selector set from the
// variation-selector-payload detector, the grapheme Extend class from the UAX
// #29 segmenter, the RGI ZWJ registry from the emoji-zwj-integrity detector, and
// the strong-bidi classes from the rtl-injection detector), never a host
// rendering or shaping library.
//
// Sub-threats (priority order):
//   1. CombiningStackOverflow    Zalgo-like combining-mark stack >= 4 on a base.
//   2. VariationSelectorVariance any variation selector present.
//   3. UnregisteredZwjVariance   ZWJ-containing input not in the RGI ZWJ set.
//   4. FullwidthVariance         a fullwidth/halfwidth codepoint present.
//   5. MixedDirectionVariance    both strong-LTR and strong-RTL codepoints.
public static partial class Security
{
    public static class RendererDivergence
    {
        // ─────────────────────────────────────────────────────────────────
        // §1 Constants
        // ─────────────────────────────────────────────────────────────────

        /// <summary>The combining-mark stack depth (on a single base) at or
        /// beyond which the input is treated as a Zalgo-style rendering-variance
        /// hazard.</summary>
        public const int MinCombiningStack = 4;

        /// <summary>The ZERO WIDTH JOINER codepoint.</summary>
        public const int Zwj = 0x200D;

        // ─────────────────────────────────────────────────────────────────
        // §2 Types
        // ─────────────────────────────────────────────────────────────────

        /// <summary>Sub-threat enumeration for RendererDivergence, in priority
        /// order. Each variant overrides <see cref="Tag"/>, so the fixture-row
        /// tag is resolved polymorphically with no catch-all.</summary>
        public abstract record SubThreat
        {
            /// <summary>Fixture-row tag string for this sub-threat (matches the
            /// Lean SubThreat.tag).</summary>
            public abstract string Tag { get; }
        }

        /// <summary>A combining-mark stack of <see cref="StackLen"/> marks on the
        /// base at <see cref="BasePos"/>.</summary>
        public sealed record CombiningStackOverflow(int BasePos, int StackLen) : SubThreat
        {
            public override string Tag => "CombiningStackOverflow";
        }

        /// <summary>A variation selector at <see cref="FirstVsPos"/> (codepoint
        /// <see cref="FirstVsCp"/>).</summary>
        public sealed record VariationSelectorVariance(int FirstVsPos, int FirstVsCp) : SubThreat
        {
            public override string Tag => "VariationSelectorVariance";
        }

        /// <summary>A ZWJ-containing input not present in the registered RGI ZWJ
        /// set. <see cref="FirstZwjPos"/> is the position of the first
        /// ZWJ.</summary>
        public sealed record UnregisteredZwjVariance(int FirstZwjPos) : SubThreat
        {
            public override string Tag => "UnregisteredZwjVariance";
        }

        /// <summary>A fullwidth/halfwidth codepoint at <see cref="FirstFwPos"/>
        /// (codepoint <see cref="FirstFwCp"/>).</summary>
        public sealed record FullwidthVariance(int FirstFwPos, int FirstFwCp) : SubThreat
        {
            public override string Tag => "FullwidthVariance";
        }

        /// <summary>Both strong-LTR and strong-RTL codepoints in one input.
        /// <see cref="LtrCount"/> and <see cref="RtlCount"/> are the strong-bidi
        /// counts.</summary>
        public sealed record MixedDirectionVariance(int LtrCount, int RtlCount) : SubThreat
        {
            public override string Tag => "MixedDirectionVariance";
        }

        /// <summary>Top-level classification (stable = <see cref="Clear"/>).</summary>
        public abstract record Classification
        {
            /// <summary>True iff the classification is Clear (i.e. stable).</summary>
            public abstract bool IsClear { get; }

            /// <summary>Human-facing tag for a hazard, or null when clear.</summary>
            public abstract string? Tag { get; }

            /// <summary>Implicated positions (empty when clear).</summary>
            public abstract IReadOnlyList<int> Positions { get; }

            /// <summary>Fully-qualified reason code
            /// (unicode.security.D.renderer-divergence.&lt;tag&gt;) routed through
            /// the port's shared reason-code machinery, or null when
            /// clear.</summary>
            public string? ReasonCode =>
                Tag is null ? null : Security.ReasonCode(Family.RendererDivergence, Tag);
        }

        /// <summary>Rendering is consistent across the documented renderer
        /// cohort.</summary>
        public sealed record Clear : Classification
        {
            public override bool IsClear => true;
            public override string? Tag => null;
            public override IReadOnlyList<int> Positions => System.Array.Empty<int>();
        }

        /// <summary>A documented variance mode fired: the sub-threat, the
        /// implicated positions, and the (always-empty for this detector)
        /// decoded-byte projection, kept for shape parity with the Lean
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
            int VsCount,
            int CombiningCount,
            int FullwidthCount,
            bool HasZwj,
            int StrongLtrCount,
            int StrongRtlCount);

        // ─────────────────────────────────────────────────────────────────
        // §3 Core predicates
        // ─────────────────────────────────────────────────────────────────

        /// <summary>True iff <paramref name="cp"/> is a variation selector
        /// (reuses the variation-selector-payload detector's own
        /// predicate).</summary>
        public static bool IsVariationSelector(int cp) => Security.IsVariationSelector(cp);

        /// <summary>True iff <paramref name="cp"/> is the ZWJ codepoint.</summary>
        public static bool IsZwj(int cp) => cp == Zwj;

        /// <summary>True iff <paramref name="cp"/> is in the Halfwidth/Fullwidth
        /// Forms block (reuses the homoglyph detector's IsFullwidthHalfwidth,
        /// which is exactly U+FF01..U+FFEF).</summary>
        public static bool IsFullwidthHalfwidth(int cp) => Security.IsFullwidthHalfwidth(cp);

        /// <summary>True iff <paramref name="cp"/> has
        /// Grapheme_Cluster_Break = Extend (reuses the UAX #29 segmenter's GCB
        /// table).</summary>
        public static bool IsGraphemeExtend(int cp) =>
            Segmentation.Grapheme.LookupGcb((uint)cp) == Segmentation.Gcb.Extend;

        // ─────────────────────────────────────────────────────────────────
        // §4 Sub-detectors
        // ─────────────────────────────────────────────────────────────────

        private static int CountVs(IReadOnlyList<int> input)
        {
            var count = 0;
            foreach (var cp in input)
            {
                if (IsVariationSelector(cp)) count++;
            }
            return count;
        }

        private static int CountCombining(IReadOnlyList<int> input)
        {
            var count = 0;
            foreach (var cp in input)
            {
                if (IsGraphemeExtend(cp)) count++;
            }
            return count;
        }

        private static int CountFullwidth(IReadOnlyList<int> input)
        {
            var count = 0;
            foreach (var cp in input)
            {
                if (IsFullwidthHalfwidth(cp)) count++;
            }
            return count;
        }

        private static bool InputHasZwj(IReadOnlyList<int> input)
        {
            foreach (var cp in input)
            {
                if (IsZwj(cp)) return true;
            }
            return false;
        }

        private static int CountStrongLtr(IReadOnlyList<int> input)
        {
            var count = 0;
            foreach (var cp in input)
            {
                if (Security.IsStrongLtr(cp)) count++;
            }
            return count;
        }

        private static int CountStrongRtl(IReadOnlyList<int> input)
        {
            var count = 0;
            foreach (var cp in input)
            {
                if (Security.IsStrongRtl(cp)) count++;
            }
            return count;
        }

        /// <summary>Position and codepoint of the first variation selector, or
        /// null when none is present.</summary>
        private static (int Pos, int Cp)? FirstVsPos(IReadOnlyList<int> input)
        {
            for (var i = 0; i < input.Count; i++)
            {
                if (IsVariationSelector(input[i])) return (i, input[i]);
            }
            return null;
        }

        /// <summary>Position of the first ZWJ, or null when none is
        /// present.</summary>
        private static int? FirstZwjPos(IReadOnlyList<int> input)
        {
            for (var i = 0; i < input.Count; i++)
            {
                if (IsZwj(input[i])) return i;
            }
            return null;
        }

        /// <summary>Position and codepoint of the first fullwidth/halfwidth
        /// codepoint, or null when none is present.</summary>
        private static (int Pos, int Cp)? FirstFullwidthPos(IReadOnlyList<int> input)
        {
            for (var i = 0; i < input.Count; i++)
            {
                if (IsFullwidthHalfwidth(input[i])) return (i, input[i]);
            }
            return null;
        }

        /// <summary>The first base position (a non-Extend codepoint) immediately
        /// followed by exactly <paramref name="minStack"/> consecutive Extend
        /// codepoints. Returns (basePos, minStack) on hit, null
        /// otherwise.</summary>
        private static (int BasePos, int StackLen)? FirstCombiningStack(IReadOnlyList<int> input, int minStack)
        {
            for (var idx = 0; idx < input.Count; idx++)
            {
                if (IsGraphemeExtend(input[idx])) continue;
                var following = new List<int>();
                for (var j = idx + 1; j < input.Count && following.Count < minStack; j++)
                {
                    following.Add(input[j]);
                }
                if (following.Count == minStack && following.All(IsGraphemeExtend))
                {
                    return (idx, minStack);
                }
            }
            return null;
        }

        // ─────────────────────────────────────────────────────────────────
        // §5 Top-level detection
        // ─────────────────────────────────────────────────────────────────

        /// <summary>The RendererDivergence detection function.</summary>
        public static Verdict Detect(IReadOnlyList<int> input)
        {
            var vsCount = CountVs(input);
            var combiningCount = CountCombining(input);
            var fullwidthCount = CountFullwidth(input);
            var hasZwj = InputHasZwj(input);
            var ltrCount = CountStrongLtr(input);
            var rtlCount = CountStrongRtl(input);

            Classification classification;
            // Priority 1: combining-mark stack overflow (Zalgo).
            if (FirstCombiningStack(input, MinCombiningStack) is (int basePos, int stackLen))
            {
                classification = new Hazard(
                    new CombiningStackOverflow(basePos, stackLen),
                    new List<int> { basePos },
                    new List<int>());
            }
            // Priority 2: any variation selector triggers presentation variance.
            else if (FirstVsPos(input) is (int vsPos, int vsCp))
            {
                classification = new Hazard(
                    new VariationSelectorVariance(vsPos, vsCp),
                    new List<int> { vsPos },
                    new List<int>());
            }
            // Priority 3: ZWJ-containing input not in the registered RGI set.
            else if (hasZwj && !EmojiZwjIntegrity.IsRegisteredZwjSequence(input))
            {
                if (FirstZwjPos(input) is int zwjPos)
                {
                    classification = new Hazard(
                        new UnregisteredZwjVariance(zwjPos),
                        new List<int> { zwjPos },
                        new List<int>());
                }
                else
                {
                    classification = new Clear();
                }
            }
            // Priority 4: fullwidth/halfwidth.
            else if (FirstFullwidthPos(input) is (int fwPos, int fwCp))
            {
                classification = new Hazard(
                    new FullwidthVariance(fwPos, fwCp),
                    new List<int> { fwPos },
                    new List<int>());
            }
            // Priority 5: mixed direction.
            else if (ltrCount > 0 && rtlCount > 0)
            {
                classification = new Hazard(
                    new MixedDirectionVariance(ltrCount, rtlCount),
                    new List<int>(),
                    new List<int>());
            }
            else
            {
                classification = new Clear();
            }

            return new Verdict(
                input.ToList(),
                classification,
                vsCount,
                combiningCount,
                fullwidthCount,
                hasZwj,
                ltrCount,
                rtlCount);
        }
    }
}
