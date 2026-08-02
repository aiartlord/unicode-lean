namespace UnicodeSecurity;

// case-expansion-mismatch (F layer) — codepoints whose UAX #21 default-locale
// case mapping changes the codepoint count.
//
// Threat model. An attacker submits text whose case-mapped form has a different
// codepoint count than the input. A receiver that fixes a 16-byte username
// column and stores toUpper(username) overflows when the user picks
// "ßßßßßßßß" (8 in → 16 stored); a receiver that checks len(stored) == len(input)
// rejects valid case-insensitive logins whose names expand under folding.
// Examples: U+00DF ß → "SS", U+FB01 ﬁ → "FI", U+0130 İ → toLower "i̇" (i + U+0307).
//
// Distinct from LocaleCaseInversion (case mapping that changes ACROSS locales):
// this fires on shapes whose mapping is locale-stable but length-changing under
// the default locale itself.
//
// Direct port of the verified Rust reference, itself a port of the Lean spec. It
// reuses the port's own UAX #21 case mapping (Security.UpperCodepoint /
// Security.LowerCodepoint, which evaluate the SpecialCasing context predicates),
// never a host casing library.
//
// Sub-threats (priority order):
//   1. UpperExpansion — first position whose default upperCodepoint yields > 1 cp.
//   2. LowerExpansion — first position whose default lowerCodepoint yields > 1 cp
//      (reached only when no upper expansion fires first).
public static partial class Security
{
    public static class CaseExpansionMismatch
    {
        // ─────────────────────────────────────────────────────────────────
        // §1 Per-position expansion scan
        // ─────────────────────────────────────────────────────────────────

        // The preceding codepoints nearest-first (input[..i] reversed) and the
        // following ones (input[i+1..]), the context the SpecialCasing predicates
        // read.
        private static (List<int> RevPrefix, List<int> Suffix) ContextAt(IReadOnlyList<int> input, int i)
        {
            var revPrefix = new List<int>();
            for (var j = i - 1; j >= 0; j--) revPrefix.Add(input[j]);
            var suffix = new List<int>();
            for (var j = i + 1; j < input.Count; j++) suffix.Add(input[j]);
            return (revPrefix, suffix);
        }

        /// <summary>The default-locale uppercase expansion length at position
        /// <paramref name="i"/>.</summary>
        private static int UpperLenAt(IReadOnlyList<int> input, int i)
        {
            var (revPrefix, suffix) = ContextAt(input, i);
            return Security.UpperCodepoint(CasingLocale.Default, revPrefix, suffix, input[i]).Count;
        }

        /// <summary>The default-locale lowercase expansion length at position
        /// <paramref name="i"/>.</summary>
        private static int LowerLenAt(IReadOnlyList<int> input, int i)
        {
            var (revPrefix, suffix) = ContextAt(input, i);
            return Security.LowerCodepoint(CasingLocale.Default, revPrefix, suffix, input[i]).Count;
        }

        /// <summary>First position whose default uppercase mapping expands to > 1
        /// codepoint, as (position, codepoint, expansionLen), or null.</summary>
        private static (int Pos, int Cp, int Len)? FirstUpperExpansion(IReadOnlyList<int> input)
        {
            for (var i = 0; i < input.Count; i++)
            {
                var len = UpperLenAt(input, i);
                if (len > 1) return (i, input[i], len);
            }
            return null;
        }

        /// <summary>First position whose default lowercase mapping expands to > 1
        /// codepoint, as (position, codepoint, expansionLen), or null.</summary>
        private static (int Pos, int Cp, int Len)? FirstLowerExpansion(IReadOnlyList<int> input)
        {
            for (var i = 0; i < input.Count; i++)
            {
                var len = LowerLenAt(input, i);
                if (len > 1) return (i, input[i], len);
            }
            return null;
        }

        /// <summary>Count of positions whose default uppercase mapping expands.</summary>
        private static int UpperExpansionCount(IReadOnlyList<int> input)
        {
            var acc = 0;
            for (var i = 0; i < input.Count; i++)
            {
                if (UpperLenAt(input, i) > 1) acc++;
            }
            return acc;
        }

        /// <summary>Count of positions whose default lowercase mapping expands.</summary>
        private static int LowerExpansionCount(IReadOnlyList<int> input)
        {
            var acc = 0;
            for (var i = 0; i < input.Count; i++)
            {
                if (LowerLenAt(input, i) > 1) acc++;
            }
            return acc;
        }

        /// <summary>Maximum case-mapped expansion length across all positions (the
        /// per-position max of the upper and lower mapped lengths); 0 for empty
        /// input.</summary>
        private static int MaxExpansionLen(IReadOnlyList<int> input)
        {
            var acc = 0;
            for (var i = 0; i < input.Count; i++)
            {
                var len = System.Math.Max(UpperLenAt(input, i), LowerLenAt(input, i));
                if (len > acc) acc = len;
            }
            return acc;
        }

        // ─────────────────────────────────────────────────────────────────
        // §2 Types
        // ─────────────────────────────────────────────────────────────────

        /// <summary>Sub-threats this detector can fire, in priority order.</summary>
        public abstract record SubThreat
        {
            /// <summary>Human-facing classification tag for this sub-threat.</summary>
            public abstract string Tag { get; }
        }

        /// <summary>A codepoint whose default uppercase mapping expands, at
        /// <see cref="BasePos"/>. <see cref="Cp"/> is the expanding codepoint;
        /// <see cref="ExpansionLen"/> is the uppercase expansion length (&gt; 1).</summary>
        public sealed record UpperExpansion(int BasePos, int Cp, int ExpansionLen) : SubThreat
        {
            public override string Tag => "UpperExpansion";
        }

        /// <summary>A codepoint whose default lowercase mapping expands, at
        /// <see cref="BasePos"/>. <see cref="Cp"/> is the expanding codepoint;
        /// <see cref="ExpansionLen"/> is the lowercase expansion length (&gt; 1).</summary>
        public sealed record LowerExpansion(int BasePos, int Cp, int ExpansionLen) : SubThreat
        {
            public override string Tag => "LowerExpansion";
        }

        /// <summary>Top-level F-layer classification.</summary>
        public abstract record Classification
        {
            /// <summary>True iff the input is clear.</summary>
            public abstract bool IsClear { get; }

            /// <summary>Human-facing tag for a hazard, or null when clear.</summary>
            public abstract string? Tag { get; }

            /// <summary>Implicated positions (empty when clear).</summary>
            public abstract IReadOnlyList<int> Positions { get; }

            /// <summary>Fully-qualified reason code
            /// (unicode.security.F.case-expansion-mismatch.&lt;tag&gt;) routed
            /// through the port's shared reason-code machinery, or null when
            /// clear.</summary>
            public string? ReasonCode =>
                Tag is null ? null : Security.ReasonCode(Family.CaseExpansionMismatch, Tag);
        }

        /// <summary>No case-mapped expansion present.</summary>
        public sealed record Clear : Classification
        {
            public override bool IsClear => true;
            public override string? Tag => null;
            public override IReadOnlyList<int> Positions => System.Array.Empty<int>();
        }

        /// <summary>An expansion fired: the sub-threat, its implicated positions,
        /// and any decoded bytes (always empty for this detector — the field
        /// mirrors the spec's Classification.hazard shape).</summary>
        public sealed record Hazard(
            SubThreat Sub,
            IReadOnlyList<int> HazardPositions,
            IReadOnlyList<byte> Decoded) : Classification
        {
            public override bool IsClear => false;
            public override string? Tag => Sub.Tag;
            public override IReadOnlyList<int> Positions => HazardPositions;
        }

        /// <summary>F-layer verdict — the structured output of <see cref="Detect"/>.</summary>
        public sealed record Verdict(
            IReadOnlyList<int> Input,
            Classification Classify,
            int UpperExpansionCountValue,
            int LowerExpansionCountValue,
            int MaxExpansionLenValue);

        // ─────────────────────────────────────────────────────────────────
        // §3 Top-level detection
        // ─────────────────────────────────────────────────────────────────

        /// <summary>The F-layer detection function. Priority 1: an uppercase
        /// expansion; priority 2 (only when no upper expansion fires): a lowercase
        /// expansion; else <see cref="Clear"/>.</summary>
        public static Verdict Detect(IReadOnlyList<int> input)
        {
            Classification classification;
            if (FirstUpperExpansion(input) is (int upperPos, int upperCp, int upperLen))
            {
                classification = new Hazard(
                    new UpperExpansion(upperPos, upperCp, upperLen),
                    new List<int> { upperPos },
                    System.Array.Empty<byte>());
            }
            else if (FirstLowerExpansion(input) is (int lowerPos, int lowerCp, int lowerLen))
            {
                classification = new Hazard(
                    new LowerExpansion(lowerPos, lowerCp, lowerLen),
                    new List<int> { lowerPos },
                    System.Array.Empty<byte>());
            }
            else
            {
                classification = new Clear();
            }
            return new Verdict(
                input.ToList(),
                classification,
                UpperExpansionCount(input),
                LowerExpansionCount(input),
                MaxExpansionLen(input));
        }
    }
}
