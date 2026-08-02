namespace UnicodeSecurity;

// stream-safe-violation (F layer) — inputs whose consecutive non-starter run
// exceeds the UAX #15 §13 streamSafeLimit of 30. Such an input (the canonical
// "Zalgo" shape, a single base codepoint followed by a long combining-mark run)
// forces unbounded combining-mark buffers in receiver-side streaming
// normalization (toNFC / toNFD / toNFKC / toNFKD) and is a known DoS vector.
//
// Direct port of ports/rust/src/security/form/stream_safe_violation.rs, itself a
// port of Unicode/Security/Form/StreamSafeViolation.lean. UAX #15 §13 defines
// Stream-Safe Text Format as the remediation: insert U+034F COMBINING GRAPHEME
// JOINER (a starter) after every 30 consecutive non-starters, which bounds the
// normalization buffer. StreamSafeViolation is the security verdict over the
// same property — distinct from RendererDivergence's combiningStackOverflow (the
// cosmetic 4-mark threshold), this is the spec-mandated DoS-prevention bound.
//
// A codepoint is a non-starter iff its Canonical_Combining_Class is non-zero
// (UAX #15 D49). This module reads CCC from the port's own bundled UCD table via
// Security.CanonicalCombiningClass, never a host normalizer.
//
// Sub-threat: StreamSafeOverrun(basePos, runLen) — the first non-starter run
// whose length exceeds streamSafeLimit. basePos is the index of that run's first
// non-starter codepoint.
public static partial class Security
{
    public static class StreamSafeViolation
    {
        // ─────────────────────────────────────────────────────────────────
        // §1 Run inventory
        // ─────────────────────────────────────────────────────────────────

        /// <summary>UAX #15 §13 Stream-Safe limit: the maximum number of
        /// consecutive non-starters permitted before a COMBINING GRAPHEME JOINER
        /// must be inserted.</summary>
        public const int StreamSafeLimit = 30;

        /// <summary>True iff <paramref name="cp"/> is a non-starter — a codepoint
        /// with non-zero Canonical_Combining_Class (UAX #15 D49). Starters have
        /// CCC = 0. Reads CCC from the port's own bundled UCD table, never a host
        /// normalizer.</summary>
        private static bool IsNonStarter(int cp) => Security.CanonicalCombiningClass(cp) != 0;

        /// <summary>Inventory of (startIndex, length) for every maximal
        /// non-starter run in <paramref name="input"/>. Mirrors collectRunsGo: a
        /// run opens on the first non-starter, its start index is fixed to that
        /// codepoint's absolute index, and it closes (emitting its (start, length)
        /// pair) on the next starter or at end of input.</summary>
        private static List<(int Start, int Length)> NonStarterRuns(IReadOnlyList<int> input)
        {
            var runs = new List<(int Start, int Length)>();
            int? curStart = null;
            var curLen = 0;
            for (var i = 0; i < input.Count; i++)
            {
                if (IsNonStarter(input[i]))
                {
                    if (curStart is null) curStart = i;
                    curLen++;
                }
                else
                {
                    if (curStart is int s) runs.Add((s, curLen));
                    curStart = null;
                    curLen = 0;
                }
            }
            if (curStart is int last) runs.Add((last, curLen));
            return runs;
        }

        /// <summary>First non-starter run whose length exceeds
        /// <see cref="StreamSafeLimit"/>, as (startIndex, length), or null when no
        /// run overruns.</summary>
        private static (int Start, int Length)? FirstOverrun(IReadOnlyList<int> input)
        {
            foreach (var run in NonStarterRuns(input))
            {
                if (run.Length > StreamSafeLimit) return run;
            }
            return null;
        }

        /// <summary>Longest non-starter run length in <paramref name="input"/>.</summary>
        private static int MaxRunLen(IReadOnlyList<int> input)
        {
            var acc = 0;
            foreach (var run in NonStarterRuns(input))
            {
                if (run.Length > acc) acc = run.Length;
            }
            return acc;
        }

        /// <summary>Number of distinct non-starter runs that exceed
        /// <see cref="StreamSafeLimit"/>.</summary>
        private static int OverrunCount(IReadOnlyList<int> input)
        {
            var acc = 0;
            foreach (var run in NonStarterRuns(input))
            {
                if (run.Length > StreamSafeLimit) acc++;
            }
            return acc;
        }

        /// <summary>Total non-starter codepoints in <paramref name="input"/> (sum
        /// of all run lengths).</summary>
        private static int TotalNonStarters(IReadOnlyList<int> input)
        {
            var acc = 0;
            foreach (var run in NonStarterRuns(input)) acc += run.Length;
            return acc;
        }

        // ─────────────────────────────────────────────────────────────────
        // §2 Types
        // ─────────────────────────────────────────────────────────────────

        /// <summary>Sub-threats this detector can fire.</summary>
        public abstract record SubThreat
        {
            /// <summary>Human-facing classification tag for this sub-threat.</summary>
            public abstract string Tag { get; }
        }

        /// <summary>The first non-starter run whose length exceeds
        /// <see cref="StreamSafeLimit"/>. <see cref="BasePos"/> is the index of
        /// the run's first non-starter codepoint; <see cref="RunLen"/> is the
        /// run's length.</summary>
        public sealed record StreamSafeOverrun(int BasePos, int RunLen) : SubThreat
        {
            public override string Tag => "StreamSafeOverrun";
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
            /// (unicode.security.F.stream-safe-violation.&lt;tag&gt;) routed
            /// through the port's shared reason-code machinery, or null when
            /// clear.</summary>
            public string? ReasonCode =>
                Tag is null ? null : Security.ReasonCode(Family.StreamSafeViolation, Tag);
        }

        /// <summary>No non-starter run exceeds the Stream-Safe limit.</summary>
        public sealed record Clear : Classification
        {
            public override bool IsClear => true;
            public override string? Tag => null;
            public override IReadOnlyList<int> Positions => System.Array.Empty<int>();
        }

        /// <summary>A hazard was found: the sub-threat, its implicated positions,
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

        /// <summary>F-layer verdict — the structured output of <see cref="Detect"/>.
        /// The run-inventory summaries (<see cref="MaxRunLength"/>,
        /// <see cref="OverrunCountValue"/>, <see cref="TotalNonStartersValue"/>)
        /// are exposed so downstream callers can size the buffer pressure a
        /// streaming normalizer would see.</summary>
        public sealed record Verdict(
            IReadOnlyList<int> Input,
            Classification Classify,
            int MaxRunLength,
            int OverrunCountValue,
            int TotalNonStartersValue);

        // ─────────────────────────────────────────────────────────────────
        // §3 Top-level detection
        // ─────────────────────────────────────────────────────────────────

        /// <summary>The F-layer detection function. Fires
        /// <see cref="StreamSafeOverrun"/> on the first non-starter run whose
        /// length exceeds <see cref="StreamSafeLimit"/>.</summary>
        public static Verdict Detect(IReadOnlyList<int> input)
        {
            Classification classification;
            if (FirstOverrun(input) is (int basePos, int runLen))
            {
                classification = new Hazard(
                    new StreamSafeOverrun(basePos, runLen),
                    new List<int> { basePos },
                    System.Array.Empty<byte>());
            }
            else
            {
                classification = new Clear();
            }
            return new Verdict(
                input.ToList(),
                classification,
                MaxRunLen(input),
                OverrunCount(input),
                TotalNonStarters(input));
        }
    }
}
