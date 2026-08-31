namespace UnicodeSecurity;

// source-display-divergence (D layer) — the aggregate "what a reviewer sees
// differs from what the machine runs" detector (display-layer aggregator).
//
// Direct port of the verified Rust reference implementation, itself a
// byte-faithful transliteration of
// Unicode/Security/Display/SourceDisplayDivergence.lean (detect +
// buildClassification).
//
// Threat model. Tier D1. A single covert or identity trick may be individually
// benign-looking, but any hit means the rendered source diverges from its
// logical content; two or more is a strong compound signal. This detector runs
// the five constituent detectors on the same codepoint stream and aggregates:
// zero fire → clear, exactly one → pass-through that family's tag, two or more →
// Compound. Every constituent fires region-agnostically — payloads inside string
// literals or comments count.
//
// It reuses the port's own five constituent detectors (nothing new): the
// tag-block-payload, variation-selector-payload, zero-width-payload,
// bidi-control-balance, and homoglyph-confusable detectors that live in the core
// scan fold. A constituent "fired" iff its own classification is non-clear (the
// scan fold produces a Finding for that family). No new data file, no new
// predicate, no host library — this detector is pure aggregation over existing
// port code.
//
// Sub-threats:
//   0 fired → Clear.
//   1 fired → that family's tag: TagBlock / VariationSelector / ZeroWidth /
//             BidiControl / IdentifierHomoglyph.
//   2+ fired → Compound.
//
// Standalone detector: it is not part of the default policy scan, matching the
// Rust reference.
public static partial class Security
{
    public static class SourceDisplayDivergence
    {
        // ─────────────────────────────────────────────────────────────────
        // §1 Types
        // ─────────────────────────────────────────────────────────────────

        /// <summary>Top-level classification (no constituent fired =
        /// <see cref="Clear"/>).</summary>
        public abstract record Classification
        {
            /// <summary>True iff the classification is Clear.</summary>
            public abstract bool IsClear { get; }

            /// <summary>Sub-threat tag for a hazard, or null when clear. A single
            /// constituent hit passes through its family tag; two or more yield
            /// "Compound".</summary>
            public abstract string? Tag { get; }

            /// <summary>Implicated positions. Always empty at this layer per the
            /// Lean spec — the per-family verdicts carry the positions.</summary>
            public IReadOnlyList<int> Positions => System.Array.Empty<int>();

            /// <summary>Fully-qualified reason code
            /// (unicode.security.D.source-display-divergence.&lt;tag&gt;) routed
            /// through the port's shared reason-code machinery, or null when
            /// clear.</summary>
            public string? ReasonCode =>
                Tag is null ? null : Security.ReasonCode(Family.SourceDisplayDivergence, Tag);
        }

        /// <summary>No constituent detector fired — the rendered source agrees
        /// with its logical content.</summary>
        public sealed record Clear : Classification
        {
            public override bool IsClear => true;
            public override string? Tag => null;
        }

        /// <summary>One or more constituents fired: <see cref="Sub"/> is the
        /// single family's tag, or "Compound" when two or more fired.</summary>
        public sealed record Hazard(string Sub) : Classification
        {
            public override bool IsClear => false;
            public override string? Tag => Sub;
        }

        /// <summary>The structured output of <see cref="Detect"/> (mirrors the
        /// Lean Verdict). <see cref="FiredTags"/> is the ordered list of
        /// constituent family tags that fired, for observability.</summary>
        public sealed record Verdict(
            IReadOnlyList<int> Input,
            Classification Classify,
            IReadOnlyList<string> FiredTags);

        // ─────────────────────────────────────────────────────────────────
        // §2 Constituent "fired" checks (reuse the port's own detectors)
        // ─────────────────────────────────────────────────────────────────

        /// <summary>True iff the tag-block-payload constituent fires on
        /// <paramref name="input"/> — reuses the core scan fold's own tag-block
        /// predicate (printable-ASCII tag range U+E0020..U+E007E).</summary>
        private static bool TagBlockFired(List<int> input) =>
            Security.PositionsWhere(input, Security.IsTagBlockAsciiPayload).Count > 0;

        /// <summary>True iff the variation-selector-payload constituent fires on
        /// <paramref name="input"/> — reuses the core scan fold's own
        /// VariationSelectorFinding classifier.</summary>
        private static bool VariationSelectorFired(List<int> input) =>
            Security.VariationSelectorFinding(input) is not null;

        /// <summary>True iff the zero-width-payload constituent fires on
        /// <paramref name="input"/> — reuses the core scan fold's own zero-width
        /// predicate (ZWSP/ZWNJ/ZWJ/WJ/BOM).</summary>
        private static bool ZeroWidthFired(List<int> input) =>
            Security.PositionsWhere(input, Security.IsZeroWidthPayload).Count > 0;

        /// <summary>True iff the bidi-control-balance constituent fires on
        /// <paramref name="input"/> — reuses the core scan fold's own
        /// embedding-control predicate (U+202A..U+202E).</summary>
        private static bool BidiControlFired(List<int> input) =>
            // The full bidi format-control set, embeddings and isolates alike: a
            // Trojan Source payload may use either, and the isolate form is
            // invisible to a predicate that stops at U+202E.
            input.Exists(cp => Security.IsBidiEmbeddingControl(cp) || Security.IsBidiIsolateControl(cp));

        /// <summary>True iff the homoglyph-confusable constituent fires on
        /// <paramref name="input"/> — reuses the core scan fold's own
        /// classifiers. The reference runs one homoglyph detector whose priority
        /// ladder ends in a CrossScriptMix branch, so a cross-script identifier
        /// fires it even though this port reports that case under
        /// mixed-script-admissibility; consulting only the first classifier
        /// misses every input whose sole homoglyph signal is the script
        /// mix.</summary>
        private static bool HomoglyphFired(List<int> input) =>
            Security.HomoglyphConfusableFinding(input) is not null
            // The constituent asks the script question about a source file, which
            // is not an identifier field, so the Restricted-status rung is off.
            || Security.MixedScriptAdmissibilityFinding(input, false) is not null;

        // ─────────────────────────────────────────────────────────────────
        // §3 Top-level detection
        // ─────────────────────────────────────────────────────────────────

        /// <summary>The SourceDisplayDivergence aggregation. Runs the five
        /// constituent detectors in canonical order, collects the fired tags, and
        /// aggregates: zero fired → clear, one → that tag, two or more →
        /// "Compound".</summary>
        public static Verdict Detect(IReadOnlyList<int> input)
        {
            var cps = input.ToList();

            // Constituent family tags in canonical aggregation order:
            // tag-block, variation-selector, zero-width, bidi-control, homoglyph.
            var fires = new List<string>();
            if (TagBlockFired(cps)) fires.Add("TagBlock");
            if (VariationSelectorFired(cps)) fires.Add("VariationSelector");
            if (ZeroWidthFired(cps)) fires.Add("ZeroWidth");
            if (BidiControlFired(cps)) fires.Add("BidiControl");
            if (HomoglyphFired(cps)) fires.Add("IdentifierHomoglyph");

            // At most five constituents can fire; the switch is exhaustive over
            // 0..5 with an impossible-state guard rather than a silent catch-all.
            Classification classification = fires.Count switch
            {
                0 => new Clear(),
                1 => new Hazard(fires[0]),
                2 or 3 or 4 or 5 => new Hazard("Compound"),
                _ => throw new InvalidOperationException(
                    $"source-display-divergence: impossible fired count {fires.Count} (max 5)"),
            };

            return new Verdict(cps, classification, fires);
        }
    }
}
