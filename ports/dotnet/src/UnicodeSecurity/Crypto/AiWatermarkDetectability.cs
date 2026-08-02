namespace UnicodeSecurity;

// ai-watermark-detectability (K layer) — character-level detector for inputs
// carrying codepoint patterns consistent with a known AI watermark scheme.
// Answers the question: does this input contain markers attributable to a
// watermarking protocol?
//
// Direct port of ports/rust/src/security/crypto/ai_watermark_detectability.rs,
// itself a port of Unicode/Security/Crypto/AiWatermarkDetectability.lean.
//
// Threat model — provenance-attribution attacker. An input either (a) carries
// an AI provider's watermark codepoints (a legitimate provenance marker) or
// (b) carries injected markers that impersonate a provider's scheme to
// discredit the content as AI-generated. Character-level detection alone
// cannot distinguish (a) from (b); the detector reports the matched scheme and
// leaves provider-specific authentication to downstream code.
//
// Probe inventory (priority order, first match wins):
//
//   1. adversarial              — NNBSP count >= 3 at arithmetic-progression positions.
//   2. gpt5ZwspModulo           — ZWSP count >= 3 at arithmetic-progression positions.
//   3. unknown                  — invisible markers from >= 2 distinct categories.
//   4. nnbspBoundary            — single-category NNBSP.
//   5. variationSelectorCarrier — VS NOT adjacent to an emoji codepoint.
//   6. zwjNonEmoji              — ZWJ NOT adjacent to an emoji codepoint.
//   7. smartQuoteAlternation    — paired curly quotes, no ASCII straight quotes.
//   8. emDashPattern            — em-dashes, no ASCII hyphen-minus.
//   9. statisticalTokenChoice   — input contains an AI-favored lexical pattern.
//  10. defaultIgnorableCarrier  — single-category residual Default_Ignorable.
//
// The Emoji property table is bundled in the port's own Data/emoji-data.txt
// (UTS #51 17.0, byte-identical to the UCD source the Lean spec cites); the
// adjacency probe parses the Emoji rows from it, never a host emoji library.
// Default_Ignorable reuses the port's own Security.IsDefaultIgnorableCodepoint,
// never a host normalizer.
public static partial class Security
{
    public static class AiWatermarkDetectability
    {
        // ─────────────────────────────────────────────────────────────────
        // §1 Types
        // ─────────────────────────────────────────────────────────────────

        /// <summary>The conceptual watermark cue class a sub-threat probes for,
        /// drawn from the fixed vocabulary in
        /// Unicode.Generated.WatermarkSchemes.CueClass. Ported here because the
        /// port exposes no generated watermark-schemes module.</summary>
        public enum CueClass
        {
            /// <summary>A codepoint-frequency bias toward a pinned "green list"
            /// of tokens.</summary>
            GreenListBias,

            /// <summary>A fixed-period or carrier-byte channel surfacing a
            /// pseudorandom function.</summary>
            PseudorandomSeq,

            /// <summary>A stylistic-distribution drift away from natural human
            /// writing.</summary>
            SemanticDrift,
        }

        /// <summary>Sub-threats this detector can fire. Each variant has a
        /// corresponding probe in <see cref="DetectWithContext"/>; the payload
        /// carries the position the conformance harness's attribution column
        /// reads back.</summary>
        public abstract record SubThreat
        {
            /// <summary>Human-facing classification tag for this sub-threat.</summary>
            public abstract string Tag { get; }

            /// <summary>The conceptual watermark cue class this sub-threat probes
            /// for. Marker-encoded sub-threats route to PseudorandomSeq;
            /// vocabulary-bias to GreenListBias; stylistic-distribution to
            /// SemanticDrift; Unknown (multi-category mixing) implicates no single
            /// scheme, so is null.</summary>
            public abstract CueClass? Cue { get; }
        }

        /// <summary>Single-category NNBSP (U+202F) markers;
        /// <see cref="MarkerCount"/> is how many.</summary>
        public sealed record NnbspBoundary(int MarkerCount) : SubThreat
        {
            public override string Tag => "NnbspBoundary";
            public override CueClass? Cue => CueClass.PseudorandomSeq;
        }

        /// <summary>Variation selector(s) not adjacent to an emoji;
        /// <see cref="MarkerCount"/> is how many.</summary>
        public sealed record VariationSelectorCarrier(int MarkerCount) : SubThreat
        {
            public override string Tag => "VariationSelectorCarrier";
            public override CueClass? Cue => CueClass.PseudorandomSeq;
        }

        /// <summary>ZWJ(s) not adjacent to an emoji; <see cref="MarkerCount"/> is
        /// how many.</summary>
        public sealed record ZwjNonEmoji(int MarkerCount) : SubThreat
        {
            public override string Tag => "ZwjNonEmoji";
            public override CueClass? Cue => CueClass.PseudorandomSeq;
        }

        /// <summary>Residual Default_Ignorable markers;
        /// <see cref="MarkerCount"/> is how many.</summary>
        public sealed record DefaultIgnorableCarrier(int MarkerCount) : SubThreat
        {
            public override string Tag => "DefaultIgnorableCarrier";
            public override CueClass? Cue => CueClass.PseudorandomSeq;
        }

        /// <summary>ZWSP (U+200B) markers at arithmetic-progression positions;
        /// <see cref="FirstPos"/> is the first ZWSP position.</summary>
        public sealed record Gpt5ZwspModulo(int FirstPos) : SubThreat
        {
            public override string Tag => "Gpt5ZwspModulo";
            public override CueClass? Cue => CueClass.PseudorandomSeq;
        }

        /// <summary>Em-dash (U+2014) stylistic signature; <see cref="FirstPos"/>
        /// is the first em-dash.</summary>
        public sealed record EmDashPattern(int FirstPos) : SubThreat
        {
            public override string Tag => "EmDashPattern";
            public override CueClass? Cue => CueClass.SemanticDrift;
        }

        /// <summary>Paired curly-quote stylistic signature;
        /// <see cref="FirstPos"/> is the first quote.</summary>
        public sealed record SmartQuoteAlternation(int FirstPos) : SubThreat
        {
            public override string Tag => "SmartQuoteAlternation";
            public override CueClass? Cue => CueClass.SemanticDrift;
        }

        /// <summary>AI-favored lexical pattern hit; <see cref="FirstPos"/> is the
        /// match start.</summary>
        public sealed record StatisticalTokenChoice(int FirstPos) : SubThreat
        {
            public override string Tag => "StatisticalTokenChoice";
            public override CueClass? Cue => CueClass.GreenListBias;
        }

        /// <summary>Over-regular marker placement impersonating a scheme;
        /// <see cref="ImpersonatedScheme"/> names the surfaced scheme,
        /// <see cref="FirstPos"/> the first marker position.</summary>
        public sealed record Adversarial(string ImpersonatedScheme, int FirstPos) : SubThreat
        {
            public override string Tag => "Adversarial";
            public override CueClass? Cue => CueClass.PseudorandomSeq;
        }

        /// <summary>Multi-category invisible-marker mixing;
        /// <see cref="AnomalyMarker"/> is the total invisible-marker count
        /// (attribution to a single scheme fails).</summary>
        public sealed record Unknown(int AnomalyMarker) : SubThreat
        {
            public override string Tag => "Unknown";
            public override CueClass? Cue => null;
        }

        /// <summary>Top-level AiWatermarkDetectability classification.</summary>
        public abstract record Classification
        {
            /// <summary>True iff no watermark marker was detected.</summary>
            public abstract bool IsClear { get; }

            /// <summary>Human-facing tag for a hazard, or null when clear.</summary>
            public abstract string? Tag { get; }

            /// <summary>Implicated positions (empty when clear).</summary>
            public abstract IReadOnlyList<int> Positions { get; }

            /// <summary>Fully-qualified reason code
            /// (unicode.security.K.ai-watermark-detectability.&lt;tag&gt;) routed
            /// through the port's shared reason-code machinery, or null when
            /// clear.</summary>
            public string? ReasonCode =>
                Tag is null ? null : Security.ReasonCode(Family.AiWatermarkDetectability, Tag);
        }

        /// <summary>No watermark marker was detected (semantically
        /// noWatermark).</summary>
        public sealed record Clear : Classification
        {
            public override bool IsClear => true;
            public override string? Tag => null;
            public override IReadOnlyList<int> Positions => System.Array.Empty<int>();
        }

        /// <summary>A hazard: the fired sub-threat plus the implicated marker
        /// positions.</summary>
        public sealed record Hazard(SubThreat Sub, IReadOnlyList<int> HazardPositions) : Classification
        {
            public override bool IsClear => false;
            public override string? Tag => Sub.Tag;
            public override IReadOnlyList<int> Positions => HazardPositions;
        }

        /// <summary>AiWatermarkDetectability verdict — the structured output of
        /// <see cref="Detect"/>. <see cref="MarkerCount"/> is the count of
        /// codepoints matching the fired scheme's probe (0 when clear).</summary>
        public sealed record Verdict(
            IReadOnlyList<int> Input,
            Classification Classify,
            int MarkerCount);

        /// <summary>Optional context for the modulo-probe tolerances. Each field
        /// controls how strictly the corresponding probe checks its
        /// arithmetic-progression condition; the defaults of 0 require exact
        /// equality of consecutive gaps.</summary>
        public sealed record Context(
            int ZwspModuloTolerance = 0,
            int AdversarialTolerance = 0)
        {
            /// <summary>The empty context: exact-arithmetic settings.</summary>
            public static readonly Context Default = new();
        }

        // ─────────────────────────────────────────────────────────────────
        // §2 Emoji property table (bundled Data/emoji-data.txt, Emoji rows)
        // ─────────────────────────────────────────────────────────────────

        private static List<(int Lo, int Hi)>? emojiRanges;

        /// <summary>Parse the Emoji (Emoji=Yes) closed intervals from
        /// emoji-data.txt. Each non-comment row is
        /// <c>&lt;range&gt; ; &lt;property&gt; # &lt;comment&gt;</c>; keep only
        /// rows whose property is exactly Emoji.</summary>
        private static List<(int Lo, int Hi)> ParseEmojiRanges(string raw)
        {
            var output = new List<(int, int)>();
            foreach (var rawLine in raw.Split('\n'))
            {
                var hash = rawLine.IndexOf('#');
                var body = (hash >= 0 ? rawLine.Substring(0, hash) : rawLine).Trim();
                if (body.Length == 0) continue;
                var fields = body.Split(';');
                if (fields.Length < 2) continue;
                if (fields[1].Trim() != "Emoji") continue;
                var range = fields[0].Trim();
                var dots = range.IndexOf("..", StringComparison.Ordinal);
                if (dots >= 0)
                {
                    var lo = Security.ParseHex(range.Substring(0, dots));
                    var hi = Security.ParseHex(range.Substring(dots + 2));
                    if (lo is not null && hi is not null) output.Add((lo.Value, hi.Value));
                }
                else
                {
                    var single = Security.ParseHex(range);
                    if (single is not null) output.Add((single.Value, single.Value));
                }
            }
            return output;
        }

        private static List<(int Lo, int Hi)> EmojiRanges()
        {
            emojiRanges ??= ParseEmojiRanges(Security.ReadDataFile("emoji-data.txt"));
            return emojiRanges;
        }

        /// <summary>True iff <paramref name="cp"/> has the Emoji = Yes property
        /// per emoji-data.txt.</summary>
        private static bool IsEmoji(int cp)
        {
            foreach (var (lo, hi) in EmojiRanges())
            {
                if (lo <= cp && cp <= hi) return true;
            }
            return false;
        }

        // ─────────────────────────────────────────────────────────────────
        // §3 Codepoint probes
        // ─────────────────────────────────────────────────────────────────

        /// <summary>True iff <paramref name="cp"/> is U+202F NARROW NO-BREAK
        /// SPACE.</summary>
        private static bool IsNnbsp(int cp) => cp == 0x202F;

        /// <summary>True iff <paramref name="cp"/> is U+200D ZERO WIDTH
        /// JOINER.</summary>
        private static bool IsZwj(int cp) => cp == 0x200D;

        /// <summary>True iff <paramref name="cp"/> is a Variation Selector — the
        /// basic block U+FE00..U+FE0F (VS1..VS16) or the Plane-14 IVS block
        /// U+E0100..U+E01EF (VS17..VS256).</summary>
        private static bool IsVariationSelector(int cp) =>
            (cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0xE0100 && cp <= 0xE01EF);

        /// <summary>True iff <paramref name="cp"/> is
        /// Default_Ignorable_Code_Point. Reuses the port's own UCD-backed
        /// predicate, never a host normalizer.</summary>
        private static bool IsDefaultIgnorable(int cp) => Security.IsDefaultIgnorableCodepoint(cp);

        /// <summary>True iff <paramref name="cp"/> is U+200B ZERO WIDTH
        /// SPACE.</summary>
        private static bool IsZwsp(int cp) => cp == 0x200B;

        /// <summary>True iff <paramref name="cp"/> is U+2014 EM DASH.</summary>
        private static bool IsEmDash(int cp) => cp == 0x2014;

        /// <summary>True iff <paramref name="cp"/> is U+002D HYPHEN-MINUS
        /// (ASCII).</summary>
        private static bool IsHyphenMinus(int cp) => cp == 0x002D;

        /// <summary>True iff <paramref name="cp"/> is one of the four "curly"
        /// quotation marks: U+2018 / U+2019 (single open/close) and U+201C /
        /// U+201D (double open/close).</summary>
        private static bool IsCurlyQuote(int cp) =>
            cp == 0x2018 || cp == 0x2019 || cp == 0x201C || cp == 0x201D;

        /// <summary>True iff <paramref name="cp"/> is an ASCII straight quote —
        /// U+0022 (double) or U+0027 (single / apostrophe).</summary>
        private static bool IsStraightQuote(int cp) => cp == 0x0022 || cp == 0x0027;

        /// <summary>True iff <c>input[i]</c> is adjacent (immediate predecessor
        /// OR immediate successor) to an emoji codepoint. Two-sided check. Used
        /// by the VS and ZWJ probes to exclude legitimate emoji-context
        /// occurrences.</summary>
        private static bool IsAdjacentToEmoji(IReadOnlyList<int> input, int i)
        {
            var prevIsEmoji = i > 0 && i - 1 < input.Count && IsEmoji(input[i - 1]);
            var nextIsEmoji = i + 1 < input.Count && IsEmoji(input[i + 1]);
            return prevIsEmoji || nextIsEmoji;
        }

        /// <summary>All positions in <paramref name="input"/> matching predicate
        /// <paramref name="p"/>.</summary>
        private static List<int> AllPositions(Func<int, bool> p, IReadOnlyList<int> input)
        {
            var output = new List<int>();
            for (var i = 0; i < input.Count; i++)
            {
                if (p(input[i])) output.Add(i);
            }
            return output;
        }

        /// <summary>True iff <paramref name="positions"/> forms an arithmetic
        /// progression with all consecutive gaps within
        /// <paramref name="tolerance"/> of the first gap. Empty + singleton lists
        /// are vacuously arithmetic. <paramref name="positions"/> is assumed
        /// ascending (produced by <see cref="AllPositions"/>), so gaps are
        /// non-negative.</summary>
        private static bool PositionsAreArithmeticWithin(IReadOnlyList<int> positions, int tolerance)
        {
            if (positions.Count < 2) return true;
            var firstGap = positions[1] - positions[0];
            for (var i = 0; i < positions.Count - 1; i++)
            {
                var gap = positions[i + 1] - positions[i];
                if (!(gap <= firstGap + tolerance && firstGap <= gap + tolerance)) return false;
            }
            return true;
        }

        /// <summary>First start-position at which <paramref name="pattern"/>
        /// appears as a contiguous sub-slice of <paramref name="input"/>, or null
        /// if absent.</summary>
        private static int? ContainsSublist(IReadOnlyList<int> pattern, IReadOnlyList<int> input)
        {
            if (pattern.Count == 0 || pattern.Count > input.Count) return null;
            var maxStart = input.Count - pattern.Count;
            for (var start = 0; start <= maxStart; start++)
            {
                var match = true;
                for (var j = 0; j < pattern.Count; j++)
                {
                    if (input[start + j] != pattern[j]) { match = false; break; }
                }
                if (match) return start;
            }
            return null;
        }

        /// <summary>The "AI-favored" lexical-pattern catalog (each word as its
        /// codepoint sequence), transcribed verbatim from the pinned
        /// aiFavoredVocabulary literal in the Lean spec (parsed from
        /// Ucd/Security/AiFavoredVocabulary.txt and drift-gated there against a
        /// fresh parse).</summary>
        private static readonly int[][] AiFavoredVocabulary =
        {
            new[] { 100, 101, 108, 118, 101 },
            new[] { 100, 101, 108, 118, 105, 110, 103 },
            new[] { 116, 97, 112, 101, 115, 116, 114, 121 },
            new[] { 105, 110, 116, 114, 105, 99, 97, 116, 101 },
            new[] { 110, 117, 97, 110, 99, 101, 100 },
            new[] { 109, 111, 114, 101, 111, 118, 101, 114 },
            new[] { 102, 117, 114, 116, 104, 101, 114, 109, 111, 114, 101 },
            new[] { 114, 101, 97, 108, 109 },
            new[] { 101, 108, 117, 99, 105, 100, 97, 116, 101 },
            new[] { 115, 104, 111, 119, 99, 97, 115, 105, 110, 103 },
            new[] { 117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 115 },
            new[] { 117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 100 },
            new[] { 112, 105, 118, 111, 116, 97, 108 },
            new[] { 98, 111, 108, 115, 116, 101, 114 },
            new[] { 109, 117, 108, 116, 105, 102, 97, 99, 101, 116, 101, 100 },
            new[] { 116, 101, 115, 116, 97, 109, 101, 110, 116 },
            new[] { 102, 111, 115, 116, 101, 114 },
            new[] { 104, 111, 108, 105, 115, 116, 105, 99 },
            new[] { 112, 97, 114, 97, 100, 105, 103, 109 },
            new[] { 116, 114, 97, 110, 115, 102, 111, 114, 109, 97, 116, 105, 118, 101 },
            new[] { 115, 112, 101, 97, 114, 104, 101, 97, 100 },
            new[] { 109, 101, 116, 105, 99, 117, 108, 111, 117, 115 },
            new[] { 109, 101, 116, 105, 99, 117, 108, 111, 117, 115, 108, 121 },
            new[] { 101, 109, 112, 111, 119, 101, 114 },
            new[] { 101, 109, 112, 111, 119, 101, 114, 105, 110, 103 },
            new[] { 112, 114, 111, 102, 111, 117, 110, 100 },
            new[] { 112, 114, 111, 102, 111, 117, 110, 100, 108, 121 },
            new[] { 99, 111, 109, 112, 101, 108, 108, 105, 110, 103 },
            new[] { 99, 111, 109, 112, 114, 101, 104, 101, 110, 115, 105, 118, 101 },
            new[] { 99, 114, 117, 99, 105, 97, 108 },
            new[] { 100, 97, 117, 110, 116, 105, 110, 103 },
            new[] { 114, 111, 98, 117, 115, 116 },
            new[] { 115, 116, 114, 101, 97, 109, 108, 105, 110, 101 },
            new[] { 101, 110, 114, 105, 99, 104 },
            new[] { 101, 120, 101, 109, 112, 108, 105, 102, 121 },
            new[] { 99, 97, 112, 116, 105, 118, 97, 116, 105, 110, 103 },
            new[] { 100, 105, 115, 99, 101, 114, 110, 105, 110, 103 },
            new[] { 109, 101, 115, 109, 101, 114, 105, 122, 101 },
            new[] { 105, 110, 116, 114, 105, 99, 97, 116, 101, 108, 121 },
            new[] { 105, 109, 98, 117, 101 },
            new[] { 112, 108, 97, 121, 115, 32, 97, 32, 99, 114, 117, 99, 105, 97, 108, 32, 114, 111, 108, 101 },
            new[] { 112, 108, 97, 121, 115, 32, 97, 32, 112, 105, 118, 111, 116, 97, 108, 32, 114, 111, 108, 101 },
            new[] { 105, 116, 32, 105, 115, 32, 105, 109, 112, 111, 114, 116, 97, 110, 116, 32, 116, 111, 32, 110, 111, 116, 101 },
            new[] { 105, 116, 32, 105, 115, 32, 119, 111, 114, 116, 104, 32, 110, 111, 116, 105, 110, 103 },
            new[] { 105, 110, 32, 99, 111, 110, 99, 108, 117, 115, 105, 111, 110 },
            new[] { 105, 110, 32, 101, 115, 115, 101, 110, 99, 101 },
            new[] { 100, 101, 108, 118, 101, 32, 105, 110, 116, 111 },
            new[] { 100, 101, 108, 118, 105, 110, 103, 32, 105, 110, 116, 111 },
            new[] { 116, 97, 112, 101, 115, 116, 114, 121, 32, 111, 102 },
            new[] { 114, 101, 97, 108, 109, 32, 111, 102 },
        };

        // ─────────────────────────────────────────────────────────────────
        // §4 Top-level detection
        // ─────────────────────────────────────────────────────────────────

        /// <summary>The detection function. Runs every probe in the fixed
        /// priority order (most-specific first); the first hit wins. See the
        /// module header for the probe inventory and the ordering
        /// rationale.</summary>
        public static Verdict DetectWithContext(Context ctx, IReadOnlyList<int> input)
        {
            var nnbspPositions = AllPositions(IsNnbsp, input);
            var nnbspCount = nnbspPositions.Count;

            // Probe 1: adversarial — NNBSP too-regular.
            var adversarialFires = nnbspCount >= 3
                && PositionsAreArithmeticWithin(nnbspPositions, ctx.AdversarialTolerance);

            // Probe 2: gpt5ZwspModulo — ZWSP arithmetic progression.
            var zwspPositions = AllPositions(IsZwsp, input);
            var zwspCount = zwspPositions.Count;
            var zwspModuloFires = zwspCount >= 3
                && PositionsAreArithmeticWithin(zwspPositions, ctx.ZwspModuloTolerance);

            var vsAllPos = AllPositions(IsVariationSelector, input);
            var vsNonEmojiPos = vsAllPos.Where(i => !IsAdjacentToEmoji(input, i)).ToList();
            var vsNonEmojiCount = vsNonEmojiPos.Count;

            var zwjAllPos = AllPositions(IsZwj, input);
            var zwjNonEmojiPos = zwjAllPos.Where(i => !IsAdjacentToEmoji(input, i)).ToList();
            var zwjNonEmojiCount = zwjNonEmojiPos.Count;

            // Probe 7: smartQuoteAlternation — curly quotes only.
            var curlyPositions = AllPositions(IsCurlyQuote, input);
            var curlyCount = curlyPositions.Count;
            var hasStraightQuote = input.Any(IsStraightQuote);
            var smartQuoteFires = curlyCount >= 2 && !hasStraightQuote;

            // Probe 8: emDashPattern — em-dashes without hyphen-minus.
            var emDashPositions = AllPositions(IsEmDash, input);
            var emDashCount = emDashPositions.Count;
            var hasHyphenMinus = input.Any(IsHyphenMinus);
            var emDashFires = emDashCount >= 2 && !hasHyphenMinus;

            // Probe 9: statisticalTokenChoice — scan the pinned vocabulary. Each
            // word is compared as a contiguous sub-slice of the input.
            int? vocabHit = null;
            foreach (var pattern in AiFavoredVocabulary)
            {
                if (ContainsSublist(pattern, input) is int hitPos)
                {
                    vocabHit = hitPos;
                    break;
                }
            }

            // Residual default-ignorables (excluding VS and ZWJ, handled above).
            bool IsResidualDi(int cp) =>
                IsDefaultIgnorable(cp) && !IsVariationSelector(cp) && !IsZwj(cp);
            var diPositions = AllPositions(IsResidualDi, input);
            var diCount = diPositions.Count;

            // Probe 3: unknown — invisible markers from >= 2 distinct categories.
            var categoryCount = (nnbspCount > 0 ? 1 : 0)
                + (vsNonEmojiCount > 0 ? 1 : 0)
                + (zwjNonEmojiCount > 0 ? 1 : 0)
                + (diCount > 0 ? 1 : 0);
            var unknownFires = categoryCount >= 2;
            var totalInvisibleCount = nnbspCount + vsNonEmojiCount + zwjNonEmojiCount + diCount;

            Classification classification;
            int firedCount;
            if (adversarialFires)
            {
                var firstPos = nnbspPositions.Count > 0 ? nnbspPositions[0] : 0;
                classification = new Hazard(new Adversarial("nnbspBoundary", firstPos), nnbspPositions);
                firedCount = nnbspCount;
            }
            else if (zwspModuloFires)
            {
                var firstPos = zwspPositions.Count > 0 ? zwspPositions[0] : 0;
                classification = new Hazard(new Gpt5ZwspModulo(firstPos), zwspPositions);
                firedCount = zwspCount;
            }
            else if (unknownFires)
            {
                var allInvisiblePos = new List<int>();
                for (var i = 0; i < input.Count; i++)
                {
                    var cp = input[i];
                    if (IsNnbsp(cp) || IsVariationSelector(cp) || IsZwj(cp) || IsDefaultIgnorable(cp))
                    {
                        allInvisiblePos.Add(i);
                    }
                }
                classification = new Hazard(new Unknown(totalInvisibleCount), allInvisiblePos);
                firedCount = totalInvisibleCount;
            }
            else if (nnbspCount > 0)
            {
                classification = new Hazard(new NnbspBoundary(nnbspCount), nnbspPositions);
                firedCount = nnbspCount;
            }
            else if (vsNonEmojiCount > 0)
            {
                classification = new Hazard(new VariationSelectorCarrier(vsNonEmojiCount), vsNonEmojiPos);
                firedCount = vsNonEmojiCount;
            }
            else if (zwjNonEmojiCount > 0)
            {
                classification = new Hazard(new ZwjNonEmoji(zwjNonEmojiCount), zwjNonEmojiPos);
                firedCount = zwjNonEmojiCount;
            }
            else if (smartQuoteFires)
            {
                var firstPos = curlyPositions.Count > 0 ? curlyPositions[0] : 0;
                classification = new Hazard(new SmartQuoteAlternation(firstPos), curlyPositions);
                firedCount = curlyCount;
            }
            else if (emDashFires)
            {
                var firstPos = emDashPositions.Count > 0 ? emDashPositions[0] : 0;
                classification = new Hazard(new EmDashPattern(firstPos), emDashPositions);
                firedCount = emDashCount;
            }
            else if (vocabHit is int pos)
            {
                classification = new Hazard(new StatisticalTokenChoice(pos), new List<int> { pos });
                firedCount = 1;
            }
            else if (diCount > 0)
            {
                classification = new Hazard(new DefaultIgnorableCarrier(diCount), diPositions);
                firedCount = diCount;
            }
            else
            {
                classification = new Clear();
                firedCount = 0;
            }

            return new Verdict(input.ToList(), classification, firedCount);
        }

        /// <summary>Convenience wrapper over <see cref="DetectWithContext"/> with
        /// the empty context — exact-arithmetic settings
        /// (ZwspModuloTolerance = 0, AdversarialTolerance = 0).</summary>
        public static Verdict Detect(IReadOnlyList<int> input) =>
            DetectWithContext(Context.Default, input);
    }
}
