namespace UnicodeSecurity;

// skin-tone-variation-forgery (I layer) — skin-tone modifier and
// variation-selector abuse on emoji bases per UTS #51 (identity-layer
// detector).
//
// Direct port of the verified Rust reference implementation, itself a
// byte-faithful transliteration of
// Unicode/Security/Identity/SkinToneVariationForgery.lean.
//
// Threat model. Tier A1. An adversary places a skin-tone modifier on a
// codepoint that does NOT bear Emoji_Modifier_Base, stacks multiple skin-tones
// on one base, or forces a text-style render on an emoji-default codepoint via
// U+FE0E (VS15) — sometimes to hide a payload-bearing glyph in plain sight.
//
// Distinct from VariationSelectorPayload (pair-aligned VS runs that decode to
// bytes): this catches the orthogonal case of semantic VS / skin-tone misuse on
// a single base. Both can fire on the same input; SourceDisplayDivergence
// aggregates.
//
// It reuses the port's own emoji property tables (the bundled emoji-data.txt),
// never a host emoji library. The skin-tone modifier predicate reuses the
// port's own EmojiZwjIntegrity.IsEmojiModifier (U+1F3FB..U+1F3FF); the
// Emoji_Modifier_Base and Emoji_Presentation predicates parse the same bundled
// emoji-data.txt for their respective property rows.
//
// Sub-threats (priority order):
//   1. StackedSkinTones      a base immediately followed by >= 2 skin-tone modifiers.
//   2. InvalidSkinToneTarget a skin-tone modifier on a non-Emoji_Modifier_Base.
//   3. ForcedTextStyle       U+FE0E on an Emoji_Presentation codepoint.
public static partial class Security
{
    public static class SkinToneVariationForgery
    {
        // ─────────────────────────────────────────────────────────────────
        // §1 Types
        // ─────────────────────────────────────────────────────────────────

        /// <summary>Sub-threat enumeration for SkinToneVariationForgery, in
        /// priority order. Each variant overrides <see cref="Tag"/>, so the
        /// fixture-row tag is resolved polymorphically with no catch-all.</summary>
        public abstract record SubThreat
        {
            /// <summary>Fixture-row tag string for this sub-threat (matches the
            /// Lean SubThreat.tag).</summary>
            public abstract string Tag { get; }
        }

        /// <summary>A base at <see cref="BasePos"/> followed by >= 2 skin-tone
        /// modifiers (<see cref="Modifiers"/>, the first two stacked
        /// modifiers).</summary>
        public sealed record StackedSkinTones(int BasePos, IReadOnlyList<int> Modifiers) : SubThreat
        {
            public override string Tag => "StackedSkinTones";
        }

        /// <summary>A skin-tone <see cref="ModifierCp"/> at
        /// <see cref="BasePos"/> + 1 on a non-modifier-base
        /// <see cref="BaseCp"/>.</summary>
        public sealed record InvalidSkinToneTarget(int BasePos, int BaseCp, int ModifierCp) : SubThreat
        {
            public override string Tag => "InvalidSkinToneTarget";
        }

        /// <summary>A U+FE0E at <see cref="BasePos"/> + 1 forcing text-style on
        /// an Emoji_Presentation <see cref="BaseCp"/>.</summary>
        public sealed record ForcedTextStyle(int BasePos, int BaseCp) : SubThreat
        {
            public override string Tag => "ForcedTextStyle";
        }

        /// <summary>Top-level classification for SkinToneVariationForgery.</summary>
        public abstract record Classification
        {
            /// <summary>True iff the classification is Clear.</summary>
            public abstract bool IsClear { get; }

            /// <summary>Human-facing tag for a hazard, or null when clear.</summary>
            public abstract string? Tag { get; }

            /// <summary>Implicated positions (empty when clear).</summary>
            public abstract IReadOnlyList<int> Positions { get; }

            /// <summary>Fully-qualified reason code
            /// (unicode.security.I.skin-tone-variation-forgery.&lt;tag&gt;)
            /// routed through the port's shared reason-code machinery, or null
            /// when clear.</summary>
            public string? ReasonCode =>
                Tag is null ? null : Security.ReasonCode(Family.SkinToneVariationForgery, Tag);
        }

        /// <summary>No skin-tone / variation-selector abuse present.</summary>
        public sealed record Clear : Classification
        {
            public override bool IsClear => true;
            public override string? Tag => null;
            public override IReadOnlyList<int> Positions => System.Array.Empty<int>();
        }

        /// <summary>A hazard: the fired sub-threat, the implicated positions, and
        /// the (always-empty for this detector) decoded-byte projection, kept for
        /// shape parity with the Lean Classification.hazard.</summary>
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
            int SkinToneCount,
            int VariationSelector15Count,
            int VariationSelector16Count);

        // ─────────────────────────────────────────────────────────────────
        // §2 Core predicates (reuse the port's own emoji tables)
        // ─────────────────────────────────────────────────────────────────

        private static List<(int Lo, int Hi)>? emojiModifierBaseRanges;
        private static List<(int Lo, int Hi)>? emojiPresentationRanges;

        /// <summary>Parse the closed intervals for a single emoji property from
        /// emoji-data.txt. Each non-comment row is
        /// <c>&lt;range&gt; ; &lt;property&gt; # &lt;comment&gt;</c>; keep only
        /// rows whose property field matches <paramref name="property"/>
        /// exactly. Mirrors the AiWatermarkDetectability Emoji-row parser,
        /// parameterised on the property name.</summary>
        private static List<(int Lo, int Hi)> ParseEmojiProperty(string property, string raw)
        {
            var output = new List<(int, int)>();
            foreach (var rawLine in raw.Split('\n'))
            {
                var hash = rawLine.IndexOf('#');
                var body = (hash >= 0 ? rawLine.Substring(0, hash) : rawLine).Trim();
                if (body.Length == 0) continue;
                var fields = body.Split(';');
                if (fields.Length < 2) continue;
                if (fields[1].Trim() != property) continue;
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

        private static List<(int Lo, int Hi)> EmojiModifierBaseRanges()
        {
            emojiModifierBaseRanges ??=
                ParseEmojiProperty("Emoji_Modifier_Base", Security.ReadDataFile("emoji-data.txt"));
            return emojiModifierBaseRanges;
        }

        private static List<(int Lo, int Hi)> EmojiPresentationRanges()
        {
            emojiPresentationRanges ??=
                ParseEmojiProperty("Emoji_Presentation", Security.ReadDataFile("emoji-data.txt"));
            return emojiPresentationRanges;
        }

        /// <summary>True iff <paramref name="cp"/> is an emoji skin-tone modifier.
        /// Reuses the port's own predicate (U+1F3FB..U+1F3FF), never a host
        /// emoji library.</summary>
        public static bool IsSkinTone(int cp) => EmojiZwjIntegrity.IsEmojiModifier(cp);

        /// <summary>True iff <paramref name="cp"/> has Emoji_Modifier_Base per
        /// emoji-data.txt.</summary>
        public static bool IsSkinToneBase(int cp)
        {
            foreach (var (lo, hi) in EmojiModifierBaseRanges())
            {
                if (lo <= cp && cp <= hi) return true;
            }
            return false;
        }

        /// <summary>True iff <paramref name="cp"/> has Emoji_Presentation per
        /// emoji-data.txt.</summary>
        public static bool IsEmojiPresentation(int cp)
        {
            foreach (var (lo, hi) in EmojiPresentationRanges())
            {
                if (lo <= cp && cp <= hi) return true;
            }
            return false;
        }

        /// <summary>True iff <paramref name="cp"/> is U+FE0E (VS15, text-style
        /// variation selector).</summary>
        public static bool IsVs15(int cp) => cp == 0xFE0E;

        /// <summary>True iff <paramref name="cp"/> is U+FE0F (VS16, emoji-style
        /// variation selector).</summary>
        public static bool IsVs16(int cp) => cp == 0xFE0F;

        // ─────────────────────────────────────────────────────────────────
        // §3 Sub-detectors
        // ─────────────────────────────────────────────────────────────────

        /// <summary>First position <c>i</c> whose next two codepoints are both
        /// skin-tone modifiers, as (basePos, [mod1, mod2]). Null when
        /// none.</summary>
        private static (int BasePos, List<int> Modifiers)? FirstStackedSkinTones(IReadOnlyList<int> input)
        {
            for (var i = 0; i < input.Count; i++)
            {
                if (i + 2 < input.Count && IsSkinTone(input[i + 1]) && IsSkinTone(input[i + 2]))
                {
                    return (i, new List<int> { input[i + 1], input[i + 2] });
                }
            }
            return null;
        }

        /// <summary>First skin-tone modifier whose preceding codepoint is NOT
        /// Emoji_Modifier_Base, as (basePos, baseCp, modifierCp). Null when
        /// none.</summary>
        private static (int BasePos, int BaseCp, int ModifierCp)? FirstInvalidSkinToneTarget(IReadOnlyList<int> input)
        {
            for (var i = 0; i < input.Count; i++)
            {
                if (i + 1 < input.Count && IsSkinTone(input[i + 1]) && !IsSkinToneBase(input[i]))
                {
                    return (i, input[i], input[i + 1]);
                }
            }
            return null;
        }

        /// <summary>First U+FE0E whose preceding codepoint has
        /// Emoji_Presentation, as (basePos, baseCp). Null when none.</summary>
        private static (int BasePos, int BaseCp)? FirstForcedTextStyle(IReadOnlyList<int> input)
        {
            for (var i = 0; i < input.Count; i++)
            {
                if (i + 1 < input.Count && IsVs15(input[i + 1]) && IsEmojiPresentation(input[i]))
                {
                    return (i, input[i]);
                }
            }
            return null;
        }

        private static int SkinToneCountOf(IReadOnlyList<int> input)
        {
            var count = 0;
            foreach (var cp in input)
            {
                if (IsSkinTone(cp)) count++;
            }
            return count;
        }

        private static int Vs15Count(IReadOnlyList<int> input)
        {
            var count = 0;
            foreach (var cp in input)
            {
                if (IsVs15(cp)) count++;
            }
            return count;
        }

        private static int Vs16Count(IReadOnlyList<int> input)
        {
            var count = 0;
            foreach (var cp in input)
            {
                if (IsVs16(cp)) count++;
            }
            return count;
        }

        // ─────────────────────────────────────────────────────────────────
        // §4 Top-level detection
        // ─────────────────────────────────────────────────────────────────

        /// <summary>The SkinToneVariationForgery detection function.</summary>
        public static Verdict Detect(IReadOnlyList<int> input)
        {
            var stc = SkinToneCountOf(input);
            var v15 = Vs15Count(input);
            var v16 = Vs16Count(input);

            Classification classification;
            if (FirstStackedSkinTones(input) is (int stackedBasePos, List<int> modifiers))
            {
                // Priority 1: a base followed by two stacked skin tones.
                var positions = new List<int>();
                for (var i = 0; i < modifiers.Count; i++)
                {
                    positions.Add(stackedBasePos + 1 + i);
                }
                classification = new Hazard(
                    new StackedSkinTones(stackedBasePos, modifiers),
                    positions,
                    new List<int>());
            }
            else if (FirstInvalidSkinToneTarget(input) is (int invalidBasePos, int baseCp, int modifierCp))
            {
                // Priority 2: a skin tone on a non-modifier-base.
                classification = new Hazard(
                    new InvalidSkinToneTarget(invalidBasePos, baseCp, modifierCp),
                    new List<int> { invalidBasePos + 1 },
                    new List<int>());
            }
            else if (FirstForcedTextStyle(input) is (int forcedBasePos, int forcedBaseCp))
            {
                // Priority 3: VS15 forcing text style on an emoji-presentation cp.
                classification = new Hazard(
                    new ForcedTextStyle(forcedBasePos, forcedBaseCp),
                    new List<int> { forcedBasePos + 1 },
                    new List<int>());
            }
            else
            {
                classification = new Clear();
            }

            return new Verdict(input.ToList(), classification, stc, v15, v16);
        }
    }
}
