namespace UnicodeSecurity;

// emoji-zwj-integrity (I layer, detector I3) — detection of malformed /
// unsanctioned emoji ZWJ-sequence shapes per UTS #51.
//
// Direct port of the verified Rust reference implementation,
// itself a byte-faithful transliteration of
// Unicode/Security/Identity/EmojiZwjIntegrity.lean.
//
// Threat model. An adversary crafts an emoji-shaped codepoint sequence
// containing one or more U+200D ZERO WIDTH JOINERs but violating the sanctioned
// RGI ZWJ-sequence shape — by exceeding the RGI length cap, by joining a
// non-emoji codepoint, by emitting adjacent ZWJ pairs, or by overflowing the
// skin-tone count. Any non-RGI ZWJ-containing sequence is renderer-dependent,
// and that renderer divergence is the attack surface.
//
// Sanctioning data. UTS #51 defines the RGI ZWJ sequences in
// emoji-zwj-sequences.txt, bundled in the port's own
// Data/emoji-zwj-sequences.txt (never a host emoji library). The registered set
// gives both the exact-match membership test (IsRegisteredZwjSequence) and the
// ZWJ alphabet — every distinct codepoint occurring at any position of any
// registered sequence, excluding the joiner — which is the canonical "what may
// flank a ZWJ?" predicate.
//
// Algorithm (one pass over input).
//   Phase 1 — collect ZWJ positions and the skin-tone count.
//   Phase 2 — short-circuit Clear if there are no ZWJs and the skin-tone count
//             is at most 1.
//   Phase 3 — a registered RGI sequence is always Clear.
//   Phase 4 — check sub-threats by priority:
//               1. DoubleZWJ            ZWJ-ZWJ adjacency
//               2. NonEmojiInjection    ZWJ adjacent to a non-emoji codepoint
//               3. OverLength           sequence longer than the RGI cap
//               4. SkinToneOverflow     skin-tone count >= 5
//               5. UnregisteredSequence catch-all when ZWJs are present but the
//                                       sequence is not registered.
public static partial class Security
{
    public static class EmojiZwjIntegrity
    {
        // ─────────────────────────────────────────────────────────────────
        // §1 Constants
        // ─────────────────────────────────────────────────────────────────

        /// <summary>Conservative cap on the length of a sanctioned RGI ZWJ
        /// sequence (maxRgiLength in the Lean spec). The longest current entry (a
        /// four-person family with skin tones) reaches ~13-14 codepoints; 16 is a
        /// safe upper bound.</summary>
        public const int MaxRgiLength = 16;

        /// <summary>The ZERO WIDTH JOINER codepoint.</summary>
        public const int Zwj = 0x200D;

        // ─────────────────────────────────────────────────────────────────
        // §2 Types
        // ─────────────────────────────────────────────────────────────────

        /// <summary>Sub-threat enumeration for EmojiZwjIntegrity, in priority
        /// order. Each variant overrides <see cref="Tag"/>, so the fixture-row
        /// tag is resolved polymorphically with no catch-all.</summary>
        public abstract record SubThreat
        {
            /// <summary>Fixture-row tag string for this sub-threat (matches the
            /// Lean SubThreat.tag).</summary>
            public abstract string Tag { get; }
        }

        /// <summary>ZWJ-ZWJ adjacency; <see cref="DoublePositions"/> are the first
        /// ZWJ of each adjacent pair.</summary>
        public sealed record DoubleZwj(IReadOnlyList<int> DoublePositions) : SubThreat
        {
            public override string Tag => "DoubleZWJ";
        }

        /// <summary>A ZWJ flanked by a non-emoji codepoint (or sitting at an input
        /// edge). <see cref="ZwjPos"/> is the offending ZWJ position;
        /// <see cref="NonEmojiCp"/> is the non-emoji codepoint that flanks it
        /// (0 for an edge ZWJ).</summary>
        public sealed record NonEmojiInjection(int ZwjPos, int NonEmojiCp) : SubThreat
        {
            public override string Tag => "NonEmojiInjection";
        }

        /// <summary>The sequence is longer than <see cref="MaxRgiLength"/>.
        /// <see cref="Length"/> is the observed length; <see cref="MaxLength"/> is
        /// the RGI cap that was exceeded.</summary>
        public sealed record OverLength(int Length, int MaxLength) : SubThreat
        {
            public override string Tag => "OverLength";
        }

        /// <summary>Five or more skin-tone modifiers (the family-emoji maximum is
        /// four). <see cref="Count"/> is the observed skin-tone modifier
        /// count.</summary>
        public sealed record SkinToneOverflow(int Count) : SubThreat
        {
            public override string Tag => "SkinToneOverflow";
        }

        /// <summary>ZWJs are present and no other sub-threat matched, but the
        /// sequence is not a registered RGI ZWJ sequence.
        /// <see cref="ChainLen"/> is the length of the unregistered ZWJ
        /// chain.</summary>
        public sealed record UnregisteredSequence(int ChainLen) : SubThreat
        {
            public override string Tag => "UnregisteredSequence";
        }

        /// <summary>Top-level classification for EmojiZwjIntegrity.</summary>
        public abstract record Classification
        {
            /// <summary>True iff the classification is Clear.</summary>
            public abstract bool IsClear { get; }

            /// <summary>Human-facing tag for a hazard, or null when clear.</summary>
            public abstract string? Tag { get; }

            /// <summary>Implicated positions (empty when clear).</summary>
            public abstract IReadOnlyList<int> Positions { get; }

            /// <summary>Fully-qualified reason code
            /// (unicode.security.I.emoji-zwj-integrity.&lt;tag&gt;) routed through
            /// the port's shared reason-code machinery, or null when
            /// clear.</summary>
            public string? ReasonCode =>
                Tag is null ? null : Security.ReasonCode(Family.EmojiZwjIntegrity, Tag);
        }

        /// <summary>A well-formed or non-ZWJ input.</summary>
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
            IReadOnlyList<int> ZwjPositions,
            int ChainLength,
            bool IsRegisteredRgi,
            int SkinToneCount);

        // ─────────────────────────────────────────────────────────────────
        // §3 RGI ZWJ-sequence data (bundled Data/emoji-zwj-sequences.txt)
        // ─────────────────────────────────────────────────────────────────

        private static List<List<int>>? zwjSequences;
        private static HashSet<int>? zwjAlphabet;

        /// <summary>Parse the registered RGI ZWJ sequences from
        /// emoji-zwj-sequences.txt. Each non-comment row is
        /// <c>&lt;cp&gt; &lt;cp&gt; ... ; RGI_Emoji_ZWJ_Sequence ; &lt;desc&gt;
        /// # &lt;cmt&gt;</c>; the codepoint list is the field before the first
        /// <c>;</c>.</summary>
        private static List<List<int>> ParseZwjSequences(string raw)
        {
            var output = new List<List<int>>();
            foreach (var rawLine in raw.Split('\n'))
            {
                var hash = rawLine.IndexOf('#');
                var body = (hash >= 0 ? rawLine.Substring(0, hash) : rawLine).Trim();
                if (body.Length == 0) continue;
                var seqField = body.Split(';')[0];
                var seq = new List<int>();
                var parsedOk = true;
                foreach (var token in seqField.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
                {
                    var cp = Security.ParseHex(token);
                    if (cp is null)
                    {
                        parsedOk = false;
                        break;
                    }
                    seq.Add(cp.Value);
                }
                if (parsedOk && seq.Count > 0) output.Add(seq);
            }
            return output;
        }

        private static List<List<int>> ZwjSequences()
        {
            zwjSequences ??= ParseZwjSequences(Security.ReadDataFile("emoji-zwj-sequences.txt"));
            return zwjSequences;
        }

        /// <summary>The ZWJ alphabet: every distinct codepoint occurring at any
        /// position of any registered RGI ZWJ sequence, excluding the joiner
        /// U+200D itself.</summary>
        private static HashSet<int> BuildZwjAlphabet()
        {
            var set = new HashSet<int>();
            foreach (var seq in ZwjSequences())
            {
                foreach (var cp in seq)
                {
                    if (cp != Zwj) set.Add(cp);
                }
            }
            return set;
        }

        private static HashSet<int> ZwjAlphabet()
        {
            zwjAlphabet ??= BuildZwjAlphabet();
            return zwjAlphabet;
        }

        /// <summary>True iff <paramref name="cps"/> is exactly a registered RGI
        /// ZWJ sequence.</summary>
        public static bool IsRegisteredZwjSequence(IReadOnlyList<int> cps)
        {
            foreach (var seq in ZwjSequences())
            {
                if (seq.Count == cps.Count && seq.SequenceEqual(cps)) return true;
            }
            return false;
        }

        /// <summary>True iff <paramref name="cp"/> appears at some position of a
        /// registered RGI ZWJ sequence (the canonical "what may flank a ZWJ?"
        /// predicate).</summary>
        public static bool IsEmojiTarget(int cp) => ZwjAlphabet().Contains(cp);

        // ─────────────────────────────────────────────────────────────────
        // §4 Core predicates
        // ─────────────────────────────────────────────────────────────────

        /// <summary>True iff <paramref name="cp"/> is the ZWJ codepoint.</summary>
        public static bool IsZwj(int cp) => cp == Zwj;

        /// <summary>True iff <paramref name="cp"/> is an emoji skin-tone modifier
        /// (U+1F3FB..U+1F3FF).</summary>
        public static bool IsEmojiModifier(int cp) => cp >= 0x1F3FB && cp <= 0x1F3FF;

        /// <summary>Positions of every ZWJ in <paramref name="input"/>.</summary>
        private static List<int> ZwjPositions(IReadOnlyList<int> input)
        {
            var output = new List<int>();
            for (var i = 0; i < input.Count; i++)
            {
                if (IsZwj(input[i])) output.Add(i);
            }
            return output;
        }

        /// <summary>Count of skin-tone modifier codepoints.</summary>
        private static int SkinToneCount(IReadOnlyList<int> input)
        {
            var count = 0;
            foreach (var cp in input)
            {
                if (IsEmojiModifier(cp)) count++;
            }
            return count;
        }

        /// <summary>Positions of the first ZWJ in each ZWJ-ZWJ adjacent
        /// pair.</summary>
        private static List<int> DoubleZwjPositions(IReadOnlyList<int> input)
        {
            var output = new List<int>();
            for (var i = 0; i < input.Count; i++)
            {
                if (i + 1 < input.Count && IsZwj(input[i]) && IsZwj(input[i + 1])) output.Add(i);
            }
            return output;
        }

        /// <summary>The first ZWJ position where either neighbour is a non-emoji
        /// codepoint, as (zwjPos, offendingCp). A ZWJ at an input edge (no
        /// preceding or no following codepoint) is itself an injection-class
        /// hazard, reported with offending codepoint 0. Null when no injection is
        /// found.</summary>
        private static (int ZwjPos, int NonEmojiCp)? FirstNonEmojiInjection(IReadOnlyList<int> input)
        {
            for (var i = 0; i < input.Count; i++)
            {
                if (!IsZwj(input[i])) continue;
                var hasPrev = i > 0;
                var hasNext = i + 1 < input.Count;
                if (hasPrev && hasNext)
                {
                    var prevCp = input[i - 1];
                    var nextCp = input[i + 1];
                    if (!IsEmojiTarget(prevCp)) return (i, prevCp);
                    if (!IsEmojiTarget(nextCp)) return (i, nextCp);
                }
                else
                {
                    // A ZWJ with no preceding OR no following codepoint is itself
                    // a NonEmojiInjection with offending codepoint 0.
                    return (i, 0);
                }
            }
            return null;
        }

        // ─────────────────────────────────────────────────────────────────
        // §5 Top-level detection
        // ─────────────────────────────────────────────────────────────────

        /// <summary>The EmojiZwjIntegrity detection function.</summary>
        public static Verdict Detect(IReadOnlyList<int> input)
        {
            var zwjs = ZwjPositions(input);
            var stCount = SkinToneCount(input);
            var isRgi = IsRegisteredZwjSequence(input);
            var chainLen = zwjs.Count == 0 ? 0 : input.Count;

            if (zwjs.Count == 0 && stCount <= 1)
            {
                return new Verdict(input.ToList(), new Clear(), new List<int>(), 0, isRgi, stCount);
            }

            Classification classification;
            if (isRgi)
            {
                // Phase 3: a registered RGI sequence is always clear.
                classification = new Clear();
            }
            else
            {
                // Phase 4.1: ZWJ-ZWJ adjacency.
                var dzwj = DoubleZwjPositions(input);
                if (dzwj.Count > 0)
                {
                    classification = new Hazard(new DoubleZwj(dzwj), dzwj, new List<int>());
                }
                // Phase 4.2: ZWJ adjacent to a non-emoji codepoint.
                else if (FirstNonEmojiInjection(input) is (int zwjPos, int offendCp))
                {
                    classification = new Hazard(
                        new NonEmojiInjection(zwjPos, offendCp),
                        new List<int> { zwjPos },
                        new List<int>());
                }
                // Phase 4.3: length cap.
                else if (input.Count > MaxRgiLength)
                {
                    classification = new Hazard(
                        new OverLength(input.Count, MaxRgiLength),
                        new List<int>(),
                        new List<int>());
                }
                // Phase 4.4: skin-tone overflow.
                else if (stCount >= 5)
                {
                    classification = new Hazard(new SkinToneOverflow(stCount), new List<int>(), new List<int>());
                }
                // Phase 4.5: catch-all for unregistered ZWJ sequences.
                else if (zwjs.Count > 0)
                {
                    classification = new Hazard(new UnregisteredSequence(input.Count), zwjs, new List<int>());
                }
                else
                {
                    classification = new Clear();
                }
            }

            return new Verdict(input.ToList(), classification, zwjs, chainLen, isRgi, stCount);
        }
    }
}
