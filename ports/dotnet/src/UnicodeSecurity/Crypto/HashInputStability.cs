namespace UnicodeSecurity;

// hash-input-stability (K layer) — detection of inputs that are not in
// canonical hash-input form. Per UTS #39 §6.1 + RFC 4880 / 9580 + RFC 8785, an
// input hashed by a signer must be byte-identical to the input hashed by the
// verifier; if the two ends pick different canonical forms (NFC vs NFD, trim
// policy, line-ending convention) the resulting hashes diverge silently while
// both sides believe they signed the same content.
//
// Direct port of ports/rust/src/security/crypto/hash_input_stability.rs, itself
// a port of Unicode/Security/Crypto/HashInputStability.lean. The canonical
// (hash-stable) form is trimTrailing(toNfc(input)), where trimTrailing strips
// only ASCII whitespace {U+0020, U+0009, U+000A, U+000D}; Unicode whitespace
// (U+00A0, U+2000..U+200A, U+3000) is content and is not stripped. NFC is the
// port's own Security.ToNfc, never a host normalizer.
//
// Six probes run in strict priority order (first hit wins):
//
//   1. encodingMismatch          (context: DeclaredEncoding)
//   2. webhookSignatureDrift     (context: ServerBytes)
//   3. auditLogReinterpretation  (context: AsWritten)
//   4. signedMessageRule         (context: RfcRule)
//   5. trailingWhitespace        (bare input)
//   6. normalizationDrift        (bare input)
//   7. clear
//
// Context-specific probes fire first because they carry more precise threat
// information than the generic probes. Detect is the convenience wrapper
// DetectWithContext(Context.Default, input) that leaves the four context-bearing
// probes silent.
public static partial class Security
{
    public static class HashInputStability
    {
        // ─────────────────────────────────────────────────────────────────
        // §1 Types
        // ─────────────────────────────────────────────────────────────────

        /// <summary>RFC canonicalisation profiles that the signedMessageRule
        /// probe checks against. Each variant names a specific canonicalisation
        /// rule from a published RFC; callers pass one as Context.RfcRule to opt
        /// the probe in.</summary>
        public enum RfcRule
        {
            /// <summary>RFC 4880 §5.2.4 — detached signatures normalise trailing
            /// whitespace; trailing whitespace in the body causes signature
            /// mismatch.</summary>
            Pgp4880TrailingWhitespace,

            /// <summary>RFC 9580 (current OpenPGP) — line-endings normalise to
            /// CRLF before signing; a bare LF or bare CR violates the
            /// canonicalisation rule.</summary>
            Pgp9580LineEnding,

            /// <summary>RFC 8785 §3.2.5 — JSON Canonicalization Scheme requires
            /// strings to be in NFC before serialisation.</summary>
            Rfc8785NfcRequirement,

            /// <summary>RFC 8259 §7 — JSON strings must escape control
            /// characters (U+0000..U+001F); unescaped control bytes in a string
            /// violate.</summary>
            Rfc8259ControlChar,

            /// <summary>RFC 7515 §2 — JWS Base64URL encoding; any character
            /// outside [A-Za-z0-9_-] is a canonicalisation violation.</summary>
            Rfc7515JwsBase64Url,

            /// <summary>RFC 6376 §3.4.4 — DKIM relaxed body canonicalization
            /// collapses internal whitespace runs to a single SP; a multi-char
            /// internal whitespace run indicates the canonicalisation has not
            /// been applied.</summary>
            Rfc6376DkimRelaxed,

            /// <summary>RFC 5751 §3.1.1 — S/MIME canonical text; like PGP 9580,
            /// a bare LF or bare CR (not part of a CRLF pair) violates.</summary>
            Rfc5751SmimeLineEnding,
        }

        /// <summary>Fixture-string identifier for an <see cref="RfcRule"/> — used
        /// by the conformance harness's attribution parser to round-trip rule
        /// selections.</summary>
        public static string Tag(RfcRule rule) => rule switch
        {
            RfcRule.Pgp4880TrailingWhitespace => "pgp4880TrailingWhitespace",
            RfcRule.Pgp9580LineEnding => "pgp9580LineEnding",
            RfcRule.Rfc8785NfcRequirement => "rfc8785NfcRequirement",
            RfcRule.Rfc8259ControlChar => "rfc8259ControlChar",
            RfcRule.Rfc7515JwsBase64Url => "rfc7515JwsBase64Url",
            RfcRule.Rfc6376DkimRelaxed => "rfc6376DkimRelaxed",
            RfcRule.Rfc5751SmimeLineEnding => "rfc5751SmimeLineEnding",
            _ => throw new ArgumentOutOfRangeException(nameof(rule), rule, "unreachable RfcRule variant"),
        };

        /// <summary>Inverse of <see cref="Tag(RfcRule)"/>. Returns null for
        /// unrecognised strings.</summary>
        public static RfcRule? FromTag(string tag) => tag switch
        {
            "pgp4880TrailingWhitespace" => RfcRule.Pgp4880TrailingWhitespace,
            "pgp9580LineEnding" => RfcRule.Pgp9580LineEnding,
            "rfc8785NfcRequirement" => RfcRule.Rfc8785NfcRequirement,
            "rfc8259ControlChar" => RfcRule.Rfc8259ControlChar,
            "rfc7515JwsBase64Url" => RfcRule.Rfc7515JwsBase64Url,
            "rfc6376DkimRelaxed" => RfcRule.Rfc6376DkimRelaxed,
            "rfc5751SmimeLineEnding" => RfcRule.Rfc5751SmimeLineEnding,
            _ => null,
        };

        /// <summary>Sub-threats this detector can fire. Two probes fire from the
        /// raw input alone (<see cref="TrailingWhitespace"/>, <see
        /// cref="NormalizationDrift"/>); the other four require the corresponding
        /// <see cref="Context"/> field to be set.</summary>
        public abstract record SubThreat
        {
            /// <summary>Human-facing classification tag for this sub-threat.</summary>
            public abstract string Tag { get; }
        }

        /// <summary>Input diverges from its NFC form;
        /// <see cref="FirstDivergentPos"/> is the first diverging codepoint
        /// index.</summary>
        public sealed record NormalizationDrift(int FirstDivergentPos) : SubThreat
        {
            public override string Tag => "NormalizationDrift";
        }

        /// <summary>Input has trailing ASCII whitespace; <see cref="Count"/> is
        /// how many codepoints.</summary>
        public sealed record TrailingWhitespace(int Count) : SubThreat
        {
            public override string Tag => "TrailingWhitespace";
        }

        /// <summary>Declared encoding disagrees with the codepoint array (or the
        /// array holds an invalid scalar).</summary>
        public sealed record EncodingMismatch(string DeclaredEnc, string DetectedEnc) : SubThreat
        {
            public override string Tag => "EncodingMismatch";
        }

        /// <summary>Input violates the named RFC's canonicalisation rule at
        /// <see cref="FirstPos"/>.</summary>
        public sealed record SignedMessageRule(string RfcRule, int FirstPos) : SubThreat
        {
            public override string Tag => "SignedMessageRule";
        }

        /// <summary>The re-read input differs from <see cref="Context.AsWritten"/>
        /// at <see cref="FirstDivergentPos"/>.</summary>
        public sealed record AuditLogReinterpretation(int FirstDivergentPos) : SubThreat
        {
            public override string Tag => "AuditLogReinterpretation";
        }

        /// <summary>The client input differs from
        /// <see cref="Context.ServerBytes"/> at <see cref="FirstPos"/>.</summary>
        public sealed record WebhookSignatureDrift(int FirstPos) : SubThreat
        {
            public override string Tag => "WebhookSignatureDrift";
        }

        /// <summary>Context passed to <see cref="DetectWithContext"/> to enable
        /// the four context-bearing probes. Each field is null by default — the
        /// empty context is the identity case:
        /// DetectWithContext(Context.Default, input) equals Detect(input).</summary>
        public sealed record Context(
            string? DeclaredEncoding = null,
            RfcRule? RfcRule = null,
            IReadOnlyList<int>? AsWritten = null,
            IReadOnlyList<int>? ServerBytes = null)
        {
            /// <summary>The empty context: every context-bearing probe silent.</summary>
            public static readonly Context Default = new();
        }

        /// <summary>Top-level K-layer classification.</summary>
        public abstract record Classification
        {
            /// <summary>True iff the input is clear.</summary>
            public abstract bool IsClear { get; }

            /// <summary>Human-facing tag for a hazard, or null when clear.</summary>
            public abstract string? Tag { get; }

            /// <summary>Implicated positions (empty when clear).</summary>
            public abstract IReadOnlyList<int> Positions { get; }

            /// <summary>Fully-qualified reason code
            /// (unicode.security.K.hash-input-stability.&lt;tag&gt;) routed
            /// through the port's shared reason-code machinery, or null when
            /// clear.</summary>
            public string? ReasonCode =>
                Tag is null ? null : Security.ReasonCode(Family.HashInputStability, Tag);
        }

        /// <summary>The input is already hash-stable under every enabled probe.</summary>
        public sealed record Clear : Classification
        {
            public override bool IsClear => true;
            public override string? Tag => null;
            public override IReadOnlyList<int> Positions => System.Array.Empty<int>();
        }

        /// <summary>A hazard was found: the sub-threat and its implicated
        /// positions.</summary>
        public sealed record Hazard(SubThreat Sub, IReadOnlyList<int> HazardPositions) : Classification
        {
            public override bool IsClear => false;
            public override string? Tag => Sub.Tag;
            public override IReadOnlyList<int> Positions => HazardPositions;
        }

        /// <summary>K-layer verdict — the structured output of <see
        /// cref="Detect"/>. <see cref="StableSize"/> is the codepoint count of
        /// the hash-stable canonical form; downstream callers compare it against
        /// Input.Count to size the byte-drift their hash sees.</summary>
        public sealed record Verdict(
            IReadOnlyList<int> Input,
            Classification Classify,
            IReadOnlyList<int> StableForm,
            int StableSize);

        // ─────────────────────────────────────────────────────────────────
        // §3 Canonicalisation pipeline
        // ─────────────────────────────────────────────────────────────────

        /// <summary>True iff <paramref name="cp"/> is an ASCII whitespace
        /// codepoint that line-oriented hash-input protocols treat as framing
        /// rather than content: U+0020 SPACE, U+0009 TAB, U+000A LF,
        /// U+000D CR.</summary>
        private static bool IsAsciiWhitespace(int cp) =>
            cp == 0x0020 || cp == 0x0009 || cp == 0x000A || cp == 0x000D;

        /// <summary>Count of trailing ASCII whitespace codepoints in
        /// <paramref name="input"/>.</summary>
        private static int CountTrailingWhitespace(IReadOnlyList<int> input)
        {
            var count = 0;
            for (var i = input.Count - 1; i >= 0; i--)
            {
                if (!IsAsciiWhitespace(input[i])) break;
                count++;
            }
            return count;
        }

        /// <summary>Strip trailing ASCII whitespace.</summary>
        private static List<int> TrimTrailing(IReadOnlyList<int> input)
        {
            var keep = input.Count - CountTrailingWhitespace(input);
            var output = new List<int>(keep);
            for (var i = 0; i < keep; i++) output.Add(input[i]);
            return output;
        }

        /// <summary>The K-layer hash-stable form of an input: NFC then trim, in
        /// spec order. NFC is the port's own <c>Security.ToNfc</c>.</summary>
        public static List<int> HashStable(IReadOnlyList<int> input) =>
            TrimTrailing(Security.ToNfc(input.ToList()));

        // ─────────────────────────────────────────────────────────────────
        // §5 Priority position-finder
        // ─────────────────────────────────────────────────────────────────

        /// <summary>First position at which <paramref name="a"/> and
        /// <paramref name="b"/> diverge, or the length of the shared prefix when
        /// one strictly extends the other. Null when identical.</summary>
        private static int? FirstArrayDivergence(IReadOnlyList<int> a, IReadOnlyList<int> b)
        {
            var common = Math.Min(a.Count, b.Count);
            for (var i = 0; i < common; i++)
            {
                if (a[i] != b[i]) return i;
            }
            if (a.Count != b.Count) return common;
            return null;
        }

        // ─────────────────────────────────────────────────────────────────
        // §6 Context-bearing probes
        // ─────────────────────────────────────────────────────────────────

        /// <summary>Lower-case an ASCII letter (U+0041..U+005A →
        /// U+0061..U+007A).</summary>
        private static int AsciiLower(int cp) =>
            cp >= 0x41 && cp <= 0x5A ? cp + 0x20 : cp;

        /// <summary>True iff <paramref name="label"/> (after ASCII case-fold)
        /// names UTF-8: accepts "utf-8", "UTF-8", "UTF8", "utf8". Non-ASCII
        /// characters pass through unchanged.</summary>
        private static bool IsUtf8Label(string label)
        {
            var sb = new System.Text.StringBuilder(label.Length);
            foreach (var c in label) sb.Append((char)AsciiLower(c));
            var normalised = sb.ToString();
            return normalised == "utf-8" || normalised == "utf8";
        }

        /// <summary>True iff <paramref name="cp"/> is a valid Unicode scalar
        /// value: in [0, 0x10FFFF] and not a surrogate [0xD800, 0xDFFF].</summary>
        private static bool IsValidScalar(int cp) =>
            cp >= 0 && cp <= 0x10FFFF && !(cp >= 0xD800 && cp <= 0xDFFF);

        /// <summary>First position in <paramref name="input"/> holding a
        /// codepoint that is not a valid Unicode scalar, or null if every
        /// codepoint is valid.</summary>
        private static int? FirstInvalidScalar(IReadOnlyList<int> input)
        {
            for (var i = 0; i < input.Count; i++)
            {
                if (!IsValidScalar(input[i])) return i;
            }
            return null;
        }

        /// <summary>Probe: encodingMismatch. Validity is dispatched first — an
        /// invalid scalar fires with DetectedEnc = "invalid" regardless of the
        /// declared label; otherwise a non-UTF-8 label fires with
        /// DetectedEnc = "utf-8" at position 0. Returns (declared, detected,
        /// firstPos) when firing.</summary>
        private static (string Declared, string Detected, int FirstPos)? EncodingMismatchProbe(
            string declared, IReadOnlyList<int> input)
        {
            if (FirstInvalidScalar(input) is int pos)
            {
                return (declared, "invalid", pos);
            }
            if (IsUtf8Label(declared)) return null;
            return (declared, "utf-8", 0);
        }

        /// <summary>Probe: signedMessageRule for pgp4880TrailingWhitespace. Same
        /// condition as trailingWhitespace; returns the first position of the
        /// trailing run.</summary>
        private static int? Pgp4880Violation(IReadOnlyList<int> input)
        {
            var trailing = CountTrailingWhitespace(input);
            return trailing > 0 ? input.Count - trailing : (int?)null;
        }

        /// <summary>Probe: signedMessageRule for pgp9580LineEnding. First bare LF
        /// (U+000A not preceded by CR) or bare CR (U+000D not followed by
        /// LF).</summary>
        private static int? Pgp9580Violation(IReadOnlyList<int> input)
        {
            for (var i = 0; i < input.Count; i++)
            {
                var cp = input[i];
                if (cp == 0x000A)
                {
                    // LF: violating iff not preceded by CR.
                    var precededByCr = i > 0 && input[i - 1] == 0x000D;
                    if (!precededByCr) return i;
                }
                else if (cp == 0x000D)
                {
                    // CR: violating iff not followed by LF.
                    var followedByLf = i + 1 < input.Count && input[i + 1] == 0x000A;
                    if (!followedByLf) return i;
                }
            }
            return null;
        }

        /// <summary>Probe: signedMessageRule for rfc8785NfcRequirement. Same
        /// condition as normalizationDrift; returns the first NFC divergence
        /// position.</summary>
        private static int? Rfc8785Violation(IReadOnlyList<int> input)
        {
            var nfc = Security.ToNfc(input.ToList());
            return input.SequenceEqual(nfc) ? null : FirstArrayDivergence(input, nfc);
        }

        /// <summary>Probe: signedMessageRule for rfc8259ControlChar. First C0
        /// control (U+0000..U+001F) — the JSON-permitted whitespace still
        /// requires escaping, so it also counts.</summary>
        private static int? Rfc8259Violation(IReadOnlyList<int> input)
        {
            for (var i = 0; i < input.Count; i++)
            {
                if (input[i] <= 0x1F) return i;
            }
            return null;
        }

        /// <summary>True iff <paramref name="cp"/> is in the JWS Base64URL
        /// alphabet [A-Za-z0-9_-].</summary>
        private static bool IsBase64Url(int cp) =>
            (cp >= 0x41 && cp <= 0x5A)       // A-Z
            || (cp >= 0x61 && cp <= 0x7A)    // a-z
            || (cp >= 0x30 && cp <= 0x39)    // 0-9
            || cp == 0x2D                    // '-'
            || cp == 0x5F;                   // LOW LINE

        /// <summary>Probe: signedMessageRule for rfc7515JwsBase64Url. First
        /// codepoint outside [A-Za-z0-9_-].</summary>
        private static int? Rfc7515Violation(IReadOnlyList<int> input)
        {
            for (var i = 0; i < input.Count; i++)
            {
                if (!IsBase64Url(input[i])) return i;
            }
            return null;
        }

        /// <summary>True iff <paramref name="cp"/> is DKIM whitespace: U+0020
        /// SPACE or U+0009 HTAB.</summary>
        private static bool IsDkimWhitespace(int cp) => cp == 0x20 || cp == 0x09;

        /// <summary>Probe: signedMessageRule for rfc6376DkimRelaxed. Position of
        /// the second whitespace codepoint in the first internal whitespace run
        /// longer than one.</summary>
        private static int? Rfc6376Violation(IReadOnlyList<int> input)
        {
            for (var i = 0; i < input.Count; i++)
            {
                if (IsDkimWhitespace(input[i]) && i > 0 && IsDkimWhitespace(input[i - 1]))
                {
                    return i;
                }
            }
            return null;
        }

        /// <summary>Probe: signedMessageRule for rfc5751SmimeLineEnding. Reuses
        /// the PGP 9580 bare-line-ending rule.</summary>
        private static int? Rfc5751Violation(IReadOnlyList<int> input) => Pgp9580Violation(input);

        /// <summary>Dispatch the RFC-rule probe. First violation position, or
        /// null if clean.</summary>
        private static int? RfcRuleViolation(RfcRule rule, IReadOnlyList<int> input) => rule switch
        {
            RfcRule.Pgp4880TrailingWhitespace => Pgp4880Violation(input),
            RfcRule.Pgp9580LineEnding => Pgp9580Violation(input),
            RfcRule.Rfc8785NfcRequirement => Rfc8785Violation(input),
            RfcRule.Rfc8259ControlChar => Rfc8259Violation(input),
            RfcRule.Rfc7515JwsBase64Url => Rfc7515Violation(input),
            RfcRule.Rfc6376DkimRelaxed => Rfc6376Violation(input),
            RfcRule.Rfc5751SmimeLineEnding => Rfc5751Violation(input),
            _ => throw new ArgumentOutOfRangeException(nameof(rule), rule, "unreachable RfcRule variant"),
        };

        // ─────────────────────────────────────────────────────────────────
        // §7 Top-level detection
        // ─────────────────────────────────────────────────────────────────

        /// <summary>The full K-layer detection function. Runs all six probes in
        /// priority order, with the context-bearing probes ahead of the generic
        /// ones.</summary>
        public static Verdict DetectWithContext(Context ctx, IReadOnlyList<int> input)
        {
            var stable = HashStable(input);

            // Probe 1: encodingMismatch.
            var encodingHit = ctx.DeclaredEncoding is string label
                ? EncodingMismatchProbe(label, input)
                : null;

            // Probe 2: webhookSignatureDrift.
            var webhookHit = ctx.ServerBytes is IReadOnlyList<int> server
                ? FirstArrayDivergence(input, server)
                : null;

            // Probe 3: auditLogReinterpretation.
            var auditHit = ctx.AsWritten is IReadOnlyList<int> written
                ? FirstArrayDivergence(written, input)
                : null;

            // Probe 4: signedMessageRule.
            (RfcRule Rule, int Pos)? rfcHit = null;
            if (ctx.RfcRule is RfcRule rule && RfcRuleViolation(rule, input) is int rfcPos)
            {
                rfcHit = (rule, rfcPos);
            }

            // Probe 5: trailingWhitespace.
            var trailingCount = CountTrailingWhitespace(input);

            // Probe 6: normalizationDrift.
            var nfc = Security.ToNfc(input.ToList());
            var nonNfcPos = input.SequenceEqual(nfc) ? null : FirstArrayDivergence(input, nfc);

            var classification = Classify(
                encodingHit,
                webhookHit,
                auditHit,
                rfcHit,
                trailingCount,
                input.Count,
                nonNfcPos);

            return new Verdict(input.ToList(), classification, stable, stable.Count);
        }

        /// <summary>The priority resolver: first hit wins, in the spec's fixed
        /// order.</summary>
        private static Classification Classify(
            (string Declared, string Detected, int FirstPos)? encodingHit,
            int? webhookHit,
            int? auditHit,
            (RfcRule Rule, int Pos)? rfcHit,
            int trailingCount,
            int inputLen,
            int? nonNfcPos)
        {
            if (encodingHit is (string declared, string detected, int encPos))
            {
                return new Hazard(
                    new EncodingMismatch(declared, detected),
                    new List<int> { encPos });
            }
            if (webhookHit is int webhookPos)
            {
                return new Hazard(
                    new WebhookSignatureDrift(webhookPos),
                    new List<int> { webhookPos });
            }
            if (auditHit is int auditPos)
            {
                return new Hazard(
                    new AuditLogReinterpretation(auditPos),
                    new List<int> { auditPos });
            }
            if (rfcHit is (RfcRule rule, int rfcPos))
            {
                return new Hazard(
                    new SignedMessageRule(Tag(rule), rfcPos),
                    new List<int> { rfcPos });
            }
            if (trailingCount > 0)
            {
                var p = inputLen - trailingCount;
                return new Hazard(
                    new TrailingWhitespace(trailingCount),
                    new List<int> { p });
            }
            if (nonNfcPos is int driftPos)
            {
                return new Hazard(
                    new NormalizationDrift(driftPos),
                    new List<int> { driftPos });
            }
            return new Clear();
        }

        /// <summary>Convenience wrapper over <see cref="DetectWithContext"/> with
        /// the empty context — equivalent to running only the two bare-input
        /// probes (trailingWhitespace, normalizationDrift).</summary>
        public static Verdict Detect(IReadOnlyList<int> input) =>
            DetectWithContext(Context.Default, input);
    }
}
