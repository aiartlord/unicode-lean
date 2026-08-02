namespace UnicodeSecurity;

// identifier-form-drift (X layer) — cross-layer identifier × form drift
// (boundary-layer detector).
//
// Direct port of the verified Rust reference implementation, itself a
// byte-faithful transliteration of the Lean specification
// Unicode.Security.Boundary.IdentifierFormDrift.
//
// Threat model. Tier A₂ two-system bypass. An identity validator and a form
// normalizer disagree about a codepoint: stage A runs the UTS #39
// Identifier_Status check before normalisation and rejects, say, U+1D44E
// MATHEMATICAL ITALIC SMALL A (Restricted); stage B normalises first and then
// runs the same check, seeing U+0061 'a' (Allowed) and accepting. The attacker
// controls which stage processes the input and exploits the disagreement. The
// same shape covers fullwidth (U+FF21), circled (U+24B6), ligature (U+FB01),
// and Roman-numeral (U+2163) compatibility forms.
//
// The detector fires on the form transition itself — it reports the first input
// position whose Identifier_Status differs from the Identifier_Status of that
// codepoint's NFKD head, and the verdict carries the total count of such
// positions. This is orthogonal to the single-form identity-spoofing detectors
// (which examine the input under one form) and stronger than a form-of-input
// fold (it asks whether the identifier verdict changes, not whether any output
// bit changes).
//
// Note on Hangul: precomposed syllables are Allowed while their NFKD-head jamos
// are Restricted, so pure Korean text fires; callers intending to accept Korean
// identifiers should apply NFC before evaluating admissibility.
//
// It reuses the port's own UTS #39 Identifier_Status predicate (IsIdAllowed,
// parsing the vendored digest-pinned IdentifierStatus.txt) and the port's own
// compatibility-decomposition pipeline (Security.ToNfkd), never a host
// normalization or identifier library.
//
// Sub-threat (direction-agnostic):
//   IdentifierStatusShift — the first input position whose Identifier_Status
//   differs from its NFKD-head's. The verdict carries the total shift count.
public static partial class Security
{
    // ─────────────────────────────────────────────────────────────────────
    // UTS #39 Identifier_Status predicate.
    // ─────────────────────────────────────────────────────────────────────
    //
    // The Allowed range set parsed from the vendored IdentifierStatus.txt (UCD
    // 17.0.0), whose bytes are digest-pinned in PinnedTableDigests and served
    // through the fail-closed ReadDataFile gate. Every codepoint not explicitly
    // listed has Identifier_Status = Restricted, so membership in this set is
    // exactly the Allowed predicate. Parsed once and cached, mirroring the
    // port's DerivedCoreProperties range-set idiom (ParseCasingProperty).
    private static List<(int Lo, int Hi)>? identifierStatusAllowedRanges;

    private static List<(int Lo, int Hi)> ParseIdentifierStatusAllowed()
    {
        var result = new List<(int Lo, int Hi)>();
        foreach (var rawLine in ReadDataFile("IdentifierStatus.txt").Split('\n'))
        {
            var line = rawLine.Split('#', 2)[0].Trim();
            if (line.Length == 0) continue;
            var parts = line.Split(';', 2);
            if (parts.Length < 2 || parts[1].Trim() != "Allowed") continue;
            var field = parts[0].Trim();
            var dots = field.IndexOf("..", StringComparison.Ordinal);
            if (dots < 0)
            {
                var cp = ParseHex(field);
                if (cp is not null) result.Add((cp.Value, cp.Value));
            }
            else
            {
                var lo = ParseHex(field[..dots]);
                var hi = ParseHex(field[(dots + 2)..]);
                if (lo is not null && hi is not null) result.Add((lo.Value, hi.Value));
            }
        }
        return result;
    }

    /// <summary>True iff <paramref name="cp"/> has UTS #39
    /// Identifier_Status = Allowed. All codepoints absent from
    /// IdentifierStatus.txt are Restricted.</summary>
    private static bool IsIdAllowed(int cp)
    {
        identifierStatusAllowedRanges ??= ParseIdentifierStatusAllowed();
        foreach (var (lo, hi) in identifierStatusAllowedRanges)
        {
            if (lo <= cp && cp <= hi) return true;
        }
        return false;
    }

    public static class IdentifierFormDrift
    {
        // ─────────────────────────────────────────────────────────────────
        // §1 Types
        // ─────────────────────────────────────────────────────────────────

        /// <summary>Sub-threat enumeration for IdentifierFormDrift. The single
        /// variant overrides <see cref="Tag"/>, so the fixture-row tag is
        /// resolved polymorphically with no catch-all.</summary>
        public abstract record SubThreat
        {
            /// <summary>Fixture-row tag string for this sub-threat (matches the
            /// Lean SubThreat.tag).</summary>
            public abstract string Tag { get; }
        }

        /// <summary>A codepoint at <see cref="BasePos"/> whose Identifier_Status
        /// differs from its NFKD-head's (codepoint <see cref="Cp"/>).</summary>
        public sealed record IdentifierStatusShift(int BasePos, int Cp) : SubThreat
        {
            public override string Tag => "IdentifierStatusShift";
        }

        /// <summary>Top-level classification (no status shift =
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
            /// (unicode.security.X.identifier-form-drift.&lt;tag&gt;) routed
            /// through the port's shared reason-code machinery, or null when
            /// clear.</summary>
            public string? ReasonCode =>
                Tag is null ? null : Security.ReasonCode(Family.IdentifierFormDrift, Tag);
        }

        /// <summary>No status shift present.</summary>
        public sealed record Clear : Classification
        {
            public override bool IsClear => true;
            public override string? Tag => null;
            public override IReadOnlyList<int> Positions => System.Array.Empty<int>();
        }

        /// <summary>A status shift fired: the sub-threat, the implicated
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
            int ShiftCount);

        // ─────────────────────────────────────────────────────────────────
        // §2 Core predicates
        // ─────────────────────────────────────────────────────────────────

        /// <summary>True iff <paramref name="cp"/> has UTS #39
        /// Identifier_Status = Allowed (reuses the port's own IsIdAllowed
        /// predicate over the digest-pinned IdentifierStatus.txt).</summary>
        public static bool IsIdAllowed(int cp) => Security.IsIdAllowed(cp);

        /// <summary>Identifier_Status = Allowed of the first codepoint of
        /// <paramref name="cp"/>'s NFKD form, or <paramref name="cp"/>'s own
        /// status when NFKD is empty (defensive — <see cref="Security.ToNfkd"/>
        /// is total and returns at least [cp]). Reuses the port's own UTS #39
        /// predicate and NFKD pipeline.</summary>
        public static bool NfkdHeadAllowed(int cp)
        {
            var nfkd = Security.ToNfkd(new[] { cp });
            return nfkd.Count > 0 ? IsIdAllowed(nfkd[0]) : IsIdAllowed(cp);
        }

        // ─────────────────────────────────────────────────────────────────
        // §3 Sub-detectors
        // ─────────────────────────────────────────────────────────────────

        /// <summary>First input position whose <see cref="IsIdAllowed"/> differs
        /// from its NFKD-head's, or null when none differs.</summary>
        private static (int Pos, int Cp)? FirstStatusShift(IReadOnlyList<int> input)
        {
            for (var idx = 0; idx < input.Count; idx++)
            {
                var cp = input[idx];
                if (IsIdAllowed(cp) != NfkdHeadAllowed(cp)) return (idx, cp);
            }
            return null;
        }

        /// <summary>Total count of input positions where the per-cp status
        /// shifts under NFKD.</summary>
        private static int StatusShiftCount(IReadOnlyList<int> input)
        {
            var count = 0;
            foreach (var cp in input)
            {
                if (IsIdAllowed(cp) != NfkdHeadAllowed(cp)) count++;
            }
            return count;
        }

        // ─────────────────────────────────────────────────────────────────
        // §4 Top-level detection
        // ─────────────────────────────────────────────────────────────────

        /// <summary>The IdentifierFormDrift detection function.</summary>
        public static Verdict Detect(IReadOnlyList<int> input)
        {
            Classification classification = FirstStatusShift(input) is (int pos, int cp)
                ? new Hazard(
                    new IdentifierStatusShift(pos, cp),
                    new List<int> { pos },
                    new List<int>())
                : new Clear();

            return new Verdict(
                input.ToList(),
                classification,
                StatusShiftCount(input));
        }
    }
}
