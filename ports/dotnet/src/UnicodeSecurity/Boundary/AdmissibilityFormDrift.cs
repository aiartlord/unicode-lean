namespace UnicodeSecurity;

// admissibility-form-drift (X layer) — cross-layer identifier-admissibility ×
// form drift (boundary-layer detector).
//
// Direct port of the verified Rust reference implementation, itself a
// byte-faithful transliteration of the Lean specification
// Unicode.Security.Boundary.AdmissibilityFormDrift.
//
// Fires on inputs whose UTS #39 whole-string IsAllowedIdentifier verdict differs
// between the input and its NFKC form. This is the string-level complement of
// IdentifierFormDrift (which scans Identifier_Status against the per-codepoint
// NFKD head): here the whole-string admissibility predicate is evaluated twice —
// once on the input, once on ToNfkc(input). The two are not redundant. In
// particular, a sequence of decomposed Hangul jamos passes the per-codepoint scan
// cleanly (each jamo has identity NFKD and Restricted status on both sides) but
// fires here: the jamo sequence is rejected by IsAllowedIdentifier, while its NFKC
// composition into a precomposed Hangul syllable is accepted.
//
// It reuses the port's own UTS #39 admissibility predicate (IsAllowedIdentifier =
// UAX #31 default identifier ∧ every codepoint Allowed) and NFKC pipeline
// (Security.ToNfkc), never a host normalization or identifier library.
//
// Sub-threat (direction-agnostic):
//   AdmissibilityFormDrift — IsAllowedIdentifier(input) !=
//   IsAllowedIdentifier(ToNfkc(input)). The pair of booleans is carried so the
//   verdict records which direction the drift goes; no position is reported
//   because the predicate is whole-string.
public static partial class Security
{
    // ─────────────────────────────────────────────────────────────────────
    // UAX #31 default-identifier predicate (whole-string).
    // ─────────────────────────────────────────────────────────────────────
    //
    // XID_Start / XID_Continue range sets parsed from the vendored
    // DerivedCoreProperties.txt (UCD 17.0.0), whose bytes are digest-pinned in
    // PinnedTableDigests and served through the fail-closed ReadDataFile gate.
    // Parsed once and cached, reusing the port's DerivedCoreProperties range-set
    // idiom (ParseCasingProperty, which selects any named property column).
    private static List<(int Lo, int Hi)>? xidStartRanges;
    private static List<(int Lo, int Hi)>? xidContinueRanges;

    /// <summary>True iff <paramref name="cp"/> has the UAX #31 XID_Start
    /// property (DerivedCoreProperties.txt).</summary>
    private static bool IsXidStart(int cp)
    {
        xidStartRanges ??= ParseCasingProperty("XID_Start");
        foreach (var (lo, hi) in xidStartRanges)
        {
            if (lo <= cp && cp <= hi) return true;
        }
        return false;
    }

    /// <summary>True iff <paramref name="cp"/> has the UAX #31 XID_Continue
    /// property (DerivedCoreProperties.txt).</summary>
    private static bool IsXidContinue(int cp)
    {
        xidContinueRanges ??= ParseCasingProperty("XID_Continue");
        foreach (var (lo, hi) in xidContinueRanges)
        {
            if (lo <= cp && cp <= hi) return true;
        }
        return false;
    }

    /// <summary>UAX #31 default identifier start: XID_Start or U+005F LOW
    /// LINE.</summary>
    private static bool IsDefaultIdStart(int cp) => IsXidStart(cp) || cp == 0x005F;

    /// <summary>UAX #31 default identifier continue: XID_Continue.</summary>
    private static bool IsDefaultIdContinue(int cp) => IsXidContinue(cp);

    /// <summary>UAX #31 default identifier: a non-empty sequence whose head is a
    /// default id-start and whose tail is all default id-continue.</summary>
    private static bool IsDefaultIdentifier(IReadOnlyList<int> cps)
    {
        if (cps.Count == 0) return false;
        if (!IsDefaultIdStart(cps[0])) return false;
        for (var idx = 1; idx < cps.Count; idx++)
        {
            if (!IsDefaultIdContinue(cps[idx])) return false;
        }
        return true;
    }

    /// <summary>UTS #39 whole-string admissibility: a UAX #31 default identifier
    /// whose every codepoint also has Identifier_Status = Allowed. Reuses the
    /// port's own IsIdAllowed predicate.</summary>
    private static bool IsAllowedIdentifier(IReadOnlyList<int> cps)
    {
        if (!IsDefaultIdentifier(cps)) return false;
        foreach (var cp in cps)
        {
            if (!IsIdAllowed(cp)) return false;
        }
        return true;
    }

    public static class AdmissibilityFormDrift
    {
        // ─────────────────────────────────────────────────────────────────
        // §1 Types
        // ─────────────────────────────────────────────────────────────────

        /// <summary>Sub-threat enumeration for AdmissibilityFormDrift. The single
        /// variant overrides <see cref="Tag"/>, so the fixture-row tag is
        /// resolved polymorphically with no catch-all.</summary>
        public abstract record SubThreat
        {
            /// <summary>Fixture-row tag string for this sub-threat (matches the
            /// Lean SubThreat.tag).</summary>
            public abstract string Tag { get; }
        }

        /// <summary>The whole-string admissibility verdict differs between the
        /// input (<see cref="InputAdmissible"/>) and its NFKC form
        /// (<see cref="NfkcAdmissible"/>).</summary>
        public sealed record AdmissibilityDrift(bool InputAdmissible, bool NfkcAdmissible) : SubThreat
        {
            public override string Tag => "AdmissibilityFormDrift";
        }

        /// <summary>Top-level classification (verdict agrees across forms =
        /// <see cref="Clear"/>).</summary>
        public abstract record Classification
        {
            /// <summary>True iff the classification is Clear.</summary>
            public abstract bool IsClear { get; }

            /// <summary>Human-facing tag for a hazard, or null when clear.</summary>
            public abstract string? Tag { get; }

            /// <summary>Implicated positions (always empty — the predicate is
            /// whole-string).</summary>
            public abstract IReadOnlyList<int> Positions { get; }

            /// <summary>Fully-qualified reason code
            /// (unicode.security.X.admissibility-form-drift.&lt;tag&gt;) routed
            /// through the port's shared reason-code machinery, or null when
            /// clear.</summary>
            public string? ReasonCode =>
                Tag is null ? null : Security.ReasonCode(Family.AdmissibilityFormDrift, Tag);
        }

        /// <summary>The admissibility verdict agrees across forms.</summary>
        public sealed record Clear : Classification
        {
            public override bool IsClear => true;
            public override string? Tag => null;
            public override IReadOnlyList<int> Positions => System.Array.Empty<int>();
        }

        /// <summary>The admissibility verdict drifts across forms: the sub-threat,
        /// the (always-empty, whole-string) implicated positions, and the
        /// (always-empty here) decoded-byte projection, kept for shape parity
        /// with the Lean Classification.hazard.</summary>
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
            bool InputAdmissible,
            bool NfkcAdmissible);

        // ─────────────────────────────────────────────────────────────────
        // §2 Core predicate
        // ─────────────────────────────────────────────────────────────────

        /// <summary>UTS #39 whole-string admissibility (reuses the port's own
        /// UAX #31 default-identifier check and per-codepoint Identifier_Status =
        /// Allowed predicate).</summary>
        public static bool IsAllowedIdentifier(IReadOnlyList<int> cps) =>
            Security.IsAllowedIdentifier(cps);

        // ─────────────────────────────────────────────────────────────────
        // §3 Top-level detection
        // ─────────────────────────────────────────────────────────────────

        /// <summary>The AdmissibilityFormDrift detection function.</summary>
        public static Verdict Detect(IReadOnlyList<int> input)
        {
            var nfkc = Security.ToNfkc(input);
            var inOk = IsAllowedIdentifier(input);
            var nfkcOk = IsAllowedIdentifier(nfkc);

            Classification classification = inOk == nfkcOk
                ? new Clear()
                : new Hazard(
                    new AdmissibilityDrift(inOk, nfkcOk),
                    new List<int>(),
                    new List<int>());

            return new Verdict(input.ToList(), classification, inOk, nfkcOk);
        }
    }
}
