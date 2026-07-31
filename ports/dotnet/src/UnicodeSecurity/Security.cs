using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace UnicodeSecurity;

public static class Security
{
    public static class Action
    {
        public const string Allow = "allow";
        public const string Reject = "reject";
        public const string Quarantine = "quarantine";
        public const string Rewrite = "rewrite";
        public const string Observe = "observe";
    }

    public static class Mode
    {
        public const string Observe = "observe";
        public const string Warn = "warn";
        public const string Enforce = "enforce";
        public const string Strict = "strict";
    }

    public static class Profile
    {
        public const string GatewayHeader = "gateway-header";
        public const string DomainName = "domain-name";
        public const string DnsLabel = "dns-label";
        public const string Url = "url";
        public const string Username = "username";
        public const string DisplayName = "display-name";
        public const string ChatMessage = "chat-message";
        public const string SourceCode = "source-code";
        public const string OpaqueSecret = "opaque-secret";
        public const string BinaryBlob = "binary-blob";
    }

    public static class Family
    {
        public const string MalformedUtf8 = "malformed-utf8";
        public const string MalformedUtf16 = "malformed-utf16";
        public const string MalformedUtf32 = "malformed-utf32";
        public const string TagBlockPayload = "tag-block-payload";
        public const string VariationSelectorPayload = "variation-selector-payload";
        public const string ZeroWidthPayload = "zero-width-payload";
        public const string SurrogateReassembly = "surrogate-reassembly";
        public const string BidiControlBalance = "bidi-control-balance";
        public const string NoncharacterControl = "noncharacter-control";
        public const string HomoglyphConfusable = "homoglyph-confusable";
        public const string MixedScriptAdmissibility = "mixed-script-admissibility";
        public const string RtlInjection = "rtl-injection";
        public const string ConfusableBidiCompound = "confusable-bidi-compound";
    }

    public sealed record Finding(
        string Code,
        string Family,
        int Severity,
        IReadOnlyList<int> Positions,
        string SubThreat,
        string Detail);

    public sealed record Verdict(
        string Action,
        string Profile,
        string Mode,
        IReadOnlyList<int> Input,
        IReadOnlyList<Finding> Findings,
        IReadOnlyList<int>? Normalized);

    private enum PolicyLevel { Restrictive, Moderate, Minimal }
    private enum ByteOrder { Big, Little }
    private sealed record ProfilePolicy(PolicyLevel Level, bool Quarantine);
    private sealed record DecodeFailure(string SubThreat, int Offset);
    private sealed record DecodeResult(List<int> Codepoints, DecodeFailure? Failure);
    private sealed record Utf8State(bool InSequence, int Remaining, int Accum, int MinCp);
    private sealed record Utf8Step(Utf8State State, int Emitted, string Kind, bool Rejected);

    private static Dictionary<int, List<int>>? confusablesMap;
    private static Dictionary<int, List<int>>? caseFoldingMap;
    private static List<string>? knownTargets;
    private static HashSet<long>? legalVariationPairs;
    private static BidiTable? bidiTable;

    public static Verdict Scan(string profile, string mode, IEnumerable<int> input)
    {
        var codepoints = input.Select(EnsureCodepoint).ToList();
        var findings = Detect(codepoints);
        return new Verdict(Decide(profile, mode, findings), profile, mode, codepoints, findings, null);
    }

    public static Verdict ScanUtf8(string profile, string mode, IEnumerable<byte> input)
    {
        var bytes = input.ToArray();
        var failure = FirstInvalidUtf8(bytes);
        if (failure is not null)
        {
            return MalformedDecodeVerdict(profile, mode, Family.MalformedUtf8, failure.SubThreat, failure.Offset);
        }
        return Scan(profile, mode, DecodeUtf8ToCodepoints(bytes));
    }

    public static Verdict ScanUtf16BE(string profile, string mode, IEnumerable<byte> input) =>
        ScanUtf16(profile, mode, input.ToArray(), ByteOrder.Big);

    public static Verdict ScanUtf16LE(string profile, string mode, IEnumerable<byte> input) =>
        ScanUtf16(profile, mode, input.ToArray(), ByteOrder.Little);

    public static Verdict ScanUtf32BE(string profile, string mode, IEnumerable<byte> input) =>
        ScanUtf32(profile, mode, input.ToArray(), ByteOrder.Big);

    public static Verdict ScanUtf32LE(string profile, string mode, IEnumerable<byte> input) =>
        ScanUtf32(profile, mode, input.ToArray(), ByteOrder.Little);

    public static string VerdictJson(Verdict verdict) =>
        JsonSerializer.Serialize(ToWire(verdict));

    public static VerdictWire ToWire(Verdict verdict) =>
        new(
            verdict.Action,
            verdict.Profile,
            verdict.Mode,
            verdict.Input.ToList(),
            verdict.Findings.Select(ToWire).ToList(),
            verdict.Normalized?.ToList());

    private static FindingWire ToWire(Finding finding) =>
        new(finding.Code, finding.Family, finding.Severity, finding.Positions.ToList(), finding.SubThreat, finding.Detail);

    private static List<Finding> Detect(List<int> input)
    {
        var findings = new List<Finding>();
        var tagPositions = PositionsWhere(input, IsTagBlockAsciiPayload);
        if (tagPositions.Count > 0) findings.Add(MakeFinding(Family.TagBlockPayload, "DirectAscii", tagPositions));
        var variation = VariationSelectorFinding(input);
        if (variation is not null) findings.Add(variation);
        var zeroWidth = PositionsWhere(input, IsZeroWidthPayload);
        if (zeroWidth.Count > 0) findings.Add(MakeFinding(Family.ZeroWidthPayload, "BareZeroWidth", zeroWidth));
        var surrogate = SurrogateReassemblyFinding(input);
        if (surrogate is not null) findings.Add(surrogate);
        var bidi = PositionsWhere(input, IsBidiEmbeddingControl);
        if (bidi.Count > 0) findings.Add(MakeFinding(Family.BidiControlBalance, "UnbalancedEmbedding", bidi));
        findings.AddRange(NoncharacterControlFindings(input));
        var homoglyph = HomoglyphConfusableFinding(input);
        if (homoglyph is not null) findings.Add(homoglyph);
        var mixedScript = MixedScriptAdmissibilityFinding(input);
        if (mixedScript is not null) findings.Add(mixedScript);
        var rtl = RtlInjectionFinding(input);
        if (rtl is not null) findings.Add(rtl);
        var compound = ConfusableBidiCompoundFinding(input);
        if (compound is not null) findings.Add(compound);
        return findings;
    }

    private static string Decide(string profile, string mode, IReadOnlyList<Finding> findings)
    {
        if (findings.Count == 0) return Action.Allow;
        if (mode is Mode.Observe or Mode.Warn) return Action.Observe;
        if (mode == Mode.Strict) return Action.Reject;
        var policy = PolicyOfProfile(profile);
        foreach (var finding in findings)
        {
            if (Blocks(policy.Level, finding.Family))
            {
                return policy.Quarantine ? Action.Quarantine : Action.Reject;
            }
        }
        return Action.Allow;
    }

    private static ProfilePolicy PolicyOfProfile(string profile) => profile switch
    {
        Profile.GatewayHeader or Profile.DomainName or Profile.DnsLabel or Profile.SourceCode => new(PolicyLevel.Restrictive, false),
        Profile.Url => new(PolicyLevel.Moderate, false),
        Profile.Username => new(PolicyLevel.Moderate, true),
        Profile.DisplayName or Profile.ChatMessage => new(PolicyLevel.Minimal, true),
        Profile.OpaqueSecret or Profile.BinaryBlob => new(PolicyLevel.Minimal, false),
        _ => new(PolicyLevel.Restrictive, false),
    };

    private static bool Blocks(PolicyLevel level, string family)
    {
        if (level == PolicyLevel.Minimal)
        {
            return family is Family.MalformedUtf8 or Family.MalformedUtf16 or Family.MalformedUtf32
                or Family.SurrogateReassembly
                or Family.BidiControlBalance or Family.NoncharacterControl;
        }
        return family is Family.MalformedUtf8 or Family.MalformedUtf16 or Family.MalformedUtf32
            or Family.TagBlockPayload or Family.VariationSelectorPayload or Family.ZeroWidthPayload
            or Family.SurrogateReassembly
            or Family.BidiControlBalance or Family.NoncharacterControl or Family.HomoglyphConfusable
            or Family.MixedScriptAdmissibility or Family.ConfusableBidiCompound;
    }

    private static Verdict MalformedDecodeVerdict(string profile, string mode, string family, string subThreat, int offset)
    {
        var findings = new List<Finding> { MakeFinding(family, subThreat, new List<int> { offset }) };
        return new Verdict(Decide(profile, mode, findings), profile, mode, new List<int>(), findings, null);
    }

    private static Finding MakeFinding(string family, string subThreat, IReadOnlyList<int> positions) =>
        new(ReasonCode(family, subThreat), family, 2, positions.ToList(), subThreat, family);

    private static string ReasonCode(string family, string subThreat) =>
        $"unicode.security.{Layer(family)}.{family}.{subThreat}";

    private static string Layer(string family) =>
        family switch
        {
            Family.HomoglyphConfusable or Family.MixedScriptAdmissibility => "I",
            Family.RtlInjection => "D",
            Family.ConfusableBidiCompound => "X",
            _ => "C",
        };

    private static List<int> PositionsWhere(List<int> input, Func<int, bool> predicate)
    {
        var positions = new List<int>();
        for (var index = 0; index < input.Count; index++)
        {
            if (predicate(input[index])) positions.Add(index);
        }
        return positions;
    }

    private static bool IsTagBlockAsciiPayload(int cp) => cp is >= 0xE0020 and <= 0xE007E;

    private static Finding? VariationSelectorFinding(List<int> input)
    {
        var positions = PositionsWhere(input, IsVariationSelector);
        if (positions.Count == 0) return null;
        if (positions.Count == 1 && IsRegisteredVariationPosition(input, positions[0])) return null;
        var subThreat = "IllegalTarget";
        if (positions.Count >= 4 && AllSameAt(input, positions)) subThreat = "RepeatedBase";
        else if (DecodeVariationSelectorRun(input, positions).Count > 0) subThreat = "DirectPayload";
        return MakeFinding(Family.VariationSelectorPayload, subThreat, positions);
    }

    private static bool IsVariationSelector(int cp) =>
        cp is >= 0xFE00 and <= 0xFE0F || cp is >= 0xE0100 and <= 0xE01EF || cp is >= 0x180B and <= 0x180D;

    private static bool IsRegisteredVariationPosition(List<int> input, int position) =>
        position > 0 && LegalVariationPairs().Contains(VariationPairKey(input[position - 1], input[position]));

    private static int? VariationSelectorNibble(int cp)
    {
        if (cp is >= 0xFE00 and <= 0xFE0F) return cp - 0xFE00;
        if (cp is >= 0xE0100 and <= 0xE01EF) return cp - 0xE0100 + 16;
        return null;
    }

    private static List<int> DecodeVariationSelectorRun(List<int> input, List<int> positions)
    {
        var outBytes = new List<int>();
        var high = 0;
        var haveHigh = false;
        foreach (var position in positions)
        {
            var nibble = VariationSelectorNibble(input[position]);
            if (nibble is null) continue;
            if (!haveHigh)
            {
                high = nibble.Value;
                haveHigh = true;
            }
            else
            {
                outBytes.Add((high << 4) | nibble.Value);
                haveHigh = false;
            }
        }
        return outBytes;
    }

    private static bool AllSameAt(List<int> input, List<int> positions) =>
        positions.Count == 0 || positions.All(position => input[position] == input[positions[0]]);

    private static bool IsZeroWidthPayload(int cp) => cp is 0x200B or 0x200C or 0x200D or 0x2060 or 0xFEFF;
    private static bool IsBidiEmbeddingControl(int cp) => cp is >= 0x202A and <= 0x202E;

    private static List<Finding> NoncharacterControlFindings(List<int> input)
    {
        var findings = new List<Finding>();
        var noncharacters = PositionsWhere(input, IsNoncharacter);
        if (noncharacters.Count > 0) findings.Add(MakeFinding(Family.NoncharacterControl, "Noncharacter", noncharacters));
        var c0 = PositionsWhere(input, IsC0Control);
        if (c0.Count > 0) findings.Add(MakeFinding(Family.NoncharacterControl, "C0Control", c0));
        var c1 = PositionsWhere(input, IsC1Control);
        if (c1.Count > 0) findings.Add(MakeFinding(Family.NoncharacterControl, "C1Control", c1));
        return findings;
    }

    private static Finding? HomoglyphConfusableFinding(List<int> input)
    {
        var subThreat = "";
        if (HomoglyphTargetMatch(input) is not null) subThreat = "TargetMatch";
        else if (input.Any(IsMathAlphanumeric)) subThreat = "MathAlpha";
        else if (input.Any(IsFullwidthHalfwidth)) subThreat = "WidthClass";
        else if (HasDecompositionSwap(input)) subThreat = "DecompositionSwap";
        return subThreat == "" ? null : MakeFinding(Family.HomoglyphConfusable, subThreat, FullSpanPositions(input));
    }

    private static Finding? MixedScriptAdmissibilityFinding(List<int> input) =>
        HasCrossScriptMix(input)
            ? MakeFinding(Family.MixedScriptAdmissibility, MixedScriptSubThreat(input), FullSpanPositions(input))
            : null;

    // Right-to-left injection detection for LTR-declared fields — a direct
    // port of Unicode/Security/Display/RtlInjection.lean. Returns the
    // highest-priority sub-threat and the offending positions, or null for
    // a clear input. Exposed for direct spot-check testing, mirroring the
    // Rust/Python/C++ detectors.
    public static (string? Sub, IReadOnlyList<int> Positions) RtlInjectionDetect(IReadOnlyList<int> input)
    {
        var strongRtl = 0;
        foreach (var cp in input)
        {
            if (IsStrongRtl(cp)) strongRtl++;
        }
        var (runLen, runStart) = LongestRtlRun(input);

        // Phase 1: bidi format-control trumps all.
        for (var index = 0; index < input.Count; index++)
        {
            if (IsBidiFormatControl(input[index])) return ("RloInLTRField", new List<int> { index });
        }

        // Phase 2: leading-RTL field-direction takeover.
        for (var index = 0; index < input.Count; index++)
        {
            if (IsStrongRtl(input[index])) return ("FieldTakeover", new List<int> { index });
            if (IsStrongLtr(input[index])) break;
        }

        // Phase 3: mid-stream strong-RTL.
        if (strongRtl == 0) return (null, System.Array.Empty<int>());
        if (runLen >= 4) return ("MixedOverflow", new List<int> { runStart });
        for (var index = 0; index < input.Count; index++)
        {
            if (IsStrongRtl(input[index])) return ("StrongRTLInLTR", new List<int> { index });
        }
        return (null, System.Array.Empty<int>());
    }

    private static Finding? RtlInjectionFinding(List<int> input)
    {
        var (sub, positions) = RtlInjectionDetect(input);
        return sub is null ? null : MakeFinding(Family.RtlInjection, sub, positions);
    }

    // Confusable-in-bidi-context compound detection (CVE-2021-42574 class) — a
    // direct port of Unicode/Security/Boundary/ConfusableBidiCompound.lean. A
    // confusable codepoint co-located with a bidi format-control is materially
    // more dangerous than either alone: the homoglyph disguises an identifier
    // while the bidi control reorders how a reviewer reads it, so the detector
    // fires only when both are present. With a confusable at some position, an
    // override-class control (LRE / RLE / LRO / RLO / PDF) fires
    // ConfusableInOverride; otherwise an isolate-class control (LRI / RLI /
    // FSI / PDI) fires ConfusableInIsolate; otherwise the input is clear. The
    // positions are [confusablePos, bidiPos]. The confusable-source predicate
    // reuses the confusables table the homoglyph detector consults. Exposed for
    // direct spot-check testing, mirroring the sibling detectors.
    public static (string? Sub, IReadOnlyList<int> Positions) ConfusableBidiCompoundDetect(IReadOnlyList<int> input)
    {
        var confusablePos = FirstPosition(input, IsConfusableSource);
        if (confusablePos < 0) return (null, System.Array.Empty<int>());
        var overridePos = FirstPosition(input, IsBidiEmbeddingControl);
        if (overridePos >= 0) return ("ConfusableInOverride", new List<int> { confusablePos, overridePos });
        var isolatePos = FirstPosition(input, IsBidiIsolateControl);
        if (isolatePos >= 0) return ("ConfusableInIsolate", new List<int> { confusablePos, isolatePos });
        return (null, System.Array.Empty<int>());
    }

    private static Finding? ConfusableBidiCompoundFinding(List<int> input)
    {
        var (sub, positions) = ConfusableBidiCompoundDetect(input);
        return sub is null ? null : MakeFinding(Family.ConfusableBidiCompound, sub, positions);
    }

    // True iff cp is a source key in confusables.txt — i.e. it maps to a
    // different skeleton sequence per UTS #39 §4. Shares the confusables table
    // the homoglyph detector consults. Plain ASCII letters are not sources;
    // only homoglyph forms (Cyrillic а, Greek ο, ...) are.
    private static bool IsConfusableSource(int cp) => ConfusablesMap().ContainsKey(cp);

    // True iff cp is an isolate-class bidi control (LRI, RLI, FSI, PDI). The
    // override-class controls (LRE / RLE / LRO / RLO / PDF, U+202A..U+202E)
    // reuse IsBidiEmbeddingControl.
    private static bool IsBidiIsolateControl(int cp) => cp is >= 0x2066 and <= 0x2069;

    private static int FirstPosition(IReadOnlyList<int> input, Func<int, bool> predicate)
    {
        for (var index = 0; index < input.Count; index++)
        {
            if (predicate(input[index])) return index;
        }
        return -1;
    }

    // Surrogate-reassembly / malformed-byte-stream detection — a direct port
    // of Unicode/Security/Covert/SurrogateReassembly.lean. The codepoint list
    // is treated as a byte stream (one octet per entry); the family only
    // applies when every entry fits in one octet (< 0x100), matching the
    // looksLikeByteStream gate. When it applies, the shared strict UTF-8
    // validator (FirstInvalidUtf8) surfaces the first violation, whose reject
    // kind is projected onto a covert-layer sub-threat. Sub == null means a
    // clear input (well-formed, or not a byte stream). Exposed for direct
    // spot-check testing, mirroring the Rust/Python/C++ detectors.
    public static (string? Sub, IReadOnlyList<int> Positions) SurrogateReassemblyDetect(IReadOnlyList<int> input)
    {
        if (!LooksLikeByteStream(input)) return (null, System.Array.Empty<int>());
        var bytes = new byte[input.Count];
        for (var index = 0; index < input.Count; index++) bytes[index] = (byte)input[index];
        var failure = FirstInvalidUtf8(bytes);
        return failure is null
            ? (null, System.Array.Empty<int>())
            : (SubThreatOfRejectKind(failure.SubThreat), new List<int> { failure.Offset });
    }

    private static Finding? SurrogateReassemblyFinding(List<int> input)
    {
        var (sub, positions) = SurrogateReassemblyDetect(input);
        return sub is null ? null : MakeFinding(Family.SurrogateReassembly, sub, positions);
    }

    // True iff every entry fits in one octet — the looksLikeByteStream gate. A
    // codepoint list containing any value >= 0x100 is not a byte stream, and
    // running the UTF-8 validator on it would be meaningless.
    private static bool LooksLikeByteStream(IReadOnlyList<int> input) => input.All(cp => cp < 0x100);

    // Project a strict-UTF-8 reject kind onto its surrogate-reassembly
    // sub-threat tag, mirroring subThreatOfRejectKind in the Lean spec. These
    // tags DIFFER from the malformed-utf8 family's reject-kind strings.
    private static string SubThreatOfRejectKind(string kind) => kind switch
    {
        "OverlongEncoding" => "Overlong",
        "SurrogateCodepoint" => "Cesu8",
        "TruncatedSequence" => "Truncated",
        "InvalidStartByte" => "InvalidStartByte",
        "InvalidContinuationByte" => "InvalidContinuation",
        "CodepointBeyondMax" => "CodepointBeyondMax",
        var other => throw new InvalidOperationException($"unknown UTF-8 reject kind: {other}"),
    };

    private static bool IsBidiFormatControl(int cp) =>
        cp is >= 0x202A and <= 0x202E || cp is >= 0x2066 and <= 0x2069;

    private static (int Length, int Start) LongestRtlRun(IReadOnlyList<int> input)
    {
        var longest = 0;
        var longestStart = 0;
        var current = 0;
        var currentStart = 0;
        for (var index = 0; index < input.Count; index++)
        {
            if (IsStrongRtl(input[index]))
            {
                var newStart = current == 0 ? index : currentStart;
                current++;
                currentStart = newStart;
                if (current > longest)
                {
                    longest = current;
                    longestStart = newStart;
                }
            }
            else
            {
                current = 0;
            }
        }
        return (longest, longestStart);
    }

    private static string? HomoglyphTargetMatch(List<int> input)
    {
        var inputLetters = LetterSkeleton(input);
        foreach (var target in KnownTargets())
        {
            var targetCps = CodepointsFromString(target);
            if (!targetCps.SequenceEqual(input) && LetterSkeleton(targetCps).SequenceEqual(inputLetters)) return target;
        }
        return null;
    }

    private static List<int> LetterSkeleton(List<int> input) =>
        IteratedSkeleton(input)
            .Where(cp => !IsCombiningMark(cp) && !IsDefaultIgnorableCodepoint(cp) && !IsWhiteSpaceCodepoint(cp))
            .ToList();

    private static List<int> IteratedSkeleton(List<int> input)
    {
        var current = input.ToList();
        for (var index = 0; index < 8; index++)
        {
            var next = Skeleton(current);
            if (next.SequenceEqual(current)) return current;
            current = next;
        }
        return current;
    }

    private static List<int> Skeleton(List<int> input)
    {
        var step1 = ToNfdCodepoints(input);
        var step2 = CaseFoldCodepoints(step1);
        var step3 = SubstituteConfusables(step2);
        var step4 = CaseFoldCodepoints(step3);
        return ToNfdCodepoints(step4);
    }

    private static List<int> SubstituteConfusables(List<int> input)
    {
        var table = ConfusablesMap();
        var output = new List<int>();
        foreach (var cp in input)
        {
            if (table.TryGetValue(cp, out var replacement)) output.AddRange(replacement);
            else output.Add(cp);
        }
        return output;
    }

    private static List<int> CaseFoldCodepoints(List<int> input)
    {
        var table = CaseFoldingMap();
        var output = new List<int>();
        foreach (var cp in input)
        {
            if (table.TryGetValue(cp, out var replacement)) output.AddRange(replacement);
            else output.Add(cp);
        }
        return output;
    }

    private static List<int> ToNfdCodepoints(List<int> input) =>
        CodepointsFromString(CodepointsToString(input).Normalize(NormalizationForm.FormD));

    private static string CodepointsToString(List<int> input)
    {
        var builder = new StringBuilder();
        foreach (var cp in input) builder.Append(char.ConvertFromUtf32(cp));
        return builder.ToString();
    }

    private static Dictionary<int, List<int>> ConfusablesMap()
    {
        if (confusablesMap is null) confusablesMap = ParseConfusables(ReadDataFile("confusables.txt"));
        return confusablesMap;
    }

    private static Dictionary<int, List<int>> CaseFoldingMap()
    {
        if (caseFoldingMap is null) caseFoldingMap = ParseCaseFolding(ReadDataFile("CaseFolding.txt"));
        return caseFoldingMap;
    }

    // The strong Bidi_Class distinction the display layer needs. Every
    // Bidi_Class that is not R, AL, or L collapses to Other, matching
    // Unicode.Generated.DerivedBidiClass and the Rust/Python/C++ ports.
    private enum BidiStrong { R, Al, L, Other }

    private sealed record BidiRange(int Lo, int Hi, BidiStrong Class);

    // Explicit ranges (sorted by lower bound) win first; otherwise the last
    // matching @missing default range wins; otherwise the codepoint is L.
    private sealed record BidiTable(IReadOnlyList<BidiRange> Explicit, IReadOnlyList<BidiRange> Defaults);

    private static BidiTable BidiClassTable()
    {
        if (bidiTable is null) bidiTable = ParseDerivedBidi(ReadDataFile("DerivedBidiClass.txt"));
        return bidiTable;
    }

    private static BidiStrong StrongOfShort(string token) => token switch
    {
        "R" => BidiStrong.R,
        "AL" => BidiStrong.Al,
        "L" => BidiStrong.L,
        _ => BidiStrong.Other,
    };

    private static BidiStrong StrongOfLong(string token) => token switch
    {
        "Right_To_Left" => BidiStrong.R,
        "Arabic_Letter" => BidiStrong.Al,
        "Left_To_Right" => BidiStrong.L,
        _ => BidiStrong.Other,
    };

    private static (int Lo, int Hi)? ParseRangeField(string field)
    {
        var s = field.Trim();
        var idx = s.IndexOf("..", StringComparison.Ordinal);
        if (idx >= 0)
        {
            var a = ParseHex(s.Substring(0, idx));
            var b = ParseHex(s.Substring(idx + 2));
            return a is null || b is null ? null : (a.Value, b.Value);
        }
        var single = ParseHex(s);
        return single is null ? null : (single.Value, single.Value);
    }

    // Mirror of Unicode.Generated.DerivedBidiClass: DATA lines
    // `LO..HI ; SHORT # ...` (or `CP ; SHORT # ...`) become explicit ranges
    // sorted by lower bound; `# @missing: LO..HI; Long_Name` comment lines
    // become default ranges kept in file order. Only the strong distinction
    // (R, AL, L) is retained; every other class collapses to Other.
    private static BidiTable ParseDerivedBidi(string raw)
    {
        const string missingPrefix = "# @missing:";
        var explicitRanges = new List<BidiRange>();
        var defaults = new List<BidiRange>();
        foreach (var line in raw.Split('\n'))
        {
            if (line.StartsWith(missingPrefix, StringComparison.Ordinal))
            {
                var rest = line.Substring(missingPrefix.Length);
                var semi = rest.IndexOf(';');
                if (semi >= 0)
                {
                    var range = ParseRangeField(rest.Substring(0, semi));
                    if (range is not null)
                    {
                        defaults.Add(new BidiRange(range.Value.Lo, range.Value.Hi, StrongOfLong(rest.Substring(semi + 1).Trim())));
                    }
                }
                continue;
            }
            var hash = line.IndexOf('#');
            var body = (hash >= 0 ? line.Substring(0, hash) : line).Trim();
            if (body.Length == 0) continue;
            var sep = body.IndexOf(';');
            if (sep < 0) continue;
            var explicitRange = ParseRangeField(body.Substring(0, sep));
            if (explicitRange is not null)
            {
                explicitRanges.Add(new BidiRange(explicitRange.Value.Lo, explicitRange.Value.Hi, StrongOfShort(body.Substring(sep + 1).Trim())));
            }
        }
        explicitRanges.Sort((left, right) => left.Lo.CompareTo(right.Lo));
        return new BidiTable(explicitRanges, defaults);
    }

    // Full Bidi_Class lookup (strong distinction only): binary-search the
    // sorted explicit ranges first, then take the last matching @missing
    // default, then fall back to L.
    private static BidiStrong BidiStrongOf(int cp)
    {
        var table = BidiClassTable();
        var ranges = table.Explicit;
        int lo = 0, hi = ranges.Count;
        while (lo < hi)
        {
            var mid = lo + (hi - lo) / 2;
            var row = ranges[mid];
            if (cp < row.Lo) hi = mid;
            else if (cp > row.Hi) lo = mid + 1;
            else return row.Class;
        }
        var result = BidiStrong.L;
        foreach (var row in table.Defaults)
        {
            if (row.Lo <= cp && cp <= row.Hi) result = row.Class;
        }
        return result;
    }

    private static bool IsStrongRtl(int cp) =>
        BidiStrongOf(cp) is BidiStrong.R or BidiStrong.Al;

    private static bool IsStrongLtr(int cp) =>
        BidiStrongOf(cp) == BidiStrong.L;

    private static List<string> KnownTargets()
    {
        if (knownTargets is null) knownTargets = ParseKnownTargets(ReadDataFile("KnownAttackTargets.txt"));
        return knownTargets;
    }

    private static HashSet<long> LegalVariationPairs()
    {
        if (legalVariationPairs is null)
        {
            legalVariationPairs = new HashSet<long>();
            ParseLegalVariationPairs(ReadDataFile("StandardizedVariants.txt"), legalVariationPairs);
            ParseLegalVariationPairs(ReadDataFile("emoji-variation-sequences.txt"), legalVariationPairs);
        }
        return legalVariationPairs;
    }

    private static Dictionary<int, List<int>> ParseConfusables(string raw)
    {
        var output = new Dictionary<int, List<int>>();
        foreach (var rawLine in raw.Split('\n'))
        {
            var body = rawLine.Split('#', 2)[0].Trim();
            if (body == "") continue;
            var fields = body.Split(';');
            if (fields.Length < 2) continue;
            var source = ParseHex(fields[0]);
            var target = ParseCodepointField(fields[1]);
            if (source is not null && target.Count > 0) output[source.Value] = target;
        }
        return output;
    }

    private static Dictionary<int, List<int>> ParseCaseFolding(string raw)
    {
        var output = new Dictionary<int, List<int>>();
        foreach (var rawLine in raw.Split('\n'))
        {
            var body = rawLine.Split('#', 2)[0].Trim();
            if (body == "") continue;
            var fields = body.Split(';');
            if (fields.Length < 3) continue;
            var status = fields[1].Trim();
            if (status != "C" && status != "F") continue;
            var codepoint = ParseHex(fields[0]);
            var mapping = ParseCodepointField(fields[2]);
            if (codepoint is not null && mapping.Count > 0) output[codepoint.Value] = mapping;
        }
        return output;
    }

    private static List<string> ParseKnownTargets(string raw) =>
        raw.Split('\n').Select(line => line.Trim()).Where(line => line != "" && !line.StartsWith('#')).ToList();

    private static void ParseLegalVariationPairs(string raw, HashSet<long> output)
    {
        foreach (var rawLine in raw.Split('\n'))
        {
            var pairPart = rawLine.Split('#', 2)[0].Split(';', 2)[0].Trim();
            if (pairPart == "") continue;
            var fields = pairPart.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length != 2) continue;
            var baseCp = ParseHex(fields[0]);
            var vs = ParseHex(fields[1]);
            if (baseCp is not null && vs is not null) output.Add(VariationPairKey(baseCp.Value, vs.Value));
        }
    }

    private static long VariationPairKey(int baseCp, int vs) => ((long)baseCp << 32) ^ (uint)vs;

    private static List<int> ParseCodepointField(string field) =>
        field.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
            .Select(ParseHex)
            .Where(value => value is not null)
            .Select(value => value!.Value)
            .ToList();

    private static int? ParseHex(string field) =>
        int.TryParse(field.Trim(), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var value) ? value : null;

    // Pinned SHA-256 digests of the vendored UCD-derived tables, embedded as
    // code constants so the code — not the co-located, swappable SHA256SUMS —
    // is the trust anchor. ReadDataFile hashes each table's raw bytes at load
    // and refuses to serve (throws) on any mismatch or unpinned table, so a
    // rolled-back, corrupted, or tampered file on a deployed node fails closed
    // instead of silently mis-classifying. Keep in sync with the port's
    // Data/SHA256SUMS and the canonical data/SHA256SUMS.
    private static readonly IReadOnlyDictionary<string, string> PinnedTableDigests =
        new Dictionary<string, string>
        {
            ["CaseFolding.txt"] = "ff8d8fefbf123574205085d6714c36149eb946d717a0c585c27f0f4ef58c4183",
            ["confusables.txt"] = "091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a",
            ["KnownAttackTargets.txt"] = "47acf87f48e23c2e3ddfb5aed877965fbe29142e61f6f85c4ee7db90c0684947",
            ["StandardizedVariants.txt"] = "f55100b2fb11d3d75a37b8c1ab752192dbd1c4b12328c5ec6b38e3807c0ca597",
            ["emoji-variation-sequences.txt"] = "bb3d09ef03f206012c7532dd52dc0a21c9efddba0135ea4cf0d9201b8b9bba7e",
            ["DerivedBidiClass.txt"] = "4867b4b7f0731ed1bfcd34cc6251211ff1542541fce0734b6fbda139ee80b3a4",
        };

    private static string ReadDataFile(string name)
    {
        if (!PinnedTableDigests.TryGetValue(name, out var expected))
        {
            throw new InvalidOperationException(
                $"refusing to load unpinned data table: {name} (fail closed)");
        }
        foreach (var path in new[]
        {
            Path.Combine(AppContext.BaseDirectory, "Data", name),
            Path.Combine("Data", name),
        })
        {
            if (File.Exists(path))
            {
                var bytes = File.ReadAllBytes(path);
                var actual = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
                if (actual != expected)
                {
                    throw new InvalidOperationException(
                        $"data table {name} failed integrity check (expected {expected}, got {actual}); " +
                        "refusing to load (fail closed)");
                }
                return Encoding.UTF8.GetString(bytes);
            }
        }
        throw new FileNotFoundException($"missing .NET runtime data file: {name}");
    }

    private static List<int> FullSpanPositions(List<int> input) => Enumerable.Range(0, input.Count).ToList();
    private static bool IsMathAlphanumeric(int cp) => cp is >= 0x1D400 and <= 0x1D7FF;
    private static bool IsFullwidthHalfwidth(int cp) => cp is >= 0xFF01 and <= 0xFFEF;

    private static bool IsNoncharacter(int cp)
    {
        if (cp is >= 0xFDD0 and <= 0xFDEF) return true;
        if (cp > 0x10FFFF) return false;
        var low16 = cp & 0xFFFF;
        return low16 is 0xFFFE or 0xFFFF;
    }

    private static bool IsC0Control(int cp) => cp <= 0x1F && cp is not 0x09 and not 0x0A and not 0x0D || cp == 0x7F;
    private static bool IsC1Control(int cp) => cp is >= 0x80 and <= 0x9F;

    private static bool IsCombiningMark(int cp) =>
        cp is >= 0x0300 and <= 0x036F || cp is >= 0x1AB0 and <= 0x1AFF ||
        cp is >= 0x1DC0 and <= 0x1DFF || cp is >= 0x20D0 and <= 0x20FF ||
        cp is >= 0xFE20 and <= 0xFE2F;

    private static bool HasDecompositionSwap(List<int> input)
    {
        for (var index = 1; index < input.Count; index++)
        {
            var previous = input[index - 1];
            var current = input[index];
            if (IsCombiningMark(current) && !IsCombiningMark(previous)) return true;
            if (IsCombiningMark(previous) && IsCombiningMark(current) && previous > current) return true;
            if (ComposeHangulPair(previous, current)) return true;
        }
        return false;
    }

    private static bool ComposeHangulPair(int first, int second)
    {
        const int sBase = 0xAC00, lBase = 0x1100, vBase = 0x1161, tBase = 0x11A7;
        const int lCount = 19, vCount = 21, tCount = 28, nCount = vCount * tCount, sCount = lCount * nCount;
        var isL = first >= lBase && first < lBase + lCount;
        var isV = second >= vBase && second < vBase + vCount;
        if (isL && isV) return true;
        var isLV = first >= sBase && first < sBase + sCount && (first - sBase) % tCount == 0;
        var isT = second > tBase && second < tBase + tCount;
        return isLV && isT;
    }

    private static bool HasCrossScriptMix(List<int> input)
    {
        var seen = new HashSet<string>();
        foreach (var cp in input)
        {
            var script = ScriptClass(cp);
            if (script is not null) seen.Add(script);
        }
        return seen.Count >= 2;
    }

    // The specific script-collision sub-threat, matching the Lean source of truth:
    // Latin/Cyrillic and Latin/Greek are named explicitly (Cyrillic before Greek);
    // every other multi-script mix is ScriptMixOther.
    private static string MixedScriptSubThreat(List<int> input)
    {
        var seen = new HashSet<string>();
        foreach (var cp in input)
        {
            var script = ScriptClass(cp);
            if (script is not null) seen.Add(script);
        }
        if (seen.Contains("Latn") && seen.Contains("Cyrl")) return "LatinCyrillic";
        if (seen.Contains("Latn") && seen.Contains("Grek")) return "LatinGreek";
        return "ScriptMixOther";
    }

    private static string? ScriptClass(int cp)
    {
        if (cp is >= 0x0041 and <= 0x005A || cp is >= 0x0061 and <= 0x007A || cp is >= 0x00C0 and <= 0x024F) return "Latn";
        if (cp is >= 0x0370 and <= 0x03FF || cp is >= 0x1F00 and <= 0x1FFF) return "Grek";
        if (cp is >= 0x0400 and <= 0x052F) return "Cyrl";
        return null;
    }

    private static bool IsDefaultIgnorableCodepoint(int cp) =>
        cp is 0x00AD or 0x034F or 0x061C ||
        cp is >= 0x115F and <= 0x1160 || cp is >= 0x17B4 and <= 0x17B5 ||
        cp is >= 0x180B and <= 0x180F || cp is >= 0x200B and <= 0x200F ||
        cp is >= 0x202A and <= 0x202E || cp is >= 0x2060 and <= 0x206F ||
        cp is >= 0xFE00 and <= 0xFE0F || cp == 0xFEFF ||
        cp is >= 0xFFF0 and <= 0xFFF8 || cp is >= 0xE0000 and <= 0xE0FFF;

    private static bool IsWhiteSpaceCodepoint(int cp) =>
        cp is 0x0009 or 0x000A or 0x000B or 0x000C or 0x000D or 0x0020 or 0x0085 or 0x00A0 or 0x1680 ||
        cp is >= 0x2000 and <= 0x200A || cp is 0x2028 or 0x2029 or 0x202F or 0x205F or 0x3000;

    private static Verdict ScanUtf16(string profile, string mode, byte[] input, ByteOrder order)
    {
        var result = DecodeUtf16ToCodepoints(input, order);
        return result.Failure is null
            ? Scan(profile, mode, result.Codepoints)
            : MalformedDecodeVerdict(profile, mode, Family.MalformedUtf16, result.Failure.SubThreat, result.Failure.Offset);
    }

    private static DecodeResult DecodeUtf16ToCodepoints(byte[] input, ByteOrder order)
    {
        var output = new List<int>();
        var offset = 0;
        while (offset < input.Length)
        {
            if (offset + 2 > input.Length) return new(new(), new("TruncatedCodeUnit", input.Length));
            var unitOffset = offset;
            var unit = ReadUInt16(input, offset, order);
            offset += 2;
            if (unit is >= 0xD800 and <= 0xDBFF)
            {
                if (offset + 2 > input.Length) return new(new(), new("TruncatedSurrogatePair", input.Length));
                var low = ReadUInt16(input, offset, order);
                if (low is < 0xDC00 or > 0xDFFF) return new(new(), new("InvalidSurrogatePair", offset));
                output.Add(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00));
                offset += 2;
            }
            else if (unit is >= 0xDC00 and <= 0xDFFF)
            {
                return new(new(), new("LoneSurrogate", unitOffset));
            }
            else output.Add(unit);
        }
        return new(output, null);
    }

    private static Verdict ScanUtf32(string profile, string mode, byte[] input, ByteOrder order)
    {
        var result = DecodeUtf32ToCodepoints(input, order);
        return result.Failure is null
            ? Scan(profile, mode, result.Codepoints)
            : MalformedDecodeVerdict(profile, mode, Family.MalformedUtf32, result.Failure.SubThreat, result.Failure.Offset);
    }

    private static DecodeResult DecodeUtf32ToCodepoints(byte[] input, ByteOrder order)
    {
        if (input.Length % 4 != 0) return new(new(), new("TruncatedCodeUnit", input.Length));
        var output = new List<int>();
        for (var offset = 0; offset < input.Length; offset += 4)
        {
            var cp = unchecked((int)ReadUInt32(input, offset, order));
            if (cp is >= 0xD800 and <= 0xDFFF) return new(new(), new("SurrogateCodepoint", offset));
            if ((uint)cp > 0x10FFFF) return new(new(), new("CodepointBeyondMax", offset));
            output.Add(cp);
        }
        return new(output, null);
    }

    private static DecodeFailure? FirstInvalidUtf8(byte[] input)
    {
        var state = new Utf8State(false, 0, 0, 0);
        var seqStart = 0;
        for (var index = 0; index < input.Length; index++)
        {
            if (!state.InSequence) seqStart = index;
            var step = Utf8DecodeStep(state, input[index]);
            if (step.Rejected) return new(step.Kind, step.Kind == "OverlongEncoding" ? seqStart : index);
            state = step.State;
        }
        return state.InSequence ? new("TruncatedSequence", input.Length) : null;
    }

    private static List<int> DecodeUtf8ToCodepoints(byte[] input)
    {
        var output = new List<int>();
        var state = new Utf8State(false, 0, 0, 0);
        foreach (var raw in input)
        {
            var step = Utf8DecodeStep(state, raw);
            if (step.Rejected) return output;
            if (!step.State.InSequence && (state.InSequence || raw < 0x80)) output.Add(step.Emitted);
            state = step.State;
        }
        return output;
    }

    private static Utf8Step Utf8DecodeStep(Utf8State state, int n)
    {
        if (!state.InSequence)
        {
            if (n < 0x80) return new(new(false, 0, 0, 0), n, "", false);
            if (n < 0xC2) return new(state, 0, "InvalidStartByte", true);
            if (n < 0xE0) return new(new(true, 1, n & 0x1F, 0x80), 0, "", false);
            if (n < 0xF0) return new(new(true, 2, n & 0x0F, 0x800), 0, "", false);
            if (n < 0xF5) return new(new(true, 3, n & 0x07, 0x10000), 0, "", false);
            return new(state, 0, "InvalidStartByte", true);
        }
        if (n is < 0x80 or >= 0xC0) return new(state, 0, "InvalidContinuationByte", true);
        var next = (state.Accum << 6) | (n & 0x3F);
        if (state.Remaining == 1)
        {
            if (next < state.MinCp) return new(state, 0, "OverlongEncoding", true);
            if (next is >= 0xD800 and <= 0xDFFF) return new(state, 0, "SurrogateCodepoint", true);
            if (next > 0x10FFFF) return new(state, 0, "CodepointBeyondMax", true);
            return new(new(false, 0, 0, 0), next, "", false);
        }
        return new(new(true, state.Remaining - 1, next, state.MinCp), 0, "", false);
    }

    private static int ReadUInt16(byte[] input, int offset, ByteOrder order) =>
        order == ByteOrder.Big
            ? (input[offset] << 8) | input[offset + 1]
            : input[offset] | (input[offset + 1] << 8);

    private static uint ReadUInt32(byte[] input, int offset, ByteOrder order) =>
        order == ByteOrder.Big
            ? ((uint)input[offset] << 24) | ((uint)input[offset + 1] << 16) | ((uint)input[offset + 2] << 8) | input[offset + 3]
            : (uint)(input[offset] | (input[offset + 1] << 8) | (input[offset + 2] << 16) | (input[offset + 3] << 24));

    private static List<int> CodepointsFromString(string value)
    {
        var output = new List<int>();
        for (var index = 0; index < value.Length;)
        {
            var cp = char.ConvertToUtf32(value, index);
            output.Add(cp);
            index += char.IsSurrogatePair(value, index) ? 2 : 1;
        }
        return output;
    }

    private static int EnsureCodepoint(int value) =>
        value is >= 0 and <= 0x10FFFF ? value : throw new ArgumentOutOfRangeException(nameof(value), value, "invalid codepoint");

    public sealed record FindingWire(
        [property: JsonPropertyName("code")] string Code,
        [property: JsonPropertyName("family")] string Family,
        [property: JsonPropertyName("severity")] int Severity,
        [property: JsonPropertyName("positions")] List<int> Positions,
        [property: JsonPropertyName("sub_threat")] string SubThreat,
        [property: JsonPropertyName("detail")] string Detail);

    public sealed record VerdictWire(
        [property: JsonPropertyName("action")] string Action,
        [property: JsonPropertyName("profile")] string Profile,
        [property: JsonPropertyName("mode")] string Mode,
        [property: JsonPropertyName("input")] List<int> Input,
        [property: JsonPropertyName("findings")] List<FindingWire> Findings,
        [property: JsonPropertyName("normalized")] List<int>? Normalized);
}
