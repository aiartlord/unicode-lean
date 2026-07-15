using System.Globalization;
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
        public const string BidiControlBalance = "bidi-control-balance";
        public const string NoncharacterControl = "noncharacter-control";
        public const string HomoglyphConfusable = "homoglyph-confusable";
        public const string MixedScriptAdmissibility = "mixed-script-admissibility";
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
    private static List<string>? knownTargets;
    private static HashSet<long>? legalVariationPairs;

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
        var bidi = PositionsWhere(input, IsBidiEmbeddingControl);
        if (bidi.Count > 0) findings.Add(MakeFinding(Family.BidiControlBalance, "UnbalancedEmbedding", bidi));
        findings.AddRange(NoncharacterControlFindings(input));
        var homoglyph = HomoglyphConfusableFinding(input);
        if (homoglyph is not null) findings.Add(homoglyph);
        var mixedScript = MixedScriptAdmissibilityFinding(input);
        if (mixedScript is not null) findings.Add(mixedScript);
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
                or Family.BidiControlBalance or Family.NoncharacterControl;
        }
        return family is Family.MalformedUtf8 or Family.MalformedUtf16 or Family.MalformedUtf32
            or Family.TagBlockPayload or Family.VariationSelectorPayload or Family.ZeroWidthPayload
            or Family.BidiControlBalance or Family.NoncharacterControl or Family.HomoglyphConfusable
            or Family.MixedScriptAdmissibility;
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
        family is Family.HomoglyphConfusable or Family.MixedScriptAdmissibility ? "I" : "C";

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
            ? MakeFinding(Family.MixedScriptAdmissibility, "CrossScriptMix", FullSpanPositions(input))
            : null;

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

    private static List<int> Skeleton(List<int> input) =>
        CaseFoldCodepoints(SubstituteConfusables(CaseFoldCodepoints(input)));

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
        var output = new List<int>();
        foreach (var cp in input) output.AddRange(CodepointsFromString(char.ConvertFromUtf32(cp).ToLowerInvariant()));
        return output;
    }

    private static Dictionary<int, List<int>> ConfusablesMap()
    {
        if (confusablesMap is null) confusablesMap = ParseConfusables(ReadDataFile("confusables.txt"));
        return confusablesMap;
    }

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

    private static string ReadDataFile(string name)
    {
        foreach (var path in new[]
        {
            Path.Combine(AppContext.BaseDirectory, "Data", name),
            Path.Combine("Data", name),
        })
        {
            if (File.Exists(path)) return File.ReadAllText(path);
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
