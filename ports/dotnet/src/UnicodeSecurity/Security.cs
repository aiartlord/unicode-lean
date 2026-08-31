using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace UnicodeSecurity;

public static partial class Security
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
        public const string CovertDisplayCompound = "covert-display-compound";
        public const string HashInputStability = "hash-input-stability";
        public const string AiWatermarkDetectability = "ai-watermark-detectability";
        public const string StreamSafeViolation = "stream-safe-violation";
        public const string CaseExpansionMismatch = "case-expansion-mismatch";
        public const string EmojiZwjIntegrity = "emoji-zwj-integrity";
        public const string RendererDivergence = "renderer-divergence";
        public const string FilenameDisguise = "filename-disguise";
        public const string SourceDisplayDivergence = "source-display-divergence";
        public const string IdentifierFormDrift = "identifier-form-drift";
        public const string AdmissibilityFormDrift = "admissibility-form-drift";
        public const string SkinToneVariationForgery = "skin-tone-variation-forgery";
        public const string NormalizationBomb = "normalization-bomb";
        public const string LocaleCaseInversion = "locale-case-inversion";
        public const string NfcIdempotenceWitness = "nfc-idempotence-witness";
        public const string WidthClassConfusion = "width-class-confusion";
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
    private static IReadOnlyList<EawRange>? eastAsianWidthTable;
    private static Dictionary<int, NormEntry>? unicodeDataMap;
    private static HashSet<int>? compositionExclusions;
    private static Dictionary<long, int>? compositionTable;

    /// <summary>True iff the profile names a field that holds one identifier
    /// rather than running text.
    ///
    /// A username, a registrable domain and a DNS label are single identifiers,
    /// so a codepoint outside the General Security Profile is a hazard in them.
    /// The remaining profiles carry prose, source, URLs or opaque bytes, where a
    /// space and a punctuation mark are ordinary content. Mirrors
    /// profileIsIdentifierField in Unicode/Security/Policy.lean.</summary>
    internal static bool ProfileIsIdentifierField(string profile) =>
        profile == Profile.DomainName || profile == Profile.DnsLabel || profile == Profile.Username;

    public static Verdict Scan(string profile, string mode, IEnumerable<int> input)
    {
        var codepoints = input.Select(EnsureCodepoint).ToList();
        var findings = Detect(codepoints, ProfileIsIdentifierField(profile));
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

    // Strict RFC 3629 UTF-8 validity, routed through the same state-machine
    // decoder (FirstInvalidUtf8) that ScanUtf8 and the surrogate-reassembly
    // detector use — never through System.Text / Encoding.UTF8. The
    // byte-refinement types Utf8Blob and ValidatedUtf8 pin their validity claim
    // to this predicate so overlong forms, surrogate code points, truncated
    // sequences, and out-of-range code points are all rejected identically to
    // the scanner's malformed-utf8 family.
    public static bool IsValidUtf8(IReadOnlyList<byte> input)
    {
        var bytes = input as byte[] ?? input.ToArray();
        return FirstInvalidUtf8(bytes) is null;
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

    // Detect runs every family over input. identifierField carries what the
    // caller knows about the field, mirroring Unicode.Security.RunAll's Context:
    // a family scoped to identifiers needs to know whether it is holding one.
    private static List<Finding> Detect(List<int> input, bool identifierField)
    {
        var findings = new List<Finding>();
        var tagPositions = PositionsWhere(input, IsTagBlockChar);
        if (tagPositions.Count > 0)
        {
            findings.Add(MakeFinding(Family.TagBlockPayload, TagBlockSubThreat(input, tagPositions), tagPositions));
        }
        var variation = VariationSelectorFinding(input);
        if (variation is not null) findings.Add(variation);
        // The sanctioning model: a ZWJ inside a registered emoji sequence and a
        // ZWNJ in an RFC 5892 CONTEXTJ-valid position both carry meaning a
        // reader depends on, so they are recorded as present but not treated as
        // suspicious. An input whose zero-width characters are all sanctioned
        // raises nothing.
        var zeroWidth = PositionsWhere(input, IsZeroWidthPayload);
        if (zeroWidth.Count > 0 && HasSuspiciousZeroWidth(input, zeroWidth))
        {
            findings.Add(
                MakeFinding(Family.ZeroWidthPayload, ZeroWidthSubThreat(input, zeroWidth), zeroWidth));
        }
        var surrogate = SurrogateReassemblyFinding(input);
        if (surrogate is not null) findings.Add(surrogate);
        var bidi = BidiFinding(input);
        if (bidi is not null) findings.Add(bidi);
        findings.AddRange(NoncharacterControlFindings(input));
        var homoglyph = HomoglyphConfusableFinding(input);
        if (homoglyph is not null) findings.Add(homoglyph);
        var mixedScript = MixedScriptAdmissibilityFinding(input, identifierField);
        if (mixedScript is not null) findings.Add(mixedScript);
        var rtl = RtlInjectionFinding(input);
        if (rtl is not null) findings.Add(rtl);
        var compound = ConfusableBidiCompoundFinding(input);
        if (compound is not null) findings.Add(compound);
        var covertDisplay = CovertDisplayCompoundFinding(input);
        if (covertDisplay is not null) findings.Add(covertDisplay);
        var emojiZwj = EmojiZwjIntegrity.Detect(input).Classify;
        if (!emojiZwj.IsClear) findings.Add(MakeFinding(Family.EmojiZwjIntegrity, emojiZwj.Tag!, emojiZwj.Positions));
        var skinTone = SkinToneVariationForgery.Detect(input).Classify;
        if (!skinTone.IsClear) findings.Add(MakeFinding(Family.SkinToneVariationForgery, skinTone.Tag!, skinTone.Positions));
        var filenameDisguise = FilenameDisguise.Detect(input).Classify;
        if (!filenameDisguise.IsClear) findings.Add(MakeFinding(Family.FilenameDisguise, filenameDisguise.Tag!, filenameDisguise.Positions));
        var rendererDivergence = RendererDivergence.Detect(input).Classify;
        if (!rendererDivergence.IsClear) findings.Add(MakeFinding(Family.RendererDivergence, rendererDivergence.Tag!, rendererDivergence.Positions));
        var streamSafe = StreamSafeViolation.Detect(input).Classify;
        if (!streamSafe.IsClear) findings.Add(MakeFinding(Family.StreamSafeViolation, streamSafe.Tag!, streamSafe.Positions));
        var caseExpansion = CaseExpansionMismatch.Detect(input).Classify;
        if (!caseExpansion.IsClear) findings.Add(MakeFinding(Family.CaseExpansionMismatch, caseExpansion.Tag!, caseExpansion.Positions));
        var identifierDrift = IdentifierFormDrift.Detect(input).Classify;
        if (!identifierDrift.IsClear) findings.Add(MakeFinding(Family.IdentifierFormDrift, identifierDrift.Tag!, identifierDrift.Positions));
        var admissibilityDrift = AdmissibilityFormDrift.Detect(input).Classify;
        if (!admissibilityDrift.IsClear) findings.Add(MakeFinding(Family.AdmissibilityFormDrift, admissibilityDrift.Tag!, admissibilityDrift.Positions));
        var normalizationBomb = NormalizationBombDetect(input);
        if (normalizationBomb.SubThreat is not null) findings.Add(MakeFinding(Family.NormalizationBomb, normalizationBomb.SubThreat, normalizationBomb.Positions));
        var localeCase = LocaleCaseInversionDetect(input);
        if (localeCase.SubThreat is not null) findings.Add(MakeFinding(Family.LocaleCaseInversion, localeCase.SubThreat, localeCase.Positions));
        var nfcWitness = NfcIdempotenceWitnessDetect(input);
        if (nfcWitness.SubThreat is not null) findings.Add(MakeFinding(Family.NfcIdempotenceWitness, nfcWitness.SubThreat, nfcWitness.Positions));
        var widthClass = WidthClassConfusionDetect(input);
        if (widthClass.SubThreat is not null) findings.Add(MakeFinding(Family.WidthClassConfusion, widthClass.SubThreat, widthClass.Positions));
        // SourceDisplayDivergence judges the input as a unit, so it localises
        // nothing and carries an empty position list.
        var sourceDisplay = SourceDisplayDivergence.Detect(input).Classify;
        if (!sourceDisplay.IsClear)
        {
            findings.Add(MakeFinding(Family.SourceDisplayDivergence, sourceDisplay.Tag!, new List<int>()));
        }
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
        Profile.GatewayHeader or Profile.DomainName or Profile.DnsLabel => new(PolicyLevel.Restrictive, false),
        // Source files legitimately carry right-to-left string literals, comments
        // written in Hebrew or Arabic, and emoji. Restrictive admits RtlInjection,
        // whose contract treats its input as a declared-LTR field, so under it an
        // ordinary Hebrew comment is rejected. Moderate retains every detector that
        // catches the Trojan Source class while dropping the field-direction
        // assumption a source file does not satisfy.
        Profile.Url or Profile.SourceCode => new(PolicyLevel.Moderate, false),
        Profile.Username => new(PolicyLevel.Moderate, true),
        Profile.DisplayName or Profile.ChatMessage => new(PolicyLevel.Minimal, true),
        Profile.OpaqueSecret or Profile.BinaryBlob => new(PolicyLevel.Minimal, false),
        _ => new(PolicyLevel.Restrictive, false),
    };

    private static bool Blocks(PolicyLevel level, string family)
    {
        if (level == PolicyLevel.Minimal)
        {
            return
            family is Family.MalformedUtf8 or Family.MalformedUtf16 or Family.MalformedUtf32
                or Family.SurrogateReassembly or Family.BidiControlBalance or Family.NoncharacterControl
                or Family.StreamSafeViolation;
        }
        if (level == PolicyLevel.Moderate)
        {
            return
            family is Family.MalformedUtf8 or Family.MalformedUtf16 or Family.MalformedUtf32
                or Family.TagBlockPayload or Family.VariationSelectorPayload or Family.ZeroWidthPayload
                or Family.SurrogateReassembly or Family.BidiControlBalance or Family.NoncharacterControl
                or Family.HomoglyphConfusable or Family.MixedScriptAdmissibility
                or Family.SkinToneVariationForgery or Family.SourceDisplayDivergence
                or Family.FilenameDisguise or Family.StreamSafeViolation or Family.LocaleCaseInversion
                or Family.CaseExpansionMismatch or Family.WidthClassConfusion
                or Family.NfcIdempotenceWitness or Family.IdentifierFormDrift
                or Family.CovertDisplayCompound or Family.ConfusableBidiCompound
                or Family.AdmissibilityFormDrift;
        }
        return
            family is Family.MalformedUtf8 or Family.MalformedUtf16 or Family.MalformedUtf32
                or Family.TagBlockPayload or Family.VariationSelectorPayload or Family.ZeroWidthPayload
                or Family.SurrogateReassembly or Family.BidiControlBalance or Family.NoncharacterControl
                or Family.HomoglyphConfusable or Family.MixedScriptAdmissibility or Family.EmojiZwjIntegrity
                or Family.SkinToneVariationForgery or Family.SourceDisplayDivergence
                or Family.FilenameDisguise or Family.RtlInjection or Family.RendererDivergence
                or Family.NormalizationBomb or Family.StreamSafeViolation or Family.LocaleCaseInversion
                or Family.CaseExpansionMismatch or Family.WidthClassConfusion
                or Family.NfcIdempotenceWitness or Family.IdentifierFormDrift
                or Family.CovertDisplayCompound or Family.ConfusableBidiCompound
                or Family.AdmissibilityFormDrift;
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
            Family.HomoglyphConfusable or Family.MixedScriptAdmissibility or Family.EmojiZwjIntegrity
                or Family.SkinToneVariationForgery => "I",
            Family.RtlInjection or Family.RendererDivergence or Family.FilenameDisguise
                or Family.SourceDisplayDivergence => "D",
            Family.ConfusableBidiCompound or Family.CovertDisplayCompound or Family.IdentifierFormDrift
                or Family.AdmissibilityFormDrift => "X",
            Family.HashInputStability or Family.AiWatermarkDetectability => "K",
            Family.StreamSafeViolation or Family.CaseExpansionMismatch
                or Family.NormalizationBomb or Family.LocaleCaseInversion
                or Family.NfcIdempotenceWitness or Family.WidthClassConfusion => "F",
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

    // The ASCII a tag character stands for, or -1 where it stands for none.
    // Only U+E0020..U+E007E carry ASCII.
    private static int TagToAscii(int cp) => cp is >= 0xE0020 and <= 0xE007E ? cp - 0xE0000 : -1;

    // The count of ASCII characters a tag run recovers, skipping the tag
    // characters carrying none.
    private static int DecodedTagLength(IReadOnlyList<int> input)
    {
        var decoded = 0;
        foreach (var cp in input)
        {
            if (TagToAscii(cp) >= 0) decoded++;
        }
        return decoded;
    }

    // Which tag-block hazard the input carries, in the priority order of
    // Unicode.Security.Covert.TagBlockPayload: a LANGUAGE TAG followed by at
    // least one further tag character revives the deprecated language-tag
    // mechanism; otherwise an all-tag input decoding to at least one ASCII
    // character is a direct payload; otherwise a run mixed with ordinary text
    // is a mixed block; otherwise the run is tag characters carrying no ASCII,
    // such as a CANCEL TAG standing alone.
    private static string TagBlockSubThreat(IReadOnlyList<int> input, IReadOnlyList<int> tagPositions)
    {
        var tagCount = tagPositions.Count;
        if (tagCount >= 2 && input[tagPositions[0]] == 0xE0001) return "LanguageTagRevival";
        if (input.Count == tagCount && DecodedTagLength(input) >= 1) return "DirectAscii";
        if (input.Count > tagCount) return "MixedBlock";
        return "BareTagPresent";
    }

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

    private static bool IsRegisteredVariationPosition(IReadOnlyList<int> input, int position) =>
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

    /// True iff cp renders as nothing, mirroring `isZeroWidth` in
    /// Unicode.Security.Covert.ZeroWidthPayload: the explicit historical set, which
    /// preserves sub-threat dispatch, extended by the UAX #44
    /// Default_Ignorable_Code_Point property, which catches every other invisible
    /// codepoint.
    ///
    /// The sibling ranges are excluded because their own family detector dispatches
    /// them with richer payload decoding or bidi-stack tracking, and counting them here
    /// as well would report one hazard twice. LRM and RLM are not excluded: they are
    /// direction markers rather than push-pop controls, and bidi-control-balance does
    /// not track them.
    private static bool IsZeroWidthPayload(int cp)
    {
        if (cp is >= 0x200B and <= 0x200F) return true;
        if (cp is >= 0x2060 and <= 0x2064) return true;
        if (cp is 0x202F or 0xFEFF) return true;
        if (cp is >= 0xFFF9 and <= 0xFFFB) return true;
        return IsDefaultIgnorableCodepoint(cp) && !IsZeroWidthSiblingHandled(cp);
    }

    /// True iff cp is Default_Ignorable but belongs to a sibling detector's family
    /// rather than to zero-width-payload.
    private static bool IsZeroWidthSiblingHandled(int cp) =>
        cp is (>= 0xFE00 and <= 0xFE0F)
            or (>= 0xE0100 and <= 0xE01EF)
            or (>= 0xE0000 and <= 0xE007F)
            or (>= 0x202A and <= 0x202E)
            or (>= 0x2066 and <= 0x2069);

    /// Which zero-width hazard the input carries, in the dispatch order of
    /// Unicode.Security.Covert.ZeroWidthPayload: an annotation outranks a word joiner,
    /// which outranks a narrow no-break space run, which outranks a binary payload, and
    /// a bare occurrence is the fallback once no richer class fits.
    private static string ZeroWidthSubThreat(IReadOnlyList<int> input, List<int> positions)
    {
        int annotation = 0, wordJoiner = 0, nnbsp = 0, zwjZwsp = 0;
        foreach (var index in positions)
        {
            var cp = input[index];
            if (cp is >= 0xFFF9 and <= 0xFFFB) annotation++;
            else if (cp == 0x2060) wordJoiner++;
            else if (cp == 0x202F) nnbsp++;
            else if (cp is 0x200B or 0x200D) zwjZwsp++;
        }
        if (annotation > 0) return "AnnotationMisuse";
        if (wordJoiner > 0) return "WordJoinerInjection";
        if (nnbsp >= 2) return "AiWatermarkNNBSP";
        if (zwjZwsp >= 2) return "BinaryPayload";
        return "BareZeroWidth";
    }
    private static bool IsBidiEmbeddingControl(int cp) => cp is >= 0x202A and <= 0x202E;

    // The embedding depth bound of UAX #9 §3.3.2.
    private const int UaxDepthLimit = 125;

    private static bool OpensEmbedding(int cp) =>
        cp is 0x202A or 0x202B or 0x202D or 0x202E;

    private static bool OpensIsolate(int cp) => cp is 0x2066 or 0x2067 or 0x2068;

    // The stack-of-stacks accumulator of
    // Unicode.Security.Covert.BidiControlBalance: each opener pushes, each
    // popper pops or records an orphan position, and MaxDepth tracks the peak
    // combined height.
    private sealed class BidiWalk
    {
        public int EmbStack;
        public int IsoStack;
        public int MaxDepth;
        public readonly List<int> Orphans = new();
        public readonly List<int> Positions = new();
    }

    private static BidiWalk RunBidiWalk(IReadOnlyList<int> input)
    {
        var walk = new BidiWalk();
        for (var index = 0; index < input.Count; index++)
        {
            var cp = input[index];
            if (!IsBidiFormatControl(cp)) continue;
            walk.Positions.Add(index);
            if (OpensEmbedding(cp))
            {
                walk.EmbStack++;
                walk.MaxDepth = Math.Max(walk.MaxDepth, walk.EmbStack + walk.IsoStack);
            }
            else if (cp == 0x202C)
            {
                if (walk.EmbStack > 0) walk.EmbStack--;
                else walk.Orphans.Add(index);
            }
            else if (OpensIsolate(cp))
            {
                walk.IsoStack++;
                walk.MaxDepth = Math.Max(walk.MaxDepth, walk.EmbStack + walk.IsoStack);
            }
            else if (cp == 0x2069)
            {
                if (walk.IsoStack > 0) walk.IsoStack--;
                else walk.Orphans.Add(index);
            }
        }
        return walk;
    }

    // The bidi-control-balance finding, or null when the controls are balanced
    // and within depth. The priority is the spec's: depth exceeded, then an
    // orphan pop, then an unbalanced embedding, then an unbalanced isolate.
    //
    // Orphan pop localises per stray popper. Depth exceeded is a whole-string
    // verdict, so it localises nothing. The unbalanced cases report every bidi
    // position, the diagnostic being that something among these controls is
    // missing its partner.
    private static Finding? BidiFinding(IReadOnlyList<int> input)
    {
        var walk = RunBidiWalk(input);
        if (walk.Positions.Count == 0) return null;
        if (walk.MaxDepth > UaxDepthLimit)
        {
            return MakeFinding(Family.BidiControlBalance, "DepthExceeded", new List<int>());
        }
        if (walk.Orphans.Count > 0)
        {
            return MakeFinding(Family.BidiControlBalance, "OrphanPop", walk.Orphans);
        }
        if (walk.EmbStack > 0)
        {
            return MakeFinding(Family.BidiControlBalance, "UnbalancedEmbedding", walk.Positions);
        }
        if (walk.IsoStack > 0)
        {
            return MakeFinding(Family.BidiControlBalance, "UnbalancedIsolate", walk.Positions);
        }
        return null;
    }

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
        // The last two rungs of the Lean ladder, in its order: a cross-script mix
        // that is not Highly Restrictive, then a string failing every restriction
        // level. Both need real script resolution.
        else if (HasCrossScriptMix(input)) subThreat = "CrossScriptMix";
        else if (RestrictionLevelOf(input) is RestrictionLevel.MinimallyRestrictive
            or RestrictionLevel.Unrestricted) subThreat = "RestrictionLow";
        return subThreat == "" ? null : MakeFinding(Family.HomoglyphConfusable, subThreat, FullSpanPositions(input));
    }

    private static Finding? MixedScriptAdmissibilityFinding(List<int> input, bool identifierField)
    {
        var subThreat = MixedScriptVerdict(input, identifierField);
        return subThreat is null
            ? null
            : MakeFinding(Family.MixedScriptAdmissibility, subThreat, FullSpanPositions(input));
    }

    // Right-to-left injection detection for LTR-declared fields — a direct
    // port of Unicode.Security.Display.RtlInjection. Returns the
    // highest-priority sub-threat and the offending positions, or null for
    // a clear input. Exposed for direct spot-check testing, mirroring the
    // Rust/Python/C++ detectors.
    /// The declared display direction of the field holding an input.
    ///
    /// A caller handling Hebrew, Arabic or Persian UI text declares its field
    /// right-to-left. Every other reading treats the input as a declared-LTR
    /// string, under which right-to-left content is itself the hazard.
    ///
    /// Mirrors FieldDirection in Unicode/Security/Display/RtlInjection.lean,
    /// that spec's alias for the UAX #9 paragraph-direction vocabulary.
    public enum FieldDirection
    {
        Ltr,
        Rtl,
    }

    /// Right-to-left injection detection in a field whose declared display
    /// direction is `direction`.
    ///
    /// A bidi format control reorders what a reviewer sees whichever way the
    /// field runs, so Phase 1 holds unconditionally and trumps all.
    ///
    /// Phases 2 and 3 ask whether right-to-left text has taken over or been
    /// spliced into a left-to-right field. That question has no premise in a
    /// right-to-left field, where right-to-left text is the content. The
    /// mirror-image hazard, strong-LTR injection into a right-to-left field,
    /// belongs to the separate detector the scope note assigns it to.
    public static (string? Sub, IReadOnlyList<int> Positions) RtlInjectionDetectWithContext(
        FieldDirection direction, IReadOnlyList<int> input)
    {
        var strongRtl = 0;
        foreach (var cp in input)
        {
            if (IsStrongRtl(cp)) strongRtl++;
        }
        var (runLen, runStart) = LongestRtlRun(input);

        // Phase 1: bidi format-control trumps all, in either direction.
        for (var index = 0; index < input.Count; index++)
        {
            if (IsBidiFormatControl(input[index])) return ("BidiControlInLTRField", new List<int> { index });
        }

        // A right-to-left field carrying right-to-left text carries its content.
        if (direction == FieldDirection.Rtl) return (null, System.Array.Empty<int>());

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

    /// Right-to-left injection detection in a field declared left-to-right, the
    /// reading the module scope note fixes for an undeclared field.
    public static (string? Sub, IReadOnlyList<int> Positions) RtlInjectionDetect(IReadOnlyList<int> input)
        => RtlInjectionDetectWithContext(FieldDirection.Ltr, input);

    private static Finding? RtlInjectionFinding(List<int> input)
    {
        var (sub, positions) = RtlInjectionDetect(input);
        return sub is null ? null : MakeFinding(Family.RtlInjection, sub, positions);
    }

    // Confusable-in-bidi-context compound detection (CVE-2021-42574 class) — a
    // direct port of Unicode.Security.Boundary.ConfusableBidiCompound. A
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

    // Covert-display compound detection — a direct port of
    // Unicode.Security.Boundary.CovertDisplayCompound. A bidi
    // format-control that reorders the visible glyphs is materially more
    // dangerous when the same input also carries a covert channel — an
    // unregistered variation selector or a tag-block character — because the
    // reorder hides where the covert payload sits. The detector fires only
    // when a bidi control coincides with one of those covert classes. With a
    // bidi format-control present, a suspicious VS (a variation selector that
    // does not form a registered (base, VS) pair) fires BidiPlusUnregisteredVs;
    // otherwise a tag-block character (U+E0000..U+E007F) fires
    // BidiPlusTagBlock; otherwise the input is clear. The positions are
    // [bidiPos, covertPos]. The bidi predicate reuses IsBidiFormatControl and
    // the VS predicates reuse IsVariationSelector / IsRegisteredVariationPosition
    // shared with the variation-selector-payload detector. Exposed for direct
    // spot-check testing, mirroring the sibling detectors.
    public static (string? Sub, IReadOnlyList<int> Positions) CovertDisplayCompoundDetect(IReadOnlyList<int> input)
    {
        var bidiPos = FirstPosition(input, IsBidiFormatControl);
        if (bidiPos < 0) return (null, System.Array.Empty<int>());
        var vsPos = FirstSuspiciousVsPos(input);
        if (vsPos >= 0) return ("BidiPlusUnregisteredVs", new List<int> { bidiPos, vsPos });
        var tagPos = FirstPosition(input, IsTagBlockChar);
        if (tagPos >= 0) return ("BidiPlusTagBlock", new List<int> { bidiPos, tagPos });
        return (null, System.Array.Empty<int>());
    }

    private static Finding? CovertDisplayCompoundFinding(List<int> input)
    {
        var (sub, positions) = CovertDisplayCompoundDetect(input);
        return sub is null ? null : MakeFinding(Family.CovertDisplayCompound, sub, positions);
    }

    // True iff cp is a tag character. The tag-block-payload family fires on the
    // whole block, not only the ASCII-bearing subrange TagToAscii decodes, so a
    // LANGUAGE TAG or a lone CANCEL TAG is a hazard in its own right.
    private static bool IsTagBlockChar(int cp) => cp is >= 0xE0000 and <= 0xE007F;

    // First position holding a suspicious variation selector — a VS that does
    // not form a registered (base, VS) pair with its predecessor. Mirrors the
    // .suspicious case of the Lean classifyPositions; reuses the shared
    // IsVariationSelector and IsRegisteredVariationPosition predicates.
    private static int FirstSuspiciousVsPos(IReadOnlyList<int> input)
    {
        for (var index = 0; index < input.Count; index++)
        {
            if (IsVariationSelector(input[index]) && !IsRegisteredVariationPosition(input, index)) return index;
        }
        return -1;
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
    // of Unicode.Security.Covert.SurrogateReassembly's module `detect`.
    // The codepoint list is treated as a byte stream: any value > 0xFF is
    // clamped to 0xFF (never a valid UTF-8 start byte), exactly as the Lean
    // toBytes helper does, so out-of-range values surface as a malformed stream
    // rather than being dropped. The shared strict UTF-8 validator
    // (FirstInvalidUtf8) surfaces the first violation, whose reject kind is
    // projected onto a covert-layer sub-threat. Sub == null means a well-formed
    // stream. The byte-stream gate lives in the scan orchestrator
    // (LooksLikeByteStream), mirroring runAll. Exposed for direct spot-check
    // testing, mirroring the Rust/Python/C++ detectors.
    public static (string? Sub, IReadOnlyList<int> Positions) SurrogateReassemblyDetect(IReadOnlyList<int> input)
    {
        var bytes = new byte[input.Count];
        for (var index = 0; index < input.Count; index++) bytes[index] = input[index] > 0xFF ? (byte)0xFF : (byte)input[index];
        var failure = FirstInvalidUtf8(bytes);
        return failure is null
            ? (null, System.Array.Empty<int>())
            : (SubThreatOfRejectKind(failure.SubThreat), new List<int> { failure.Offset });
    }

    // Scan-orchestrator wrapper. Mirrors runAll: SurrogateReassembly only
    // applies to byte-stream input (every codepoint <= 0xFF); on codepoint-array
    // input the family is clear.
    private static Finding? SurrogateReassemblyFinding(List<int> input)
    {
        if (!LooksLikeByteStream(input)) return null;
        var (sub, positions) = SurrogateReassemblyDetect(input);
        return sub is null ? null : MakeFinding(Family.SurrogateReassembly, sub, positions);
    }

    // True iff every entry fits in one octet — the looksLikeByteStream gate
    // from Unicode.Security.RunAll. A codepoint list containing any value
    // >= 0x100 is not a byte stream; the scan orchestrator uses this to skip
    // the family on such inputs, exactly as runAll does.
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

    // ── Canonical / compatibility normalization from the pinned UCD tables ──
    // NFD/NFKD/NFKC are computed from UnicodeData.txt (field-3 CCC, field-5
    // decompositions) and CompositionExclusions.txt, mirroring
    // Unicode.Normalization.{Decompose,Reorder,Compose,NFKD,NFKC} and the verified
    // from-tables ports. Independent of string.Normalize, whose Unicode version
    // tracks the .NET runtime (ICU) rather than the pinned UCD.

    private const int HangulSBase = 0xAC00;
    private const int HangulLBase = 0x1100;
    private const int HangulVBase = 0x1161;
    private const int HangulTBase = 0x11A7;
    private const int HangulLCount = 19;
    private const int HangulVCount = 21;
    private const int HangulTCount = 28;
    private const int HangulNCount = HangulVCount * HangulTCount;
    private const int HangulSCount = HangulLCount * HangulNCount;

    // One UnicodeData row's normalization fields: CCC and the canonical /
    // compatibility decompositions (null when absent). A field-5 mapping with a
    // <tag> prefix is a compatibility mapping; without a tag it is canonical.
    private sealed record NormEntry(int Ccc, List<int>? Canonical, List<int>? Compat);

    private static Dictionary<int, NormEntry> ParseUnicodeData(string raw)
    {
        var result = new Dictionary<int, NormEntry>();
        foreach (var line in raw.Split('\n'))
        {
            if (line.Length == 0) continue;
            var f = line.Split(';');
            if (f.Length < 6) continue;
            var cp = ParseHex(f[0]);
            if (cp is null) continue;
            var ccc = int.TryParse(f[3].Trim(), out var value) ? value : 0;
            var decomp = f[5].Trim();
            List<int>? canonical = null;
            List<int>? compat = null;
            if (decomp.Length != 0)
            {
                if (decomp.StartsWith('<'))
                    compat = ParseCodepointField(decomp[(decomp.IndexOf('>') + 1)..]);
                else
                    canonical = ParseCodepointField(decomp);
            }
            result[cp.Value] = new NormEntry(ccc, canonical, compat);
        }
        return result;
    }

    private static HashSet<int> ParseCompositionExclusions(string raw)
    {
        var result = new HashSet<int>();
        foreach (var line in raw.Split('\n'))
        {
            var hash = line.IndexOf('#');
            var body = (hash >= 0 ? line[..hash] : line).Trim();
            if (body.Length == 0) continue;
            var cp = ParseHex(body);
            if (cp is not null) result.Add(cp.Value);
        }
        return result;
    }

    private static Dictionary<int, NormEntry> UnicodeDataMap()
    {
        unicodeDataMap ??= ParseUnicodeData(ReadDataFile("UnicodeData.txt"));
        return unicodeDataMap;
    }

    private static HashSet<int> CompositionExclusions()
    {
        compositionExclusions ??= ParseCompositionExclusions(ReadDataFile("CompositionExclusions.txt"));
        return compositionExclusions;
    }

    private static int CanonicalCombiningClass(int cp) =>
        UnicodeDataMap().TryGetValue(cp, out var entry) ? entry.Ccc : 0;

    // ── UAX #21 case mapping (ToLower) from the pinned UCD tables ──────────────
    // Mirrors Unicode.Casing: full case mappings from SpecialCasing.txt over the
    // simple lowercase in UnicodeData.txt field 13, with the context predicates
    // driven by CCC and the Cased / Soft_Dotted properties from
    // DerivedCoreProperties.txt. Keystone for bip39-canonical; computed from the
    // pinned tables, not the runtime.

    /// <summary>SpecialCasing locales; Default covers everything not tagged
    /// Turkish / Azeri / Lithuanian.</summary>
    public enum CasingLocale { Default, Turkish, Azeri, Lithuanian }

    private sealed record CasingRow(List<int> Lower, List<int> Upper, List<string> Conditions);

    private static Dictionary<int, List<CasingRow>>? specialCasingMap;
    private static Dictionary<int, int>? simpleLowercaseMap;
    private static Dictionary<int, int>? simpleUppercaseMap;
    private static List<(int Lo, int Hi)>? casedRanges;
    private static List<(int Lo, int Hi)>? softDottedRanges;
    private static List<(int Lo, int Hi)>? defaultIgnorableRanges;

    private static Dictionary<int, List<CasingRow>> ParseSpecialCasing(string raw)
    {
        var result = new Dictionary<int, List<CasingRow>>();
        foreach (var rawLine in raw.Split('\n'))
        {
            var line = rawLine.Split('#', 2)[0].Trim();
            if (line.Length == 0) continue;
            var f = line.Split(';');
            if (f.Length < 4) continue;
            var code = ParseHex(f[0].Trim());
            if (code is null) continue;
            var conditions = new List<string>();
            if (f.Length > 4 && f[4].Trim().Length != 0)
            {
                conditions.AddRange(f[4].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
            }
            if (!result.TryGetValue(code.Value, out var list))
            {
                list = new List<CasingRow>();
                result[code.Value] = list;
            }
            // Field layout (0-based): code(0); lower(1); title(2); upper(3);
            // conditions(4). Capture both the lowercase (field 1) and uppercase
            // (field 3) full mappings so the SpecialCasing context drives either.
            list.Add(new CasingRow(ParseCodepointField(f[1]), ParseCodepointField(f[3]), conditions));
        }
        return result;
    }

    private static Dictionary<int, List<CasingRow>> SpecialCasing()
    {
        specialCasingMap ??= ParseSpecialCasing(ReadDataFile("SpecialCasing.txt"));
        return specialCasingMap;
    }

    private static Dictionary<int, int> ParseSimpleLowercase(string raw)
    {
        var lower = new Dictionary<int, int>();
        foreach (var line in raw.Split('\n'))
        {
            if (line.Length == 0) continue;
            var f = line.Split(';');
            if (f.Length < 15) continue;
            var cp = ParseHex(f[0]);
            if (cp is null) continue;
            if (f[13].Length != 0)
            {
                var l = ParseHex(f[13]);
                if (l is not null) lower[cp.Value] = l.Value;
            }
        }
        return lower;
    }

    private static int SimpleLowercase(int cp)
    {
        simpleLowercaseMap ??= ParseSimpleLowercase(ReadDataFile("UnicodeData.txt"));
        return simpleLowercaseMap.TryGetValue(cp, out var l) ? l : cp;
    }

    private static Dictionary<int, int> ParseSimpleUppercase(string raw)
    {
        var upper = new Dictionary<int, int>();
        foreach (var line in raw.Split('\n'))
        {
            if (line.Length == 0) continue;
            var f = line.Split(';');
            if (f.Length < 15) continue;
            var cp = ParseHex(f[0]);
            if (cp is null) continue;
            // Field 12 (0-based) is the simple uppercase mapping, the uppercase
            // counterpart of the simple lowercase in field 13.
            if (f[12].Length != 0)
            {
                var u = ParseHex(f[12]);
                if (u is not null) upper[cp.Value] = u.Value;
            }
        }
        return upper;
    }

    private static int SimpleUppercase(int cp)
    {
        simpleUppercaseMap ??= ParseSimpleUppercase(ReadDataFile("UnicodeData.txt"));
        return simpleUppercaseMap.TryGetValue(cp, out var u) ? u : cp;
    }

    private static List<(int Lo, int Hi)> ParseCasingProperty(string name)
    {
        var result = new List<(int Lo, int Hi)>();
        foreach (var rawLine in ReadDataFile("DerivedCoreProperties.txt").Split('\n'))
        {
            var line = rawLine.Split('#', 2)[0].Trim();
            if (line.Length == 0) continue;
            var parts = line.Split(';', 2);
            if (parts.Length < 2 || parts[1].Trim() != name) continue;
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

    private static bool IsCased(int cp)
    {
        casedRanges ??= ParseCasingProperty("Cased");
        foreach (var (lo, hi) in casedRanges)
        {
            if (lo <= cp && cp <= hi) return true;
        }
        return false;
    }

    private static bool IsSoftDotted(int cp)
    {
        softDottedRanges ??= ParseCasingProperty("Soft_Dotted");
        foreach (var (lo, hi) in softDottedRanges)
        {
            if (lo <= cp && cp <= hi) return true;
        }
        return false;
    }

    private static bool MoreAboveAfter(List<int> suffix)
    {
        foreach (var cp in suffix)
        {
            var c = CanonicalCombiningClass(cp);
            if (c == 230) return true;
            if (c == 0) return false;
        }
        return false;
    }

    private static bool AfterSoftDotted(List<int> revPrefix)
    {
        foreach (var cp in revPrefix)
        {
            if (IsSoftDotted(cp)) return true;
            var c = CanonicalCombiningClass(cp);
            if (c == 0 || c == 230) return false;
        }
        return false;
    }

    private static bool AfterI(List<int> revPrefix)
    {
        foreach (var cp in revPrefix)
        {
            if (cp == 0x0049) return true;
            var c = CanonicalCombiningClass(cp);
            if (c == 0 || c == 230) return false;
        }
        return false;
    }

    private static bool BeforeDot(List<int> suffix)
    {
        foreach (var cp in suffix)
        {
            if (cp == 0x0307) return true;
            if (CanonicalCombiningClass(cp) == 0) return false;
        }
        return false;
    }

    private static bool HasCasedBefore(List<int> revPrefix)
    {
        foreach (var cp in revPrefix)
        {
            if (IsCased(cp)) return true;
            if (CanonicalCombiningClass(cp) == 0) return false;
        }
        return false;
    }

    private static bool HasCasedAfter(List<int> suffix)
    {
        foreach (var cp in suffix)
        {
            if (IsCased(cp)) return true;
            if (CanonicalCombiningClass(cp) == 0) return false;
        }
        return false;
    }

    private static bool FinalSigma(List<int> revPrefix, List<int> suffix) =>
        HasCasedBefore(revPrefix) && !HasCasedAfter(suffix);

    private static bool IsLocaleCondition(string condition) =>
        condition is "tr" or "az" or "lt";

    private static bool LocaleMatches(CasingLocale locale, List<string> conditions)
    {
        if (!conditions.Any(IsLocaleCondition)) return true;
        return conditions.Any(c =>
            (c == "tr" && locale == CasingLocale.Turkish)
            || (c == "az" && locale == CasingLocale.Azeri)
            || (c == "lt" && locale == CasingLocale.Lithuanian));
    }

    private static bool ConditionsHold(
        CasingLocale locale, List<int> revPrefix, List<int> suffix, List<string> conditions)
    {
        if (!LocaleMatches(locale, conditions)) return false;
        foreach (var c in conditions)
        {
            if (IsLocaleCondition(c)) continue;
            bool ok = c switch
            {
                "Final_Sigma" => FinalSigma(revPrefix, suffix),
                "Not_Final_Sigma" => !FinalSigma(revPrefix, suffix),
                "After_Soft_Dotted" => AfterSoftDotted(revPrefix),
                "More_Above" => MoreAboveAfter(suffix),
                "Not_Before_Dot" => !BeforeDot(suffix),
                "After_I" => AfterI(revPrefix),
                _ => false,
            };
            if (!ok) return false;
        }
        return true;
    }

    private static CasingRow? FindSpecialRow(
        CasingLocale locale, List<int> revPrefix, List<int> suffix, int cp)
    {
        if (!SpecialCasing().TryGetValue(cp, out var candidates)) return null;
        foreach (var row in candidates)
        {
            if (row.Conditions.Count > 0 && ConditionsHold(locale, revPrefix, suffix, row.Conditions))
            {
                return row;
            }
        }
        foreach (var row in candidates)
        {
            if (row.Conditions.Count == 0) return row;
        }
        return null;
    }

    /// <summary>Lowercase a codepoint sequence under <paramref name="locale"/>
    /// (UAX #21 full mapping): a SpecialCasing row where its conditions hold,
    /// else the simple lowercase mapping.</summary>
    public static List<int> ToLower(CasingLocale locale, List<int> cps)
    {
        var output = new List<int>();
        var revPrefix = new List<int>();
        for (var i = 0; i < cps.Count; i++)
        {
            var cp = cps[i];
            var suffix = cps.GetRange(i + 1, cps.Count - i - 1);
            var row = FindSpecialRow(locale, revPrefix, suffix, cp);
            if (row is not null)
            {
                output.AddRange(row.Lower);
            }
            else
            {
                output.Add(SimpleLowercase(cp));
            }
            revPrefix.Insert(0, cp);
        }
        return output;
    }

    // ── locale-case-inversion: per-position lowercase divergence across locales ─
    // Mirrors Unicode.Security.Form.LocaleCaseInversion. Inputs whose lowercase
    // fold inverts across locales — the homograph-via-locale attack
    // (CVE-2007-6692, CVE-2021-30245, the Spotify "İSTANBUL" / "iSTANBUL"
    // incident class). Compares per-position lowercase under each locale against
    // the default, so the SpecialCasing context predicates read full context.

    /// <summary>Lowercase a single codepoint in its full input context: the
    /// SpecialCasing row whose conditions hold, else the simple lowercase
    /// mapping.</summary>
    private static List<int> LowerCodepoint(
        CasingLocale locale, List<int> revPrefix, List<int> suffix, int cp)
    {
        var row = FindSpecialRow(locale, revPrefix, suffix, cp);
        if (row is not null) return row.Lower;
        return new List<int> { SimpleLowercase(cp) };
    }

    /// <summary>Uppercase a single codepoint in its full input context: the
    /// SpecialCasing row whose conditions hold (its uppercase column), else the
    /// simple uppercase mapping. Mirrors <see cref="LowerCodepoint"/> exactly,
    /// returning the uppercase side of the same context-resolved row.</summary>
    private static List<int> UpperCodepoint(
        CasingLocale locale, List<int> revPrefix, List<int> suffix, int cp)
    {
        var row = FindSpecialRow(locale, revPrefix, suffix, cp);
        if (row is not null) return row.Upper;
        return new List<int> { SimpleUppercase(cp) };
    }

    /// <summary>First input position whose <see cref="LowerCodepoint"/> under
    /// <paramref name="locale"/> differs from the default-locale result, or null
    /// when the two folds agree at every position.</summary>
    private static int? FirstLocaleDivergence(CasingLocale locale, List<int> input)
    {
        var revPrefix = new List<int>();
        for (var i = 0; i < input.Count; i++)
        {
            var cp = input[i];
            var suffix = input.GetRange(i + 1, input.Count - i - 1);
            var defaultLower = LowerCodepoint(CasingLocale.Default, revPrefix, suffix, cp);
            var localeLower = LowerCodepoint(locale, revPrefix, suffix, cp);
            if (!defaultLower.SequenceEqual(localeLower)) return i;
            revPrefix.Insert(0, cp);
        }
        return null;
    }

    /// <summary>One locale-case-inversion scan result. <c>SubThreat</c> is null
    /// for a clear input, else the divergent locale's tag with the first
    /// divergent input position in <c>Positions</c>.</summary>
    public sealed record LocaleCaseInversionResult(string? SubThreat, List<int> Positions);

    /// <summary>Detect an input whose lowercase fold inverts across locales.
    /// Turkish divergence takes priority (covering Azeri); Lithuanian is reached
    /// only when no Turkish divergence is found.</summary>
    public static LocaleCaseInversionResult LocaleCaseInversionDetect(List<int> input)
    {
        if (FirstLocaleDivergence(CasingLocale.Turkish, input) is int turkishPos)
        {
            return new LocaleCaseInversionResult("TurkishCaseDivergence", new List<int> { turkishPos });
        }
        if (FirstLocaleDivergence(CasingLocale.Lithuanian, input) is int lithuanianPos)
        {
            return new LocaleCaseInversionResult("LithuanianCaseDivergence", new List<int> { lithuanianPos });
        }
        return new LocaleCaseInversionResult(null, new List<int>());
    }

    // ── normalization-bomb: NFD/NFKD expansion beyond documented bounds ────────
    // Mirrors Unicode.Security.Form.NormalizationBomb. Inputs whose NFD or NFKD
    // expansion exceeds documented bounds — the classic normalization-expansion
    // DoS. A small input that expands to a very large normalized form exhausts
    // memory/CPU at the receiving layer (Arabic ligature U+FDFA → 18 codepoints
    // under NFKD). Three priority-ordered checks: a per-codepoint blow-up scan,
    // an overall NFKD ratio, an overall NFD ratio. Ratios are expressed in
    // hundredths to avoid floats.

    /// <summary>Maximum allowed NFKD expansion per single codepoint. Hangul ≤ 3,
    /// Greek extended forms 4, the largest non-FDFA Arabic ligature (FDFB) 8;
    /// anything greater than 8 is flagged.</summary>
    private const int MaxNfkdPerCp = 8;

    /// <summary>Overall-sequence NFD expansion ratio threshold, in hundredths
    /// (300 = 3×). Pure Hangul sits at exactly 300 and stays clear under strict
    /// <c>&gt;</c>.</summary>
    private const int NfdRatioPct = 300;

    /// <summary>Overall-sequence NFKD expansion ratio threshold, in hundredths
    /// (400 = 4×).</summary>
    private const int NfkdRatioPct = 400;

    /// <summary>First position whose single-codepoint NFKD expansion exceeds
    /// <see cref="MaxNfkdPerCp"/>, or null when no codepoint blows up.</summary>
    private static int? FirstBlowupCp(List<int> input)
    {
        for (var i = 0; i < input.Count; i++)
        {
            if (ToNfkd(new List<int> { input[i] }).Count > MaxNfkdPerCp) return i;
        }
        return null;
    }

    /// <summary>NFD ratio percentage (<c>100 * nfdLen / inputLen</c>); 0 on empty
    /// input.</summary>
    private static int NfdRatioPercent(List<int> input) =>
        input.Count == 0 ? 0 : ToNfdCodepoints(input).Count * 100 / input.Count;

    /// <summary>NFKD ratio percentage (<c>100 * nfkdLen / inputLen</c>); 0 on
    /// empty input.</summary>
    private static int NfkdRatioPercent(List<int> input) =>
        input.Count == 0 ? 0 : ToNfkd(input).Count * 100 / input.Count;

    /// <summary>One normalization-bomb scan result. <c>SubThreat</c> is null for a
    /// clear input; a per-codepoint blow-up carries the offending position in
    /// <c>Positions</c>, the ratio hazards carry no position.</summary>
    public sealed record NormalizationBombResult(string? SubThreat, List<int> Positions);

    /// <summary>Detect a normalization-expansion bomb. Priority: per-codepoint
    /// blow-up, then overall NFKD ratio, then overall NFD ratio.</summary>
    public static NormalizationBombResult NormalizationBombDetect(List<int> input)
    {
        if (FirstBlowupCp(input) is int i)
        {
            return new NormalizationBombResult("SingleCpBlowup", new List<int> { i });
        }
        if (NfkdRatioPercent(input) > NfkdRatioPct)
        {
            return new NormalizationBombResult("NfkdHighExpansion", new List<int>());
        }
        if (NfdRatioPercent(input) > NfdRatioPct)
        {
            return new NormalizationBombResult("NfdHighExpansion", new List<int>());
        }
        return new NormalizationBombResult(null, new List<int>());
    }

    // ── nfc-idempotence-witness: inputs not already in NFC (or NFKC) form ──────
    // Mirrors Unicode.Security.Form.NfcIdempotenceWitness. Inputs that are not
    // already in NFC (or, failing that, not in NFKC) — the silent
    // normalization-drift class where a signer and verifier pick different
    // canonical forms and their hashes diverge. Compares input element-wise
    // against its NFC and NFKC forms, reporting the first divergent position: a
    // mismatch against NFC is NonNfcForm; a sequence already in NFC but not NFKC
    // is NonNfkcCompatForm.

    /// <summary>First index at which two sequences diverge (in element, or one
    /// ends); null when identical.</summary>
    private static int? FirstDivergence(IReadOnlyList<int> a, IReadOnlyList<int> b)
    {
        var common = Math.Min(a.Count, b.Count);
        for (var i = 0; i < common; i++)
        {
            if (a[i] != b[i]) return i;
        }
        if (a.Count != b.Count) return common;
        return null;
    }

    /// <summary>One NFC-idempotence-witness scan result. <c>SubThreat</c> is null
    /// for a clear input (already in NFC and NFKC); else the divergence tag with
    /// its first position in <c>Positions</c>.</summary>
    public sealed record NfcIdempotenceWitnessResult(string? SubThreat, List<int> Positions);

    /// <summary>Detect an input that is not in canonical (NFC), or not in
    /// compatibility (NFKC), form. NFC divergence takes priority over NFKC.</summary>
    public static NfcIdempotenceWitnessResult NfcIdempotenceWitnessDetect(List<int> input)
    {
        var nfc = ToNfc(input);
        if (FirstDivergence(input, nfc) is int p)
        {
            return new NfcIdempotenceWitnessResult("NonNfcForm", new List<int> { p });
        }
        var nfkc = ToNfkc(input).ToList();
        if (FirstDivergence(input, nfkc) is int q)
        {
            return new NfcIdempotenceWitnessResult("NonNfkcCompatForm", new List<int> { q });
        }
        return new NfcIdempotenceWitnessResult(null, new List<int>());
    }

    // ── width-class-confusion: UAX #11 East Asian Width fold ──────────────────
    // Mirrors Unicode.Security.Form.WidthClassConfusion (and the verified Rust
    // port src/security/form/width_class_confusion.rs). A Fullwidth (EAW = F) or
    // Halfwidth (EAW = H) codepoint whose NFKD head carries a different EAW
    // class is a compatibility-fold homograph:
    //
    //   U+FF21 'Ａ' (F)  ->  U+0041 'A' (Na)
    //   U+FF71 'ｱ' (H)  ->  U+30A2 'ア' (W)
    //
    // The two-system bypass: a validator that whitelists ASCII rejects Ａ, while
    // a downstream NFKC step at storage or comparison time folds it to plain A,
    // so ＡＤＭＩＮ claims the username ADMIN. Distinct from renderer
    // divergence's FullwidthVariance, which fires on F-class codepoints for
    // renderer-cohort reasons; this is the NFKC-fold verdict and both can fire
    // independently. Hangul syllables decompose to jamos that are still W class,
    // so pure Hangul stays clear.

    /// <summary>One width-class-confusion scan result; SubThreat is null when clear.</summary>
    public sealed record WidthClassConfusionResult(string? SubThreat, List<int> Positions);

    private static bool HasWidthFold(int cp)
    {
        var folded = ToNfkd(new List<int> { cp });
        if (folded.Count == 0) return false;
        return EastAsianWidthOf(folded[0]) != EastAsianWidthOf(cp);
    }

    private static int? FirstWidthFold(IReadOnlyList<int> input, EastAsianWidth want)
    {
        for (var i = 0; i < input.Count; i++)
        {
            if (EastAsianWidthOf(input[i]) == want && HasWidthFold(input[i])) return i;
        }
        return null;
    }

    /// <summary>
    /// Classify a codepoint sequence. A Fullwidth fold takes priority over a
    /// Halfwidth one, matching the reference's sub-threat order.
    /// </summary>
    public static WidthClassConfusionResult WidthClassConfusionDetect(IReadOnlyList<int> input)
    {
        var fullwidth = FirstWidthFold(input, EastAsianWidth.F);
        if (fullwidth is not null) return new WidthClassConfusionResult("FullwidthFold", new List<int> { fullwidth.Value });
        var halfwidth = FirstWidthFold(input, EastAsianWidth.H);
        if (halfwidth is not null) return new WidthClassConfusionResult("HalfwidthFold", new List<int> { halfwidth.Value });
        return new WidthClassConfusionResult(null, new List<int>());
    }

    // ── bip39-canonical: BIP-39 mnemonic canonicalisation + wordlist checks ────
    // Mirrors Unicode.Security.Crypto.Bip39Canonical.

    private static readonly string[] Bip39Languages =
    {
        "english", "japanese", "korean", "spanish", "chinese_simplified",
        "chinese_traditional", "french", "italian", "czech", "portuguese",
    };

    private static List<(string Name, HashSet<string> Words)>? bip39WordlistCache;

    private static List<(string Name, HashSet<string> Words)> Bip39Wordlists()
    {
        if (bip39WordlistCache is null)
        {
            var lists = new List<(string, HashSet<string>)>();
            foreach (var lang in Bip39Languages)
            {
                var set = new HashSet<string>();
                foreach (var line in ReadDataFile($"bip39/{lang}.txt").Split('\n'))
                {
                    if (line.Length != 0) set.Add(line);
                }
                lists.Add((lang, set));
            }
            bip39WordlistCache = lists;
        }
        return bip39WordlistCache;
    }

    private static string Bip39CpsToKey(List<int> cps)
    {
        var sb = new StringBuilder();
        foreach (var cp in cps) sb.Append(char.ConvertFromUtf32(cp));
        return sb.ToString();
    }

    /// <summary>One bip39-canonical scan result. <c>SubThreat</c> is null for a
    /// clear input (with <c>Language</c> set).</summary>
    public sealed record Bip39CanonicalResult(
        string? SubThreat, List<int> Positions, string? Language,
        List<int> Canonical, int WordCount);

    private static bool IsBip39Whitespace(int cp) => cp == 0x0020 || cp == 0x3000;

    private static List<int> CollapseBip39Whitespace(List<int> cps)
    {
        var output = new List<int>();
        var inWs = false;
        foreach (var cp in cps)
        {
            if (IsBip39Whitespace(cp))
            {
                if (!inWs) output.Add(0x0020);
                inWs = true;
            }
            else
            {
                output.Add(cp);
                inWs = false;
            }
        }
        return output;
    }

    private static List<int> TrimBip39(List<int> cps)
    {
        var start = 0;
        var end = cps.Count;
        while (start < end && cps[start] == 0x0020) start++;
        while (end > start && cps[end - 1] == 0x0020) end--;
        return cps.GetRange(start, end - start);
    }

    private static List<int> Bip39CanonicalForm(List<int> cps)
    {
        var lowered = ToLower(CasingLocale.Default, ToNfkd(cps).ToList());
        return TrimBip39(CollapseBip39Whitespace(lowered));
    }

    private static List<List<int>> Bip39SplitWords(List<int> cps)
    {
        var words = new List<List<int>>();
        var current = new List<int>();
        foreach (var cp in cps)
        {
            if (cp == 0x0020)
            {
                if (current.Count > 0)
                {
                    words.Add(current);
                    current = new List<int>();
                }
            }
            else
            {
                current.Add(cp);
            }
        }
        if (current.Count > 0) words.Add(current);
        return words;
    }

    /// <summary>Six probes in priority order (first hit wins), mirroring
    /// Bip39Canonical.detect.</summary>
    public static Bip39CanonicalResult Bip39CanonicalDetect(List<int> input)
    {
        var canonical = Bip39CanonicalForm(input);
        var words = Bip39SplitWords(canonical);
        var wordCount = words.Count;

        var trailing = 0;
        for (var i = input.Count - 1; i >= 0; i--)
        {
            if (IsBip39Whitespace(input[i])) trailing++;
            else break;
        }
        if (trailing > 0)
        {
            return new Bip39CanonicalResult(
                "TrailingWhitespace", new List<int> { input.Count - trailing }, null, canonical, wordCount);
        }
        for (var i = 0; i < input.Count; i++)
        {
            if (input[i] >= 0x41 && input[i] <= 0x5A)
            {
                return new Bip39CanonicalResult("MixedCase", new List<int> { i }, null, canonical, wordCount);
            }
        }
        for (var i = 0; i < input.Count; i++)
        {
            if (IsBip39Whitespace(input[i])
                && (i == 0 || (i + 1 < input.Count && IsBip39Whitespace(input[i + 1]))))
            {
                return new Bip39CanonicalResult("WhitespaceAnomaly", new List<int> { i }, null, canonical, wordCount);
            }
        }
        var nfkd = ToNfkd(input).ToList();
        if (!input.SequenceEqual(nfkd))
        {
            var limit = Math.Min(input.Count, nfkd.Count);
            var pos = limit;
            for (var i = 0; i < limit; i++)
            {
                if (input[i] != nfkd[i])
                {
                    pos = i;
                    break;
                }
            }
            return new Bip39CanonicalResult("NonNFKD", new List<int> { pos }, null, canonical, wordCount);
        }
        for (var idx = 0; idx < words.Count; idx++)
        {
            var key = Bip39CpsToKey(words[idx]);
            var found = false;
            foreach (var (_, set) in Bip39Wordlists())
            {
                if (set.Contains(key))
                {
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                return new Bip39CanonicalResult("WordlistMismatch", new List<int> { idx }, null, canonical, wordCount);
            }
        }
        foreach (var (name, set) in Bip39Wordlists())
        {
            var all = true;
            foreach (var word in words)
            {
                if (!set.Contains(Bip39CpsToKey(word)))
                {
                    all = false;
                    break;
                }
            }
            if (all)
            {
                return new Bip39CanonicalResult(null, new List<int>(), name, canonical, wordCount);
            }
        }
        return new Bip39CanonicalResult("LanguageAmbiguous", new List<int>(), null, canonical, wordCount);
    }

    private static long ComposeKey(int d, int c) => ((long)d << 32) | (uint)c;

    // Canonical composition table: inverse of the two-codepoint canonical
    // decompositions, excluding singleton decompositions, Composition-Exclusion
    // codepoints, and pairs whose first element is a non-starter (CCC != 0).
    private static Dictionary<long, int> CompositionTable()
    {
        if (compositionTable is null)
        {
            var table = new Dictionary<long, int>();
            var exclusions = CompositionExclusions();
            foreach (var (cp, entry) in UnicodeDataMap())
            {
                var decomp = entry.Canonical;
                if (decomp is null || decomp.Count != 2) continue;
                if (exclusions.Contains(cp)) continue;
                if (CanonicalCombiningClass(decomp[0]) != 0) continue;
                table[ComposeKey(decomp[0], decomp[1])] = cp;
            }
            compositionTable = table;
        }
        return compositionTable;
    }

    private static bool HangulDecompose(int cp, List<int> output)
    {
        if (cp < HangulSBase || cp >= HangulSBase + HangulSCount) return false;
        var sIndex = cp - HangulSBase;
        output.Add(HangulLBase + sIndex / HangulNCount);
        output.Add(HangulVBase + (sIndex % HangulNCount) / HangulTCount);
        var tIndex = sIndex % HangulTCount;
        if (tIndex != 0) output.Add(HangulTBase + tIndex);
        return true;
    }

    private static int? HangulCompose(int a, int b)
    {
        if (a >= HangulLBase && a < HangulLBase + HangulLCount
            && b >= HangulVBase && b < HangulVBase + HangulVCount)
        {
            var lIndex = a - HangulLBase;
            var vIndex = b - HangulVBase;
            return HangulSBase + (lIndex * HangulVCount + vIndex) * HangulTCount;
        }
        if (a >= HangulSBase && a < HangulSBase + HangulSCount
            && (a - HangulSBase) % HangulTCount == 0
            && b > HangulTBase && b < HangulTBase + HangulTCount)
        {
            return a + (b - HangulTBase);
        }
        return null;
    }

    private static void DecomposeOne(int cp, List<int> output)
    {
        if (HangulDecompose(cp, output)) return;
        if (UnicodeDataMap().TryGetValue(cp, out var entry) && entry.Canonical is not null)
        {
            foreach (var child in entry.Canonical) DecomposeOne(child, output);
            return;
        }
        output.Add(cp);
    }

    private static void CompatDecomposeOne(int cp, List<int> output)
    {
        if (HangulDecompose(cp, output)) return;
        if (UnicodeDataMap().TryGetValue(cp, out var entry))
        {
            if (entry.Compat is not null)
            {
                foreach (var child in entry.Compat) CompatDecomposeOne(child, output);
                return;
            }
            if (entry.Canonical is not null)
            {
                foreach (var child in entry.Canonical) CompatDecomposeOne(child, output);
                return;
            }
        }
        output.Add(cp);
    }

    // Stable canonical ordering: sort each non-starter run by CCC, preserving the
    // relative order of equal-CCC codepoints (insertion sort that swaps only on a
    // strict CCC decrease and never crosses a starter).
    private static void CanonicalOrder(List<int> values)
    {
        for (var index = 1; index < values.Count; index++)
        {
            var currentCcc = CanonicalCombiningClass(values[index]);
            if (currentCcc == 0) continue;
            for (var j = index; j > 0; j--)
            {
                var previousCcc = CanonicalCombiningClass(values[j - 1]);
                if (previousCcc == 0 || previousCcc <= currentCcc) break;
                (values[j - 1], values[j]) = (values[j], values[j - 1]);
            }
        }
    }

    // Canonical composition (UAX #15 D115), matching Unicode.Normalization.Compose
    // and the D115-corrected blocked rule shared by the from-tables ports.
    private static List<int> CanonicalCompose(List<int> seq)
    {
        if (seq.Count == 0) return new List<int>();
        var table = CompositionTable();
        var output = new List<int>();
        var starterIndex = -1;
        var lastCcc = -1;
        foreach (var cp in seq)
        {
            var cpCcc = CanonicalCombiningClass(cp);
            if (starterIndex >= 0)
            {
                var starter = output[starterIndex];
                var composed = HangulCompose(starter, cp);
                if (composed is null && table.TryGetValue(ComposeKey(starter, cp), out var mapped))
                    composed = mapped;
                // Blocked check (UAX #15 D115): lastCcc != 0 means a combiner is
                // buffered between the active starter and this candidate. A starter
                // candidate (cpCcc == 0) is blocked outright by any buffered combiner;
                // a non-starter is blocked when the buffered combiner has CCC >= its own.
                var blocked = lastCcc != 0 && (cpCcc == 0 || lastCcc >= cpCcc);
                if (!blocked && composed is not null)
                {
                    output[starterIndex] = composed.Value;
                    continue;
                }
            }
            output.Add(cp);
            if (cpCcc == 0)
            {
                starterIndex = output.Count - 1;
                lastCcc = 0;
            }
            else
            {
                lastCcc = cpCcc;
            }
        }
        return output;
    }

    private static List<int> ToNfdCodepoints(List<int> input)
    {
        var output = new List<int>();
        foreach (var cp in input) DecomposeOne(cp, output);
        CanonicalOrder(output);
        return output;
    }

    private static List<int> ToNfkdCodepoints(IEnumerable<int> input)
    {
        var output = new List<int>();
        foreach (var cp in input) CompatDecomposeOne(EnsureCodepoint(cp), output);
        CanonicalOrder(output);
        return output;
    }

    // Compatibility decomposition (NFKD), matching Unicode.Normalization.NFKD.
    public static IReadOnlyList<int> ToNfkd(IEnumerable<int> input) => ToNfkdCodepoints(input);

    // NFKD followed by canonical composition, matching Unicode.Normalization.NFKC.
    public static IReadOnlyList<int> ToNfkc(IEnumerable<int> input) =>
        CanonicalCompose(ToNfkdCodepoints(input));

    // NFD followed by canonical composition, matching Unicode.Normalization.NFC.
    private static List<int> ToNfc(List<int> input) =>
        CanonicalCompose(ToNfdCodepoints(input)).ToList();

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

    // UAX #11 East_Asian_Width class.
    private enum EastAsianWidth { A, F, H, N, Na, W }

    private sealed record EawRange(int Lo, int Hi, EastAsianWidth Class);

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
    private static IReadOnlyList<EawRange> EastAsianWidthTable()
    {
        if (eastAsianWidthTable is null)
        {
            eastAsianWidthTable = ParseEastAsianWidth(ReadDataFile("EastAsianWidth.txt"));
        }
        return eastAsianWidthTable;
    }

    private static EastAsianWidth EawOfToken(string token) => token switch
    {
        "A" => EastAsianWidth.A,
        "F" => EastAsianWidth.F,
        "H" => EastAsianWidth.H,
        "Na" => EastAsianWidth.Na,
        "W" => EastAsianWidth.W,
        _ => EastAsianWidth.N,
    };

    // Mirror of Unicode.Generated.EastAsianWidth. The file's
    //  line declares Neutral over the whole
    // codepoint space, so an unlisted codepoint is N and there is no default
    // range list to scan, unlike DerivedBidiClass.
    private static IReadOnlyList<EawRange> ParseEastAsianWidth(string raw)
    {
        var rows = new List<EawRange>();
        foreach (var line in raw.Split('\n'))
        {
            var hash = line.IndexOf('#');
            var body = (hash >= 0 ? line.Substring(0, hash) : line).Trim();
            if (body.Length == 0) continue;
            var semi = body.IndexOf(';');
            if (semi < 0) continue;
            var range = ParseRangeField(body.Substring(0, semi));
            if (range is null) continue;
            rows.Add(new EawRange(range.Value.Lo, range.Value.Hi, EawOfToken(body.Substring(semi + 1).Trim())));
        }
        rows.Sort((a, b) => a.Lo.CompareTo(b.Lo));
        return rows;
    }

    private static EastAsianWidth EastAsianWidthOf(int cp)
    {
        var table = EastAsianWidthTable();
        int lo = 0, hi = table.Count;
        while (lo < hi)
        {
            var mid = lo + (hi - lo) / 2;
            var row = table[mid];
            if (cp < row.Lo) hi = mid;
            else if (cp > row.Hi) lo = mid + 1;
            else return row.Class;
        }
        return EastAsianWidth.N;
    }

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
            ["EastAsianWidth.txt"] = "ea7ce50f3444a050333448dffef1cadd9325af55cbb764b4a2280faf52170a33",
            ["UnicodeData.txt"] = "2e1efc1dcb59c575eedf5ccae60f95229f706ee6d031835247d843c11d96470c",
            ["CompositionExclusions.txt"] = "2f239196ef3b5b61db5cc476e9bd80f534d15aa1b74e1be1dea5d042a344c85f",
            ["DerivedCoreProperties.txt"] = "24c7fed1195c482faaefd5c1e7eb821c5ee1fb6de07ecdbaa64b56a99da22c08",
            ["DerivedJoiningType.txt"] = "f39ebe974825d6736aee15582250307aa532b2cfab3caf3f86bd23fddc9c5c4d",
            ["IdentifierStatus.txt"] = "617228a16da13850bf8af28b6cd08f5e9b6595d2eb60404fe6eee2c85b4e4a35",
            ["Scripts.txt"] = "9f5e50d3abaee7d6ce09480f325c706f485ae3240912527e651954d2d6b035bf",
            ["ScriptExtensions.txt"] = "ec2107e58825a1586acee8e0911ce18260394ac8b87e535ca325f1ccbeb06bc6",
            ["PropertyValueAliases.txt"] = "64e9a5f76f7a1e8b5a47d6a1f9a26522a251208f5276bdfa1559dac7cf2e827a",
            ["SpecialCasing.txt"] = "efc25faf19de21b92c1194c111c932e03d2a5eaf18194e33f1156e96de4c9588",
            ["emoji-data.txt"] = "2cb2bb9455cda83e8481541ecf5b6dfda66a3bb89efa3fa7c5297eccf607b72b",
            ["emoji-zwj-sequences.txt"] = "5b25441daed2322b068c5e70cda522946a4f0274df864445a1965a92e5fc5cad",
            ["bip39/chinese_simplified.txt"] = "5c5942792bd8340cb8b27cd592f1015edf56a8c5b26276ee18a482428e7c5726",
            ["bip39/chinese_traditional.txt"] = "417b26b3d8500a4ae3d59717d7011952db6fc2fb84b807f3f94ac734e89c1b5f",
            ["bip39/czech.txt"] = "7e80e161c3e93d9554c2efb78d4e3cebf8fc727e9c52e03b83b94406bdcc95fc",
            ["bip39/english.txt"] = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
            ["bip39/french.txt"] = "ebc3959ab7801a1df6bac4fa7d970652f1df76b683cd2f4003c941c63d517e59",
            ["bip39/italian.txt"] = "d392c49fdb700a24cd1fceb237c1f65dcc128f6b34a8aacb58b59384b5c648c2",
            ["bip39/japanese.txt"] = "2eed0aef492291e061633d7ad8117f1a2b03eb80a29d0e4e3117ac2528d05ffd",
            ["bip39/korean.txt"] = "9e95f86c167de88f450f0aaf89e87f6624a57f973c67b516e338e8e8b8897f60",
            ["bip39/portuguese.txt"] = "2685e9c194c82ae67e10ba59d9ea5345a23dc093e92276fc5361f6667d79cd3f",
            ["bip39/spanish.txt"] = "46846a5a0139d1e3cb77293e521c2865f7bcdb82c44e8d0a06a2cd0ecba48c0b",
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

    /// True iff the input is not already in NFC, which is the rung's definition in
    /// Unicode.Security.Identity.HomoglyphConfusable: `toNFC input ≠ input`. An input
    /// that renders as its own composed form carries no swap, whatever its individual
    /// codepoints look like.
    ///
    /// The predicate is the comparison itself rather than a structural stand-in for it.
    /// Adjacency tests over the raw codepoints cannot decide it: canonical ordering is a
    /// stable sort on Canonical_Combining_Class, so two marks of equal class never
    /// reorder however their codepoint values compare, and whether a mark composes with
    /// the character before it is a question for the composition table.
    private static bool HasDecompositionSwap(List<int> input)
    {
        var nfc = ToNfc(input);
        if (nfc.Count != input.Count) return true;
        for (var index = 0; index < input.Count; index++)
        {
            if (input[index] != nfc[index]) return true;
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

    // UTS #39 §5.1 restriction levels, mirroring Unicode/Restriction.lean.
    //
    // Script resolution reads the vendored Scripts.txt and ScriptExtensions.txt:
    // a codepoint's Script_Extensions where the file gives one, otherwise the
    // abbreviation of its primary Script. The abbreviation vocabulary is exactly
    // the set occurring in ScriptExtensions.txt, which is what
    // Unicode/ResolvedScripts.lean models as its ScriptAbbrev enum, so a primary
    // script outside it resolves to nothing on both sides. Returning a singleton
    // there instead would make every unknown-script codepoint look Single-Script,
    // putting RestrictionLevelOf one rung too strict and hiding RestrictionLow.

    internal enum RestrictionLevel
    {
        AsciiOnly,
        SingleScript,
        HighlyRestrictive,
        ModeratelyRestrictive,
        MinimallyRestrictive,
        Unrestricted,
    }

    private static List<(int Lo, int Hi, string[] Value)>? scriptRanges;
    private static List<(int Lo, int Hi, string[] Value)>? scriptExtRanges;
    private static HashSet<string>? scriptExtAbbrevs;
    private static Dictionary<string, string>? scriptLongToAbbrev;

    // Parse a "RANGE ; VALUE" table into ascending ranges. The value field splits
    // on whitespace, so a Scripts.txt row yields one long name and a
    // ScriptExtensions.txt row yields its abbreviation list.
    private static List<(int Lo, int Hi, string[] Value)> ParseScriptRanges(string fileName)
    {
        var result = new List<(int Lo, int Hi, string[] Value)>();
        foreach (var rawLine in ReadDataFile(fileName).Split('\n'))
        {
            var line = rawLine.Split('#', 2)[0].Trim();
            if (line.Length == 0) continue;
            var parts = line.Split(';', 2);
            if (parts.Length < 2) continue;
            var value = parts[1].Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (value.Length == 0) continue;
            var field = parts[0].Trim();
            var dots = field.IndexOf("..", StringComparison.Ordinal);
            int? lo;
            int? hi;
            if (dots < 0)
            {
                lo = ParseHex(field);
                hi = lo;
            }
            else
            {
                lo = ParseHex(field[..dots]);
                hi = ParseHex(field[(dots + 2)..]);
            }
            if (lo is null || hi is null) continue;
            result.Add((lo.Value, hi.Value, value));
        }
        result.Sort((a, b) => a.Lo.CompareTo(b.Lo));
        return result;
    }

    private static string[]? FindScriptRange(List<(int Lo, int Hi, string[] Value)> ranges, int cp)
    {
        foreach (var row in ranges)
        {
            if (row.Lo <= cp && cp <= row.Hi) return row.Value;
        }
        return null;
    }

    private static List<(int Lo, int Hi, string[] Value)> ScriptsTable() =>
        scriptRanges ??= ParseScriptRanges("Scripts.txt");

    private static List<(int Lo, int Hi, string[] Value)>? joiningTypeRanges;

    // DerivedJoiningType.txt shares the "RANGE ; VALUE" shape, so it reuses the
    // same range parser and lookup the script tables use. RFC 5892 Appendix A.1
    // reads Joining_Type to decide whether a ZERO WIDTH NON-JOINER sits in a
    // position its script actually requires.
    private static List<(int Lo, int Hi, string[] Value)> JoiningTypeTable() =>
        joiningTypeRanges ??= ParseScriptRanges("DerivedJoiningType.txt");

    // Joining_Type for one codepoint, as its single-letter token. The file's
    // @missing line declares Non_Joining over the whole space, so an unlisted
    // codepoint is "U".
    private static string JoiningTypeOf(int cp)
    {
        var value = FindScriptRange(JoiningTypeTable(), cp);
        if (value is null || value.Length == 0) return "U";
        return value[0] switch
        {
            "C" => "C",
            "D" => "D",
            "L" => "L",
            "R" => "R",
            "T" => "T",
            _ => "U",
        };
    }

    // True iff cp has Canonical_Combining_Class 9, the Virama used to request an
    // explicit conjunct in scripts like Devanagari.
    private static bool IsViramaCodepoint(int cp) => CanonicalCombiningClass(cp) == 9;

    // The Joining_Type of the first non-Transparent codepoint before i, or null.
    private static string? JoiningTypeBefore(IReadOnlyList<int> input, int i)
    {
        for (var j = i - 1; j >= 0; j--)
        {
            var jt = JoiningTypeOf(input[j]);
            if (jt != "T") return jt;
        }
        return null;
    }

    // The Joining_Type of the first non-Transparent codepoint after i, or null.
    private static string? JoiningTypeAfter(IReadOnlyList<int> input, int i)
    {
        for (var j = i + 1; j < input.Count; j++)
        {
            var jt = JoiningTypeOf(input[j]);
            if (jt != "T") return jt;
        }
        return null;
    }

    // True iff the ZWNJ at index i occupies a position where it is
    // orthographically required, by RFC 5892 Appendix A.1: it follows a Virama,
    // which is how a Devanagari conjunct is suppressed, or it sits between a
    // left- or dual-joining character and a right- or dual-joining one, skipping
    // Transparent characters on both sides, which is how a Persian word boundary
    // is written inside a cursive run.
    //
    // A ZWNJ outside such a position carries no orthographic duty and stays
    // reportable.
    private static bool IsLegitimateZwnjContext(IReadOnlyList<int> input, int i)
    {
        if (i > 0 && IsViramaCodepoint(input[i - 1])) return true;
        var left = JoiningTypeBefore(input, i);
        var right = JoiningTypeAfter(input, i);
        if (left is null || right is null) return false;
        var leftJoins = left == "L" || left == "D";
        var rightJoins = right == "R" || right == "D";
        return leftJoins && rightJoins;
    }

    // True iff the ZWJ at index i is flanked by two codepoints that both
    // participate in some registered RGI emoji ZWJ sequence. Strictly narrower
    // than "is an emoji": a codepoint carrying the Emoji property but appearing
    // in no registered sequence does not sanction a ZWJ beside it. A ZWJ in head
    // or tail position is never legitimate.
    private static bool IsLegitimateZwjContext(IReadOnlyList<int> input, int i)
    {
        if (i == 0 || i + 1 >= input.Count) return false;
        return EmojiZwjIntegrity.IsEmojiTarget(input[i - 1])
            && EmojiZwjIntegrity.IsEmojiTarget(input[i + 1]);
    }

    // True iff at least one of the given zero-width positions is unsanctioned. A
    // ZWJ inside a registered emoji sequence and a ZWNJ in an RFC 5892
    // CONTEXTJ-valid position both carry meaning a reader depends on, so they are
    // recorded as present but do not make the family fire.
    internal static bool HasSuspiciousZeroWidth(IReadOnlyList<int> input, List<int> positions)
    {
        foreach (var i in positions)
        {
            var cp = input[i];
            var sanctioned = (cp == 0x200D && IsLegitimateZwjContext(input, i))
                || (cp == 0x200C && IsLegitimateZwnjContext(input, i));
            if (!sanctioned) return true;
        }
        return false;
    }

    private static List<(int Lo, int Hi, string[] Value)> ScriptExtensionsTable()
    {
        if (scriptExtRanges is null)
        {
            scriptExtRanges = ParseScriptRanges("ScriptExtensions.txt");
            scriptExtAbbrevs = new HashSet<string>();
            foreach (var row in scriptExtRanges)
            {
                foreach (var abbrev in row.Value) scriptExtAbbrevs.Add(abbrev);
            }
        }
        return scriptExtRanges;
    }

    // Script long name to four-letter abbreviation, from the "sc" rows of
    // PropertyValueAliases.txt.
    private static Dictionary<string, string> ScriptAliasMap()
    {
        if (scriptLongToAbbrev is null)
        {
            scriptLongToAbbrev = new Dictionary<string, string>();
            foreach (var rawLine in ReadDataFile("PropertyValueAliases.txt").Split('\n'))
            {
                var line = rawLine.Split('#', 2)[0];
                var fields = line.Split(';');
                if (fields.Length < 3 || fields[0].Trim() != "sc") continue;
                var abbrev = fields[1].Trim();
                var name = fields[2].Trim();
                if (abbrev.Length > 0 && name.Length > 0) scriptLongToAbbrev[name] = abbrev;
            }
        }
        return scriptLongToAbbrev;
    }

    private static string ScriptOf(int cp)
    {
        var value = FindScriptRange(ScriptsTable(), cp);
        return value is null ? "Unknown" : value[0];
    }

    private static IReadOnlyList<string> ResolveScripts(int cp)
    {
        var ext = FindScriptRange(ScriptExtensionsTable(), cp);
        if (ext is not null) return ext;
        ScriptExtensionsTable();
        if (!ScriptAliasMap().TryGetValue(ScriptOf(cp), out var abbrev)) return Array.Empty<string>();
        if (scriptExtAbbrevs is null || !scriptExtAbbrevs.Contains(abbrev)) return Array.Empty<string>();
        return new[] { abbrev };
    }

    private static bool IsIgnoredForIntersection(int cp)
    {
        var script = ScriptOf(cp);
        return script == "Common" || script == "Inherited";
    }

    private static bool IntersectsScripts(IReadOnlyList<string> a, IReadOnlyList<string> b)
    {
        foreach (var x in a)
        {
            foreach (var y in b)
            {
                if (x == y) return true;
            }
        }
        return false;
    }

    private static HashSet<string> StringScriptUnion(List<int> input)
    {
        var union = new HashSet<string>();
        foreach (var cp in input)
        {
            if (IsIgnoredForIntersection(cp)) continue;
            foreach (var s in ResolveScripts(cp)) union.Add(s);
        }
        return union;
    }

    private static List<string> StringResolvedScripts(List<int> input)
    {
        List<string>? acc = null;
        foreach (var cp in input)
        {
            if (IsIgnoredForIntersection(cp)) continue;
            var resolved = ResolveScripts(cp);
            if (acc is null)
            {
                acc = new List<string>(resolved);
                continue;
            }
            acc.RemoveAll(s => !resolved.Contains(s));
        }
        return acc ?? new List<string>();
    }

    private static bool IsAsciiOnly(List<int> input)
    {
        foreach (var cp in input)
        {
            if (cp >= 0x80) return false;
        }
        return true;
    }

    private static bool IsSingleScript(List<int> input) =>
        !IsAsciiOnly(input) && StringResolvedScripts(input).Count > 0;

    private static bool AllWithinCovered(List<int> input, string[] covered)
    {
        foreach (var cp in input)
        {
            if (IsIgnoredForIntersection(cp)) continue;
            var resolved = ResolveScripts(cp);
            if (resolved.Count == 0 || !IntersectsScripts(resolved, covered)) return false;
        }
        return true;
    }

    private static bool IsCoveredCjk(List<int> input) =>
        AllWithinCovered(input, new[] { "Latn", "Hani", "Hira", "Kana" })
        || AllWithinCovered(input, new[] { "Latn", "Hani", "Bopo" })
        || AllWithinCovered(input, new[] { "Latn", "Hani", "Hang" });

    private static bool IsHighlyRestrictive(List<int> input) =>
        IsSingleScript(input) || IsCoveredCjk(input);

    // Every codepoint resolves to Latin or to one fixed other Recommended script,
    // with that other script neither Cyrillic nor Greek.
    private static bool IsModeratelyRestrictiveShape(List<int> input)
    {
        string? other = null;
        foreach (var cp in input)
        {
            if (IsIgnoredForIntersection(cp)) continue;
            var resolved = ResolveScripts(cp);
            if (resolved.Count == 0) return false;
            if (resolved.Contains("Latn")) continue;
            var s = resolved[0];
            if (s == "Cyrl" || s == "Grek") return false;
            if (other is null)
            {
                other = s;
                continue;
            }
            if (s != other) return false;
        }
        return other is not null;
    }

    private static bool IsMinimallyRestrictive(List<int> input)
    {
        foreach (var cp in input)
        {
            if (!IsIdAllowed(cp)) return false;
        }
        return true;
    }

    internal static RestrictionLevel RestrictionLevelOf(List<int> input)
    {
        if (IsAsciiOnly(input)) return RestrictionLevel.AsciiOnly;
        if (IsSingleScript(input)) return RestrictionLevel.SingleScript;
        if (IsHighlyRestrictive(input)) return RestrictionLevel.HighlyRestrictive;
        if (IsModeratelyRestrictiveShape(input)) return RestrictionLevel.ModeratelyRestrictive;
        if (IsMinimallyRestrictive(input)) return RestrictionLevel.MinimallyRestrictive;
        return RestrictionLevel.Unrestricted;
    }

    private static bool HasCrossScriptMix(List<int> input) =>
        StringScriptUnion(input).Count >= 2 && !IsHighlyRestrictive(input);

    // The mixed-script sub-threat for input, or null when it is admissible.
    //
    // The rung order is Unicode/Security/Identity/MixedScriptAdmissibility.lean's:
    // a Restricted-status codepoint outranks every script question, then the two
    // named Latin pairs, then a multi-script mix split by whether it stays inside
    // a CJK covered set, and finally an Unrestricted level with no script mix.
    //
    // identifierField carries what the caller knows about the field, mirroring
    // that module's Context. Phase 1 is sound for an identifier, which cannot
    // contain a space, and unsound for a document, where every space and every
    // punctuation mark is Restricted.
    private static string? MixedScriptVerdict(List<int> input, bool identifierField)
    {
        if (identifierField)
        {
            foreach (var cp in input)
            {
                if (!IsIdAllowed(cp)) return "RestrictedStatusCp";
            }
        }
        var union = StringScriptUnion(input);
        if (union.Contains("Latn") && union.Contains("Cyrl")) return "LatinCyrillic";
        if (union.Contains("Latn") && union.Contains("Grek")) return "LatinGreek";
        if (union.Count >= 2 && !IsHighlyRestrictive(input))
        {
            return IsCoveredCjk(input) ? "CjkMix" : "ScriptMixOther";
        }
        if (identifierField && RestrictionLevelOf(input) == RestrictionLevel.Unrestricted)
        {
            return "UnrestrictedLevel";
        }
        return null;
    }

    private static string MixedScriptSubThreat(List<int> input) =>
        MixedScriptVerdict(input, true) ?? "ScriptMixOther";

    // The UAX #44 Default_Ignorable_Code_Point property, read from the bundled
    // DerivedCoreProperties.txt through the same reader the Cased and Soft_Dotted
    // predicates use, rather than transcribed, so the predicate tracks the UCD
    // revision the port ships against. A transcribed set omits ranges a reader
    // never sees but an attacker can still send, such as the musical-symbol beams
    // at U+1D173..U+1D17A.
    private static bool IsDefaultIgnorableCodepoint(int cp)
    {
        defaultIgnorableRanges ??= ParseCasingProperty("Default_Ignorable_Code_Point");
        foreach (var (lo, hi) in defaultIgnorableRanges)
        {
            if (lo <= cp && cp <= hi) return true;
        }
        return false;
    }

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
