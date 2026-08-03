using System.Text.Json;
using UnicodeSecurity;
using UnicodeSecurity.Segmentation;
using His = UnicodeSecurity.Security.HashInputStability;
using Awd = UnicodeSecurity.Security.AiWatermarkDetectability;
using Ezwj = UnicodeSecurity.Security.EmojiZwjIntegrity;
using Stvf = UnicodeSecurity.Security.SkinToneVariationForgery;
using Rd = UnicodeSecurity.Security.RendererDivergence;
using Fd = UnicodeSecurity.Security.FilenameDisguise;
using Sdd = UnicodeSecurity.Security.SourceDisplayDivergence;
using Ifd = UnicodeSecurity.Security.IdentifierFormDrift;
using Afd = UnicodeSecurity.Security.AdmissibilityFormDrift;

TestCovertDisplayCompoundVectors();
TestConfusableBidiCompoundVectors();
TestSurrogateReassemblyVectors();
TestRtlInjectionVectors();
TestPolicyContract();
TestVerdictContract();
TestUtf8DecodeContract();
TestMultiEncodingDecodeContract();
TestDetectorFixtures();
TestCompatNormalizationVectors();
TestCasing();
TestBip39();
TestLocaleCaseInversion();
TestNormalizationBomb();
TestNfcIdempotenceWitness();
TestHashInputStabilityFixture();
TestHashInputStabilityContextVectors();
TestAiWatermarkDetectabilityFixture();
TestAiWatermarkDetectabilityContextVectors();
TestEmojiZwjIntegrityFixture();
TestEmojiZwjIntegritySpotChecks();
TestSkinToneVariationForgeryFixture();
TestSkinToneVariationForgerySpotChecks();
TestRendererDivergenceFixture();
TestRendererDivergenceSpotChecks();
TestFilenameDisguiseFixture();
TestFilenameDisguiseSpotChecks();
TestSourceDisplayDivergenceFixture();
TestSourceDisplayDivergenceSpotChecks();
TestIdentifierFormDriftFixture();
TestIdentifierFormDriftSpotChecks();
TestAdmissibilityFormDriftFixture();
TestAdmissibilityFormDriftSpotChecks();
TestStreamSafeViolationFixture();
TestStreamSafeViolationBoundary();
TestCaseExpansionMismatchFixture();
TestCaseExpansionMismatchSpotChecks();
TestUtf8Blob();
TestValidatedUtf8();
TestGraphemeVectors();
TestGraphemeBreakTestFile();
Console.WriteLine("clean: .NET contract tests pass");

// Direct spot-check of the covert-display-compound detector, mirroring the
// detect_* spot-check theorems in
// Unicode/Security/Boundary/CovertDisplayCompound.lean and the Rust port's
// tests. Runs first so its result is visible before every other test. Sub ==
// null means a clear input; otherwise it is the compound sub-threat tag.
static void TestCovertDisplayCompoundVectors()
{
    var vectors = new (int[] Input, string? Sub)[]
    {
        (System.Array.Empty<int>(), null),
        (new[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F }, null),
        (new[] { 0x202E }, null),
        (new[] { 0x0041, 0xFE00 }, null),
        (new[] { 0x202E, 0x0041, 0xFE00 }, "BidiPlusUnregisteredVs"),
        (new[] { 0x202E, 0x0041, 0xE0001 }, "BidiPlusTagBlock"),
    };
    foreach (var (input, expected) in vectors)
    {
        var (actual, _) = Security.CovertDisplayCompoundDetect(input);
        var name = "covert-display-compound [" + string.Join(",", input.Select(cp => "0x" + cp.ToString("X"))) + "]";
        AssertEqual(expected ?? "<clear>", actual ?? "<clear>", name);
    }
    Console.WriteLine("clean: .NET covert-display-compound 6-vector spot-check passes");
}

// Direct spot-check of the confusable-bidi-compound detector, mirroring the
// detect_* spot-check theorems in
// Unicode/Security/Boundary/ConfusableBidiCompound.lean and the Rust port's
// tests. Runs first so its result is visible before every other test. Sub ==
// null means a clear input; otherwise it is the compound sub-threat tag.
static void TestConfusableBidiCompoundVectors()
{
    var vectors = new (int[] Input, string? Sub)[]
    {
        (System.Array.Empty<int>(), null),
        (new[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F }, null),
        (new[] { 0x202E, 0x0041, 0x0042, 0x0043 }, null),
        (new[] { 0x0430 }, null),
        (new[] { 0x202E, 0x0430 }, "ConfusableInOverride"),
        (new[] { 0x2066, 0x03BF }, "ConfusableInIsolate"),
    };
    foreach (var (input, expected) in vectors)
    {
        var (actual, _) = Security.ConfusableBidiCompoundDetect(input);
        var name = "confusable-bidi-compound [" + string.Join(",", input.Select(cp => "0x" + cp.ToString("X"))) + "]";
        AssertEqual(expected ?? "<clear>", actual ?? "<clear>", name);
    }
    Console.WriteLine("clean: .NET confusable-bidi-compound 6-vector spot-check passes");
}

// Direct spot-check of the surrogate-reassembly detector, mirroring the
// detect_* spot-check theorems in Unicode/Security/Covert/SurrogateReassembly.lean
// and the Rust port's tests. Runs first so its result is visible before every
// other test. Sub == null means a clear input (well-formed, or not a byte
// stream); otherwise it is the malformed-UTF-8 sub-threat tag.
static void TestSurrogateReassemblyVectors()
{
    var vectors = new (int[] Input, string? Sub)[]
    {
        (System.Array.Empty<int>(), null),
        (new[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F }, null),
        (new[] { 0xC3, 0xA9 }, null),
        (new[] { 0xE4, 0xB8, 0xAD }, null),
        (new[] { 0xF0, 0x9F, 0x98, 0x80 }, null),
        (new[] { 0xC0, 0x80 }, "InvalidStartByte"),
        (new[] { 0xC0, 0xAF }, "InvalidStartByte"),
        (new[] { 0xFE }, "InvalidStartByte"),
        (new[] { 0x80 }, "InvalidStartByte"),
        (new[] { 0xFF }, "InvalidStartByte"),
        (new[] { 0xE0, 0x80, 0xAF }, "Overlong"),
        (new[] { 0xF0, 0x80, 0x80, 0xAF }, "Overlong"),
        (new[] { 0xED, 0xA0, 0x80 }, "Cesu8"),
        (new[] { 0xED, 0xAF, 0xBF }, "Cesu8"),
        (new[] { 0xC3 }, "Truncated"),
        (new[] { 0xF0, 0x9F, 0x98 }, "Truncated"),
        // The unit detect clamps values > 0xFF to 0xFF (mirroring the Lean
        // toBytes helper), so it surfaces InvalidStartByte. The scan
        // orchestrator gates these out (mirroring runAll).
        (new[] { 0x1F600 }, "InvalidStartByte"),
        (new[] { 0x41, 0x100 }, "InvalidStartByte"),
    };
    foreach (var (input, expected) in vectors)
    {
        var (actual, _) = Security.SurrogateReassemblyDetect(input);
        var name = "surrogate-reassembly [" + string.Join(",", input.Select(cp => "0x" + cp.ToString("X"))) + "]";
        AssertEqual(expected ?? "<clear>", actual ?? "<clear>", name);
    }
    Console.WriteLine("clean: .NET surrogate-reassembly 18-vector spot-check passes");
}

// Direct spot-check of the rtl-injection detector's DerivedBidiClass-backed
// strong-Bidi lookup, mirroring the Rust/Python/C++ port tests. Runs first so
// its result is visible before the shared contract tests. Sub == null means a
// clear input; otherwise it is the highest-priority sub-threat.
static void TestRtlInjectionVectors()
{
    var vectors = new (int[] Input, string? Sub)[]
    {
        (new[] { 0x30, 0x31, 0x32, 0x33 }, null),
        (new[] { 0x043F }, null),
        (new[] { 0x41, 0x202E, 0x42 }, "RloInLTRField"),
        (new[] { 0x05D0, 0x42, 0x43 }, "FieldTakeover"),
        (new[] { 0x0627, 0x42, 0x43 }, "FieldTakeover"),
        (new[] { 0x41, 0x42, 0x05D0, 0x44 }, "StrongRTLInLTR"),
        (new[] { 0x41, 0x42, 0x05D0, 0x05D1, 0x05D2, 0x05D3, 0x44 }, "MixedOverflow"),
    };
    foreach (var (input, expected) in vectors)
    {
        var (actual, _) = Security.RtlInjectionDetect(input);
        var name = "rtl-injection [" + string.Join(",", input.Select(cp => "0x" + cp.ToString("X"))) + "]";
        AssertEqual(expected ?? "<clear>", actual ?? "<clear>", name);
    }
    Console.WriteLine("clean: .NET rtl-injection 7-vector spot-check passes");
}

static void TestPolicyContract()
{
    using var contract = LoadFixture("policy_contract.json");
    AssertEqual(1, contract.RootElement.GetProperty("schema").GetInt32(), "policy schema");
    AssertEqual("unicode-security-policy-v0", contract.RootElement.GetProperty("contract").GetString(), "policy contract");
    foreach (var entry in contract.RootElement.GetProperty("cases").EnumerateArray())
    {
        var verdict = Security.Scan(String(entry, "profile"), String(entry, "mode"), Ints(entry.GetProperty("input")));
        AssertEqual(String(entry, "action"), verdict.Action, String(entry, "name"));
        foreach (var required in Strings(entry.GetProperty("required_findings")))
        {
            AssertTrue(HasFinding(verdict.Findings, required), $"{String(entry, "name")}: missing {required}");
        }
    }
}

static void TestVerdictContract()
{
    using var contract = LoadFixture("verdict_contract.json");
    AssertEqual(1, contract.RootElement.GetProperty("schema").GetInt32(), "verdict schema");
    AssertEqual("unicode-security-verdict-v0", contract.RootElement.GetProperty("contract").GetString(), "verdict contract");
    foreach (var entry in contract.RootElement.GetProperty("cases").EnumerateArray())
    {
        var verdict = Security.Scan(String(entry, "profile"), String(entry, "mode"), Ints(entry.GetProperty("input")));
        var expected = JsonSerializer.Serialize(entry.GetProperty("verdict"));
        AssertEqual(expected, Security.VerdictJson(verdict), String(entry, "name"));
    }
}

static void TestUtf8DecodeContract()
{
    using var contract = LoadFixture("decode_contract.json");
    AssertEqual(1, contract.RootElement.GetProperty("schema").GetInt32(), "decode schema");
    AssertEqual("unicode-security-decode-v0", contract.RootElement.GetProperty("contract").GetString(), "decode contract");
    foreach (var entry in contract.RootElement.GetProperty("cases").EnumerateArray())
    {
        var verdict = Security.ScanUtf8(String(entry, "profile"), String(entry, "mode"), Bytes(entry.GetProperty("input_bytes")));
        AssertDecodeEntry(entry, verdict);
    }
}

static void TestMultiEncodingDecodeContract()
{
    using var contract = LoadFixture("decode_multiencoding_contract.json");
    AssertEqual(1, contract.RootElement.GetProperty("schema").GetInt32(), "multi-encoding schema");
    AssertEqual("unicode-security-multiencoding-decode-v0", contract.RootElement.GetProperty("contract").GetString(), "multi-encoding contract");
    foreach (var entry in contract.RootElement.GetProperty("cases").EnumerateArray())
    {
        var verdict = String(entry, "encoding") switch
        {
            "utf-8" => Security.ScanUtf8(String(entry, "profile"), String(entry, "mode"), Bytes(entry.GetProperty("input_bytes"))),
            "utf-16be" => Security.ScanUtf16BE(String(entry, "profile"), String(entry, "mode"), Bytes(entry.GetProperty("input_bytes"))),
            "utf-16le" => Security.ScanUtf16LE(String(entry, "profile"), String(entry, "mode"), Bytes(entry.GetProperty("input_bytes"))),
            "utf-32be" => Security.ScanUtf32BE(String(entry, "profile"), String(entry, "mode"), Bytes(entry.GetProperty("input_bytes"))),
            "utf-32le" => Security.ScanUtf32LE(String(entry, "profile"), String(entry, "mode"), Bytes(entry.GetProperty("input_bytes"))),
            var other => throw new InvalidOperationException($"unknown encoding: {other}"),
        };
        AssertDecodeEntry(entry, verdict);
    }
}

static void TestDetectorFixtures()
{
    foreach (var fixture in new[]
    {
        "detectors/tag_block_payload.json",
        "detectors/variation_selector_payload.json",
        "detectors/zero_width_payload.json",
        "detectors/bidi_control_balance.json",
        "detectors/noncharacter_control.json",
        "detectors/homoglyph_confusable.json",
        "detectors/mixed_script_admissibility.json",
    })
    {
        using var detector = LoadFixture(fixture);
        AssertEqual(1, detector.RootElement.GetProperty("schema").GetInt32(), $"{fixture} schema");
        var family = String(detector.RootElement, "family");
        foreach (var entry in detector.RootElement.GetProperty("cases").EnumerateArray())
        {
            var verdict = Security.Scan("gateway-header", "observe", Ints(entry.GetProperty("input")));
            var requiredFindings = Strings(entry.GetProperty("required_findings")).ToList();
            foreach (var required in requiredFindings)
            {
                AssertTrue(HasFinding(verdict.Findings, required), $"{fixture}:{String(entry, "name")}: missing {required}");
            }
            if (requiredFindings.Count == 0)
            {
                AssertTrue(!HasFamilyFinding(verdict.Findings, family), $"{fixture}:{String(entry, "name")}: unexpected family");
            }
        }
    }
}

// Direct spot-check of compatibility normalization (NFKD / NFKC), mirroring
// Unicode.Normalization.NFKD / NFKC and the Rust port's to_nfkd / to_nfkc.
// NFKC applies the compatibility mappings and then composes; NFKD stops after
// compatibility decomposition.
static void TestCompatNormalizationVectors()
{
    var nfkc = new (int[] Input, int[] Expected)[]
    {
        (new[] { 0xFB01 }, new[] { 0x66, 0x69 }),
        (new[] { 0x2460 }, new[] { 0x31 }),
        (new[] { 0xFF21 }, new[] { 0x41 }),
        (new[] { 0x00E9 }, new[] { 0x00E9 }),
        (new[] { 0x0065, 0x0301 }, new[] { 0x00E9 }),
        (new[] { 0x1112, 0x1161, 0x11AB }, new[] { 0xD55C }),
    };
    foreach (var (input, expected) in nfkc)
    {
        var actual = Security.ToNfkc(input);
        var name = "ToNfkc [" + string.Join(",", input.Select(cp => "0x" + cp.ToString("X"))) + "]";
        AssertSequence(expected, actual, name);
    }
    var nfkd = new (int[] Input, int[] Expected)[]
    {
        (new[] { 0xFF21 }, new[] { 0x41 }),
        (new[] { 0x00E9 }, new[] { 0x0065, 0x0301 }),
    };
    foreach (var (input, expected) in nfkd)
    {
        var actual = Security.ToNfkd(input);
        var name = "ToNfkd [" + string.Join(",", input.Select(cp => "0x" + cp.ToString("X"))) + "]";
        AssertSequence(expected, actual, name);
    }
    Console.WriteLine("clean: .NET NFKD/NFKC 8-vector spot-check passes");
}

static void AssertDecodeEntry(JsonElement entry, Security.Verdict verdict)
{
    AssertEqual(String(entry, "action"), verdict.Action, $"{String(entry, "name")} action");
    AssertSequence(Ints(entry.GetProperty("input")), verdict.Input, $"{String(entry, "name")} input");
    foreach (var required in Strings(entry.GetProperty("required_findings")))
    {
        AssertTrue(HasFinding(verdict.Findings, required), $"{String(entry, "name")}: missing {required}");
    }
    foreach (var expected in entry.GetProperty("required_positions").EnumerateArray())
    {
        var code = String(expected, "code");
        var finding = verdict.Findings.FirstOrDefault(candidate => candidate.Code == code);
        AssertTrue(finding is not null, $"{String(entry, "name")}: missing positions for {code}");
        AssertSequence(Ints(expected.GetProperty("positions")), finding!.Positions, $"{String(entry, "name")}: {code}");
    }
}

static JsonDocument LoadFixture(string name)
{
    var path = Path.Combine(AppContext.BaseDirectory, "testdata", "fixtures", "security", name);
    if (!File.Exists(path)) path = Path.Combine("testdata", "fixtures", "security", name);
    return JsonDocument.Parse(File.ReadAllText(path));
}

static string String(JsonElement element, string name) => element.GetProperty(name).GetString() ?? "";

static IEnumerable<string> Strings(JsonElement array) =>
    array.EnumerateArray().Select(item => item.GetString() ?? "");

static List<int> Ints(JsonElement array) =>
    array.EnumerateArray().Select(item => item.GetInt32()).ToList();

static byte[] Bytes(JsonElement array) =>
    array.EnumerateArray().Select(item => (byte)item.GetInt32()).ToArray();

static bool HasFinding(IReadOnlyList<Security.Finding> findings, string code) =>
    findings.Any(finding => finding.Code == code);

static bool HasFamilyFinding(IReadOnlyList<Security.Finding> findings, string family) =>
    findings.Any(finding => finding.Family == family);

static void AssertTrue(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}

// Ground truth: the toLower spot-check theorems in Unicode.Casing.
static void TestCasing()
{
    AssertSequence(new[] { 0x68, 0x65, 0x6C, 0x6C, 0x6F },
        Security.ToLower(Security.CasingLocale.Default, new List<int> { 0x48, 0x65, 0x6C, 0x6C, 0x6F }), "toLower hello");
    AssertSequence(new[] { 0x0069 },
        Security.ToLower(Security.CasingLocale.Default, new List<int> { 0x0049 }), "toLower I default");
    AssertSequence(new[] { 0x0131 },
        Security.ToLower(Security.CasingLocale.Turkish, new List<int> { 0x0049 }), "toLower I turkish");
    AssertSequence(new[] { 0x0131 },
        Security.ToLower(Security.CasingLocale.Azeri, new List<int> { 0x0049 }), "toLower I azeri");
    AssertSequence(new[] { 0x0069 },
        Security.ToLower(Security.CasingLocale.Turkish, new List<int> { 0x0130 }), "toLower dotted-I turkish");
    AssertSequence(new[] { 0x0069, 0x0307 },
        Security.ToLower(Security.CasingLocale.Default, new List<int> { 0x0130 }), "toLower dotted-I default");
    Console.WriteLine("clean: .NET toLower 6-theorem spot-check passes");
}

// Ground truth: the detect spot-check theorems in Bip39CanonicalVectorsDetect.
static void TestBip39()
{
    var abandon = new List<int> { 0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E };
    var about = new List<int> { 0x61, 0x62, 0x6F, 0x75, 0x74 };
    string? Tag(List<int> input) => Security.Bip39CanonicalDetect(input).SubThreat;

    var trailing = new List<int>(abandon) { 0x20 };
    AssertEqual("TrailingWhitespace", Tag(trailing), "bip39 trailing");
    AssertSequence(new[] { 7 }, Security.Bip39CanonicalDetect(trailing).Positions, "bip39 trailing pos");
    AssertEqual("MixedCase", Tag(new List<int> { 0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E }), "bip39 mixed");
    var dbl = new List<int>(abandon) { 0x20, 0x20 };
    dbl.AddRange(about);
    AssertEqual("WhitespaceAnomaly", Tag(dbl), "bip39 double");
    var lead = new List<int> { 0x20 };
    lead.AddRange(abandon);
    AssertEqual("WhitespaceAnomaly", Tag(lead), "bip39 leading");
    AssertEqual("NonNFKD", Tag(new List<int> { 0xFB00 }), "bip39 ligature");
    AssertEqual("NonNFKD", Tag(new List<int> { 0x61, 0x00A0, 0x62 }), "bip39 nbsp");
    AssertEqual("WordlistMismatch", Tag(new List<int> { 0x71, 0x7A, 0x71, 0x7A }), "bip39 mismatch");

    var empty = Security.Bip39CanonicalDetect(new List<int>());
    AssertEqual<string?>(null, empty.SubThreat, "bip39 empty sub");
    AssertEqual("english", empty.Language, "bip39 empty lang");

    var mnemonic = new List<int>();
    for (var i = 0; i < 11; i++)
    {
        mnemonic.AddRange(abandon);
        mnemonic.Add(0x20);
    }
    mnemonic.AddRange(about);
    var verdict = Security.Bip39CanonicalDetect(mnemonic);
    AssertEqual<string?>(null, verdict.SubThreat, "bip39 12word sub");
    AssertEqual("english", verdict.Language, "bip39 12word lang");
    AssertEqual(12, verdict.WordCount, "bip39 12word count");
    Console.WriteLine("clean: .NET bip39-canonical detect spot-check passes");
}

// Ground truth: the detect_* spot-check theorems in
// Unicode/Security/Form/LocaleCaseInversion.lean and the Rust/Go ports' tests.
static void TestLocaleCaseInversion()
{
    string? Sub(List<int> input) => Security.LocaleCaseInversionDetect(input).SubThreat;

    AssertEqual<string?>(null, Sub(new List<int>()), "locale-case empty");
    AssertEqual<string?>(null, Sub(new List<int> { 0x48, 0x65, 0x6C, 0x6C, 0x6F }), "locale-case ascii");
    AssertEqual("TurkishCaseDivergence", Sub(new List<int> { 0x0049 }), "locale-case capital-I turkish");
    AssertSequence(new[] { 0 }, Security.LocaleCaseInversionDetect(new List<int> { 0x0049 }).Positions, "locale-case capital-I pos");
    AssertEqual("TurkishCaseDivergence", Sub(new List<int> { 0x0130 }), "locale-case dotted-I turkish");
    AssertEqual("TurkishCaseDivergence", Sub(new List<int> { 0x0049, 0x0300 }), "locale-case I-grave turkish-first");
    AssertEqual("LithuanianCaseDivergence", Sub(new List<int> { 0x004A, 0x0300 }), "locale-case J-grave lithuanian");
    Console.WriteLine("clean: .NET locale-case-inversion detect spot-check passes");
}

// Ground truth: the detect_* spot-check theorems in
// Unicode/Security/Form/NormalizationBomb.lean and the Rust port's tests.
static void TestNormalizationBomb()
{
    string? Sub(List<int> input) => Security.NormalizationBombDetect(input).SubThreat;

    AssertEqual<string?>(null, Sub(new List<int>()), "norm-bomb empty");
    AssertEqual<string?>(null, Sub(new List<int> { 0x48, 0x65, 0x6C, 0x6C, 0x6F }), "norm-bomb ascii");
    AssertEqual<string?>(null, Sub(new List<int> { 0xD55C }), "norm-bomb korean");
    AssertEqual<string?>(null, Sub(new List<int> { 0x2460 }), "norm-bomb circled-one");
    AssertEqual("SingleCpBlowup", Sub(new List<int> { 0xFDFA }), "norm-bomb fdfa blowup");
    AssertSequence(new[] { 0 }, Security.NormalizationBombDetect(new List<int> { 0xFDFA }).Positions, "norm-bomb fdfa pos");
    AssertEqual("NfkdHighExpansion", Sub(new List<int> { 0xFDFB }), "norm-bomb fdfb nfkd");
    AssertEqual("NfdHighExpansion", Sub(new List<int> { 0x1F82 }), "norm-bomb greek nfd");
    Console.WriteLine("clean: .NET normalization-bomb detect spot-check passes");
}

// Ground truth: the detect_* spot-check theorems in
// Unicode/Security/Form/NfcIdempotenceWitness.lean and the Rust port's tests.
static void TestNfcIdempotenceWitness()
{
    string? Sub(List<int> input) => Security.NfcIdempotenceWitnessDetect(input).SubThreat;

    AssertEqual<string?>(null, Sub(new List<int>()), "nfc-witness empty");
    AssertEqual<string?>(null, Sub(new List<int> { 0x48, 0x65, 0x6C, 0x6C, 0x6F }), "nfc-witness ascii");
    AssertEqual<string?>(null, Sub(new List<int> { 0x00E9 }), "nfc-witness precomposed-e-acute");
    AssertEqual("NonNfcForm", Sub(new List<int> { 0x0065, 0x0301 }), "nfc-witness decomposed-e-acute");
    AssertSequence(new[] { 0 }, Security.NfcIdempotenceWitnessDetect(new List<int> { 0x0065, 0x0301 }).Positions, "nfc-witness decomposed-e-acute pos");
    AssertEqual("NonNfkcCompatForm", Sub(new List<int> { 0xFB01 }), "nfc-witness fi-ligature");
    Console.WriteLine("clean: .NET nfc-idempotence-witness detect spot-check passes");
}

// Ground truth: the shared context-free detector fixture
// fixtures/security/detectors/hash_input_stability.json, run through
// Security.HashInputStability.Detect (the empty-context wrapper). Each case's
// required_findings is the fully-qualified reason code
// (unicode.security.K.hash-input-stability.<tag>); an empty list means the
// input must classify Clear. Mirrors the Rust port's §8 detect spot checks.
static void TestHashInputStabilityFixture()
{
    using var detector = LoadFixture("detectors/hash_input_stability.json");
    AssertEqual(1, detector.RootElement.GetProperty("schema").GetInt32(), "hash-input-stability schema");
    AssertEqual("hash-input-stability", String(detector.RootElement, "family"), "hash-input-stability family");
    var cases = 0;
    foreach (var entry in detector.RootElement.GetProperty("cases").EnumerateArray())
    {
        var name = String(entry, "name");
        var input = Ints(entry.GetProperty("input"));
        var verdict = Security.HashInputStability.Detect(input);
        var required = Strings(entry.GetProperty("required_findings")).ToList();
        if (required.Count == 0)
        {
            AssertTrue(verdict.Classify.IsClear, $"hash-input-stability {name}: expected clear, got {verdict.Classify.Tag}");
        }
        else
        {
            foreach (var code in required)
            {
                AssertEqual<string?>(code, verdict.Classify.ReasonCode, $"hash-input-stability {name}: reason code");
            }
        }
        cases++;
    }
    Console.WriteLine($"clean: .NET hash-input-stability {cases}-case shared-fixture detect passes");
}

// Ground truth: the verbatim Context-vector comment block in the Rust port's
// hash_input_stability.rs test module (the shared detector-fixture schema
// cannot express a Context, so these live only in-source). Every vector is
// transcribed here: the four context-bearing probes, their clear cases, and the
// three cross-probe priority vectors, plus the RfcRule tag round-trip and the
// hash_stable / default-context identity spot checks.
static void TestHashInputStabilityContextVectors()
{
    string? CtxTag(His.Context ctx, int[] input) =>
        Security.HashInputStability.DetectWithContext(ctx, input).Classify.Tag;
    IReadOnlyList<int> CtxPos(His.Context ctx, int[] input) =>
        Security.HashInputStability.DetectWithContext(ctx, input).Classify.Positions;

    // encodingMismatch: non-UTF-8 label, invalid surrogate, out-of-range scalar.
    var encUtf16 = new His.Context(DeclaredEncoding: "utf-16");
    AssertEqual<string?>("EncodingMismatch", CtxTag(encUtf16, new[] { 0x61, 0x62, 0x63 }), "his utf-16 label tag");
    AssertSequence(new[] { 0 }, CtxPos(encUtf16, new[] { 0x61, 0x62, 0x63 }), "his utf-16 label pos");
    var encUtf8 = new His.Context(DeclaredEncoding: "utf-8");
    AssertEqual<string?>("EncodingMismatch", CtxTag(encUtf8, new[] { 0x61, 0xD800, 0x62 }), "his invalid surrogate tag");
    AssertSequence(new[] { 1 }, CtxPos(encUtf8, new[] { 0x61, 0xD800, 0x62 }), "his invalid surrogate pos");
    AssertEqual<string?>("EncodingMismatch", CtxTag(encUtf8, new[] { 0x61, 0x110000, 0x62 }), "his out-of-range tag");
    AssertSequence(new[] { 1 }, CtxPos(encUtf8, new[] { 0x61, 0x110000, 0x62 }), "his out-of-range pos");
    foreach (var label in new[] { "UTF-8", "utf-8", "UTF8", "utf8" })
    {
        AssertEqual<string?>(null, CtxTag(new His.Context(DeclaredEncoding: label), new[] { 0x61, 0x62, 0x63 }),
            $"his utf-8 label {label} clear");
    }

    // signedMessageRule: one firing and (where present) one clear vector per RFC rule.
    var pgp4880 = new His.Context(RfcRule: His.RfcRule.Pgp4880TrailingWhitespace);
    AssertEqual<string?>("SignedMessageRule", CtxTag(pgp4880, new[] { 0x61, 0x20 }), "his pgp4880 tag");
    AssertSequence(new[] { 1 }, CtxPos(pgp4880, new[] { 0x61, 0x20 }), "his pgp4880 pos");
    var pgp9580 = new His.Context(RfcRule: His.RfcRule.Pgp9580LineEnding);
    AssertEqual<string?>("SignedMessageRule", CtxTag(pgp9580, new[] { 0x61, 0x0A, 0x62 }), "his pgp9580 bare-lf tag");
    AssertSequence(new[] { 1 }, CtxPos(pgp9580, new[] { 0x61, 0x0A, 0x62 }), "his pgp9580 bare-lf pos");
    AssertEqual<string?>(null, CtxTag(pgp9580, new[] { 0x61, 0x62, 0x63, 0x0D, 0x0A, 0x64, 0x65, 0x66 }),
        "his pgp9580 crlf clear");
    var rfc8785 = new His.Context(RfcRule: His.RfcRule.Rfc8785NfcRequirement);
    AssertEqual<string?>("SignedMessageRule", CtxTag(rfc8785, new[] { 0x0065, 0x0301 }), "his rfc8785 tag");
    AssertSequence(new[] { 0 }, CtxPos(rfc8785, new[] { 0x0065, 0x0301 }), "his rfc8785 pos");
    var rfc8259 = new His.Context(RfcRule: His.RfcRule.Rfc8259ControlChar);
    AssertEqual<string?>("SignedMessageRule", CtxTag(rfc8259, new[] { 0x61, 0x01, 0x62 }), "his rfc8259 tag");
    AssertSequence(new[] { 1 }, CtxPos(rfc8259, new[] { 0x61, 0x01, 0x62 }), "his rfc8259 pos");
    var rfc7515 = new His.Context(RfcRule: His.RfcRule.Rfc7515JwsBase64Url);
    AssertEqual<string?>("SignedMessageRule", CtxTag(rfc7515, new[] { 0x41, 0x2B, 0x42 }), "his rfc7515 plus tag");
    AssertSequence(new[] { 1 }, CtxPos(rfc7515, new[] { 0x41, 0x2B, 0x42 }), "his rfc7515 plus pos");
    AssertEqual<string?>(null, CtxTag(rfc7515, new[] { 0x41, 0x61, 0x30, 0x2D, 0x5F, 0x7A, 0x5A, 0x39 }),
        "his rfc7515 clean clear");
    var rfc6376 = new His.Context(RfcRule: His.RfcRule.Rfc6376DkimRelaxed);
    AssertEqual<string?>("SignedMessageRule", CtxTag(rfc6376, new[] { 0x61, 0x20, 0x20, 0x62 }), "his rfc6376 double-space tag");
    AssertSequence(new[] { 2 }, CtxPos(rfc6376, new[] { 0x61, 0x20, 0x20, 0x62 }), "his rfc6376 double-space pos");
    AssertEqual<string?>(null, CtxTag(rfc6376, new[] { 0x61, 0x20, 0x62 }), "his rfc6376 single-space clear");
    var rfc5751 = new His.Context(RfcRule: His.RfcRule.Rfc5751SmimeLineEnding);
    AssertEqual<string?>("SignedMessageRule", CtxTag(rfc5751, new[] { 0x61, 0x0A, 0x62 }), "his rfc5751 bare-lf tag");
    AssertSequence(new[] { 1 }, CtxPos(rfc5751, new[] { 0x61, 0x0A, 0x62 }), "his rfc5751 bare-lf pos");

    // auditLogReinterpretation.
    var audit = new His.Context(AsWritten: new[] { 0x61, 0x62, 0x63 });
    AssertEqual<string?>("AuditLogReinterpretation", CtxTag(audit, new[] { 0x61, 0x62, 0x64 }), "his audit tag");
    AssertSequence(new[] { 2 }, CtxPos(audit, new[] { 0x61, 0x62, 0x64 }), "his audit pos");
    AssertEqual<string?>(null, CtxTag(audit, new[] { 0x61, 0x62, 0x63 }), "his audit identical clear");

    // webhookSignatureDrift.
    var webhook = new His.Context(ServerBytes: new[] { 0x61, 0x62, 0x64 });
    AssertEqual<string?>("WebhookSignatureDrift", CtxTag(webhook, new[] { 0x61, 0x62, 0x63 }), "his webhook tag");
    AssertSequence(new[] { 2 }, CtxPos(webhook, new[] { 0x61, 0x62, 0x63 }), "his webhook pos");
    AssertEqual<string?>(null, CtxTag(new His.Context(ServerBytes: new[] { 0x61, 0x62, 0x63 }), new[] { 0x61, 0x62, 0x63 }),
        "his webhook match clear");

    // Cross-probe priority vectors.
    var encOverRfc = new His.Context(DeclaredEncoding: "utf-16", RfcRule: His.RfcRule.Pgp9580LineEnding);
    AssertEqual<string?>("EncodingMismatch", CtxTag(encOverRfc, new[] { 0x0065, 0x0301, 0x0A }), "his encoding-over-rfc priority");
    var webhookOverAudit = new His.Context(AsWritten: new[] { 0x61, 0x62, 0x66 }, ServerBytes: new[] { 0x61, 0x62, 0x65 });
    AssertEqual<string?>("WebhookSignatureDrift", CtxTag(webhookOverAudit, new[] { 0x61, 0x62, 0x63 }), "his webhook-over-audit priority");
    AssertEqual<string?>("SignedMessageRule", CtxTag(pgp4880, new[] { 0x61, 0x20 }), "his rfc-over-trailing priority");

    // Empty context is the identity of Detect.
    var bare = Security.HashInputStability.Detect(new[] { 0x61, 0x62, 0x63 });
    var withDefault = Security.HashInputStability.DetectWithContext(His.Context.Default, new[] { 0x61, 0x62, 0x63 });
    AssertEqual(bare.Classify.Tag, withDefault.Classify.Tag, "his default-context tag matches detect");
    AssertEqual(bare.StableSize, withDefault.StableSize, "his default-context stable-size matches detect");

    // §4 hash_stable spot checks.
    AssertSequence(System.Array.Empty<int>(), Security.HashInputStability.HashStable(System.Array.Empty<int>()), "his stable empty");
    AssertSequence(new[] { 0x61, 0x62, 0x63 }, Security.HashInputStability.HashStable(new[] { 0x61, 0x62, 0x63 }), "his stable ascii");
    AssertSequence(new[] { 0x61 }, Security.HashInputStability.HashStable(new[] { 0x61, 0x20 }), "his stable strip space");
    AssertSequence(new[] { 0x61 }, Security.HashInputStability.HashStable(new[] { 0x61, 0x0D, 0x0A }), "his stable strip crlf");
    AssertSequence(new[] { 0x00E9 }, Security.HashInputStability.HashStable(new[] { 0x0065, 0x0301 }), "his stable compose nfc");
    AssertSequence(new[] { 0x61, 0x00A0 }, Security.HashInputStability.HashStable(new[] { 0x61, 0x00A0 }), "his stable keep nbsp");

    // RfcRule tag round-trip.
    foreach (var rule in new[]
    {
        His.RfcRule.Pgp4880TrailingWhitespace,
        His.RfcRule.Pgp9580LineEnding,
        His.RfcRule.Rfc8785NfcRequirement,
        His.RfcRule.Rfc8259ControlChar,
        His.RfcRule.Rfc7515JwsBase64Url,
        His.RfcRule.Rfc6376DkimRelaxed,
        His.RfcRule.Rfc5751SmimeLineEnding,
    })
    {
        AssertEqual<His.RfcRule?>(rule, Security.HashInputStability.FromTag(Security.HashInputStability.Tag(rule)), $"his rfc-rule roundtrip {rule}");
    }
    AssertEqual<His.RfcRule?>(null, Security.HashInputStability.FromTag("nope"), "his rfc-rule unknown tag");

    Console.WriteLine("clean: .NET hash-input-stability 21-vector context spot-check passes");
}

// Ground truth: the shared context-free detector fixture
// fixtures/security/detectors/stream_safe_violation.json, run through
// Security.StreamSafeViolation.Detect. Each case's required_findings is the
// fully-qualified reason code
// (unicode.security.F.stream-safe-violation.<tag>); an empty list means the
// input must classify Clear. Mirrors the Rust port's detect spot checks.
static void TestStreamSafeViolationFixture()
{
    using var detector = LoadFixture("detectors/stream_safe_violation.json");
    AssertEqual(1, detector.RootElement.GetProperty("schema").GetInt32(), "stream-safe-violation schema");
    AssertEqual("stream-safe-violation", String(detector.RootElement, "family"), "stream-safe-violation family");
    var cases = 0;
    foreach (var entry in detector.RootElement.GetProperty("cases").EnumerateArray())
    {
        var name = String(entry, "name");
        var input = Ints(entry.GetProperty("input"));
        var verdict = Security.StreamSafeViolation.Detect(input);
        var required = Strings(entry.GetProperty("required_findings")).ToList();
        if (required.Count == 0)
        {
            AssertTrue(verdict.Classify.IsClear, $"stream-safe-violation {name}: expected clear, got {verdict.Classify.Tag}");
        }
        else
        {
            foreach (var code in required)
            {
                AssertEqual<string?>(code, verdict.Classify.ReasonCode, $"stream-safe-violation {name}: reason code");
            }
        }
        cases++;
    }
    Console.WriteLine($"clean: .NET stream-safe-violation {cases}-case shared-fixture detect passes");
}

// The strict > 30 boundary and the run-inventory summaries, mirroring the Rust
// port's detect_thirty_marks_clear / detect_thirtyone_marks_hazard tests. "a"
// (CCC = 0, a starter) followed by n combining acute accents U+0301 (CCC = 230,
// non-starters): 30 stays clear under strict >, 31 fires StreamSafeOverrun with
// firstOverrun = (1, 31) and positions [1].
static void TestStreamSafeViolationBoundary()
{
    const int acute = 0x0301;
    List<int> APlusMarks(int n)
    {
        var v = new List<int> { 0x61 };
        for (var i = 0; i < n; i++) v.Add(acute);
        return v;
    }

    var thirty = Security.StreamSafeViolation.Detect(APlusMarks(30));
    AssertTrue(thirty.Classify.IsClear, "stream-safe 30-marks clear");
    AssertEqual<string?>(null, thirty.Classify.Tag, "stream-safe 30-marks tag");
    AssertEqual(30, thirty.MaxRunLength, "stream-safe 30-marks max-run");
    AssertEqual(0, thirty.OverrunCountValue, "stream-safe 30-marks overrun-count");
    AssertEqual(30, thirty.TotalNonStartersValue, "stream-safe 30-marks total");

    var thirtyOne = Security.StreamSafeViolation.Detect(APlusMarks(31));
    AssertTrue(!thirtyOne.Classify.IsClear, "stream-safe 31-marks hazard");
    AssertEqual<string?>("StreamSafeOverrun", thirtyOne.Classify.Tag, "stream-safe 31-marks tag");
    AssertSequence(new[] { 1 }, thirtyOne.Classify.Positions, "stream-safe 31-marks pos");
    AssertEqual<string?>("unicode.security.F.stream-safe-violation.StreamSafeOverrun", thirtyOne.Classify.ReasonCode, "stream-safe 31-marks reason code");
    var overrun = thirtyOne.Classify as Security.StreamSafeViolation.Hazard;
    AssertTrue(overrun is not null, "stream-safe 31-marks hazard shape");
    var sub = overrun!.Sub as Security.StreamSafeViolation.StreamSafeOverrun;
    AssertTrue(sub is not null, "stream-safe 31-marks sub-threat shape");
    AssertEqual(1, sub!.BasePos, "stream-safe 31-marks base-pos");
    AssertEqual(31, sub.RunLen, "stream-safe 31-marks run-len");
    AssertEqual(31, thirtyOne.MaxRunLength, "stream-safe 31-marks max-run");
    AssertEqual(1, thirtyOne.OverrunCountValue, "stream-safe 31-marks overrun-count");
    AssertEqual(31, thirtyOne.TotalNonStartersValue, "stream-safe 31-marks total");

    Console.WriteLine("clean: .NET stream-safe-violation 30/31 boundary + run-inventory spot-check passes");
}

// Ground truth: the shared context-free detector fixture
// detectors/case_expansion_mismatch.json, run through
// Security.CaseExpansionMismatch.Detect. Each case's required_findings is the
// fully-qualified reason code
// (unicode.security.F.case-expansion-mismatch.<tag>); an empty list means the
// input must classify Clear. Mirrors the Rust port's detect spot checks.
static void TestCaseExpansionMismatchFixture()
{
    using var detector = LoadFixture("detectors/case_expansion_mismatch.json");
    AssertEqual(1, detector.RootElement.GetProperty("schema").GetInt32(), "case-expansion-mismatch schema");
    AssertEqual("case-expansion-mismatch", String(detector.RootElement, "family"), "case-expansion-mismatch family");
    var cases = 0;
    foreach (var entry in detector.RootElement.GetProperty("cases").EnumerateArray())
    {
        var name = String(entry, "name");
        var input = Ints(entry.GetProperty("input"));
        var verdict = Security.CaseExpansionMismatch.Detect(input);
        var required = Strings(entry.GetProperty("required_findings")).ToList();
        if (required.Count == 0)
        {
            AssertTrue(verdict.Classify.IsClear, $"case-expansion-mismatch {name}: expected clear, got {verdict.Classify.Tag}");
        }
        else
        {
            foreach (var code in required)
            {
                AssertEqual<string?>(code, verdict.Classify.ReasonCode, $"case-expansion-mismatch {name}: reason code");
            }
        }
        cases++;
    }
    Console.WriteLine($"clean: .NET case-expansion-mismatch {cases}-case shared-fixture detect passes");
}

// The Rust port's detect spot checks: empty / "Hello" ASCII clear; ß U+00DF →
// UpperExpansion (SS, len 2); ﬁ U+FB01 → UpperExpansion (FI); ﬃ U+FB03 →
// UpperExpansion with maxExpansionLen 3 (FFI); İ U+0130 → LowerExpansion (the
// default fold i + U+0307, reached only when no upper expansion fires); and the
// mid-string position case [0x61, 0x00DF], whose upper expansion is reported at
// position 1.
static void TestCaseExpansionMismatchSpotChecks()
{
    string? Tag(int[] input) => Security.CaseExpansionMismatch.Detect(input).Classify.Tag;

    var empty = Security.CaseExpansionMismatch.Detect(System.Array.Empty<int>());
    AssertTrue(empty.Classify.IsClear, "case-expansion empty clear");
    AssertEqual(0, empty.MaxExpansionLenValue, "case-expansion empty max-len");

    var hello = Security.CaseExpansionMismatch.Detect(new[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F });
    AssertTrue(hello.Classify.IsClear, "case-expansion hello clear");
    AssertEqual(1, hello.MaxExpansionLenValue, "case-expansion hello max-len");

    var sharpS = Security.CaseExpansionMismatch.Detect(new[] { 0x00DF });
    AssertEqual<string?>("UpperExpansion", sharpS.Classify.Tag, "case-expansion sharp-s tag");
    AssertSequence(new[] { 0 }, sharpS.Classify.Positions, "case-expansion sharp-s pos");
    AssertEqual(1, sharpS.UpperExpansionCountValue, "case-expansion sharp-s upper-count");
    AssertEqual(2, sharpS.MaxExpansionLenValue, "case-expansion sharp-s max-len");

    AssertEqual<string?>("UpperExpansion", Tag(new[] { 0xFB01 }), "case-expansion fi tag");

    var ffi = Security.CaseExpansionMismatch.Detect(new[] { 0xFB03 });
    AssertEqual<string?>("UpperExpansion", ffi.Classify.Tag, "case-expansion ffi tag");
    AssertEqual(3, ffi.MaxExpansionLenValue, "case-expansion ffi max-len");

    var dottedI = Security.CaseExpansionMismatch.Detect(new[] { 0x0130 });
    AssertEqual<string?>("LowerExpansion", dottedI.Classify.Tag, "case-expansion dotted-I tag");
    AssertEqual(1, dottedI.LowerExpansionCountValue, "case-expansion dotted-I lower-count");

    var midString = Security.CaseExpansionMismatch.Detect(new[] { 0x61, 0x00DF });
    AssertSequence(new[] { 1 }, midString.Classify.Positions, "case-expansion mid-string pos");
    AssertEqual<string?>("UpperExpansion", midString.Classify.Tag, "case-expansion mid-string tag");

    AssertEqual<string?>(
        "unicode.security.F.case-expansion-mismatch.UpperExpansion",
        sharpS.Classify.ReasonCode, "case-expansion sharp-s reason code");
    AssertEqual<string?>(
        "unicode.security.F.case-expansion-mismatch.LowerExpansion",
        dottedI.Classify.ReasonCode, "case-expansion dotted-I reason code");

    Console.WriteLine("clean: .NET case-expansion-mismatch detect spot-check passes");
}

// Ground truth: the shared context-free detector fixture
// fixtures/security/detectors/ai_watermark_detectability.json, run through
// Security.AiWatermarkDetectability.Detect (the empty-context wrapper). Each
// case's required_findings is the fully-qualified reason code
// (unicode.security.K.ai-watermark-detectability.<tag>); an empty list means
// the input must classify Clear. Mirrors the Rust port's §6/§7 detect spot
// checks.
static void TestAiWatermarkDetectabilityFixture()
{
    using var detector = LoadFixture("detectors/ai_watermark_detectability.json");
    AssertEqual(1, detector.RootElement.GetProperty("schema").GetInt32(), "ai-watermark-detectability schema");
    AssertEqual("ai-watermark-detectability", String(detector.RootElement, "family"), "ai-watermark-detectability family");
    var cases = 0;
    foreach (var entry in detector.RootElement.GetProperty("cases").EnumerateArray())
    {
        var name = String(entry, "name");
        var input = Ints(entry.GetProperty("input"));
        var verdict = Awd.Detect(input);
        var required = Strings(entry.GetProperty("required_findings")).ToList();
        if (required.Count == 0)
        {
            AssertTrue(verdict.Classify.IsClear, $"ai-watermark-detectability {name}: expected clear, got {verdict.Classify.Tag}");
        }
        else
        {
            foreach (var code in required)
            {
                AssertEqual<string?>(code, verdict.Classify.ReasonCode, $"ai-watermark-detectability {name}: reason code");
            }
        }
        cases++;
    }
    Console.WriteLine($"clean: .NET ai-watermark-detectability {cases}-case shared-fixture detect passes");
}

// Ground truth: the Context-tolerance vectors and every probe/priority/cue-class
// spot-check theorem in the Rust port's ai_watermark_detectability.rs test
// module (the shared detector-fixture schema cannot express a Context, so the
// tolerance vectors live only in-source). Detect(input).Classify.Tag maps each
// theorem's classification to one assertion.
static void TestAiWatermarkDetectabilityContextVectors()
{
    string? Tag(int[] input) => Awd.Detect(input).Classify.Tag;

    // §4 detect spot checks.
    AssertEqual<string?>(null, Tag(System.Array.Empty<int>()), "awd empty clear");
    AssertEqual<string?>(null, Tag(new[] { 0x61, 0x62, 0x63 }), "awd ascii clear");
    AssertEqual<string?>(null, Tag(new[] { 0x4E2D, 0x6587 }), "awd han clear");

    var nnbsp = Awd.Detect(new[] { 0x61, 0x202F, 0x62 });
    AssertEqual<string?>("NnbspBoundary", nnbsp.Classify.Tag, "awd nnbsp tag");
    AssertSequence(new[] { 1 }, nnbsp.Classify.Positions, "awd nnbsp pos");
    AssertEqual(1, nnbsp.MarkerCount, "awd nnbsp count");

    var vsPlain = Awd.Detect(new[] { 0x61, 0xFE0F, 0x62 });
    AssertEqual<string?>("VariationSelectorCarrier", vsPlain.Classify.Tag, "awd vs-plain tag");
    AssertEqual(1, vsPlain.MarkerCount, "awd vs-plain count");
    AssertEqual<string?>(null, Tag(new[] { 0x1F600, 0xFE0F }), "awd vs-after-emoji clear");

    var zwjPlain = Awd.Detect(new[] { 0x61, 0x200D, 0x62 });
    AssertEqual<string?>("ZwjNonEmoji", zwjPlain.Classify.Tag, "awd zwj-plain tag");
    AssertEqual(1, zwjPlain.MarkerCount, "awd zwj-plain count");
    AssertEqual<string?>(null, Tag(new[] { 0x1F469, 0x200D, 0x1F52C }), "awd zwj-emoji-seq clear");

    AssertEqual<string?>("DefaultIgnorableCarrier", Tag(new[] { 0x61, 0x00AD, 0x62 }), "awd soft-hyphen tag");
    AssertEqual<string?>("DefaultIgnorableCarrier", Tag(new[] { 0x61, 0x200B, 0x62 }), "awd zwsp tag");

    var multiNnbsp = Awd.Detect(new[] { 0x61, 0x202F, 0x62, 0x202F, 0x63 });
    AssertEqual<string?>("NnbspBoundary", multiNnbsp.Classify.Tag, "awd multi-nnbsp tag");
    AssertEqual(2, multiNnbsp.MarkerCount, "awd multi-nnbsp count");
    AssertSequence(new[] { 1, 3 }, multiNnbsp.Classify.Positions, "awd multi-nnbsp pos");

    // §7 refinement-probe spot checks.
    var adv = Awd.Detect(new[] { 0x61, 0x202F, 0x62, 0x202F, 0x63, 0x202F, 0x64 });
    AssertEqual<string?>("Adversarial", adv.Classify.Tag, "awd adversarial tag");
    AssertEqual(3, adv.MarkerCount, "awd adversarial count");
    AssertEqual<string?>("NnbspBoundary", Tag(new[] { 0x61, 0x202F, 0x62, 0x202F, 0x63 }), "awd nnbsp-below-adversarial");

    var gpt5 = Awd.Detect(new[] { 0x61, 0x200B, 0x62, 0x200B, 0x63, 0x200B, 0x64 });
    AssertEqual<string?>("Gpt5ZwspModulo", gpt5.Classify.Tag, "awd gpt5-zwsp-modulo tag");
    AssertEqual(3, gpt5.MarkerCount, "awd gpt5-zwsp-modulo count");
    AssertEqual<string?>("DefaultIgnorableCarrier", Tag(new[] { 0x61, 0x200B, 0x62, 0x200B, 0x63 }), "awd zwsp-below-modulo");

    var smart = Awd.Detect(new[] { 0x201C, 0x61, 0x62, 0x63, 0x201D });
    AssertEqual<string?>("SmartQuoteAlternation", smart.Classify.Tag, "awd smart-quote tag");
    AssertEqual(2, smart.MarkerCount, "awd smart-quote count");
    AssertEqual<string?>(null, Tag(new[] { 0x201C, 0x61, 0x22, 0x201D }), "awd smart-quote-with-straight clear");

    var emDash = Awd.Detect(new[] { 0x61, 0x62, 0x20, 0x2014, 0x20, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66 });
    AssertEqual<string?>("EmDashPattern", emDash.Classify.Tag, "awd em-dash tag");
    AssertEqual(2, emDash.MarkerCount, "awd em-dash count");
    AssertEqual<string?>(null, Tag(new[] { 0x61, 0x62, 0x2D, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66 }), "awd em-dash-with-hyphen clear");

    var delve = Awd.Detect(new[] { 0x64, 0x65, 0x6C, 0x76, 0x65 });
    AssertEqual<string?>("StatisticalTokenChoice", delve.Classify.Tag, "awd statistical-delve tag");
    AssertEqual(1, delve.MarkerCount, "awd statistical-delve count");
    var moreover = Awd.Detect(new[] { 0x3B, 0x20, 0x6D, 0x6F, 0x72, 0x65, 0x6F, 0x76, 0x65, 0x72, 0x2C, 0x20 });
    AssertEqual<string?>("StatisticalTokenChoice", moreover.Classify.Tag, "awd statistical-moreover tag");
    AssertSequence(new[] { 2 }, moreover.Classify.Positions, "awd statistical-moreover pos");

    // Unknown priority (>= 2 distinct invisible categories).
    var unkNnbspDi = Awd.Detect(new[] { 0x61, 0x202F, 0x00AD, 0x62 });
    AssertEqual<string?>("Unknown", unkNnbspDi.Classify.Tag, "awd unknown-nnbsp-di tag");
    AssertEqual(2, unkNnbspDi.MarkerCount, "awd unknown-nnbsp-di count");
    var unkVsZwj = Awd.Detect(new[] { 0x61, 0xFE0F, 0x200D, 0x62 });
    AssertEqual<string?>("Unknown", unkVsZwj.Classify.Tag, "awd unknown-vs-zwj tag");
    AssertEqual(2, unkVsZwj.MarkerCount, "awd unknown-vs-zwj count");
    var unkNnbspZwj = Awd.Detect(new[] { 0x61, 0x202F, 0x200D, 0x62 });
    AssertEqual<string?>("Unknown", unkNnbspZwj.Classify.Tag, "awd unknown-nnbsp-zwj tag");
    AssertEqual(2, unkNnbspZwj.MarkerCount, "awd unknown-nnbsp-zwj count");
    AssertEqual<string?>("NnbspBoundary", Tag(new[] { 0x61, 0x202F, 0x62 }), "awd single-category-skips-unknown");

    // §8 tolerance-parameterised probes (the two Context vectors).
    var jitter = new[] { 0x61, 0x200B, 0x62, 0x200B, 0x63, 0x64, 0x200B, 0x65 };
    AssertEqual<string?>("DefaultIgnorableCarrier", Tag(jitter), "awd zwsp-jittered-strict clear");
    var tolerant = new Awd.Context(ZwspModuloTolerance: 1);
    AssertEqual<string?>("Gpt5ZwspModulo", Awd.DetectWithContext(tolerant, jitter).Classify.Tag, "awd zwsp-jittered-tolerant fires");

    var bare = Awd.Detect(new[] { 0x61, 0x202F, 0x62 });
    var withDefault = Awd.DetectWithContext(Awd.Context.Default, new[] { 0x61, 0x202F, 0x62 });
    AssertEqual(bare.Classify.Tag, withDefault.Classify.Tag, "awd default-context matches detect");

    // §7 cue-class coverage: every CueClass is probed by some sub-threat.
    var cueClasses = new[] { Awd.CueClass.GreenListBias, Awd.CueClass.PseudorandomSeq, Awd.CueClass.SemanticDrift };
    var probed = new Awd.SubThreat[]
    {
        new Awd.NnbspBoundary(0),
        new Awd.VariationSelectorCarrier(0),
        new Awd.ZwjNonEmoji(0),
        new Awd.DefaultIgnorableCarrier(0),
        new Awd.Gpt5ZwspModulo(0),
        new Awd.EmDashPattern(0),
        new Awd.SmartQuoteAlternation(0),
        new Awd.StatisticalTokenChoice(0),
        new Awd.Adversarial("", 0),
    };
    foreach (var cls in cueClasses)
    {
        AssertTrue(probed.Any(st => st.Cue == cls), $"awd cue class {cls} is probed");
    }
    AssertEqual<Awd.CueClass?>(null, new Awd.Unknown(0).Cue, "awd unknown has no cue class");

    Console.WriteLine("clean: .NET ai-watermark-detectability 34-vector context spot-check passes");
}

// Ground truth: the shared context-free detector fixture
// fixtures/security/detectors/emoji_zwj_integrity.json, run through
// Security.EmojiZwjIntegrity.Detect. Each case's required_findings is the
// fully-qualified reason code
// (unicode.security.I.emoji-zwj-integrity.<tag>); an empty list means the input
// must classify Clear. Mirrors the Rust port's §5 detect spot checks.
static void TestEmojiZwjIntegrityFixture()
{
    using var detector = LoadFixture("detectors/emoji_zwj_integrity.json");
    AssertEqual(1, detector.RootElement.GetProperty("schema").GetInt32(), "emoji-zwj-integrity schema");
    AssertEqual("emoji-zwj-integrity", String(detector.RootElement, "family"), "emoji-zwj-integrity family");
    var cases = 0;
    foreach (var entry in detector.RootElement.GetProperty("cases").EnumerateArray())
    {
        var name = String(entry, "name");
        var input = Ints(entry.GetProperty("input"));
        var verdict = Ezwj.Detect(input);
        var required = Strings(entry.GetProperty("required_findings")).ToList();
        if (required.Count == 0)
        {
            AssertTrue(verdict.Classify.IsClear, $"emoji-zwj-integrity {name}: expected clear, got {verdict.Classify.Tag}");
        }
        else
        {
            foreach (var code in required)
            {
                AssertEqual<string?>(code, verdict.Classify.ReasonCode, $"emoji-zwj-integrity {name}: reason code");
            }
        }
        cases++;
    }
    Console.WriteLine($"clean: .NET emoji-zwj-integrity {cases}-case shared-fixture detect passes");
}

// Ground truth: the data-layer sanity, §5 detect spot-check, and structural
// tests in the Rust port's emoji_zwj_integrity.rs test module. The registered
// RGI set and the ZWJ alphabet are parsed from the bundled
// Data/emoji-zwj-sequences.txt; the emoji-modifier range is inlined
// (U+1F3FB..U+1F3FF), never a host emoji / normalization library.
static void TestEmojiZwjIntegritySpotChecks()
{
    string? Tag(int[] input) => Ezwj.Detect(input).Classify.Tag;

    // ── data-layer sanity ────────────────────────────────────────────────
    AssertTrue(Ezwj.IsEmojiModifier(0x1F3FB), "ezwj modifier lo");
    AssertTrue(Ezwj.IsEmojiModifier(0x1F3FF), "ezwj modifier hi");
    AssertTrue(!Ezwj.IsEmojiModifier(0x1F3FA), "ezwj modifier below");
    AssertTrue(!Ezwj.IsEmojiModifier(0x1F600), "ezwj modifier grinning");

    AssertTrue(Ezwj.IsEmojiTarget(0x2764), "ezwj alphabet heart");
    AssertTrue(Ezwj.IsEmojiTarget(0x1F468), "ezwj alphabet man");
    AssertTrue(!Ezwj.IsEmojiTarget(0x1F600), "ezwj alphabet grinning");
    AssertTrue(!Ezwj.IsEmojiTarget(Ezwj.Zwj), "ezwj alphabet excludes joiner");

    AssertTrue(Ezwj.IsRegisteredZwjSequence(new[] { 0x1F468, 0x200D, 0x1F4BB }), "ezwj registered man-technologist");
    AssertTrue(!Ezwj.IsRegisteredZwjSequence(new[] { 0x1F468, 0x200D, 0x1F469 }), "ezwj unregistered man-woman");

    // ── §5 detect spot checks (one per Lean theorem) ─────────────────────
    var empty = Ezwj.Detect(System.Array.Empty<int>());
    AssertTrue(empty.Classify.IsClear, "ezwj empty clear");
    AssertEqual<string?>(null, empty.Classify.Tag, "ezwj empty tag");
    AssertSequence(System.Array.Empty<int>(), empty.ZwjPositions, "ezwj empty zwj-positions");
    AssertEqual(0, empty.ChainLength, "ezwj empty chain-length");
    AssertEqual(0, empty.SkinToneCount, "ezwj empty skin-tone-count");

    AssertTrue(Ezwj.Detect(new[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F }).Classify.IsClear, "ezwj ascii clear");
    AssertTrue(Ezwj.Detect(new[] { 0x1F600 }).Classify.IsClear, "ezwj plain-emoji clear");

    var oneSkin = Ezwj.Detect(new[] { 0x1F44B, 0x1F3FB });
    AssertTrue(oneSkin.Classify.IsClear, "ezwj one-skintone clear");
    AssertEqual(1, oneSkin.SkinToneCount, "ezwj one-skintone count");

    var family = Ezwj.Detect(new[] { 0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466 });
    AssertTrue(family.Classify.IsClear, "ezwj family-rgi clear");
    AssertTrue(family.IsRegisteredRgi, "ezwj family-rgi registered");

    var dbl = Ezwj.Detect(new[] { 0x1F600, 0x200D, 0x200D, 0x1F600 });
    AssertEqual<string?>("DoubleZWJ", dbl.Classify.Tag, "ezwj double-zwj tag");
    AssertSequence(new[] { 1 }, dbl.Classify.Positions, "ezwj double-zwj pos");

    AssertEqual<string?>("NonEmojiInjection", Tag(new[] { 0x1F600, 0x200D, 0x0061 }), "ezwj non-emoji-injection tag");

    var overflow = Ezwj.Detect(new[] { 0x1F44B, 0x1F3FB, 0x1F3FC, 0x1F3FD, 0x1F3FE, 0x1F3FF });
    AssertEqual<string?>("SkinToneOverflow", overflow.Classify.Tag, "ezwj skin-tone-overflow tag");
    AssertEqual(5, overflow.SkinToneCount, "ezwj skin-tone-overflow count");

    AssertTrue(Ezwj.Detect(new[] { 0x1F468, 0x200D, 0x1F4BB }).Classify.IsClear, "ezwj man-laptop-registered clear");
    AssertEqual<string?>("UnregisteredSequence", Tag(new[] { 0x1F468, 0x200D, 0x1F469 }), "ezwj unregistered tag");
    AssertEqual<string?>("NonEmojiInjection", Tag(new[] { 0x1F600, 0x200D, 0x1F4BB }), "ezwj grinning-laptop tag");

    // ── structural checks (follow from the priority ladder) ──────────────
    // 9 men joined by 8 ZWJs = 17 codepoints (> MaxRgiLength).
    var over = new List<int>();
    for (var i = 0; i < 9; i++)
    {
        if (i > 0) over.Add(0x200D);
        over.Add(0x1F468);
    }
    AssertEqual(17, over.Count, "ezwj over-length input size");
    var overVerdict = Ezwj.Detect(over);
    AssertEqual<string?>("OverLength", overVerdict.Classify.Tag, "ezwj over-length tag");
    var overSub = (overVerdict.Classify as Ezwj.Hazard)?.Sub as Ezwj.OverLength;
    AssertTrue(overSub is not null, "ezwj over-length sub shape");
    AssertEqual(17, overSub!.Length, "ezwj over-length length");
    AssertEqual(16, overSub.MaxLength, "ezwj over-length max-length");

    var trailing = Ezwj.Detect(new[] { 0x1F468, 0x200D });
    AssertEqual<string?>("NonEmojiInjection", trailing.Classify.Tag, "ezwj trailing-zwj tag");
    AssertSequence(new[] { 1 }, trailing.Classify.Positions, "ezwj trailing-zwj pos");

    AssertEqual<string?>("DoubleZWJ", Tag(new[] { 0x1F468, 0x200D, 0x200D, 0x1F466 }), "ezwj double-beats-unregistered tag");

    Console.WriteLine("clean: .NET emoji-zwj-integrity data + detect + structural spot-check passes");
}

// Ground truth: the shared context-free detector fixture
// fixtures/security/detectors/skin_tone_variation_forgery.json, run through
// Security.SkinToneVariationForgery.Detect. Each case's required_findings is the
// fully-qualified reason code
// (unicode.security.I.skin-tone-variation-forgery.<tag>); an empty list means
// the input must classify Clear. Mirrors the Rust port's §4 detect spot checks.
static void TestSkinToneVariationForgeryFixture()
{
    using var detector = LoadFixture("detectors/skin_tone_variation_forgery.json");
    AssertEqual(1, detector.RootElement.GetProperty("schema").GetInt32(), "skin-tone-variation-forgery schema");
    AssertEqual("skin-tone-variation-forgery", String(detector.RootElement, "family"), "skin-tone-variation-forgery family");
    var cases = 0;
    foreach (var entry in detector.RootElement.GetProperty("cases").EnumerateArray())
    {
        var name = String(entry, "name");
        var input = Ints(entry.GetProperty("input"));
        var verdict = Stvf.Detect(input);
        var required = Strings(entry.GetProperty("required_findings")).ToList();
        if (required.Count == 0)
        {
            AssertTrue(verdict.Classify.IsClear, $"skin-tone-variation-forgery {name}: expected clear, got {verdict.Classify.Tag}");
        }
        else
        {
            foreach (var code in required)
            {
                AssertEqual<string?>(code, verdict.Classify.ReasonCode, $"skin-tone-variation-forgery {name}: reason code");
            }
        }
        cases++;
    }
    Console.WriteLine($"clean: .NET skin-tone-variation-forgery {cases}-case shared-fixture detect passes");
}

// Ground truth: the data-layer sanity and detect spot-check theorems in the Rust
// port's skin_tone_variation_forgery.rs test module. The Emoji_Modifier_Base and
// Emoji_Presentation intervals are parsed from the bundled Data/emoji-data.txt;
// the skin-tone modifier predicate reuses the port's own
// EmojiZwjIntegrity.IsEmojiModifier (U+1F3FB..U+1F3FF), never a host emoji /
// normalization library.
static void TestSkinToneVariationForgerySpotChecks()
{
    string? Tag(int[] input) => Stvf.Detect(input).Classify.Tag;

    // ── data-layer sanity ────────────────────────────────────────────────
    AssertTrue(Stvf.IsSkinTone(0x1F3FB), "stvf skin-tone lo");
    AssertTrue(Stvf.IsSkinTone(0x1F3FF), "stvf skin-tone hi");
    AssertTrue(!Stvf.IsSkinTone(0x1F600), "stvf skin-tone grinning");
    AssertTrue(Stvf.IsSkinToneBase(0x1F44B), "stvf modifier-base waving-hand");
    AssertTrue(!Stvf.IsSkinToneBase(0x0041), "stvf modifier-base ascii-A");
    AssertTrue(!Stvf.IsSkinToneBase(0x1F600), "stvf modifier-base grinning");
    AssertTrue(Stvf.IsEmojiPresentation(0x1F600), "stvf emoji-presentation grinning");
    AssertTrue(!Stvf.IsEmojiPresentation(0x0041), "stvf emoji-presentation ascii-A");
    AssertTrue(Stvf.IsVs15(0xFE0E), "stvf vs15");
    AssertTrue(Stvf.IsVs16(0xFE0F), "stvf vs16");

    // ── detect spot checks (one per Lean theorem) ────────────────────────
    var empty = Stvf.Detect(System.Array.Empty<int>());
    AssertTrue(empty.Classify.IsClear, "stvf empty clear");
    AssertEqual(0, empty.SkinToneCount, "stvf empty skin-tone-count");
    AssertEqual(0, empty.VariationSelector15Count, "stvf empty vs15-count");
    AssertEqual(0, empty.VariationSelector16Count, "stvf empty vs16-count");

    AssertTrue(Stvf.Detect(new[] { 0x48, 0x65 }).Classify.IsClear, "stvf ascii clear");
    AssertTrue(Stvf.Detect(new[] { 0x1F600 }).Classify.IsClear, "stvf plain-emoji clear");

    var wave = Stvf.Detect(new[] { 0x1F44B, 0x1F3FB });
    AssertTrue(wave.Classify.IsClear, "stvf wave-skin-tone clear");
    AssertEqual(1, wave.SkinToneCount, "stvf wave-skin-tone count");

    var stacked = Stvf.Detect(new[] { 0x1F44B, 0x1F3FB, 0x1F3FC });
    AssertEqual<string?>("StackedSkinTones", stacked.Classify.Tag, "stvf stacked tag");
    AssertSequence(new[] { 1, 2 }, stacked.Classify.Positions, "stvf stacked pos");
    var stackedSub = (stacked.Classify as Stvf.Hazard)?.Sub as Stvf.StackedSkinTones;
    AssertTrue(stackedSub is not null, "stvf stacked sub shape");
    AssertEqual(0, stackedSub!.BasePos, "stvf stacked base-pos");
    AssertSequence(new[] { 0x1F3FB, 0x1F3FC }, stackedSub.Modifiers, "stvf stacked modifiers");

    var invalidAscii = Stvf.Detect(new[] { 0x0041, 0x1F3FB });
    AssertEqual<string?>("InvalidSkinToneTarget", invalidAscii.Classify.Tag, "stvf invalid-ascii tag");
    AssertSequence(new[] { 1 }, invalidAscii.Classify.Positions, "stvf invalid-ascii pos");
    var invalidSub = (invalidAscii.Classify as Stvf.Hazard)?.Sub as Stvf.InvalidSkinToneTarget;
    AssertTrue(invalidSub is not null, "stvf invalid-ascii sub shape");
    AssertEqual(0, invalidSub!.BasePos, "stvf invalid-ascii base-pos");
    AssertEqual(0x0041, invalidSub.BaseCp, "stvf invalid-ascii base-cp");
    AssertEqual(0x1F3FB, invalidSub.ModifierCp, "stvf invalid-ascii modifier-cp");

    AssertEqual<string?>("InvalidSkinToneTarget", Tag(new[] { 0x1F600, 0x1F3FB }), "stvf invalid-smiley tag");

    var forced = Stvf.Detect(new[] { 0x1F600, 0xFE0E });
    AssertEqual<string?>("ForcedTextStyle", forced.Classify.Tag, "stvf forced-text-style tag");
    AssertSequence(new[] { 1 }, forced.Classify.Positions, "stvf forced-text-style pos");
    AssertEqual(1, forced.VariationSelector15Count, "stvf forced-text-style vs15-count");

    // ── reason-code composition (both stable) ────────────────────────────
    AssertEqual<string?>(
        "unicode.security.I.skin-tone-variation-forgery.StackedSkinTones",
        stacked.Classify.ReasonCode, "stvf stacked reason-code");
    AssertEqual<string?>(
        "unicode.security.I.skin-tone-variation-forgery.ForcedTextStyle",
        forced.Classify.ReasonCode, "stvf forced-text-style reason-code");

    Console.WriteLine("clean: .NET skin-tone-variation-forgery data + detect spot-check passes");
}

// Ground truth: the shared context-free detector fixture
// fixtures/security/detectors/renderer_divergence.json, run through
// Security.RendererDivergence.Detect. Each case's required_findings is the
// fully-qualified reason code
// (unicode.security.D.renderer-divergence.<tag>); an empty list means the input
// must classify Clear. Mirrors the Rust port's §5 detect spot checks.
static void TestRendererDivergenceFixture()
{
    using var detector = LoadFixture("detectors/renderer_divergence.json");
    AssertEqual(1, detector.RootElement.GetProperty("schema").GetInt32(), "renderer-divergence schema");
    AssertEqual("renderer-divergence", String(detector.RootElement, "family"), "renderer-divergence family");
    var cases = 0;
    foreach (var entry in detector.RootElement.GetProperty("cases").EnumerateArray())
    {
        var name = String(entry, "name");
        var input = Ints(entry.GetProperty("input"));
        var verdict = Rd.Detect(input);
        var required = Strings(entry.GetProperty("required_findings")).ToList();
        if (required.Count == 0)
        {
            AssertTrue(verdict.Classify.IsClear, $"renderer-divergence {name}: expected clear, got {verdict.Classify.Tag}");
        }
        else
        {
            foreach (var code in required)
            {
                AssertEqual<string?>(code, verdict.Classify.ReasonCode, $"renderer-divergence {name}: reason code");
            }
        }
        cases++;
    }
    Console.WriteLine($"clean: .NET renderer-divergence {cases}-case shared-fixture detect passes");
}

// Ground truth: the data-layer sanity, §5 detect spot-check, and structural
// priority-ladder tests in the Rust port's renderer_divergence.rs test module.
// The variation-selector set is reused from the variation-selector-payload
// detector, the grapheme Extend class from the UAX #29 segmenter, the registered
// RGI ZWJ set from the emoji-zwj-integrity detector, and the strong-bidi classes
// from the rtl-injection detector — never a host rendering / shaping library.
static void TestRendererDivergenceSpotChecks()
{
    string? Tag(int[] input) => Rd.Detect(input).Classify.Tag;

    // ── data-layer sanity (reused predicates) ────────────────────────────
    AssertTrue(Rd.IsVariationSelector(0xFE0F), "rd vs FE0F");
    AssertTrue(Rd.IsVariationSelector(0xE0100), "rd vs E0100");
    AssertTrue(!Rd.IsVariationSelector(0x0041), "rd vs non-A");
    AssertTrue(Rd.IsGraphemeExtend(0x0301), "rd extend combining-acute");
    AssertTrue(!Rd.IsGraphemeExtend(0x0061), "rd extend non-a");
    AssertTrue(Rd.IsFullwidthHalfwidth(0xFF21), "rd fullwidth A");
    AssertTrue(!Rd.IsFullwidthHalfwidth(0x0041), "rd fullwidth non-A");
    AssertTrue(Rd.IsZwj(0x200D), "rd zwj");

    // ── §5 detect spot checks (one per Lean/Rust theorem) ────────────────
    // detect_empty_clear
    AssertTrue(Rd.Detect(System.Array.Empty<int>()).Classify.IsClear, "rd empty clear");
    // detect_ascii_clear
    AssertTrue(Rd.Detect(new[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F }).Classify.IsClear, "rd ascii clear");
    // detect_han_clear
    AssertTrue(Rd.Detect(new[] { 0x4E2D, 0x6587 }).Classify.IsClear, "rd han clear");
    // detect_vs_variance
    AssertEqual<string?>("VariationSelectorVariance", Tag(new[] { 0x1F600, 0xFE0F }), "rd vs-variance tag");
    // detect_rgi_family_clear
    var rgiFamily = Rd.Detect(new[] { 0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466 });
    AssertTrue(rgiFamily.Classify.IsClear, "rd rgi-family clear");
    AssertTrue(rgiFamily.HasZwj, "rd rgi-family has-zwj");
    // detect_unregistered_zwj_variance
    AssertEqual<string?>("UnregisteredZwjVariance", Tag(new[] { 0x1F468, 0x200D, 0x1F469 }), "rd unregistered-zwj tag");
    // detect_zalgo_variance
    var zalgo = Rd.Detect(new[] { 0x0061, 0x0301, 0x0302, 0x0303, 0x0304 });
    AssertEqual<string?>("CombiningStackOverflow", zalgo.Classify.Tag, "rd zalgo tag");
    AssertSequence(new[] { 0 }, zalgo.Classify.Positions, "rd zalgo positions");
    AssertEqual(4, zalgo.CombiningCount, "rd zalgo combining-count");
    // detect_fullwidth_variance
    AssertEqual<string?>("FullwidthVariance", Tag(new[] { 0xFF21 }), "rd fullwidth tag");
    // detect_mixed_direction
    var mixed = Rd.Detect(new[] { 0x41, 0x42, 0x05D0, 0x05D1 });
    AssertEqual<string?>("MixedDirectionVariance", mixed.Classify.Tag, "rd mixed-direction tag");
    AssertTrue(mixed.StrongLtrCount > 0 && mixed.StrongRtlCount > 0, "rd mixed-direction counts");

    // ── priority-ladder structural checks ────────────────────────────────
    // A combining stack outranks a variation selector present later.
    AssertEqual<string?>(
        "CombiningStackOverflow",
        Tag(new[] { 0x0061, 0x0301, 0x0302, 0x0303, 0x0304, 0xFE0F }),
        "rd combining-stack-beats-vs");
    // Exactly three combining marks is below the stack threshold — no overflow.
    AssertTrue(
        Tag(new[] { 0x0061, 0x0301, 0x0302, 0x0303 }) != "CombiningStackOverflow",
        "rd three-marks-below-threshold");

    Console.WriteLine("clean: .NET renderer-divergence data + detect + structural spot-check passes");
}
static void TestFilenameDisguiseFixture()
{
    using var detector = LoadFixture("detectors/filename_disguise.json");
    AssertEqual(1, detector.RootElement.GetProperty("schema").GetInt32(), "filename-disguise schema");
    AssertEqual("filename-disguise", String(detector.RootElement, "family"), "filename-disguise family");
    var cases = 0;
    foreach (var entry in detector.RootElement.GetProperty("cases").EnumerateArray())
    {
        var name = String(entry, "name");
        var input = Ints(entry.GetProperty("input"));
        var verdict = Fd.Detect(input);
        var required = Strings(entry.GetProperty("required_findings")).ToList();
        if (required.Count == 0)
        {
            AssertTrue(verdict.Classify.IsClear, $"filename-disguise {name}: expected clear, got {verdict.Classify.Tag}");
        }
        else
        {
            foreach (var code in required)
            {
                AssertEqual<string?>(code, verdict.Classify.ReasonCode, $"filename-disguise {name}: reason code");
            }
        }
        cases++;
    }
    Console.WriteLine($"clean: .NET filename-disguise {cases}-case shared-fixture detect passes");
}
static void TestIdentifierFormDriftFixture()
{
    using var detector = LoadFixture("detectors/identifier_form_drift.json");
    AssertEqual(1, detector.RootElement.GetProperty("schema").GetInt32(), "identifier-form-drift schema");
    AssertEqual("identifier-form-drift", String(detector.RootElement, "family"), "identifier-form-drift family");
    var cases = 0;
    foreach (var entry in detector.RootElement.GetProperty("cases").EnumerateArray())
    {
        var name = String(entry, "name");
        var input = Ints(entry.GetProperty("input"));
        var verdict = Ifd.Detect(input);
        var required = Strings(entry.GetProperty("required_findings")).ToList();
        if (required.Count == 0)
        {
            AssertTrue(verdict.Classify.IsClear, $"identifier-form-drift {name}: expected clear, got {verdict.Classify.Tag}");
        }
        else
        {
            foreach (var code in required)
            {
                AssertEqual<string?>(code, verdict.Classify.ReasonCode, $"identifier-form-drift {name}: reason code");
            }
        }
        cases++;
    }
    Console.WriteLine($"clean: .NET identifier-form-drift {cases}-case shared-fixture detect passes");
}
static void TestIdentifierFormDriftSpotChecks()
{
    string? Tag(int[] input) => Ifd.Detect(input).Classify.Tag;

    // ── data-layer sanity (reused UTS #39 Identifier_Status + NFKD) ───────
    AssertTrue(Ifd.IsIdAllowed(0x0061), "ifd allowed lowercase-a");
    AssertTrue(Ifd.IsIdAllowed(0x03B1), "ifd allowed greek-alpha");
    AssertTrue(!Ifd.IsIdAllowed(0x1D44E), "ifd restricted math-italic-a");
    AssertTrue(!Ifd.IsIdAllowed(0xFF21), "ifd restricted fullwidth-A");
    AssertTrue(Ifd.NfkdHeadAllowed(0x1D44E), "ifd nfkd-head math-italic-a allowed (→ a)");
    AssertTrue(Ifd.NfkdHeadAllowed(0xFF21), "ifd nfkd-head fullwidth-A allowed (→ A)");

    // ── §4 detect spot checks (one per Lean/Rust theorem) ─────────────────
    // detect_empty_clear
    AssertTrue(Ifd.Detect(System.Array.Empty<int>()).Classify.IsClear, "ifd empty clear");
    // detect_ascii_clear — "Hello"; every ASCII letter is Allowed, identity NFKD.
    var hello = Ifd.Detect(new[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F });
    AssertTrue(hello.Classify.IsClear, "ifd ascii-hello clear");
    AssertEqual(0, hello.ShiftCount, "ifd ascii-hello shift-count");
    // detect_greek_alpha_clear — α is Allowed with identity NFKD.
    AssertTrue(Ifd.Detect(new[] { 0x03B1 }).Classify.IsClear, "ifd greek-alpha clear");
    // detect_math_italic_a_shift — U+1D44E Restricted, NFKD head U+0061 Allowed.
    var mia = Ifd.Detect(new[] { 0x1D44E });
    AssertEqual<string?>("IdentifierStatusShift", mia.Classify.Tag, "ifd math-italic-a tag");
    AssertSequence(new[] { 0 }, mia.Classify.Positions, "ifd math-italic-a positions");
    AssertEqual(1, mia.ShiftCount, "ifd math-italic-a shift-count");
    // detect_fullwidth_A_shift — U+FF21 Restricted, NFKD head U+0041 Allowed.
    AssertEqual<string?>("IdentifierStatusShift", Tag(new[] { 0xFF21 }), "ifd fullwidth-A tag");
    // detect_circled_A_shift — U+24B6 CIRCLED LATIN CAPITAL LETTER A → A.
    AssertEqual<string?>("IdentifierStatusShift", Tag(new[] { 0x24B6 }), "ifd circled-A tag");
    // detect_fi_ligature_shift — U+FB01 'ﬁ' ligature → f.
    AssertEqual<string?>("IdentifierStatusShift", Tag(new[] { 0xFB01 }), "ifd fi-ligature tag");
    // detect_roman_iv_shift — U+2163 ROMAN NUMERAL FOUR → I.
    AssertEqual<string?>("IdentifierStatusShift", Tag(new[] { 0x2163 }), "ifd roman-iv tag");
    // detect_reports_first_shift_position — "ab" + U+1D44E: first shift at position 2.
    var mid = Ifd.Detect(new[] { 0x61, 0x62, 0x1D44E });
    AssertSequence(new[] { 2 }, mid.Classify.Positions, "ifd mid-string positions");
    AssertEqual(1, mid.ShiftCount, "ifd mid-string shift-count");
    // reason_code_is_stable — the composed reason code for the sole sub-threat.
    AssertEqual<string?>(
        "unicode.security.X.identifier-form-drift.IdentifierStatusShift",
        mia.Classify.ReasonCode,
        "ifd reason code");

    Console.WriteLine("clean: .NET identifier-form-drift detect spot-check passes");
}
static void TestAdmissibilityFormDriftFixture()
{
    using var detector = LoadFixture("detectors/admissibility_form_drift.json");
    AssertEqual(1, detector.RootElement.GetProperty("schema").GetInt32(), "admissibility-form-drift schema");
    AssertEqual("admissibility-form-drift", String(detector.RootElement, "family"), "admissibility-form-drift family");
    var cases = 0;
    foreach (var entry in detector.RootElement.GetProperty("cases").EnumerateArray())
    {
        var name = String(entry, "name");
        var input = Ints(entry.GetProperty("input"));
        var verdict = Afd.Detect(input);
        var required = Strings(entry.GetProperty("required_findings")).ToList();
        if (required.Count == 0)
        {
            AssertTrue(verdict.Classify.IsClear, $"admissibility-form-drift {name}: expected clear, got {verdict.Classify.Tag}");
        }
        else
        {
            foreach (var code in required)
            {
                AssertEqual<string?>(code, verdict.Classify.ReasonCode, $"admissibility-form-drift {name}: reason code");
            }
        }
        cases++;
    }
    Console.WriteLine($"clean: .NET admissibility-form-drift {cases}-case shared-fixture detect passes");
}
static void TestAdmissibilityFormDriftSpotChecks()
{
    string? Tag(int[] input) => Afd.Detect(input).Classify.Tag;

    // ── data-layer sanity (reused UAX #31 default-identifier + UTS #39) ───
    AssertTrue(Afd.IsAllowedIdentifier(new[] { 0x61, 0x64, 0x6D, 0x69, 0x6E }), "afd admissible admin");
    AssertTrue(!Afd.IsAllowedIdentifier(System.Array.Empty<int>()), "afd empty inadmissible");
    AssertTrue(!Afd.IsAllowedIdentifier(new[] { 0xFB01 }), "afd fi-ligature inadmissible");
    AssertTrue(Afd.IsAllowedIdentifier(new[] { 0xD55C }), "afd precomposed-hangul admissible");
    AssertTrue(!Afd.IsAllowedIdentifier(new[] { 0x1112, 0x1161, 0x11AB }), "afd jamo-sequence inadmissible");

    // ── §3 detect spot checks (one per Lean/Rust theorem) ─────────────────
    // detect_empty_clear — both admissibility calls return false, so they agree.
    AssertTrue(Afd.Detect(System.Array.Empty<int>()).Classify.IsClear, "afd empty clear");
    // detect_ascii_clear — "admin"; admissible on both sides (NFKC is identity).
    var admin = Afd.Detect(new[] { 0x61, 0x64, 0x6D, 0x69, 0x6E });
    AssertTrue(admin.Classify.IsClear, "afd ascii-admin clear");
    AssertTrue(admin.InputAdmissible, "afd ascii-admin input admissible");
    AssertTrue(admin.NfkcAdmissible, "afd ascii-admin nfkc admissible");
    // detect_fi_ligature_drift — U+FB01 Restricted (inadmissible), NFKC → "fi".
    var fi = Afd.Detect(new[] { 0xFB01 });
    AssertEqual<string?>("AdmissibilityFormDrift", fi.Classify.Tag, "afd fi-ligature tag");
    AssertTrue(!fi.InputAdmissible, "afd fi-ligature input inadmissible");
    AssertTrue(fi.NfkcAdmissible, "afd fi-ligature nfkc admissible");
    AssertSequence(System.Array.Empty<int>(), fi.Classify.Positions, "afd fi-ligature positions empty");
    // detect_jamo_sequence_drift — [U+1112,U+1161,U+11AB] inadmissible, NFKC → 한.
    AssertEqual<string?>("AdmissibilityFormDrift", Tag(new[] { 0x1112, 0x1161, 0x11AB }), "afd jamo-sequence tag");
    // reason_code_is_stable — the composed reason code for the sole sub-threat.
    AssertEqual<string?>(
        "unicode.security.X.admissibility-form-drift.AdmissibilityFormDrift",
        fi.Classify.ReasonCode,
        "afd reason code");

    Console.WriteLine("clean: .NET admissibility-form-drift detect spot-check passes");
}
static void TestFilenameDisguiseSpotChecks()
{
    string? Tag(int[] input) => Fd.Detect(input).Classify.Tag;

    // ── data-layer sanity (reused predicates) ────────────────────────────
    AssertTrue(Fd.IsAsciiDot(0x2E), "fd ascii dot");
    AssertTrue(!Fd.IsAsciiDot(0x41), "fd ascii dot non-.");
    AssertTrue(Fd.IsBidiFormatControl(0x202E), "fd bidi RLO");
    AssertTrue(Fd.IsBidiFormatControl(0x2067), "fd bidi RLI");
    AssertTrue(!Fd.IsBidiFormatControl(0x0041), "fd bidi non-A");
    AssertTrue(Fd.IsFullwidthHalfwidth(0xFF25), "fd fullwidth E");
    AssertTrue(!Fd.IsFullwidthHalfwidth(0x0045), "fd fullwidth non-E");
    AssertTrue(Fd.IsGraphemeExtend(0x0301), "fd extend combining-acute");
    AssertTrue(!Fd.IsGraphemeExtend(0x0065), "fd extend non-e");

    // ── §5 detect spot checks (one per Lean/Rust theorem) ────────────────
    // detect_empty_clear
    AssertTrue(Fd.Detect(System.Array.Empty<int>()).Classify.IsClear, "fd empty clear");
    // detect_plain_txt_clear — "document.txt"
    var plain = Fd.Detect(new[] { 0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x2E, 0x74, 0x78, 0x74 });
    AssertTrue(plain.Classify.IsClear, "fd plain-txt clear");
    AssertEqual<int?>(8, plain.LastDotPos, "fd plain-txt last-dot");
    // detect_no_extension_clear — "foo"
    var noExt = Fd.Detect(new[] { 0x66, 0x6F, 0x6F });
    AssertTrue(noExt.Classify.IsClear, "fd no-extension clear");
    AssertEqual<int?>(null, noExt.LastDotPos, "fd no-extension last-dot");
    // detect_tar_gz_clear — "archive.tar.gz" (2 dots, below the multi-ext bound)
    AssertTrue(
        Fd.Detect(new[] { 0x61, 0x72, 0x63, 0x68, 0x69, 0x76, 0x65, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A }).Classify.IsClear,
        "fd tar.gz clear");
    // detect_hebrew_clear — native Hebrew name, no bidi controls.
    AssertTrue(
        Fd.Detect(new[] { 0x05D0, 0x05D1, 0x05D2, 0x2E, 0x74, 0x78, 0x74 }).Classify.IsClear,
        "fd hebrew clear");
    // detect_rlo_flip — "document<RLO>txt.exe"
    var rlo = Fd.Detect(new[] { 0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x202E, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65 });
    AssertEqual<string?>("RloFlip", rlo.Classify.Tag, "fd rlo-flip tag");
    AssertSequence(new[] { 8 }, rlo.Classify.Positions, "fd rlo-flip positions");
    // detect_isolate_flip — RLI/PDI isolate variant, also RloFlip.
    AssertEqual<string?>(
        "RloFlip",
        Tag(new[] { 0x64, 0x6F, 0x63, 0x2067, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65, 0x2069 }),
        "fd isolate-flip tag");
    // detect_fullwidth_exe — "file.ＥＸＥ"
    AssertEqual<string?>(
        "WidthClassExt",
        Tag(new[] { 0x66, 0x69, 0x6C, 0x65, 0x2E, 0xFF25, 0xFF38, 0xFF25 }),
        "fd fullwidth-ext tag");
    // detect_combining_in_ext — "file.é xe" (combining acute in the extension)
    AssertEqual<string?>(
        "CombiningInExt",
        Tag(new[] { 0x66, 0x69, 0x6C, 0x65, 0x2E, 0x65, 0x0301, 0x78, 0x65 }),
        "fd combining-in-ext tag");
    // detect_triple_extension — "setup.tar.gz.sig"
    AssertEqual<string?>(
        "MultipleExtensions",
        Tag(new[] { 0x73, 0x65, 0x74, 0x75, 0x70, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A, 0x2E, 0x73, 0x69, 0x67 }),
        "fd triple-extension tag");

    // ── priority-ladder structural check ─────────────────────────────────
    // A bidi control outranks a fullwidth extension.
    AssertEqual<string?>("RloFlip", Tag(new[] { 0x202E, 0x66, 0x2E, 0xFF25 }), "fd bidi-beats-fullwidth");

    Console.WriteLine("clean: .NET filename-disguise data + detect + structural spot-check passes");
}

// Ground truth: the shared context-free detector fixture
// fixtures/security/detectors/source_display_divergence.json, run through the
// aggregator's Detect. Each case asserts the aggregated reason code
// (unicode.security.D.source-display-divergence.<Tag>) or clear.
static void TestSourceDisplayDivergenceFixture()
{
    using var detector = LoadFixture("detectors/source_display_divergence.json");
    AssertEqual(1, detector.RootElement.GetProperty("schema").GetInt32(), "source-display-divergence schema");
    AssertEqual("source-display-divergence", String(detector.RootElement, "family"), "source-display-divergence family");
    var cases = 0;
    foreach (var entry in detector.RootElement.GetProperty("cases").EnumerateArray())
    {
        var name = String(entry, "name");
        var input = Ints(entry.GetProperty("input"));
        var verdict = Sdd.Detect(input);
        var required = Strings(entry.GetProperty("required_findings")).ToList();
        if (required.Count == 0)
        {
            AssertTrue(verdict.Classify.IsClear, $"source-display-divergence {name}: expected clear, got {verdict.Classify.Tag}");
        }
        else
        {
            foreach (var code in required)
            {
                AssertEqual<string?>(code, verdict.Classify.ReasonCode, $"source-display-divergence {name}: reason code");
            }
        }
        cases++;
    }
    Console.WriteLine($"clean: .NET source-display-divergence {cases}-case shared-fixture detect passes");
}

// Ground truth: the detect spot-check theorems in the Rust port's
// source_display_divergence.rs test module. The aggregator reuses the port's own
// five constituent detectors (tag-block-payload, variation-selector-payload,
// zero-width-payload, bidi-control-balance, homoglyph-confusable) from the core
// scan fold — no new predicate, no new data file, no host library. Zero fired →
// clear, one → that family's tag, two or more → Compound.
static void TestSourceDisplayDivergenceSpotChecks()
{
    string? Tag(int[] input) => Sdd.Detect(input).Classify.Tag;

    // ── clear cases ──────────────────────────────────────────────────────
    AssertTrue(Sdd.Detect(System.Array.Empty<int>()).Classify.IsClear, "sdd empty clear");
    // "Hello world"
    AssertTrue(
        Sdd.Detect(new[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64 }).Classify.IsClear,
        "sdd hello-world clear");
    // "let x = 1;"
    AssertTrue(
        Sdd.Detect(new[] { 0x6C, 0x65, 0x74, 0x20, 0x78, 0x20, 0x3D, 0x20, 0x31, 0x3B }).Classify.IsClear,
        "sdd let-x-1 clear");

    // ── single-fire pass-through (one per constituent, canonical order) ───
    // tag-encoded "AB"
    AssertEqual<string?>("TagBlock", Tag(new[] { 0xE0041, 0xE0042 }), "sdd tag-block passthrough");
    // A + VS16
    AssertEqual<string?>("VariationSelector", Tag(new[] { 0x0041, 0xFE0F }), "sdd variation-selector passthrough");
    // H + ZWSP + i
    AssertEqual<string?>("ZeroWidth", Tag(new[] { 0x0048, 0x200B, 0x69 }), "sdd zero-width passthrough");
    // RLO + A
    AssertEqual<string?>("BidiControl", Tag(new[] { 0x202E, 0x41 }), "sdd bidi-control passthrough");
    // "Neth<Cyrillic е>um"
    AssertEqual<string?>(
        "IdentifierHomoglyph",
        Tag(new[] { 0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D }),
        "sdd identifier-homoglyph passthrough");

    // ── two or more fired → Compound ─────────────────────────────────────
    // A + VS16 + ZWSP
    AssertEqual<string?>("Compound", Tag(new[] { 0x0041, 0xFE0F, 0x200B }), "sdd compound vs+zw");
    // tag "AB" + ZWSP
    AssertEqual<string?>("Compound", Tag(new[] { 0xE0041, 0xE0042, 0x200B }), "sdd compound tag+zw");

    // ── reason-code + fired-tags observability ───────────────────────────
    var zw = Sdd.Detect(new[] { 0x0048, 0x200B, 0x69 });
    AssertEqual<string?>(
        "unicode.security.D.source-display-divergence.ZeroWidth",
        zw.Classify.ReasonCode,
        "sdd zero-width reason code");
    AssertEqual<string?>("ZeroWidth", string.Join(",", zw.FiredTags), "sdd zero-width fired-tags");
    var compound = Sdd.Detect(new[] { 0x0041, 0xFE0F, 0x200B });
    AssertEqual<string?>(
        "unicode.security.D.source-display-divergence.Compound",
        compound.Classify.ReasonCode,
        "sdd compound reason code");
    AssertEqual<string?>("VariationSelector,ZeroWidth", string.Join(",", compound.FiredTags), "sdd compound fired-tags");

    Console.WriteLine("clean: .NET source-display-divergence clear + passthrough + compound spot-check passes");
}

// Opaque-blob refinement: structurally valid strict UTF-8 under a size bound,
// validity routed through Security.IsValidUtf8 (the port's strict decoder),
// mirroring ports/rust/src/opaque_blob.rs.
static void TestUtf8Blob()
{
    // Accepted: ASCII, 2-byte (é), 4-byte (😀), empty under any bound.
    AssertTrue(Utf8Blob.Of(new byte[] { 0x41, 0x42 }, 10) is not null, "blob ascii accepted");
    AssertTrue(Utf8Blob.Of(new byte[] { 0xC3, 0xA9 }, 10) is not null, "blob 2-byte accepted");
    AssertTrue(Utf8Blob.Of(new byte[] { 0xF0, 0x9F, 0x98, 0x80 }, 10) is not null, "blob 4-byte accepted");
    AssertTrue(Utf8Blob.Of(System.Array.Empty<byte>(), 0) is not null, "blob empty accepted bound 0");
    AssertTrue(Utf8Blob.Of(System.Array.Empty<byte>(), 5) is not null, "blob empty accepted bound 5");

    // Rejected: overlong C0 80, surrogate ED A0 80, over-bound.
    AssertTrue(Utf8Blob.Of(new byte[] { 0xC0, 0x80 }, 10) is null, "blob overlong rejected");
    AssertTrue(Utf8Blob.Of(new byte[] { 0xED, 0xA0, 0x80 }, 10) is null, "blob surrogate rejected");
    AssertTrue(Utf8Blob.Of(new byte[] { 0x41, 0x42, 0x43 }, 2) is null, "blob over-bound rejected");

    // Predicate agrees with the smart constructor's validity gate.
    AssertTrue(Utf8Blob.IsUtf8Blob(new byte[] { 0xC3, 0xA9 }), "blob predicate valid");
    AssertTrue(!Utf8Blob.IsUtf8Blob(new byte[] { 0xC0, 0x80 }), "blob predicate overlong");

    // Bytes / MaxBytes are carried faithfully.
    var blob = Utf8Blob.Of(new byte[] { 0x41 }, 5);
    AssertTrue(blob is not null, "blob single built");
    AssertSequence(new[] { 0x41 }, blob!.Bytes.Select(b => (int)b).ToList(), "blob bytes roundtrip");
    AssertEqual(5, blob.MaxBytes, "blob max bytes");
    Console.WriteLine("clean: .NET utf8-blob refinement spot-check passes");
}

// ValidatedUtf8 refinement: strict RFC 3629 validity pinned at construction,
// validity routed through Security.IsValidUtf8, mirroring
// ports/rust/src/validated_utf8.rs.
static void TestValidatedUtf8()
{
    // Empty and every well-formed width validate.
    AssertTrue(ValidatedUtf8.Validate(System.Array.Empty<byte>()) is not null, "validated empty accepted");
    AssertTrue(ValidatedUtf8.Validate(new byte[] { 0x41, 0x42 }) is not null, "validated ascii accepted");
    AssertTrue(ValidatedUtf8.Validate(new byte[] { 0xE4, 0xB8, 0xAD }) is not null, "validated 3-byte accepted");
    AssertTrue(ValidatedUtf8.Validate(new byte[] { 0xF0, 0x9F, 0x98, 0x80 }) is not null, "validated 4-byte accepted");

    // Overlong and surrogate forms fail the strict state machine.
    AssertTrue(ValidatedUtf8.Validate(new byte[] { 0xC0, 0x80 }) is null, "validated overlong rejected");
    AssertTrue(ValidatedUtf8.Validate(new byte[] { 0xED, 0xA0, 0x80 }) is null, "validated surrogate rejected");

    // Validate + AsBytes + Unwrap roundtrip preserves the exact bytes.
    var input = new byte[] { 0xF0, 0x9F, 0x98, 0x80, 0x41 };
    var validated = ValidatedUtf8.Validate(input);
    AssertTrue(validated is not null, "validated roundtrip built");
    AssertSequence(input.Select(b => (int)b).ToList(), validated!.AsBytes.Select(b => (int)b).ToList(), "validated as-bytes roundtrip");
    AssertSequence(input.Select(b => (int)b).ToList(), validated.Unwrap().Select(b => (int)b).ToList(), "validated unwrap roundtrip");
    Console.WriteLine("clean: .NET validated-utf8 refinement spot-check passes");
}

// UAX #29 grapheme segmentation targeted vectors, mirroring
// ports/rust/tests/segmentation.rs and the rust grapheme.rs unit tests.
static void TestGraphemeVectors()
{
    AssertBoolSequence(new[] { true, true, true, true }, Grapheme.GraphemeBreaks(new[] { 0x61, 0x62, 0x63 }), "grapheme abc breaks");
    AssertBoolSequence(new[] { true, false, true }, Grapheme.GraphemeBreaks(new[] { 0x65, 0x0301 }), "grapheme e+acute breaks");
    AssertBoolSequence(new[] { true, false, true }, Grapheme.GraphemeBreaks(new[] { 0x0D, 0x0A }), "grapheme CR LF breaks");
    AssertBoolSequence(new[] { true, false, true }, Grapheme.GraphemeBreaks(new[] { 0x1F1EF, 0x1F1F5 }), "grapheme flag pair breaks");

    AssertEqual(3, Grapheme.GraphemeClusters(new[] { 0x61, 0x62, 0x63 }).Count, "grapheme abc clusters");
    AssertEqual(1, Grapheme.GraphemeClusters(new[] { 0x65, 0x0301 }).Count, "grapheme e+acute clusters");
    AssertEqual(1, Grapheme.GraphemeClusters(new[] { 0x1F1EF, 0x1F1F5 }).Count, "grapheme flag pair clusters");
    AssertEqual(2, Grapheme.GraphemeClusters(new[] { 0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8 }).Count, "grapheme four RI clusters");
    AssertEqual(1, Grapheme.GraphemeClusters(new[] { 0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467 }).Count, "grapheme ZWJ family clusters");
    Console.WriteLine("clean: .NET grapheme targeted-vector spot-check passes");
}

// Full UAX #29 conformance corpus. Every "÷"/"×"-marked row of the pinned
// GraphemeBreakTest.txt must reproduce under Grapheme.GraphemeBreaks.
static void TestGraphemeBreakTestFile()
{
    var path = Path.Combine(AppContext.BaseDirectory, "testdata", "GraphemeBreakTest.txt");
    if (!File.Exists(path)) path = Path.Combine("testdata", "GraphemeBreakTest.txt");
    var rows = 0;
    foreach (var raw in File.ReadAllLines(path))
    {
        var hash = raw.IndexOf('#');
        var body = (hash >= 0 ? raw.Substring(0, hash) : raw).Trim();
        if (body.Length == 0)
        {
            continue;
        }
        var tokens = body.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        var codepoints = new List<int>();
        var expected = new List<bool>();
        foreach (var token in tokens)
        {
            if (token == "÷")
            {
                expected.Add(true);
            }
            else if (token == "×")
            {
                expected.Add(false);
            }
            else
            {
                codepoints.Add(Convert.ToInt32(token, 16));
            }
        }
        var actual = Grapheme.GraphemeBreaks(codepoints);
        AssertBoolSequence(expected, actual, $"GraphemeBreakTest row {rows + 1}: [{string.Join(" ", tokens)}]");
        rows++;
    }
    AssertEqual(766, rows, "GraphemeBreakTest row count");
    Console.WriteLine($"clean: .NET GraphemeBreakTest.txt {rows}-row conformance passes");
}

static void AssertBoolSequence(IReadOnlyList<bool> expected, IReadOnlyList<bool> actual, string message)
{
    if (!expected.SequenceEqual(actual))
    {
        throw new Exception($"{message}\nexpected: [{string.Join(",", expected)}]\nactual:   [{string.Join(",", actual)}]");
    }
}

static void AssertEqual<T>(T expected, T actual, string message)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
    {
        throw new Exception($"{message}\nexpected: {expected}\nactual:   {actual}");
    }
}

static void AssertSequence(IReadOnlyList<int> expected, IReadOnlyList<int> actual, string message)
{
    if (!expected.SequenceEqual(actual))
    {
        throw new Exception($"{message}\nexpected: [{string.Join(",", expected)}]\nactual:   [{string.Join(",", actual)}]");
    }
}
